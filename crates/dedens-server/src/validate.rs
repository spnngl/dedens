//! DNSSEC validation in the forward stage (D77): what `dedens_dnssec`'s validator needs from the pipeline, and what
//! a response is once its verdict is known.
//!
//! The pipeline asks upstream with DO and CD (RFC 6840 §5.9) and validates the response itself: only a secure
//! verdict sets AD, whatever the AD bit upstream says (RFC 6840 §5.8). Each question the validator asks, DS and
//! DNSKEY, is one more query to the upstream servers, kept in a [`Check`]; its response is untrusted input the
//! validator checks. The answer cache is not read for them: a cache of keys belongs to the validator (D75), and
//! slots in [`Check::answer`].

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use dedens_dnssec::validator::{Cost, Next, Validation, Validator, Verdict, covered};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Decoded, Flags, Message, Question, RecordType, Ttl};

use crate::metrics::Metrics;

/// Seconds since the Unix epoch, as signatures count them: read each time a response starts being validated.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Questions one client query may cost upstream, the validator's own limit and the chasing of CNAME chains
/// included: past it the verdict is indeterminate.
const MAX_QUESTIONS: u16 = 64;

/// Names of a CNAME chain one client query chases, as far as `dedens` chases (`apps/dedens/src/validate.rs`): past
/// it the verdict is indeterminate. The validator leaves the chasing to the caller, and an upstream's chain is
/// untrusted input.
const MAX_CHASES: u8 = 8;

/// SHA-1 blocks of NSEC3 hashing that cost one unit of [`Allowance`]: 4096 blocks take about as long as a
/// signature check of the slowest key (`docs/benchmarks.md`).
const BLOCKS_PER_UNIT: u32 = 4096;

/// What the queries of all clients may cost a validating forward stage, in units (D77): a client's question
/// upstream, a question of the validator's, a signature verification, or 4096 SHA-1 blocks of NSEC3 hashing (a
/// hash of a short name with no salt is one block per iteration, D106). A unit takes about 10
/// µs of a core on the checks of the common algorithms and up to 340 µs on a P-384 one (`docs/benchmarks.md`).
/// A response from the cache costs none, a validation that finds the zone's keys in the validator's key cache
/// (D86) two units.
///
/// A token bucket: `burst` units, refilled `per_second`. A query that finds none left is answered SERVFAIL without
/// being validated. A query started with one left may run into debt, as the bucket does not tell what a query will
/// cost before it runs, but a query that finds the bucket in debt asks no more questions and is answered the same
/// (D106): the work past the first debt is one validation step of each query running then, at most 130 units a
/// step, and `per_query` bounds a query only to within the step that goes over it. The debt is kept down to
/// `burst` units and no further (the rest is forgiven), so that validation is back `burst / per_second + 1`
/// seconds after a flood of expensive queries stops, however large it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowance {
    /// Units refilled each second: the sustained rate of validation work.
    pub per_second: u32,
    /// Units the bucket holds at most: the work a flood after a quiet time may cost. Also the largest debt it
    /// keeps (D106).
    pub burst: u32,
    /// Units one client query may cost, its CNAME chain included: past it the verdict is indeterminate.
    pub per_query: u32,
}

impl Default for Allowance {
    /// A tenth of a core on the common algorithms, a few cores on P-384 alone, and two seconds of burst.
    fn default() -> Self {
        Self {
            per_second: 10_000,
            burst: 20_000,
            per_query: 256,
        }
    }
}

/// The units left of an [`Allowance`], shared by the clones of a [`Validating`].
#[derive(Debug)]
struct Bucket {
    allowance: Allowance,
    state: Mutex<Tokens>,
}

#[derive(Debug)]
struct Tokens {
    /// Negative in debt.
    units: i64,
    /// The latest time the clock read, in seconds: it never goes back, and the bucket is not refilled by it going
    /// forward again.
    at: Option<u64>,
}

impl Bucket {
    fn new(allowance: Allowance) -> Self {
        Self {
            allowance,
            state: Mutex::new(Tokens {
                units: i64::from(allowance.burst),
                at: None,
            }),
        }
    }

    /// Whether a query may start at `now`: some unit is left, after the refill, and is taken.
    fn admit(&self, now: u64) -> bool {
        let mut tokens = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(at) = tokens.at.filter(|at| *at < now) {
            let refill = u64::from(self.allowance.per_second).saturating_mul(now - at);
            let burst = i64::from(self.allowance.burst);
            tokens.units = tokens
                .units
                .saturating_add(i64::try_from(refill).unwrap_or(i64::MAX))
                .min(burst);
        }
        tokens.at = tokens.at.max(Some(now));
        let admitted = tokens.units > 0;
        if admitted {
            tokens.units = tokens.units.saturating_sub(1);
        }
        admitted
    }

    /// Whether work done left the bucket owing units: a query in this state asks no more questions (D106).
    fn in_debt(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .units
            < 0
    }

    /// Takes `units` of work done, down to a debt of one burst and no further (D106).
    fn charge(&self, units: u32) {
        let mut tokens = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let floor = -i64::from(self.allowance.burst);
        tokens.units = tokens.units.saturating_sub(i64::from(units)).max(floor);
    }
}

/// The validator, the clock and the allowance of a forward stage (D77).
#[derive(Clone)]
pub struct Validating {
    validator: Validator,
    clock: Clock,
    bucket: Arc<Bucket>,
    metrics: Metrics,
    tag: Arc<str>,
}

impl fmt::Debug for Validating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Validating")
            .field("validator", &self.validator)
            .finish_non_exhaustive()
    }
}

impl Validating {
    /// Validates with `validator`, at the time `clock` reads.
    #[must_use]
    pub fn new(validator: Validator, clock: Clock) -> Self {
        Self {
            validator,
            clock,
            bucket: Arc::new(Bucket::new(Allowance::default())),
            metrics: Metrics::new(),
            tag: Arc::from(""),
        }
    }

    /// Bounds what the queries cost to `allowance` instead of [`Allowance::default`]: the clones of the result
    /// share one bucket.
    #[must_use]
    pub fn allowing(mut self, allowance: Allowance) -> Self {
        self.bucket = Arc::new(Bucket::new(allowance));
        self
    }

    /// Names the settings of the validator, the trust anchors and what else it was built from, which it cannot
    /// tell: [`Forward::validation_tag`](crate::Forward::validation_tag) gives it back, for a caller to tell
    /// whether two forward stages validate the same way.
    #[must_use]
    pub fn tagged(mut self, tag: &str) -> Self {
        self.tag = Arc::from(tag);
        self
    }

    /// The name [`Validating::tagged`] gave the validation, empty if none.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The validator, whose clones share its cache of keys.
    #[must_use]
    pub const fn validator(&self) -> &Validator {
        &self.validator
    }

    pub(crate) const fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Whether a query to validate may start: the allowance has units left, one of which the client's question
    /// costs. Counted when not (D77).
    pub(crate) fn admit(&self) -> bool {
        let admitted = self.bucket.admit((self.clock)());
        if !admitted {
            self.metrics.shed();
        }
        admitted
    }

    fn start(&self, question: &Question<'_>, response: &Message<'_>) -> Validation {
        self.validator.start(question, response, (self.clock)())
    }
}

/// What validation made of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Authentic: AD is set.
    Secure,
    /// Not validated, or not to be: AD clear, the response as it is.
    Insecure,
    /// Failed validation: SERVFAIL with this error (RFC 4035 §5.5).
    Bogus(InfoCode),
    /// No verdict: SERVFAIL with this error, and the failure held.
    Indeterminate(InfoCode),
}

/// What a [`Check`] wants next.
pub(crate) enum Progress {
    /// Ask [`Check::asking`] of the upstream servers and give the response to [`Check::answer`].
    Ask,
    Done(Outcome),
    /// The allowance is in debt (D106): stop, with the answer of a query refused at [`Validating::admit`]. Not an
    /// [`Outcome`]: no verdict, and no failure to hold, as the response is not at fault.
    Shed,
}

/// The validation of one upstream response, between the questions it asks.
#[derive(Debug)]
pub(crate) struct Check {
    validation: Validation,
    /// The response to the client's question, to hand out once checked.
    answer: Decoded<'static>,
    /// The question to ask upstream: the validator's, or the name a CNAME chain goes on at.
    asking: Question<'static>,
    /// Whether `asking` is a chased name: its response is validated as one of its own.
    chasing: bool,
    /// Whether a chain was chased: the answer is then not wholly authentic.
    chased: bool,
    /// The client's question type: a chased name is asked for it.
    qtype: RecordType,
    /// The least TTL the verdicts allow the records.
    cap: Option<Ttl>,
    sent: u16,
    /// The names chased so far, at most [`MAX_CHASES`].
    chases: u8,
    /// The work of the validations of the names chased before, in units.
    done: u32,
    /// What the allowance was charged so far, in units.
    charged: u32,
}

impl Check {
    /// Starts validating `response`, upstream's answer to `question`.
    pub(crate) fn new(
        validating: &Validating,
        question: &Question<'_>,
        response: Decoded<'static>,
    ) -> Self {
        Self {
            validation: validating.start(question, &response.message),
            answer: response,
            asking: question.clone().into_owned(),
            chasing: false,
            chased: false,
            qtype: question.qtype,
            cap: None,
            sent: 0,
            chases: 0,
            done: 0,
            charged: 0,
        }
    }

    /// The question to ask upstream, once [`Check::next`] said [`Progress::Ask`].
    pub(crate) const fn asking(&self) -> &Question<'static> {
        &self.asking
    }

    /// The least TTL the verdicts allow the records, if any limits them.
    pub(crate) const fn cap(&self) -> Option<Ttl> {
        self.cap
    }

    /// The response to the client's question.
    pub(crate) fn into_answer(self) -> Decoded<'static> {
        self.answer
    }

    /// What to do next: ask [`Check::asking`], or the outcome. What the query has cost since the last time is
    /// charged to `validating`'s allowance, after the step: a query past [`Allowance::per_query`] gets no more
    /// questions, nor one that finds the allowance in debt (D106), which is counted shed.
    pub(crate) fn next(&mut self, validating: &Validating) -> Progress {
        let progress = self.advance();
        let spent = self.spent();
        validating.bucket.charge(spent.saturating_sub(self.charged));
        self.charged = spent;
        if matches!(progress, Progress::Ask) {
            if spent > validating.bucket.allowance.per_query {
                return Progress::Done(Outcome::Indeterminate(InfoCode::DNSSEC_INDETERMINATE));
            }
            if validating.bucket.in_debt() {
                validating.metrics.shed();
                return Progress::Shed;
            }
        }
        progress
    }

    /// What the query has cost so far, in units: the questions sent and the work of its validations.
    fn spent(&self) -> u32 {
        u32::from(self.sent)
            .saturating_add(self.done)
            .saturating_add(work(self.validation.cost()))
    }

    /// The next step of the validation, without the allowance.
    ///
    /// An incomplete verdict is a CNAME chain that stops short of the type asked: the name it goes on at is asked,
    /// and the response validated as one of its own. The answer to the client stays the first response and is
    /// never secure: AD says all of an answer is authentic (RFC 6840 §5.8), and the rest of the chain was left
    /// out of it.
    fn advance(&mut self) -> Progress {
        if self.chasing {
            return self.ask();
        }
        match self.validation.step() {
            Next::Ask(question) => {
                self.asking = question;
                self.ask()
            }
            Next::Done(Verdict::Incomplete { .. }) if self.chases >= MAX_CHASES => {
                Progress::Done(Outcome::Indeterminate(InfoCode::DNSSEC_INDETERMINATE))
            }
            Next::Done(Verdict::Incomplete { next, ttl }) => {
                self.limit(ttl);
                self.chases += 1;
                self.asking = Question::new(next, self.qtype);
                self.chasing = true;
                self.chased = true;
                self.ask()
            }
            Next::Done(Verdict::Secure { ttl }) => {
                self.limit(ttl);
                Progress::Done(if self.chased {
                    Outcome::Insecure
                } else {
                    Outcome::Secure
                })
            }
            // A referral is no answer; the validator gives it for `start_referral` only.
            Next::Done(Verdict::Insecure { .. } | Verdict::Referral { .. }) => {
                Progress::Done(Outcome::Insecure)
            }
            Next::Done(Verdict::Bogus { ede }) => Progress::Done(Outcome::Bogus(ede.code)),
            Next::Done(Verdict::Indeterminate { ede }) => {
                Progress::Done(Outcome::Indeterminate(ede.code))
            }
        }
    }

    fn ask(&mut self) -> Progress {
        if self.sent >= MAX_QUESTIONS {
            return Progress::Done(Outcome::Indeterminate(InfoCode::DNSSEC_INDETERMINATE));
        }
        self.sent += 1;
        Progress::Ask
    }

    fn limit(&mut self, ttl: Ttl) {
        self.cap = Some(self.cap.map_or(ttl, |cap| cap.min(ttl)));
    }

    /// Gives the response to the question asked, `None` when the servers gave none. Untrusted: the validator
    /// checks it is the answer to the question, and what it proves.
    pub(crate) fn answer(&mut self, validating: &Validating, response: Option<&Message<'_>>) {
        if self.chasing {
            self.chasing = false;
            self.done = self.done.saturating_add(work(self.validation.cost()));
            // No response is no answer to the name: indeterminate, never the first response alone.
            self.validation =
                validating.start(&self.asking, response.unwrap_or(&Message::default()));
        } else {
            self.validation.answer(response);
        }
    }
}

/// The units a validation's work cost: its signature verifications and NSEC3 hashing (`Cost::nsec3_blocks` counts
/// SHA-1 blocks, D106).
fn work(cost: Cost) -> u32 {
    cost.verifications
        .saturating_add(cost.nsec3_blocks.div_ceil(BLOCKS_PER_UNIT))
}

/// Makes `message`, upstream's response, what the client of `outcome` gets (RFC 4035 §3.2): AD set for a secure
/// one only, clear otherwise, whatever upstream said (RFC 6840 §5.8).
///
/// A secure response is cut to what the verdict covers, by [`covered()`]: not the additional section (RFC 4035
/// §3.2.3), nor a set the validator ignored. The records' TTL is at most `cap`. A client without DO gets no
/// signature nor denial record it did not ask for (RFC 4035 §3.2.1).
pub(crate) fn present(
    message: &mut Message<'static>,
    outcome: Outcome,
    cap: Option<Ttl>,
    dnssec_ok: bool,
) {
    let secure = outcome == Outcome::Secure;
    if secure {
        *message = covered(message);
    }
    if let Some(cap) = cap {
        for record in message
            .answer
            .iter_mut()
            .chain(&mut message.authority)
            .chain(&mut message.additional)
        {
            record.ttl = record.ttl.min(cap);
        }
    }
    let flags = message.header.flags.without(Flags::AD);
    message.header.flags = if secure { flags.with(Flags::AD) } else { flags };
    if !dnssec_ok {
        let asked = message.questions.first().map(|question| question.qtype);
        let unasked = |rtype: RecordType| {
            matches!(
                rtype,
                RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
            ) && asked != Some(rtype)
        };
        for section in [
            &mut message.answer,
            &mut message.authority,
            &mut message.additional,
        ] {
            section.retain(|record| !unasked(record.rtype()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D106: the debt stops at one burst. 10 000 queries admitted together, each then charged `per_query`, would
    /// leave 2.5 million units owed, 256 s of refill; the bucket admits again once `burst / per_second + 1`
    /// seconds have passed, and not before the debt is paid down to nothing.
    #[test]
    fn the_debt_of_a_flood_stops_at_one_burst() {
        let allowance = Allowance::default();
        let bucket = Bucket::new(allowance);
        let start = 1_000;
        assert!((0..10_000).all(|_| bucket.admit(start)));
        for _ in 0..10_000 {
            bucket.charge(allowance.per_query);
        }
        let repay = u64::from(allowance.burst / allowance.per_second);
        assert!(!bucket.admit(start));
        assert!(!bucket.admit(start + repay));
        assert!(bucket.admit(start + repay + 1));
    }

    /// D106: the bucket is in debt once work done took more than it held, and not before.
    #[test]
    fn the_bucket_is_in_debt_only_below_zero() {
        let bucket = Bucket::new(Allowance {
            per_second: 1,
            burst: 10,
            per_query: 256,
        });
        assert!(bucket.admit(1));
        bucket.charge(9);
        assert!(!bucket.in_debt());
        bucket.charge(1);
        assert!(bucket.in_debt());
    }

    /// D106: a debt within the burst is kept whole, so that the clamp costs a query that owes less nothing.
    #[test]
    fn a_debt_within_the_burst_is_repaid_as_owed() {
        let allowance = Allowance {
            per_second: 10,
            burst: 100,
            per_query: 256,
        };
        let bucket = Bucket::new(allowance);
        assert!(bucket.admit(1));
        bucket.charge(150);
        // 100 - 1 - 150 = -51: five seconds repay 50, which leaves a unit owed; a sixth admits.
        assert!(!bucket.admit(6));
        assert!(bucket.admit(7));
    }
}
