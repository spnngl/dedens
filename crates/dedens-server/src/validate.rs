//! DNSSEC validation in the forward stage (D77): what `dedens_dnssec`'s validator needs from the pipeline, and what
//! a response is once its verdict is known.
//!
//! The pipeline asks upstream with DO and CD (RFC 6840 §5.9) and validates the response itself: only a secure
//! verdict sets AD, whatever the AD bit upstream says (RFC 6840 §5.8). Each question the validator asks, DS and
//! DNSKEY, is one more query to the upstream servers, kept in a [`Check`]; its response is untrusted input the
//! validator checks. The answer cache is not read for them: a cache of keys belongs to the validator (D75), and
//! slots in [`Check::answer`].

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use dedens_dnssec::validator::{Cost, Next, Validation, Validator, Verdict, covered};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Decoded, Flags, Message, Question, RecordType, Ttl};

use crate::budget::{Budget, Budgets, MAX_BUDGET, Slot};
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

/// What a client network may spend of the [`Allowance`] by default, a /24 of IPv4 or a /48 of IPv6 (D117): a tenth
/// of its rate and burst, so that ten networks spending it together spend it all, over a table of 65 536 buckets,
/// 512 KiB.
pub const DEFAULT_SHARE: Budget = Budget {
    per_second: 1_000,
    burst: 2_000,
    table: 1 << 16,
};

/// Where a query comes from, for the share of the allowance it spends (D117).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Source {
    pub(crate) address: IpAddr,
    /// Whether the address cannot be spoofed: a connection, or a valid Server Cookie (D113). The queries of a
    /// proven address have a share of their own, so that a flood from spoofed sources of its network, which a
    /// UDP server cannot tell from the network's own, does not shed them.
    pub(crate) proven: bool,
}

/// A query admitted: the share it spends of the allowance, if any (D117).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Admitted {
    share: Option<Slot>,
}

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
/// seconds after a flood of expensive queries stops, however large it was. A burst over [`MAX_BUDGET`] is
/// taken as that.
///
/// A client network spends it only up to its share, [`DEFAULT_SHARE`] (D117): a query of a network that spent its
/// own is shed the same way, counted as `shed_share`, and does not touch the units the others share. Sources on
/// the rate limit's exempt list (D113) have no share.
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

/// The validator, the clock and the allowance of a forward stage (D77).
#[derive(Clone)]
pub struct Validating {
    validator: Validator,
    clock: Clock,
    allowance: Allowance,
    /// The allowance of all clients: a table of one bucket.
    bucket: Arc<Budgets>,
    /// What each client network may spend of it (D117).
    shares: Arc<Budgets>,
    /// Boxed: a forward stage holds one, and the stages of a pipeline are of the size of the largest.
    metrics: Arc<Metrics>,
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
    ///
    /// # Panics
    ///
    /// Never: [`DEFAULT_SHARE`] is within the bounds of [`Budgets::new`].
    #[must_use]
    pub fn new(validator: Validator, clock: Clock) -> Self {
        Self {
            validator,
            clock,
            allowance: Allowance::default(),
            bucket: Arc::new(global(Allowance::default())),
            shares: Arc::new(Budgets::new(DEFAULT_SHARE).expect("the default share is in bounds")),
            metrics: Arc::new(Metrics::new()),
            tag: Arc::from(""),
        }
    }

    /// Bounds what the queries cost to `allowance` instead of [`Allowance::default`]: the clones of the result
    /// share one bucket.
    #[must_use]
    pub fn allowing(mut self, allowance: Allowance) -> Self {
        self.allowance = allowance;
        self.bucket = Arc::new(global(allowance));
        self
    }

    /// Bounds what each client network may spend of the allowance to `shares` instead of [`DEFAULT_SHARE`] (D117):
    /// the clones of the result share the buckets. Time counts in seconds of the pipeline's clock, the `now` of
    /// [`Pipeline::query`](crate::Pipeline::query).
    #[must_use]
    pub fn sharing(mut self, shares: Budgets) -> Self {
        self.shares = Arc::new(shares);
        self
    }

    /// The settings of the shares of the client networks.
    #[must_use]
    pub fn share(&self) -> Budget {
        self.shares.config()
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

    pub(crate) fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Whether a query to validate may start at second `now` (the clock of the cache, D43): its share has units
    /// left, then the allowance has, and one of each is taken for the client's question. Counted when not (D77,
    /// D117).
    ///
    /// The share is taken first, so that a client over it never touches the allowance of the others; its unit is
    /// given back when the allowance refuses. A source on the rate limit's exempt list (D113), `exempt`, has no
    /// share.
    pub(crate) fn admit(&self, source: Source, exempt: bool, now: u32) -> Option<Admitted> {
        let share = (!exempt).then(|| Slot::new(source.address, source.proven));
        if let Some(share) = share
            && !self.shares.admit(share, now)
        {
            self.metrics.shed_share();
            return None;
        }
        if !self.bucket.admit(Slot::ONLY, now) {
            if let Some(share) = share {
                self.shares.refund(share);
            }
            self.metrics.shed();
            return None;
        }
        Some(Admitted { share })
    }

    /// Takes `units` of work done for `admitted` from its share and from the allowance (D106).
    fn charge(&self, admitted: Admitted, units: u32) {
        if let Some(share) = admitted.share {
            self.shares.charge(share, units);
        }
        self.bucket.charge(Slot::ONLY, units);
    }

    /// Counts and tells whether the share of `admitted` or the allowance owes units (D106).
    fn shed(&self, admitted: Admitted) -> bool {
        if admitted
            .share
            .is_some_and(|share| self.shares.in_debt(share))
        {
            self.metrics.shed_share();
            return true;
        }
        if self.bucket.in_debt(Slot::ONLY) {
            self.metrics.shed();
            return true;
        }
        false
    }

    fn start(&self, question: &Question<'_>, response: &Message<'_>) -> Validation {
        self.validator.start(question, response, (self.clock)())
    }
}

/// The allowance of all clients as one bucket.
fn global(allowance: Allowance) -> Budgets {
    Budgets::new(Budget {
        per_second: allowance.per_second,
        burst: allowance.burst.min(MAX_BUDGET),
        table: 1,
    })
    .expect("a burst within the bound and one bucket are in bounds")
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
    /// The allowance or the client's share is in debt (D106, D117): stop, with the answer of a query refused at
    /// [`Validating::admit`]. Not an [`Outcome`]: no verdict, and no failure to hold, as the response is not at
    /// fault.
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
    /// The share of the allowance the client spends (D117), charged with it.
    admitted: Admitted,
}

impl Check {
    /// Starts validating `response`, upstream's answer to `question`.
    pub(crate) fn new(
        validating: &Validating,
        question: &Question<'_>,
        response: Decoded<'static>,
        admitted: Admitted,
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
            admitted,
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
    /// charged to `validating`'s allowance and the client's share of it, after the step: a query past
    /// [`Allowance::per_query`] gets no more questions, nor one that finds either in debt (D106, D117), which is
    /// counted shed.
    pub(crate) fn next(&mut self, validating: &Validating) -> Progress {
        let progress = self.advance();
        let spent = self.spent();
        validating.charge(self.admitted, spent.saturating_sub(self.charged));
        self.charged = spent;
        if matches!(progress, Progress::Ask) {
            if spent > validating.allowance.per_query {
                return Progress::Done(Outcome::Indeterminate(InfoCode::DNSSEC_INDETERMINATE));
            }
            if validating.shed(self.admitted) {
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

    /// D117: a query the allowance refuses gives back the unit it took of its share, so that the clients of a
    /// network are not shed for the others' shed queries.
    #[test]
    fn a_query_the_allowance_refuses_keeps_its_unit_of_the_share() {
        let validating = Validating::new(
            Validator::new(
                dedens_dnssec::anchor::TrustAnchors::root(),
                dedens_dnssec::validator::Limits::default(),
            ),
            Arc::new(|| 0),
        )
        .allowing(Allowance {
            per_second: 1,
            burst: 0,
            per_query: 1,
        })
        .sharing(
            Budgets::new(Budget {
                per_second: 1,
                burst: 1,
                table: 1,
            })
            .expect("a share in bounds"),
        );
        let source = Source {
            address: IpAddr::from([192, 0, 2, 1]),
            proven: false,
        };
        // The allowance holds nothing; the share's one unit is given back each time.
        assert!(
            (0..10).all(|_| validating.admit(source, false, 0).is_none()),
            "the share is not drained by the shed"
        );
        let slot = Slot::new(source.address, source.proven);
        assert!(validating.shares.admit(slot, 0));
    }

    /// D106: a verification is a unit, and so is each started 4096 SHA-1 blocks of NSEC3 hashing.
    #[test]
    fn the_work_counts_verifications_and_started_units_of_hashing() {
        let mut cost = Cost::default();
        assert_eq!(work(cost), 0);
        cost.verifications = 5;
        cost.nsec3_blocks = BLOCKS_PER_UNIT + 1;
        assert_eq!(work(cost), 7);
    }
}
