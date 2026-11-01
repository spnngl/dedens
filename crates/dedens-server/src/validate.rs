//! DNSSEC validation in the forward stage (D77): what `dedens_dnssec`'s validator needs from the pipeline, and what
//! a response is once its verdict is known.
//!
//! The pipeline asks upstream with DO and CD (RFC 6840 §5.9) and validates the response itself: only a secure
//! verdict sets AD, whatever the AD bit upstream says (RFC 6840 §5.8). Each question the validator asks, DS and
//! DNSKEY, is one more query to the upstream servers, kept in a [`Check`]; its response is untrusted input the
//! validator checks. The answer cache is not read for them: a cache of keys belongs to the validator (D75), and
//! slots in [`Check::answer`].

use std::fmt;
use std::sync::Arc;

use dedens_dnssec::validator::{Next, Validation, Validator, Verdict};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Class, Decoded, Flags, Message, Question, RecordType, Ttl};

use crate::metrics::Metrics;

/// Seconds since the Unix epoch, as signatures count them: read each time a response starts being validated.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Questions one client query may cost upstream, the validator's own limit and the chasing of CNAME chains
/// included: past it the verdict is indeterminate.
const MAX_QUESTIONS: u16 = 64;

/// The validator and the clock of a forward stage (D77).
#[derive(Clone)]
pub struct Validating {
    validator: Validator,
    clock: Clock,
    metrics: Metrics,
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
            metrics: Metrics::new(),
        }
    }

    pub(crate) const fn metrics(&self) -> &Metrics {
        &self.metrics
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

    /// What to do next: ask [`Check::asking`], or the outcome.
    ///
    /// An incomplete verdict is a CNAME chain that stops short of the type asked: the name it goes on at is asked,
    /// and the response validated as one of its own. The answer to the client stays the first response and is
    /// never secure: AD says all of an answer is authentic (RFC 6840 §5.8), and the rest of the chain was left
    /// out of it.
    pub(crate) fn next(&mut self) -> Progress {
        if self.chasing {
            return self.ask();
        }
        match self.validation.step() {
            Next::Ask(question) => {
                self.asking = question;
                self.ask()
            }
            Next::Done(Verdict::Incomplete { next, ttl }) => {
                self.limit(ttl);
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
            // No response is no answer to the name: indeterminate, never the first response alone.
            self.validation =
                validating.start(&self.asking, response.unwrap_or(&Message::default()));
        } else {
            self.validation.answer(response);
        }
    }
}

/// Makes `message`, upstream's response, what the client of `outcome` gets (RFC 4035 §3.2): AD set for a secure
/// one only, clear otherwise, whatever upstream said (RFC 6840 §5.8).
///
/// A secure response is cut to what the verdict covers: IN records of the answer and authority sections, not the
/// additional section (RFC 4035 §3.2.3). The unsigned CNAME of a DNAME stays: the validator only accepts the one
/// the DNAME makes. The records' TTL is at most `cap`. A client without DO gets no signature nor denial record
/// it did not ask for (RFC 4035 §3.2.1).
pub(crate) fn present(
    message: &mut Message<'static>,
    outcome: Outcome,
    cap: Option<Ttl>,
    dnssec_ok: bool,
) {
    let secure = outcome == Outcome::Secure;
    if secure {
        message.additional.clear();
        message.answer.retain(|record| record.class == Class::IN);
        message.authority.retain(|record| record.class == Class::IN);
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
