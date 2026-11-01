//! The validating resolver's judgment of a response: secure, insecure, bogus or indeterminate, with the extended
//! error to attach (RFC 4033 §5, RFC 4035 §4.3, §5, RFC 6840 §4, §5, RFC 8914 §4, RFC 7646 §2).
//!
//! Sans I/O (D69): the validator never sends a query. The caller starts a [`Validation`] with the response to
//! check, then asks it what it needs and answers, until it is done:
//!
//! ```
//! # use dedens_dnssec::anchor::TrustAnchors;
//! # use dedens_dnssec::validator::{Limits, Next, Validator, Verdict};
//! # use dedens_proto::{Message, Name, Question, RecordType};
//! let validator = Validator::new(TrustAnchors::root(), Limits::default());
//! let question = Question::new(Name::root(), RecordType::NS);
//! let response = Message::query(1, question.clone());
//! let mut validation = validator.start(&question, &response, 1_700_000_000);
//! let verdict = loop {
//!     match validation.step() {
//!         // Send `ask` with RD, DO and CD set (RFC 6840 §5.9), then give the response, or `None` when
//!         // there is none: a timeout, a network error.
//!         Next::Ask(_ask) => validation.answer(None),
//!         Next::Done(verdict) => break verdict,
//!     }
//! };
//! assert!(matches!(verdict, Verdict::Indeterminate { .. }));
//! ```
//!
//! What the caller owes: the response to a question is of that question, CD set so a bogus zone answers.
//! `now` is the time in Unix seconds, given once per validation: the caches and the pipeline count seconds
//! from any origin, signatures from 1970, so the time of day is the caller's to read (D75).
//!
//! The chain of trust runs top-down: for the zone of each name the validator asks the parent's DS then the
//! zone's DNSKEY, one label at a time from the closest trust anchor, however the response names its signers
//! (RFC 4035 §5.2). The outcome for each zone is written by one private function and read by one other, where
//! a cache of keys goes (06b).

mod chain;
mod response;
mod section;
mod verdict;

use std::collections::HashMap;
use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::{Class, Flags, Message, Name, Question, RecordType};

use self::chain::Zone;
use self::response::Parsed;
pub use self::verdict::{Delegation, InsecureReason, Verdict};
use crate::anchor::TrustAnchors;
use crate::crypto::Budget;
use crate::denial::MaxIterations;

/// What one validation may do before it gives up, so that no response makes the validator loop or work for
/// long (RFC 9276 §3.2, CVE-2023-50387).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Questions one validation may ask the caller: 32 (D75), the DS and DNSKEY of ten labels and the
    /// chains of a few CNAMEs. Past it the verdict is [`Verdict::Indeterminate`].
    pub questions: usize,
    /// Labels of a name the chain of trust may be walked down: 32 (D75). Past it the verdict is
    /// [`Verdict::Indeterminate`].
    pub depth: usize,
    /// The signature checks and NSEC3 hashes of the validation, its chain of trust included (D71). Past it the
    /// verdict is [`Verdict::Bogus`], as an attacker could cause it, and insecure would let one downgrade.
    pub budget: Budget,
    /// The NSEC3 iterations above which a zone's denials are insecure (RFC 9276 §3.2, D74).
    pub iterations: MaxIterations,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            questions: 32,
            depth: 32,
            budget: Budget::default(),
            iterations: MaxIterations::default(),
        }
    }
}

#[derive(Debug)]
struct Config {
    anchors: TrustAnchors,
    limits: Limits,
}

/// The trust anchors and the limits, which validations share.
#[derive(Debug, Clone)]
pub struct Validator {
    config: Arc<Config>,
}

impl Validator {
    /// A validator whose chains of trust start at `anchors`, within `limits`.
    #[must_use]
    pub fn new(anchors: TrustAnchors, limits: Limits) -> Self {
        Self {
            config: Arc::new(Config { anchors, limits }),
        }
    }

    /// Starts validating `response`, the final answer to `question`, at the time `now` (Unix seconds).
    ///
    /// The validation keeps what it needs of `response`. A response that is no answer to `question` (another
    /// name, type or class, no question or more than one, truncated) is [`Verdict::Indeterminate`]. A referral
    /// given here is judged as the answer it is: it has no answer, so its NS records are unsigned data of a secure
    /// zone and it is bogus, or insecure below an insecure zone; use [`Validator::start_referral`] for a referral.
    #[must_use]
    pub fn start(&self, question: &Question<'_>, response: &Message<'_>, now: u64) -> Validation {
        self.begin(question, response, now, Entry::Final)
    }

    /// Starts validating `response`, a referral to a zone below `question`'s name, as far as the parent that sent
    /// it vouches for the delegation: its DS records or their proven absence (RFC 4035 §5.2). The verdict is
    /// [`Verdict::Referral`] and never secure: the NS records and the glue of a referral are not signed by the
    /// parent, so no answer comes of it; the caller follows the delegation and validates the answer of the
    /// child with [`Validator::start`].
    ///
    /// Not a referral (see [`Message::referral`]), or one to a name `question` is not within, or to the root:
    /// [`Verdict::Indeterminate`].
    #[must_use]
    pub fn start_referral(
        &self,
        question: &Question<'_>,
        response: &Message<'_>,
        now: u64,
    ) -> Validation {
        let child = response
            .referral()
            .filter(|child| !child.is_root() && question.name.is_within(child))
            .map(|child| child.clone().into_owned());
        self.begin(question, response, now, Entry::Referral(child))
    }

    fn begin(
        &self,
        question: &Question<'_>,
        response: &Message<'_>,
        now: u64,
        entry: Entry,
    ) -> Validation {
        let question = question.clone().into_owned();
        let response = Arc::new(response.clone().into_owned());
        // Signatures count seconds modulo 2^32 (RFC 4034 §3.1.5).
        let [_, _, _, _, a, b, c, d] = now.to_be_bytes();
        let mut validation = Validation {
            config: Arc::clone(&self.config),
            parsed: Arc::new(Parsed::new(&question, &response.answer, &response.authority)),
            mode: Mode::Final,
            question,
            response,
            now: u32::from_be_bytes([a, b, c, d]),
            answers: HashMap::new(),
            asked: 0,
            pending: None,
            budget: self.config.limits.budget.clone(),
            zones: HashMap::new(),
            done: None,
        };
        if !answers_question(&validation.response, &validation.question) {
            validation.done = Some(Verdict::indeterminate(
                InfoCode::DNSSEC_INDETERMINATE,
                format!(
                    "the response is no complete answer to {} {}",
                    validation.question.name, validation.question.qtype
                ),
            ));
            return validation;
        }
        match entry {
            Entry::Final => {}
            Entry::Referral(None) => {
                validation.done = Some(Verdict::indeterminate(
                    InfoCode::DNSSEC_INDETERMINATE,
                    format!("the response is no referral for {}", validation.question.name),
                ));
                return validation;
            }
            Entry::Referral(Some(child)) => {
                validation.answers.insert(
                    (child.clone(), RecordType::DS),
                    Some(Arc::clone(&validation.response)),
                );
                validation.mode = Mode::Referral(child);
            }
        }
        if matches!(validation.question.qtype, RecordType::DS | RecordType::DNSKEY) {
            validation.answers.insert(
                (
                    validation.question.name.clone(),
                    validation.question.qtype,
                ),
                Some(Arc::clone(&validation.response)),
            );
        }
        validation
    }
}

/// Whether `response` is a whole answer to `question`: its only question, in class IN (RFC 9619 §4), and not
/// truncated (RFC 1035 §4.1.1: the part that came is no proof of what was cut).
fn answers_question(response: &Message<'_>, question: &Question<'_>) -> bool {
    question.qclass == Class::IN
        && !response.header.flags.contains(Flags::TC)
        && matches!(
            response.questions.as_slice(),
            [got] if got.name == question.name && got.qtype == question.qtype && got.qclass == Class::IN
        )
}

/// What a [`Validation`] wants next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Send this question and give the response to [`Validation::answer`]: with RD, DO and CD set (RFC 6840
    /// §5.9), so that a zone that fails validation still answers.
    Ask(Question<'static>),
    /// The validation is over.
    Done(Verdict),
}

/// What a validation needs of an answer: its question.
struct Need(Question<'static>);

/// How a validation was started: for a referral, its child, or none when the response is not one.
enum Entry {
    Final,
    Referral(Option<Name<'static>>),
}

/// What the response is validated as.
#[derive(Debug, Clone)]
enum Mode {
    /// The final answer to the question.
    Final,
    /// A referral to this child: its delegation is what is judged.
    Referral(Name<'static>),
}

/// One response being validated, and what it asked and learned on the way (RFC 4035 §5).
#[derive(Debug)]
pub struct Validation {
    config: Arc<Config>,
    question: Question<'static>,
    response: Arc<Message<'static>>,
    /// The response's sections, read once.
    parsed: Arc<Parsed>,
    mode: Mode,
    /// The time, in seconds modulo 2^32.
    now: u32,
    /// The responses given, by question; `None` for a question that got none.
    answers: HashMap<(Name<'static>, RecordType), Option<Arc<Message<'static>>>>,
    asked: usize,
    pending: Option<Question<'static>>,
    budget: Budget,
    /// What the walk found of each name that is, or sits below, an apex: written by `settle` only, read by
    /// `zone_of` only, never an outcome of a limit (06b caches these).
    zones: HashMap<Name<'static>, Zone>,
    done: Option<Verdict>,
}

impl Validation {
    /// What the validation needs: a question to ask, or the verdict.
    ///
    /// Asking again before [`Validation::answer`] repeats the question. Asking after the verdict repeats it.
    pub fn step(&mut self) -> Next {
        if let Some(verdict) = &self.done {
            return Next::Done(verdict.clone());
        }
        if let Some(question) = &self.pending {
            return Next::Ask(question.clone());
        }
        match self.judge() {
            Ok(verdict) => self.finish(verdict),
            Err(Need(_)) if self.asked >= self.config.limits.questions => {
                let limit = self.config.limits.questions;
                self.finish(Verdict::indeterminate(
                    InfoCode::DNSSEC_INDETERMINATE,
                    format!("{} needs more than {limit} questions", self.question.name),
                ))
            }
            Err(Need(question)) => {
                self.asked += 1;
                self.pending = Some(question.clone());
                Next::Ask(question)
            }
        }
    }

    fn finish(&mut self, verdict: Verdict) -> Next {
        self.done = Some(verdict.clone());
        Next::Done(verdict)
    }

    /// Gives the response to the question last asked, or `None` when there was none: the query failed.
    ///
    /// A response that is no complete answer to that question (see [`Validator::start`]) counts as none, and
    /// so does a truncated one, which leaves the validation [`Verdict::Indeterminate`], never bogus. Nothing
    /// happens when no question is pending.
    pub fn answer(&mut self, response: Option<&Message<'_>>) {
        let Some(question) = self.pending.take() else {
            return;
        };
        let response = response
            .filter(|message| answers_question(message, &question))
            .map(|message| Arc::new(message.clone().into_owned()));
        self.answers
            .insert((question.name, question.qtype), response);
    }
}
