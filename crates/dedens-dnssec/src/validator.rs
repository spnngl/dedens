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
use dedens_proto::{Message, Name, Question, RecordType};

use self::chain::{Delegation, Zone};
pub use self::verdict::{InsecureReason, Verdict};
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

    /// Starts validating `response` to `question`, at the time `now` (Unix seconds).
    ///
    /// The validation keeps what it needs of `response`. A response that is a referral, or the answer to a DS
    /// or DNSKEY question, is also the one the validation would otherwise ask for.
    #[must_use]
    pub fn start(&self, question: &Question<'_>, response: &Message<'_>, now: u64) -> Validation {
        let question = question.clone().into_owned();
        let response = Arc::new(response.clone().into_owned());
        let mut answers = HashMap::new();
        if matches!(question.qtype, RecordType::DS | RecordType::DNSKEY) {
            answers.insert(
                (question.name.clone(), question.qtype),
                Some(Arc::clone(&response)),
            );
        }
        if let Some(child) = response
            .referral()
            .filter(|child| question.name.is_within(child))
        {
            answers.insert(
                (child.clone().into_owned(), RecordType::DS),
                Some(Arc::clone(&response)),
            );
        }
        // Signatures count seconds modulo 2^32 (RFC 4034 §3.1.5).
        let [_, _, _, _, a, b, c, d] = now.to_be_bytes();
        Validation {
            config: Arc::clone(&self.config),
            question,
            response,
            now: u32::from_be_bytes([a, b, c, d]),
            answers,
            asked: 0,
            pending: None,
            budget: self.config.limits.budget.clone(),
            zones: HashMap::new(),
            cuts: HashMap::new(),
            done: None,
        }
    }
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

/// One response being validated, and what it asked and learned on the way (RFC 4035 §5).
#[derive(Debug)]
pub struct Validation {
    config: Arc<Config>,
    question: Question<'static>,
    response: Arc<Message<'static>>,
    /// The time, in seconds modulo 2^32.
    now: u32,
    /// The responses given, by question; `None` for a question that got none.
    answers: HashMap<(Name<'static>, RecordType), Option<Arc<Message<'static>>>>,
    asked: usize,
    pending: Option<Question<'static>>,
    budget: Budget,
    /// What the walk found of each name that is, or sits below, an apex.
    zones: HashMap<Name<'static>, Zone>,
    /// What the parent says of each name as a cut.
    cuts: HashMap<Name<'static>, Delegation>,
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
    /// A response whose question section names another question counts as none. Nothing happens when no
    /// question is pending.
    pub fn answer(&mut self, response: Option<&Message<'_>>) {
        let Some(question) = self.pending.take() else {
            return;
        };
        let wanted = |message: &Message<'_>| {
            message
                .questions
                .first()
                .is_none_or(|got| got.name == question.name && got.qtype == question.qtype)
        };
        let response = response
            .filter(|message| wanted(message))
            .map(|message| Arc::new(message.clone().into_owned()));
        self.answers
            .insert((question.name, question.qtype), response);
    }
}
