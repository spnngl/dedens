//! The validator (RFC 4035 §5, D75); its guide is the crate doc's "Validation".

mod cache;
mod chain;
mod covered;
mod response;
mod section;
mod verdict;

use std::collections::HashMap;
use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::{Class, Flags, Message, Name, Question, RecordType};

use self::cache::KeyCache;
use self::chain::Zone;
pub use self::covered::covered;
use self::response::Parsed;
pub use self::verdict::{Delegation, InsecureReason, MAX_CHASES, Verdict};
use crate::anchor::TrustAnchors;
use crate::crypto::{Budget, Verifications};
use crate::denial::MaxIterations;

/// What one validation may do before it gives up, so that no response makes the validator loop or work for
/// long (RFC 9276 §3.2, CVE-2023-50387).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Questions one validation may ask the caller: 64 (D75). The walk asks the DS of each label below the
    /// last zone, so an IPv6 reverse name of 34 labels takes about 40 with the DNSKEY of each zone, and a few
    /// CNAMEs more; the key cache answers the walk of a name seen before from memory (D86). Past the limit the
    /// verdict is [`Verdict::Indeterminate`].
    pub questions: usize,
    /// Labels of a name below its closest trust anchor: 127 (D75), the most a name has, so that the limit
    /// is the number of questions's. A name deeper is walked no further, and the verdict is
    /// [`Verdict::Indeterminate`], whatever the order of the questions.
    pub depth: usize,
    /// The signature checks and NSEC3 hashes of the validation, its chain of trust included (D71): 128
    /// signature checks here, where [`Budget::default`] has 64, for the proofs of no DS of each label of a
    /// 34-label name need about 80 (D75). Past it the verdict is [`Verdict::Indeterminate`]: the budget says
    /// nothing of the data, bogus would blame a zone for a long walk, and insecure would let a forger downgrade.
    pub budget: Budget,
    /// The NSEC3 iterations above which a zone's denials are insecure (RFC 9276 §3.2, D74).
    pub iterations: MaxIterations,
    /// Entries of the validator's key cache, in each of its two tables, keys of secure zones, and names and
    /// insecure zones: 4096 (D86, D92). Full, a table drops its least recently used entry. 0 turns the cache
    /// off.
    pub key_cache: usize,
    /// Bytes of the validator's key cache, all tables: 4 MiB, Unbound's `key-cache-size` (D86). Half is for
    /// keys and half for names and insecure zones, so that neither can push out the other. A set of keys of more
    /// than 16 KiB is never kept.
    pub key_cache_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            questions: 64,
            depth: 127,
            budget: Budget::new(Verifications(128), Budget::DEFAULT_NSEC3_BLOCKS),
            iterations: MaxIterations::default(),
            key_cache: 4096,
            key_cache_bytes: 4 << 20,
        }
    }
}

#[derive(Debug)]
struct Config {
    anchors: TrustAnchors,
    limits: Limits,
    cache: KeyCache,
}

/// The judge of responses of a validating resolver (RFC 4035 §5): the trust anchors, the limits and the cache of
/// keys, which validations share. Clones of a validator share them, and a validator with other anchors or limits
/// is a new one, with a new cache (D86).
#[derive(Debug, Clone)]
pub struct Validator {
    config: Arc<Config>,
}

impl Validator {
    /// A validator whose chains of trust start at `anchors`, within `limits`.
    #[must_use]
    pub fn new(anchors: TrustAnchors, limits: Limits) -> Self {
        let cache = KeyCache::new(limits.key_cache, limits.key_cache_bytes);
        Self {
            config: Arc::new(Config {
                anchors,
                limits,
                cache,
            }),
        }
    }

    /// Whether `other` is a clone of this validator, which shares its anchors, limits and cache of keys.
    #[must_use]
    pub fn shares_cache(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.config, &other.config)
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

    /// Starts validating `response`, a referral to a delegation on the path to `question`'s name (the child is
    /// the name or above it, not the root), as far as the parent that sent it vouches for it: its DS records or
    /// their proven absence (RFC 4035 §5.2). The verdict is [`Verdict::Referral`] and never secure: the NS
    /// records and the glue of a referral are not signed by the parent, and that the parent sent it is not
    /// proven; the caller follows the delegation and validates the answer of the child with [`Validator::start`].
    /// [`Delegation::Signed`] says the DS `RRset` is authentic and has a record of a supported algorithm and
    /// digest, nothing more.
    ///
    /// Not a referral (see [`Message::referral`]), or one to a name that `question`'s is not at or below, or to
    /// the root: [`Verdict::Indeterminate`].
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
            parsed: Arc::new(Parsed::new(
                &question,
                &response.answer,
                &response.authority,
            )),
            mode: Mode::Final,
            question,
            response,
            now: u32::from_be_bytes([a, b, c, d]),
            at: now,
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
                    format!(
                        "the response is no referral for {}",
                        validation.question.name
                    ),
                ));
                return validation;
            }
            Entry::Referral(Some(child)) => {
                validation.seed(child.clone(), RecordType::DS);
                validation.mode = Mode::Referral(child);
            }
        }
        if matches!(
            validation.question.qtype,
            RecordType::DS | RecordType::DNSKEY
        ) {
            validation.seed(validation.question.name.clone(), validation.question.qtype);
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

/// What a [`Validation`] spent so far: the questions it asked the caller and the work it did, the units of
/// [`Limits::questions`] and [`Limits::budget`] (D75). A caller bounding what a client's query costs across
/// validations (a CNAME chain starts one for each name) or what all clients cost adds these up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cost {
    /// Questions asked.
    pub questions: usize,
    /// Signature verifications done.
    pub verifications: u32,
    /// SHA-1 blocks of NSEC3 hashing computed (D106): one per iteration for a short name and no salt, more for a
    /// longer name or a salt (RFC 5155 §5).
    pub nsec3_blocks: u32,
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
    /// The time as given, in Unix seconds: the key cache's.
    at: u64,
    /// The responses given, by question; `None` for a question that got none.
    answers: HashMap<(Name<'static>, RecordType), Option<Arc<Message<'static>>>>,
    asked: usize,
    pending: Option<Question<'static>>,
    budget: Budget,
    /// What the walk found of each name that is, or sits below, an apex: written by `settle` only (and
    /// copied from the key cache by `zone_of`), read by `zone_of` only, never an outcome of a limit.
    zones: HashMap<Name<'static>, Zone>,
    done: Option<Verdict>,
}

impl Validation {
    /// Takes the response `start` was given as the answer to `name` and `rtype`.
    fn seed(&mut self, name: Name<'static>, rtype: RecordType) {
        self.answers
            .insert((name, rtype), Some(Arc::clone(&self.response)));
    }

    /// What the validation has cost so far.
    #[must_use]
    pub fn cost(&self) -> Cost {
        let start = &self.config.limits.budget;
        Cost {
            questions: self.asked,
            verifications: start
                .verifications_left()
                .0
                .saturating_sub(self.budget.verifications_left().0),
            nsec3_blocks: start
                .nsec3_blocks_left()
                .0
                .saturating_sub(self.budget.nsec3_blocks_left().0),
        }
    }

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
