//! DNSSEC validation, sans-IO: what a validator does with the records it is given (RFC 4033, 4034, 4035).
//! [`crypto`] (D71) is the cryptography on `ring`, [`rrsig`] (D73) an `RRset` checked by its signatures,
//! [`denial`] (D74) what NSEC and NSEC3 records prove; [`TrustAnchors`] (D72) are where the chain of trust
//! starts, and [`Validator`] (D75) judges a response.
//!
//! # Validation
//!
//! The validating resolver's judgment of a response: secure, insecure, bogus or indeterminate, with the extended
//! error to attach (RFC 4033 §5, RFC 4035 §4.3, §5, RFC 6840 §4, §5, RFC 8914 §4, RFC 7646 §2).
//!
//! Sans I/O (D69): the validator never sends a query. The caller starts a [`Validation`] with the response to
//! check, then asks it what it needs and answers, until it is done:
//!
//! ```
//! # use dedens_dnssec::{Limits, Next, TrustAnchors, Validator, Verdict};
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
//! The chain of trust runs top-down from the closest trust anchor to the owner of each `RRset`: the validator
//! asks the DS of each label then, where there is a zone, its DNSKEY (RFC 4035 §5.2, §5.3.1). It walks to the
//! owner, never to the signer the RRSIGs name, which a forger writes: an `RRset` is authentic when a key of the
//! zone of its owner verifies it. The price is one DS question for each label below the last zone, that the cache
//! of keys pays once (D86). The outcome for each zone is written by one private function, `settle`, and read
//! by one other, `zone_of`; a failure (bogus, or indeterminate) is never written to the cache. The cache is
//! the validator's, shared by all its validations, which is why anchors and limits are fixed for a validator:
//! change them by building another, and its cache starts empty. What goes in is only what the data decided: keys
//! and proofs that verified, for the TTL they carry, never a bogus zone: whoever answers a DNSKEY question could
//! make one for every validation (D92), so the next validation walks it again.
//!
//! What [`Verdict::Secure`] covers: every `RRset` of class IN in the answer and authority sections is authentic,
//! what the response lacks is proven absent, and the rcode agrees (RFC 4035 §3.2.3, §5). It does not cover the
//! additional section, records of another class, or the unsigned CNAME a DNAME synthesizes (RFC 6672 §5.3.3).
//! Only the `RRsets` of the answer (the question's name, the names its CNAME and DNAME chain leads through) and,
//! in the authority section, those at or above such a name are checked: others are out of bailiwick, neither
//! walked nor verified, and the verdict says nothing of them. [`covered()`] is the response cut to what a secure
//! verdict covers, the one definition: the caller hands out or shows that, never the response.
//! [`Verdict::Incomplete`] is the same for a CNAME chain that stops before the type asked: the caller follows it
//! to `next`, bounds how many CNAMEs it chases ([`MAX_CHASES`]; a loop of them never ends otherwise) and does not
//! take the names it chases for entropy (0x20): they come from the server. A referral is no answer:
//! [`Validator::start_referral`] judges it by its delegation alone, and never gives Secure for it.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod denial;
pub mod rrsig;

mod anchor;
mod validator;

// One path per item (D160): `crypto`, `rrsig` and `denial` are the families a reader names; `anchor` and
// `validator` are flat here.
pub use anchor::{Anchor, AnchorError, TrustAnchors};
pub use validator::{
    Cost, Delegation, InsecureReason, Limits, MAX_CHASES, Next, Validation, Validator, Verdict,
    covered,
};
