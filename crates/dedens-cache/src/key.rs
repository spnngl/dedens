//! What an answer is cached under: the question, case-folded (RFC 4343), and the bits that change the answer.

use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{EdnsFlags, Flags, Query, Question};

/// Name, type, class and the DO and CD bits.
const MAX_KEY_LEN: usize = MAX_NAME_LEN + 5;

/// The DO bit (RFC 3225) of a key: a DNSSEC-aware client gets signatures in its answer.
const DNSSEC_OK: u8 = 1;
/// The CD bit (RFC 4035 §3.2.2) of a key: the client validates itself.
const CHECKING_DISABLED: u8 = 2;

/// A cache key, built on the stack: the lowercased wire name, type, class, and the DO and CD bits.
#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    bytes: [u8; MAX_KEY_LEN],
    len: usize,
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Key").field(&self.as_bytes()).finish()
    }
}

impl Key {
    /// The key of `question` asked with these DO and CD bits.
    #[must_use]
    pub fn new(question: &Question<'_>, dnssec_ok: bool, checking_disabled: bool) -> Self {
        let mut bytes = [0; MAX_KEY_LEN];
        let mut buf = [0; MAX_NAME_LEN];
        let wire = question.name.to_wire(&mut buf);
        let name = wire.len();
        // Length octets are under 64, below b'A', so only label bytes change.
        for (to, from) in bytes.iter_mut().zip(wire) {
            *to = from.to_ascii_lowercase();
        }
        bytes[name..name + 2].copy_from_slice(&question.qtype.0.to_be_bytes());
        bytes[name + 2..name + 4].copy_from_slice(&question.qclass.0.to_be_bytes());
        bytes[name + 4] =
            (u8::from(dnssec_ok) * DNSSEC_OK) | (u8::from(checking_disabled) * CHECKING_DISABLED);
        Self {
            bytes,
            len: name + 5,
        }
    }

    /// The key of the first question of `query`, with its DO (EDNS) and CD (header) bits; none without a
    /// question.
    #[must_use]
    pub fn of(query: &Query<'_>) -> Option<Self> {
        let dnssec_ok = query
            .edns()
            .is_some_and(|e| e.flags.contains(EdnsFlags::DO));
        let checking_disabled = query.header().flags.contains(Flags::CD);
        query
            .question()
            .map(|q| Self::new(q, dnssec_ok, checking_disabled))
    }

    /// The bytes compared and hashed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Whether `question` is the one of this key, whatever its case.
    pub(crate) fn asks(&self, question: &Question<'_>) -> bool {
        let other = Self::new(question, false, false);
        self.len == other.len && self.bytes[..self.len - 1] == other.bytes[..other.len - 1]
    }

    /// Length of the question name in wire form.
    pub(crate) const fn name_len(&self) -> usize {
        self.len - 5
    }
}
