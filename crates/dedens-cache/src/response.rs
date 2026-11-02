use std::sync::Arc;

use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::header::HEADER_LEN;
use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{
    Decoded, EdnsFlags, EncodeError, Flags, Message, Name, Opcode, Query, Question, RData, Rcode,
    Record, RecordType, message,
};
use thiserror::Error;

use crate::config::Config;
use crate::key::Key;

/// Why a response was not cached.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NotCached {
    /// The query is not one the cache answers ([`crate::Key::of`] gives none).
    #[error("the query is not one the cache answers")]
    Query,
    /// The response breaks a protocol rule (`Decoded::violations`); kept out rather than served again.
    #[error("the response breaks a protocol rule")]
    Violations,
    /// QR clear or an opcode other than QUERY.
    #[error("not a response to a standard query")]
    NotResponse,
    /// TC set: the full answer comes over TCP (RFC 2181 §9).
    #[error("the response is truncated")]
    Truncated,
    /// Not exactly the one question of the query.
    #[error("the response does not answer the question of the query")]
    OtherQuestion,
    /// Neither NOERROR nor NXDOMAIN; failures go through `Cache::fail`.
    #[error("response code {0} is not cached")]
    Rcode(Rcode),
    /// A negative answer without an SOA record at or above the name it ends at in the authority section (RFC 2308
    /// §5).
    #[error("a negative answer without SOA is not cached")]
    NoSoa,
    /// Some record has TTL 0: use once, do not cache (RFC 1035 §3.2.1).
    #[error("TTL 0 is not cached")]
    ZeroTtl,
    /// The answer is tailored to a client subnet (RFC 7871 §7.3.1: a SCOPE PREFIX-LENGTH above 0), which the
    /// cache does not key on.
    #[error("an answer for a client subnet is not cached")]
    ClientSubnet,
    /// The entry would take more than a shard's budget.
    #[error("the response is larger than a shard's budget")]
    TooLarge,
}

impl From<EncodeError> for NotCached {
    fn from(_: EncodeError) -> Self {
        Self::TooLarge
    }
}

/// What the caller found out about a response before storing it: the one fact of DNSSEC the cache keeps (D77),
/// which sets the AD bit of every reply it serves, or makes it a bogus one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Checked {
    /// Not validated: replies have AD clear, whatever the response said. Only a verdict of ours makes an answer
    /// authentic (RFC 6840 §5.8, RFC 4035 §3.2.3, D114); unlike [`Checked::Insecure`], the TTL is not capped.
    #[default]
    Unchecked,
    /// Validated and secure: replies have AD (to a client that asked for it, RFC 6840 §5.7).
    Secure,
    /// Validated, or not to be, and not secure: replies have AD clear.
    Insecure,
    /// Validation failed, with this extended error (RFC 8914): kept for `Config::bogus_ttl` at most, never served
    /// stale nor prefetched; the caller answers SERVFAIL with the error (RFC 4035 §5.5).
    Bogus(InfoCode),
}

/// A cached response, without OPT record; serving writes the ID, flags and question case of the query, and one
/// TTL in every record.
#[derive(Debug)]
pub(crate) struct Response {
    shared: Shared,
    /// Lifetime given at insert, in seconds.
    ttl: u32,
    /// When it stops being fresh.
    pub(crate) expires: u32,
    /// When it stops being served stale.
    pub(crate) stale_until: u32,
    /// Failed validation: never refreshed ahead of its end.
    bad: bool,
}

impl Response {
    /// What the caller found out about it.
    pub(crate) const fn checked(&self) -> Checked {
        self.shared.checked
    }

    /// Checks `decoded`, the answer to the question of `key`, against the RFC 2308 caching rules and stores it.
    /// `bad` data failed validation: it lives at most `Config::bogus_ttl`, never stale (RFC 4035 §4.7). An
    /// insecure one lives at most `Config::insecure_ttl` (D93).
    pub(crate) fn build(
        key: &Key,
        decoded: &Decoded<'_>,
        now: u32,
        checked: Checked,
        bad: bool,
        config: &Config,
    ) -> Result<Self, NotCached> {
        if !decoded.violations.is_empty() {
            return Err(NotCached::Violations);
        }
        let message = &decoded.message;
        let flags = message.header.flags;
        if !flags.contains(Flags::QR) || message.header.opcode != Opcode::QUERY {
            return Err(NotCached::NotResponse);
        }
        if flags.contains(Flags::TC) {
            return Err(NotCached::Truncated);
        }
        let [question] = message.questions.as_slice() else {
            return Err(NotCached::OtherQuestion);
        };
        if !key.asks(question) {
            return Err(NotCached::OtherQuestion);
        }
        let rcode = message.rcode();
        if rcode != Rcode::NOERROR && rcode != Rcode::NXDOMAIN {
            return Err(NotCached::Rcode(rcode));
        }
        if for_subnet(message) {
            return Err(NotCached::ClientSubnet);
        }
        let mut ttl = lifetime(message, question, rcode, config)?;
        if checked == Checked::Insecure {
            ttl = ttl.min(config.insecure_ttl());
        }
        let mut stale = config.max_stale;
        if bad {
            ttl = ttl.min(config.bogus_ttl);
            stale = 0;
        }
        // The caller adds its own OPT record to each response served.
        let wire = message.to_vec_without_edns()?;
        let len = u16::try_from(wire.len()).expect("a message is at most 65535 bytes");
        // The TTL offsets follow the message, big-endian, in the same allocation.
        let records = message.answer.len() + message.authority.len() + message.additional.len();
        let mut offsets = Vec::with_capacity(2 * records);
        message::ttl_offsets(&wire, |at| offsets.extend(at.to_be_bytes()))
            .expect("the encoder writes messages that decode");
        Ok(Self {
            shared: Shared {
                bytes: wire.iter().chain(&offsets).copied().collect(),
                wire: len,
                checked,
            },
            ttl,
            expires: now.saturating_add(ttl),
            stale_until: now.saturating_add(ttl).saturating_add(stale),
            bad,
        })
    }

    /// Bytes this response takes in a shard.
    pub(crate) fn cost(&self) -> usize {
        self.shared.bytes.len()
    }

    /// Whether under `percent` of its lifetime is left at `now`.
    pub(crate) fn ending(&self, now: u32, percent: u8) -> bool {
        if self.bad {
            return false;
        }
        let left = u64::from(self.expires.saturating_sub(now));
        left * 100 < u64::from(self.ttl) * u64::from(percent)
    }

    /// Seconds left at `now`, at most the lifetime given at insert, should `now` be before the insert.
    pub(crate) fn left(&self, now: u32) -> u32 {
        self.expires.saturating_sub(now).min(self.ttl)
    }

    /// Copies the response into `out` patched for `query`, every record with TTL `ttl`, `stale` if it expired;
    /// `None` when it does not fit.
    pub(crate) fn serve(
        &self,
        query: &Query<'_>,
        ttl: u32,
        stale: bool,
        out: &mut [u8],
    ) -> Option<usize> {
        let wire = self.shared.wire();
        let out = out.get_mut(..wire.len())?;
        out.copy_from_slice(wire);
        self.shared.patch(out, query, ttl, stale);
        Some(out.len())
    }

    /// The stored bytes, to truncate once the lock is released.
    pub(crate) fn share(&self) -> Shared {
        self.shared.clone()
    }
}

/// The bytes of a response then the offsets of their TTL fields, in one allocation shared so that a hit too large
/// for the client is truncated outside the shard's lock.
#[derive(Debug, Clone)]
pub(crate) struct Shared {
    bytes: Arc<[u8]>,
    /// Length of the response: the offsets follow, two bytes each.
    wire: u16,
    checked: Checked,
}

impl Shared {
    fn wire(&self) -> &[u8] {
        &self.bytes[..usize::from(self.wire)]
    }

    /// Sets the ID, flags and question case of `query`, and TTL `ttl`, in `out`, a copy of the response. A secure
    /// one that is `stale` is no longer vouched for: AD is clear (D77).
    fn patch(&self, out: &mut [u8], query: &Query<'_>, ttl: u32, stale: bool) {
        let checked = match self.checked {
            Checked::Secure if stale => Checked::Insecure,
            checked => checked,
        };
        patch(out, query, checked);
        set_ttls(out, ttl, offsets_in(&self.bytes[usize::from(self.wire)..]));
    }

    /// The response patched as [`Response::serve`] does, then encoded again into `out` without the records that
    /// do not fit (RFC 2181 §9). Allocates: the slow path of a response larger than the client takes.
    pub(crate) fn serve_truncated(
        &self,
        query: &Query<'_>,
        ttl: u32,
        stale: bool,
        out: &mut [u8],
    ) -> Option<message::Encoded> {
        let mut full = self.wire().to_vec();
        self.patch(&mut full, query, ttl, stale);
        let decoded = Message::decode(&full).ok()?;
        decoded.message.encode_truncated(out).ok()
    }
}

/// Whether `message` is tailored to the client subnet of its query: a client subnet option with a SCOPE
/// PREFIX-LENGTH above 0 (RFC 7871 §7.3: none, or 0, suits every client).
fn for_subnet(message: &Message<'_>) -> bool {
    message.edns.as_ref().is_some_and(|edns| {
        edns.options
            .iter()
            .any(|o| matches!(o, EdnsOption::ClientSubnet(s) if s.scope_prefix() > 0))
    })
}

/// How long `message`, answering `question`, may be cached: the smallest TTL of its records, within `max_ttl`.
///
/// A negative answer (RFC 2308 §2: NXDOMAIN, or NODATA, NOERROR without a record of the type asked, both maybe
/// after a CNAME chain) lives at most as long as its SOA's TTL and MINIMUM allow and `max_negative_ttl` (§5), the
/// records of the chain included. The SOA must be at or above the name the answer ends at: the zone that denies
/// it (§2.1, §2.2).
fn lifetime(
    message: &Message<'_>,
    question: &Question<'_>,
    rcode: Rcode,
    config: &Config,
) -> Result<u32, NotCached> {
    let records = || {
        message
            .answer
            .iter()
            .chain(&message.authority)
            .chain(&message.additional)
    };
    let smallest = records().map(|r| r.ttl.get()).min().unwrap_or(u32::MAX);
    let answered = message
        .answer
        .iter()
        .any(|r| question.qtype == RecordType::ANY || r.rtype() == question.qtype);
    let ttl = if rcode == Rcode::NXDOMAIN || !answered {
        let end = chain_end(&question.name, &message.answer);
        let soa = message
            .authority
            .iter()
            .filter(|r| end.is_within(&r.name))
            .find_map(|r| match r.data() {
                RData::Soa(soa) => Some(r.ttl.get().min(soa.minimum)),
                _ => None,
            })
            .ok_or(NotCached::NoSoa)?;
        smallest.min(soa).min(config.max_negative_ttl)
    } else {
        smallest.min(config.max_ttl)
    };
    if ttl == 0 {
        return Err(NotCached::ZeroTtl);
    }
    Ok(ttl)
}

/// The name a CNAME chain from `qname` ends at, following the CNAME records of `answer` in order, as servers
/// write them (RFC 1034 §4.3.2 step 3a).
fn chain_end<'m>(qname: &Name<'m>, answer: &'m [Record<'_>]) -> Name<'m> {
    let mut name = qname.clone();
    for record in answer {
        if record.rtype() == RecordType::CNAME
            && record.name == name
            && let RData::Cname(target) = record.data()
        {
            name = target;
        }
    }
    name
}

/// The offsets in `bytes`, two big-endian bytes each.
fn offsets_in(bytes: &[u8]) -> impl Iterator<Item = usize> {
    bytes
        .as_chunks()
        .0
        .iter()
        .map(|&at| usize::from(u16::from_be_bytes(at)))
}

/// Sets TTL `ttl` at every offset.
fn set_ttls(out: &mut [u8], ttl: u32, ttl_offsets: impl Iterator<Item = usize>) {
    let ttl = ttl.to_be_bytes();
    for at in ttl_offsets {
        out[at..at + 4].copy_from_slice(&ttl);
    }
}

/// Sets the ID, flags and question case of `query`, and the AD bit `checked` gives.
fn patch(out: &mut [u8], query: &Query<'_>, checked: Checked) {
    let asked = query.header().flags;
    out[..2].copy_from_slice(&query.header().id.to_be_bytes());
    let word = u16::from_be_bytes([out[2], out[3]]);
    let stored = Flags::from_word(word);
    // A cache is not authoritative, recurses, and keeps Z clear (RFC 1035 §4.1.1).
    let mut flags = stored.without(Flags::AA).without(Flags::Z).with(Flags::RA);
    for bit in [Flags::RD, Flags::CD] {
        flags = if asked.contains(bit) {
            flags.with(bit)
        } else {
            flags.without(bit)
        };
    }
    flags = match checked {
        Checked::Secure => flags.with(Flags::AD),
        Checked::Unchecked | Checked::Insecure | Checked::Bogus(_) => flags.without(Flags::AD),
    };
    // AD only to a client that asked for it with AD or DO (RFC 6840 §5.8).
    let dnssec_ok = query
        .edns()
        .is_some_and(|e| e.flags.contains(EdnsFlags::DO));
    if !asked.contains(Flags::AD) && !dnssec_ok {
        flags = flags.without(Flags::AD);
    }
    let word = word & !stored.bits() | flags.bits();
    out[2..4].copy_from_slice(&word.to_be_bytes());
    if let Some(question) = query.question() {
        let mut buf = [0; MAX_NAME_LEN];
        let name = question.name.to_wire(&mut buf);
        if let Some(stored) = out.get_mut(HEADER_LEN..HEADER_LEN + name.len()) {
            stored.copy_from_slice(name);
        }
    }
}
