//! A response as stored: encoded once at insert, served by copying the bytes and patching a few fields.

use dedens_proto::header::HEADER_LEN;
use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{
    DecodeError, EncodeError, Flags, Message, Opcode, Query, RData, Rcode, Ttl, message,
};
use thiserror::Error;

use crate::config::Config;
use crate::key::Key;

/// Why a response was not cached.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NotCached {
    /// The response does not decode.
    #[error("the response does not decode: {0}")]
    Malformed(#[from] DecodeError),
    /// The response breaks a protocol rule (`Decoded::violations`); kept out rather than served again.
    #[error("the response breaks a protocol rule")]
    Violations,
    /// QR clear or an opcode other than QUERY.
    #[error("not a response to a standard query")]
    NotResponse,
    /// TC set: the full answer comes over TCP (RFC 2181 §9).
    #[error("the response is truncated")]
    Truncated,
    /// Not exactly the one question of the key.
    #[error("the response does not answer the question of the key")]
    OtherQuestion,
    /// Neither NOERROR nor NXDOMAIN; failures go through `Cache::fail`.
    #[error("response code {0} is not cached")]
    Rcode(Rcode),
    /// A negative answer without an SOA record in the authority section (RFC 2308 §5).
    #[error("a negative answer without SOA is not cached")]
    NoSoa,
    /// Some record has TTL 0: use once, do not cache (RFC 1035 §3.2.1).
    #[error("TTL 0 is not cached")]
    ZeroTtl,
    /// The entry would take more than a shard's budget.
    #[error("the response is larger than a shard's budget")]
    TooLarge,
}

impl From<EncodeError> for NotCached {
    fn from(_: EncodeError) -> Self {
        // Only `BufferFull`: re-encoded with less compression than upstream used, over 65535 bytes.
        Self::TooLarge
    }
}

/// A cached response: no OPT record, ID 0, question lowercased, every record with the same TTL.
#[derive(Debug)]
pub(crate) struct Response {
    wire: Box<[u8]>,
    ttl_offsets: Box<[u16]>,
    /// Lifetime given at insert, in seconds.
    ttl: u32,
    /// When it stops being fresh.
    pub(crate) expires: u32,
    /// When it stops being served stale.
    pub(crate) stale_until: u32,
}

impl Response {
    /// Checks `response` against the RFC 2308 caching rules and stores it.
    pub(crate) fn build(
        key: &Key,
        response: &[u8],
        now: u32,
        config: &Config,
    ) -> Result<Self, NotCached> {
        let decoded = Message::decode(response)?;
        if !decoded.violations.is_empty() {
            return Err(NotCached::Violations);
        }
        let mut message = decoded.message;
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
        let ttl = lifetime(&message, rcode, config)?;
        let records = message
            .answer
            .iter_mut()
            .chain(&mut message.authority)
            .chain(&mut message.additional);
        for record in records {
            record.ttl = Ttl::from_wire(ttl);
        }
        message.header.id = 0;
        message.edns = None;
        let mut wire = message.to_vec()?;
        // The question name is written first, so in full at the header's end.
        let name = HEADER_LEN..HEADER_LEN + key.name_len();
        wire[name].make_ascii_lowercase();
        let ttl_offsets = ttl_offsets(&wire)?;
        Ok(Self {
            wire: wire.into_boxed_slice(),
            ttl_offsets,
            ttl,
            expires: now.saturating_add(ttl),
            stale_until: now.saturating_add(ttl).saturating_add(config.max_stale),
        })
    }

    /// Bytes this response takes in a shard.
    pub(crate) const fn cost(&self) -> usize {
        self.wire.len() + 2 * self.ttl_offsets.len()
    }

    /// Whether under `percent` of its lifetime is left at `now`.
    pub(crate) fn ending(&self, now: u32, percent: u8) -> bool {
        let left = u64::from(self.expires.saturating_sub(now));
        left * 100 < u64::from(self.ttl) * u64::from(percent)
    }

    /// Copies the response into `out` patched for `query`, every record with TTL `ttl`; `None` when it does not
    /// fit.
    pub(crate) fn serve(&self, query: &Query<'_>, ttl: u32, out: &mut [u8]) -> Option<usize> {
        let out = out.get_mut(..self.wire.len())?;
        out.copy_from_slice(&self.wire);
        patch(out, query, ttl, &self.ttl_offsets);
        Some(out.len())
    }

    /// A patched copy of the whole response, for one too large for the client to be truncated outside the lock.
    pub(crate) fn serve_full(&self, query: &Query<'_>, ttl: u32) -> Vec<u8> {
        let mut full = self.wire.to_vec();
        patch(&mut full, query, ttl, &self.ttl_offsets);
        full
    }
}

/// How long `message` may be cached: the smallest TTL of its records, and for a negative answer at most the SOA's
/// (RFC 2308 §5), within the configured caps.
fn lifetime(message: &Message<'_>, rcode: Rcode, config: &Config) -> Result<u32, NotCached> {
    let records = || {
        message
            .answer
            .iter()
            .chain(&message.authority)
            .chain(&message.additional)
    };
    let smallest = records().map(|r| r.ttl.get()).min().unwrap_or(u32::MAX);
    let ttl = if rcode == Rcode::NXDOMAIN || message.answer.is_empty() {
        let soa = message
            .authority
            .iter()
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

/// Offsets of the TTL fields of every record of `wire`.
fn ttl_offsets(wire: &[u8]) -> Result<Box<[u16]>, NotCached> {
    message::ttl_offsets(wire)?
        .into_iter()
        .map(|at| u16::try_from(at).map_err(|_| NotCached::TooLarge))
        .collect()
}

/// Sets the ID, flags and question case of `query`, and TTL `ttl` at every offset.
fn patch(out: &mut [u8], query: &Query<'_>, ttl: u32, ttl_offsets: &[u16]) {
    let asked = query.header().flags;
    out[..2].copy_from_slice(&query.header().id.to_be_bytes());
    let stored = Flags::from_word(u16::from_be_bytes([out[2], out[3]]));
    // Not authoritative from a cache; RD and CD echo the query (RFC 1035 §4.1.1, RFC 4035 §3.2.2); AD only to
    // a client that asked for it (RFC 6840 §5.7).
    let mut flags = stored.without(Flags::AA).with(Flags::RA);
    for bit in [Flags::RD, Flags::CD] {
        flags = if asked.contains(bit) {
            flags.with(bit)
        } else {
            flags.without(bit)
        };
    }
    let dnssec_ok = query
        .edns()
        .is_some_and(|e| e.flags.contains(dedens_proto::EdnsFlags::DO));
    if !asked.contains(Flags::AD) && !dnssec_ok {
        flags = flags.without(Flags::AD);
    }
    let word = u16::from_be_bytes([out[2], out[3]]) & !stored.bits() | flags.bits();
    out[2..4].copy_from_slice(&word.to_be_bytes());
    // Echo the question in the case asked (RFC 4343 §4).
    if let Some(question) = query.question() {
        let mut buf = [0; MAX_NAME_LEN];
        let name = question.name.to_wire(&mut buf);
        if let Some(stored) = out.get_mut(HEADER_LEN..HEADER_LEN + name.len()) {
            stored.copy_from_slice(name);
        }
    }
    let ttl = ttl.to_be_bytes();
    for &at in ttl_offsets {
        let at = usize::from(at);
        out[at..at + 4].copy_from_slice(&ttl);
    }
}
