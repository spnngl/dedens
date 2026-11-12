use std::collections::HashMap;

use dedens_proto::edns::{EdnsFlags, EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Decoded, EncodeError, Flags, HEADER_LEN, MAX_NAME_LEN, Message, Name, Opcode, Query, Question,
    Rcode, Record, RecordType, ttl_offsets,
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
    /// The entry would take more than `Config::entry_limit`, or the response does not encode.
    #[error("the response is larger than the entry size limit")]
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
    /// The response as encoded, then what serving it cut to a small buffer needs, in one allocation:
    ///
    /// - the offsets of the TTL fields of its records, two big-endian bytes each, in wire order: the end of a
    ///   record is its TTL offset + 6 + its RDLENGTH;
    /// - the cuts of the additional section that leave `RRset`s whole: bit `k` (byte `k / 8`, bit `k % 8`) is set
    ///   when the first `k` additional records are such a cut (RFC 2181 §9), for `k` up to the record count.
    bytes: Box<[u8]>,
    /// Length of the response: the offsets follow.
    wire: u16,
    /// End of the question: the shortest a response is cut to.
    head: u16,
    /// Number of records, so of offsets.
    records: u16,
    checked: Checked,
    /// Lifetime given at insert, in seconds.
    ttl: u32,
    /// When it stops being fresh.
    pub(crate) expires: u32,
    /// When it stops being served stale.
    pub(crate) stale_until: u32,
    /// Failed validation: never refreshed ahead of its end.
    bad: bool,
    /// What the caller marked it with (`Cache::insert`): opaque here, 0 if nothing.
    pub(crate) mark: u64,
}

impl Response {
    /// What the caller found out about it.
    pub(crate) const fn checked(&self) -> Checked {
        self.checked
    }

    /// Checks `decoded`, the answer to the question of `key`, against the RFC 2308 caching rules and stores it.
    /// `bad` data failed validation: it lives at most `Config::bogus_ttl`, never stale (RFC 4035 §4.7). An
    /// insecure one lives at most `Config::insecure_ttl` (D93). Unless secure, it lives at least `Config::min_ttl`
    /// (D124), within the caps.
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
        // A secure answer is not raised: only the validator knows how long its signatures hold (D124).
        let floor = if checked == Checked::Secure {
            0
        } else {
            config.min_ttl
        };
        let mut ttl = lifetime(message, question, rcode, floor, config)?;
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
        // The entry takes more than the wire: refuse before building the rest of it.
        let limit = config.entry_limit();
        let too_large = |bytes: usize| key.as_bytes().len() + bytes > limit;
        if too_large(wire.len()) {
            return Err(NotCached::TooLarge);
        }
        let len = u16::try_from(wire.len()).expect("a message is at most 65535 bytes");
        let records = message.answer.len() + message.authority.len() + message.additional.len();
        let mut bytes =
            Vec::with_capacity(wire.len() + 2 * records + message.additional.len() / 8 + 1);
        bytes.extend_from_slice(&wire);
        ttl_offsets(&wire, |at| bytes.extend(at.to_be_bytes()))
            .expect("the encoder writes messages that decode");
        if bytes.len() != wire.len() + 2 * records {
            // An OPT record among the others has no TTL offset: not one a cache stores.
            return Err(NotCached::Violations);
        }
        bytes.extend(whole_cuts(&message.additional));
        if too_large(bytes.len()) {
            return Err(NotCached::TooLarge);
        }
        let mut name = [0; MAX_NAME_LEN];
        let head = HEADER_LEN + question.name.to_wire(&mut name).len() + 4;
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            wire: len,
            records: u16::try_from(records)
                .expect("a message of at most 65535 bytes holds under 65536 records"),
            head: u16::try_from(head).expect("a question is at most 259 bytes after the header"),
            checked,
            ttl,
            expires: now.saturating_add(ttl),
            stale_until: now.saturating_add(ttl).saturating_add(stale),
            bad,
            mark: 0,
        })
    }

    /// Bytes this response takes in a shard.
    pub(crate) fn cost(&self) -> usize {
        self.bytes.len()
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

    /// Copies the response into `out` patched for `query`, every record with TTL `ttl`, `stale` if it expired. One
    /// too large for `out` is cut where [`Message::encode_truncated`] cuts it (RFC 2181 §9, D10): at the first
    /// record that does not fit, TC set if it is in the answer or authority section; otherwise at the last cut
    /// before it that leaves every `RRset` of the additional section whole, TC clear. `None` when not even the
    /// header and the question fit.
    ///
    /// No allocation: the cut is read off the stored offsets, as a response that fits is copied.
    pub(crate) fn serve(
        &self,
        query: &Query<'_>,
        ttl: u32,
        stale: bool,
        out: &mut [u8],
    ) -> Option<Served> {
        // A secure response that is `stale` is no longer vouched for: AD is clear (D77).
        let checked = match self.checked {
            Checked::Secure if stale => Checked::Insecure,
            checked => checked,
        };
        let wire = self.wire();
        let (ends, cuts) = self.bytes[wire.len()..].split_at(2 * usize::from(self.records));
        let ends = ends.as_chunks::<2>().0;
        if let Some(out) = out.get_mut(..wire.len()) {
            out.copy_from_slice(wire);
            patch(out, query, checked);
            set_ttls(out, ttl, offsets_in(ends));
            return Some(Served {
                len: out.len(),
                truncated: false,
            });
        }
        let [answers, authority, _] = self.counts();
        let sections = answers + authority;
        // The records that fit whole: their ends are in order.
        let fit = ends.partition_point(|&at| self.record_end(at) <= out.len());
        let tc = fit < sections;
        let kept = if tc {
            fit
        } else {
            sections + whole_cut(cuts, fit - sections)
        };
        let len = kept
            .checked_sub(1)
            .map_or(usize::from(self.head), |last| self.record_end(ends[last]));
        let out = out.get_mut(..len)?;
        out.copy_from_slice(&wire[..len]);
        patch(out, query, checked);
        set_ttls(out, ttl, offsets_in(&ends[..kept]));
        for (at, count) in [
            (6, kept.min(answers)),
            (8, kept.saturating_sub(answers).min(authority)),
            (10, kept.saturating_sub(sections)),
        ] {
            let count = u16::try_from(count).expect("the sections hold at most 65535 records");
            out[at..at + 2].copy_from_slice(&count.to_be_bytes());
        }
        if tc {
            let word = u16::from_be_bytes([out[2], out[3]]) | Flags::TC.bits();
            out[2..4].copy_from_slice(&word.to_be_bytes());
        }
        Some(Served {
            len,
            truncated: true,
        })
    }

    fn wire(&self) -> &[u8] {
        &self.bytes[..usize::from(self.wire)]
    }

    /// `[answers, authority, additional]`: the record counts of the stored header.
    fn counts(&self) -> [usize; 3] {
        let wire = self.wire();
        [6, 8, 10].map(|at| usize::from(u16::from_be_bytes([wire[at], wire[at + 1]])))
    }

    /// Where the record whose TTL field is at offset `ttl_at` ends: after its RDATA, the RDLENGTH 4 bytes into the
    /// field.
    fn record_end(&self, ttl_at: [u8; 2]) -> usize {
        let at = usize::from(u16::from_be_bytes(ttl_at));
        let wire = self.wire();
        at + 6 + usize::from(u16::from_be_bytes([wire[at + 4], wire[at + 5]]))
    }
}

/// A response [`Response::serve`] wrote.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Served {
    /// Bytes written.
    pub(crate) len: usize,
    /// Cut short of the stored response.
    pub(crate) truncated: bool,
}

/// How many additional records to keep, at most `most`, so that no `RRset` has records on both sides of the cut:
/// the largest such count, from the bits [`Response::bytes`] keeps. Bit 0 is always set.
fn whole_cut(cuts: &[u8], most: usize) -> usize {
    let last = most / 8;
    for (at, &byte) in cuts.iter().enumerate().take(last + 1).rev() {
        // Bits above `most` do not count in its own byte.
        let bits = if at == last {
            byte & (0xFF >> (7 - most % 8))
        } else {
            byte
        };
        if bits != 0 {
            return at * 8 + usize::try_from(bits.ilog2()).unwrap_or_default();
        }
    }
    0
}

/// The bits [`Response::bytes`] keeps for `additional`: one for each count of records, up to all of them, that no
/// `RRset` (same owner, type and class, RFC 2181 §5) straddles. The rule of `Message::encode_truncated`, which
/// the `truncation` test holds this to. One hash per record, so that thousands of records are not quadratic.
fn whole_cuts(additional: &[Record<'_>]) -> Vec<u8> {
    let mut first_of = HashMap::with_capacity(additional.len());
    let firsts: Vec<usize> = additional
        .iter()
        .enumerate()
        .map(|(i, r)| *first_of.entry((&r.name, r.rtype(), r.class)).or_insert(i))
        .collect();
    let mut cuts = vec![0_u8; additional.len() / 8 + 1];
    // A cut is whole when no record after it belongs to an `RRset` that starts before it.
    let mut low = additional.len();
    for keep in (0..=additional.len()).rev() {
        if let Some(&first) = firsts.get(keep) {
            low = low.min(first);
        }
        if low >= keep {
            cuts[keep / 8] |= 1 << (keep % 8);
        }
    }
    cuts
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

/// How long `message`, answering `question`, may be cached: the smallest TTL of its records, raised to `floor`
/// (D124), within `max_ttl`. A smallest TTL of 0 is not raised: the answer is not cached (RFC 1035 §3.2.1, RFC 2181
/// §8). The raise keeps data past the time its zone allows (RFC 1035 §3.2.1: how long a record may be cached): a
/// deviation, chosen by the operator.
///
/// A negative answer (RFC 2308 §2: NXDOMAIN, or NODATA, NOERROR without a record of the type asked at the name the
/// answer ends at, both maybe after a CNAME chain) lives at most as long as its SOA's TTL and MINIMUM allow, the
/// records of the chain included, raised to `floor` as well and within `max_negative_ttl` (§5). The SOA must be at
/// or above the name the answer ends at: the zone that denies it (§2.1, §2.2). A record of the type asked at
/// another name is no answer (§2.2: "no relevant answers").
fn lifetime(
    message: &Message<'_>,
    question: &Question<'_>,
    rcode: Rcode,
    floor: u32,
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
    let end = chain_end(question, &message.answer);
    let answered = message.answer.iter().any(|r| {
        r.name == end && (question.qtype == RecordType::ANY || r.rtype() == question.qtype)
    });
    let (smallest, cap) = if rcode == Rcode::NXDOMAIN || !answered {
        let soa = message
            .authority
            .iter()
            .filter(|r| end.is_within(&r.name))
            .find_map(|r| match r.data() {
                RData::Soa(soa) => Some(r.ttl.get().min(soa.minimum)),
                _ => None,
            })
            .ok_or(NotCached::NoSoa)?;
        (smallest.min(soa), config.max_negative_ttl)
    } else {
        (smallest, config.max_ttl)
    };
    if smallest == 0 {
        return Err(NotCached::ZeroTtl);
    }
    match smallest.max(floor).min(cap) {
        0 => Err(NotCached::ZeroTtl),
        ttl => Ok(ttl),
    }
}

/// The name the answer to `question` ends at: its name, after the CNAME records of `answer` in whatever order they
/// come, at most one hop for each, so that a loop ends. A question for CNAME or ANY stops at the first CNAME, which
/// answers it (RFC 1034 §4.3.2 step 3a).
fn chain_end<'m>(question: &Question<'m>, answer: &'m [Record<'_>]) -> Name<'m> {
    let mut name = question.name.clone();
    if matches!(question.qtype, RecordType::CNAME | RecordType::ANY) {
        return name;
    }
    let targets: HashMap<&Name<'_>, Name<'m>> = answer
        .iter()
        .filter_map(|record| match record.data() {
            RData::Cname(target) => Some((&record.name, target)),
            _ => None,
        })
        .collect();
    for _ in 0..targets.len() {
        match targets.get(&name) {
            Some(target) => name = target.clone(),
            None => break,
        }
    }
    name
}

/// The offsets `ends` hold, two big-endian bytes each.
fn offsets_in(ends: &[[u8; 2]]) -> impl Iterator<Item = usize> {
    ends.iter().map(|&at| usize::from(u16::from_be_bytes(at)))
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

/// Kani proof of [`whole_cut`] (D145), on every bit set of up to 3 bytes.
#[cfg(kani)]
mod proofs {
    use super::whole_cut;

    /// [`whole_cut`] returns the highest count at most `most` whose bit is set, 0 when none is, for every set of
    /// bits of up to 3 bytes and every `most` they cover.
    #[kani::proof]
    #[kani::unwind(25)]
    fn the_cut_is_the_highest_whole_one() {
        let bytes: [u8; 3] = kani::any();
        let len = kani::any_where(|&len: &usize| (1..=3).contains(&len));
        let cuts = &bytes[..len];
        let most = kani::any_where(|&most: &usize| most < len * 8);
        let set = |count: usize| cuts[count / 8] >> (count % 8) & 1 == 1;
        let highest = (0..=most).rev().find(|&count| set(count)).unwrap_or(0);
        assert_eq!(whole_cut(cuts, most), highest);
    }
}
