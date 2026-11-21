//! Targets of dedens-resolver: the scrubbing of a response (D192), its `RRset` cache fed the records of
//! responses off the wire, and a resolution answered with one response to each query (D191).

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Checked, Config};
use dedens_dnssec::{TrustAnchors, Validator};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Message, Name, Question, Record, RecordType, Section};
use dedens_resolver::{
    Caches, Failure, InfraCache, Inserted, Limit, Limits, Marks, Minimisation, Next, Outcome, Rank,
    Reply, Resolution, Resolved, Rrset, RrsetCache, Scrubbed, scrub,
};
use dedens_roots::RootHints;
use rand_core::{TryCryptoRng, TryRng};

/// The cache's capacity: small, so that a large response evicts.
const CAPACITY: usize = 64 << 10;

const RANKS: [Rank; 6] = [
    Rank::AdditionalNonAuthoritative,
    Rank::AuthorityNonAuthoritative,
    Rank::AdditionalAuthoritative,
    Rank::AnswerNonAuthoritative,
    Rank::AuthorityAuthoritative,
    Rank::AnswerAuthoritative,
];

const CHECKED: [Checked; 4] = [
    Checked::Unchecked,
    Checked::Secure,
    Checked::Insecure,
    Checked::Bogus(InfoCode::DNSSEC_BOGUS),
];

/// A response off the wire, its sections grouped into `RRsets`, the same whatever the order of the records, and
/// each stored at a rank, a verdict and a time drawn from the message ID and its place (D193): what the cache holds
/// after is found again, the same `Arc`; its TTL is within `(0, max_ttl]`; storing the same data again with the
/// same trust keeps the entry; the cache stays within its capacity.
///
/// # Panics
///
/// On a bug in the `RRset` cache, or in the grouping of records.
pub fn rrset_cache_insert(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let message = decoded.message;
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let max_ttl = config.max_ttl;
    let cache = RrsetCache::new(CAPACITY, config).expect("a valid config");
    let seed = usize::from(message.header.id);
    let mut place = 0;
    for records in [&message.answer, &message.authority, &message.additional] {
        let rrsets = Rrset::group(records);
        assert_order_free(records, &rrsets);
        for rrset in rrsets {
            assert!(!rrset.rdatas().is_empty(), "an RRset holds records");
            place += 1;
            let draw = seed.wrapping_mul(place);
            let rank = RANKS[draw % RANKS.len()];
            let checked = CHECKED[draw / RANKS.len() % CHECKED.len()];
            let now = u32::try_from(draw % 1024 * 100).expect("below 2^32");
            let (owner, rtype, class) = (rrset.owner().clone(), rrset.rtype(), rrset.class());
            let Ok(inserted) = cache.insert(rrset.clone(), rank, checked, now) else {
                continue;
            };
            let held = inserted.held();
            assert!(
                (1..=max_ttl).contains(&held.ttl.get()),
                "a TTL within bounds"
            );
            let found = cache
                .get(&owner, rtype, class, now)
                .expect("an RRset the cache holds is found");
            assert!(
                Arc::ptr_eq(&found.rrset, &held.rrset),
                "the RRset held is found"
            );
            if *held.rrset == rrset && (held.rank, held.checked) == (rank, checked) {
                let again = cache.insert(rrset, rank, checked, now);
                assert!(
                    matches!(&again, Ok(Inserted::Kept(hit)) if Arc::ptr_eq(&hit.rrset, &held.rrset)),
                    "the same data keeps the entry"
                );
            }
            assert!(cache.used() <= CAPACITY, "the cache within its capacity");
        }
    }
}

/// `records` reversed group into `rrsets`, in whatever order, with the same TTLs. Quadratic in the `RRsets`, cheap
/// at libFuzzer's default 4 KiB inputs: index `again` by key if the fuzz job raises `-max_len`.
fn assert_order_free(records: &[Record<'_>], rrsets: &[Rrset]) {
    let mut reversed = records.to_vec();
    reversed.reverse();
    let again = Rrset::group(&reversed);
    assert_eq!(again.len(), rrsets.len(), "as many RRsets in any order");
    for rrset in rrsets {
        assert!(
            again.iter().any(|a| a == rrset && a.ttl() == rrset.ttl()),
            "the same RRsets in any order"
        );
    }
}

/// A response off the wire, scrubbed as from a server of an ancestor of its question's name, the one the ID picks:
/// every record kept is of the question's class, within that zone, and of RDATA that parses; a referral's child is
/// below the zone and above the name; each record dropped is one of the response's, once; and the records kept and
/// those dropped are the response's, each in one of the two, but for the CNAMEs synthesised from a DNAME kept;
/// each record kept for the cache is in an `RRset` of its rank, an RRSIG with the `RRset` it covers; the others are
/// the signatures answering an RRSIG question, each an RRSIG owned by the chain's end. A lame or unusable response
/// keeps and drops nothing.
///
/// # Panics
///
/// On a panic of `scrub`, or on a record kept or dropped against those rules.
pub fn scrub_response(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let response = &decoded.message;
    let Some(question) = response.questions.first() else {
        return;
    };
    let labels = question.name.label_count();
    let cut = usize::from(response.header.id) % (labels + 1);
    let Ok(zone) = Name::from_labels(question.name.labels().skip(cut)) else {
        return;
    };
    let scrubbed = scrub(response, question, &zone);
    let signatures = signatures(&question.name, &scrubbed.outcome);
    let kept: Vec<&Record<'_>> = scrubbed
        .records()
        .into_iter()
        .map(|(_, record)| record)
        .chain(signatures)
        .collect();
    if matches!(scrubbed.outcome, Outcome::Lame | Outcome::Unusable(_)) {
        assert!(kept.is_empty(), "{:?} keeps records", scrubbed.outcome);
        assert!(
            scrubbed.dropped.is_empty(),
            "{:?} drops records",
            scrubbed.outcome
        );
        return;
    }
    for record in &kept {
        assert!(
            record.name.is_within(&zone),
            "{} kept outside {zone}",
            record.name
        );
        assert_eq!(
            record.class, question.qclass,
            "{} kept of another class",
            record.name
        );
        assert!(
            !malformed(record),
            "{} {} kept malformed",
            record.name,
            record.rtype()
        );
    }
    grouped(&scrubbed);
    if let Outcome::Referral { child, .. } = &scrubbed.outcome {
        assert!(
            child.is_within(&zone) && *child != zone,
            "a referral to {child} from {zone}"
        );
        assert!(
            question.name.is_within(child),
            "a referral to {child} for {}",
            question.name
        );
    }
    partitioned(response, &scrubbed, &kept);
}

/// The round-trip time the transport reports for a response.
const RTT: Duration = Duration::from_millis(20);

/// The time a replay starts at, so that a TTL of a response is fresh.
const START: Duration = Duration::from_secs(1_760_000_000);

/// A response off the wire, which every query of a resolution of its question is answered with, as often as the
/// draws seeded by its bytes say, the others met by a timeout, a failed exchange or a datagram that does not decode;
/// half the inputs have the answer validated. The resolution ends within [`Limits`]: the queries it sent, the
/// validator's beside them, and the time; the caches hold within capacity. D191, D197.
///
/// # Panics
///
/// On a panic of the resolution, or on a bound of [`Limits`] it passed.
pub fn resolve_replay(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let mut response = decoded.message;
    let question = (response.questions.first())
        .filter(|question| question.qclass == Class::IN)
        .map_or_else(
            || Question::new("example.com.".parse().expect("a name"), RecordType::A),
            |question| Question::new(question.name.clone().into_owned(), question.qtype),
        );
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let caches = Arc::new(Caches {
        rrsets: RrsetCache::new(CAPACITY, config).expect("a valid config"),
        infra: InfraCache::new(CAPACITY, 1).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: None,
    });
    let limits = Limits::default();
    let Ok(resolution) = Resolution::start(
        question,
        Arc::clone(&caches),
        START,
        limits,
        Minimisation::Off,
    ) else {
        return;
    };
    let length = u16::try_from(data.len()).unwrap_or(u16::MAX);
    let mut draws = Draws(u64::from(response.header.id) << 16 | u64::from(length));
    let mut resolution = if draws.below(2) == 0 {
        resolution
    } else {
        let validator = Validator::new(TrustAnchors::root(), dedens_dnssec::Limits::default());
        resolution.validated(validator, START.as_secs())
    };
    let mut elapsed = Duration::ZERO;
    loop {
        let step = match resolution.step(START + elapsed, &mut draws) {
            Next::Done(resolved) => Err(matches!(
                resolved,
                Resolved::Failed(Failure::Limit(Limit::Time))
            )),
            Next::Send(query) => Ok(query.clone()),
        };
        let query = match step {
            Err(late) => {
                assert!(
                    resolution.sent() <= limits.queries + limits.validation,
                    "{} queries",
                    resolution.sent()
                );
                assert!(
                    late || elapsed <= limits.time + RTT,
                    "{elapsed:?} to end without the time limit"
                );
                assert!(
                    caches.rrsets.used() <= CAPACITY,
                    "the cache within its capacity"
                );
                return;
            }
            Ok(query) => query,
        };
        assert!(
            resolution.sent() <= limits.queries + limits.validation,
            "{} queries, still asking",
            resolution.sent()
        );
        match draws.below(8) {
            0 => resolution.receive(Reply::Timeout, START + elapsed + query.timeout),
            1 => resolution.receive(Reply::Undecodable, START + elapsed + RTT),
            2 => resolution.receive(Reply::ServerError, START + elapsed + RTT),
            _ => {
                // The transport matches the response to the query: its question is the query's.
                response.questions = vec![query.question.clone()];
                let reply = Reply::Response {
                    message: &response,
                    seen: Marks::default(),
                    rtt: Some(RTT),
                };
                resolution.receive(reply, START + elapsed + RTT);
            }
        }
        elapsed += match draws.below(8) {
            0 => query.timeout,
            _ => RTT,
        };
    }
}

/// `SplitMix64`, seeded by the input: a CSPRNG by marker only, so that a failing input replays.
struct Draws(u64);

impl Draws {
    fn below(&mut self, bound: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) % bound
    }
}

impl TryRng for Draws {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::try_from(self.try_next_u64()? >> 32).unwrap_or_default())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.below(u64::MAX))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Draws {}

/// The signatures `outcome` answers an RRSIG question with: each an RRSIG owned by the end of its chain from `name`.
fn signatures<'a, 'm>(name: &Name<'m>, outcome: &'a Outcome<'m>) -> &'a [Record<'m>] {
    let Outcome::Signatures { chain, records } = outcome else {
        return &[];
    };
    let end = chain
        .iter()
        .rev()
        .find_map(|r| match r.data() {
            RData::Cname(target) => Some(target),
            _ => None,
        })
        .unwrap_or_else(|| name.clone());
    for record in records {
        assert!(
            record.rtype() == RecordType::RRSIG && record.name == end,
            "{} {} answers an RRSIG question at {end}",
            record.name,
            record.rtype()
        );
    }
    records
}

/// Whether each record of `response` is either one of `kept` or dropped by `scrubbed`, once, but for the CNAMEs
/// synthesised from a DNAME kept.
fn partitioned(response: &Message<'_>, scrubbed: &Scrubbed<'_>, kept: &[&Record<'_>]) {
    let section = |section| match section {
        Section::Answer => &response.answer,
        Section::Authority => &response.authority,
        Section::Additional => &response.additional,
    };
    // How many times each record of the response is neither kept nor dropped yet.
    let mut left: HashMap<&Record<'_>, usize> = HashMap::new();
    for record in response
        .answer
        .iter()
        .chain(&response.authority)
        .chain(&response.additional)
    {
        *left.entry(record).or_default() += 1;
    }
    let mut seen = HashSet::new();
    for d in &scrubbed.dropped {
        let records = section(d.section);
        assert!(d.index < records.len(), "{d:?} past its section");
        assert!(seen.insert((d.section, d.index)), "{d:?} dropped twice");
        if let Some(n) = left.get_mut(&records[d.index]) {
            *n -= 1;
        }
    }
    for record in kept {
        match left.get_mut(*record) {
            Some(n) if *n > 0 => *n -= 1,
            _ => assert!(
                record.rtype() == RecordType::CNAME
                    && kept.iter().any(|d| d.rtype() == RecordType::DNAME
                        && record.name.is_within(&d.name)
                        && record.name != d.name),
                "{} {} kept, not the response's",
                record.name,
                record.rtype()
            ),
        }
    }
    for (record, n) in left {
        assert_eq!(
            n,
            0,
            "{} {} neither kept nor dropped",
            record.name,
            record.rtype()
        );
    }
}

/// Whether each record `scrubbed` keeps is in an `RRset` of its rank, an RRSIG with the `RRset` it covers.
fn grouped(scrubbed: &Scrubbed<'_>) {
    let ranked = scrubbed.ranked();
    for (rank, record) in &scrubbed.records() {
        let rtype = match record.data() {
            RData::Rrsig(sig) => sig.type_covered,
            _ => record.rtype(),
        };
        assert!(
            ranked.iter().any(|(k, set)| *k == *rank
                && *set.owner() == record.name
                && set.rtype() == rtype
                && (record.rtype() != RecordType::RRSIG || !set.rrsigs().is_empty())),
            "{rank:?} {} {} kept in no RRset of its rank",
            record.name,
            record.rtype()
        );
    }
}

/// Whether the RDATA of `record` does not parse for its type: a DNAME's target is a name not compressed.
fn malformed(record: &Record<'_>) -> bool {
    match record.data() {
        RData::Opaque(data) if record.rtype() == RecordType::DNAME => {
            Name::from_uncompressed(data.data()).is_err()
        }
        RData::Opaque(_) => RData::has_typed_form(record.rtype()),
        _ => false,
    }
}
