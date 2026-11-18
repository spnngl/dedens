//! Targets of dedens-resolver: the scrubbing of a response (D192), and its `RRset` cache fed the records of
//! responses off the wire.

use std::sync::Arc;

use dedens_cache::{Checked, Config};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Message, Name, Record, Section};
use dedens_resolver::{Inserted, Outcome, Rank, Rrset, RrsetCache, scrub};

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
            let held = inserted.hit();
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
/// every record kept is of the question's class and within that zone, a referral's child is below it and above the
/// name, and each record dropped is one of the response's, once.
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
    for (rank, record) in scrubbed.ranked() {
        assert!(
            record.name.is_within(&zone),
            "{rank:?} {} kept outside {zone}",
            record.name
        );
        assert_eq!(
            record.class, question.qclass,
            "{rank:?} {} kept of another class",
            record.name
        );
    }
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
    let mut seen = Vec::new();
    for d in &scrubbed.dropped {
        let len = match d.section {
            Section::Answer => response.answer.len(),
            Section::Authority => response.authority.len(),
            Section::Additional => response.additional.len(),
        };
        assert!(d.index < len, "{d:?} past its section");
        assert!(!seen.contains(&(d.section, d.index)), "{d:?} dropped twice");
        seen.push((d.section, d.index));
    }
}
