//! Targets of dedens-resolver: its `RRset` cache fed the records of responses off the wire.

use std::sync::Arc;

use dedens_cache::{Checked, Config};
use dedens_proto::{Flags, Message, Section};
use dedens_resolver::{Rank, Rrset, RrsetCache};

/// The cache's capacity: small, so that a large response evicts.
const CAPACITY: usize = 64 << 10;

/// A response off the wire, its sections grouped into `RRsets` and each stored at the rank its section and AA give
/// (D193): what was stored is found again, the same `Arc`; its TTL is within `(0, max_ttl]`; storing the same data
/// again at the same rank keeps the entry; the cache stays within its capacity.
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
    let authoritative = message.header.flags.contains(Flags::AA);
    for (section, records) in [
        (Section::Answer, &message.answer),
        (Section::Authority, &message.authority),
        (Section::Additional, &message.additional),
    ] {
        let rank = Rank::of(section, authoritative);
        for rrset in Rrset::group(records) {
            assert!(!rrset.rdatas().is_empty(), "an RRset holds records");
            let (owner, rtype, class) = (rrset.owner().clone(), rrset.rtype(), rrset.class());
            let Ok(held) = cache.insert(rrset.clone(), rank, Checked::Unchecked, 0) else {
                continue;
            };
            assert!(
                (1..=max_ttl).contains(&held.ttl.get()),
                "a TTL within bounds"
            );
            let found = cache
                .get(&owner, rtype, class, 0)
                .expect("an RRset just stored is found");
            assert!(
                Arc::ptr_eq(&found.rrset, &held.rrset),
                "the RRset held is found"
            );
            if *held.rrset == rrset && held.rank == rank {
                let again = cache
                    .insert(rrset, rank, Checked::Unchecked, 1)
                    .expect("stored before");
                assert!(
                    Arc::ptr_eq(&again.rrset, &held.rrset),
                    "the same data keeps the entry"
                );
            }
            assert!(cache.used() <= CAPACITY, "the cache within its capacity");
        }
    }
}
