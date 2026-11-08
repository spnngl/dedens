//! RFC 2181 §9: a hit larger than the client's buffer is cut where D10 says `Message::encode_truncated` cuts the
//! full response, whatever the sizes, sections, `RRsets` and freshness (D116).

mod common;

use std::fs;

use common::{T0, a, dns, insert, query, record, response};
use dedens_cache::{Cache, Hit, Lookup, StalePolicy};
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::rdata::RData;
use dedens_proto::{Message, Query, Rcode, Record, RecordType};
use proptest::prelude::*;

/// Owners of the records: the question's and others, so that the records of an `RRset` may be apart.
const OWNERS: [&str; 4] = ["www.example", "a.example", "bb.example", "c.longer.example"];

/// One record of a section: an A of owner `owner`, or an NS of it naming `target` (a name in its RDATA).
fn records() -> impl Strategy<Value = Vec<(usize, Option<usize>)>> {
    prop::collection::vec((0..OWNERS.len(), prop::option::of(0..OWNERS.len())), 0..40)
}

fn built(spec: &[(usize, Option<usize>)], ttl: u32) -> Vec<Record<'static>> {
    spec.iter()
        .enumerate()
        .map(|(i, &(owner, target))| match target {
            None => a(OWNERS[owner], ttl, u8::try_from(i).unwrap_or(0)),
            Some(target) => record(OWNERS[owner], ttl, &RData::Ns(dns(OWNERS[target]))),
        })
        .collect()
}

/// What the client gets from a buffer of `limit` bytes: the whole response cut as `encode_truncated` cuts it.
fn expected(full: &[u8], limit: usize) -> Option<Vec<u8>> {
    let decoded = Message::decode(full).expect("a served response decodes");
    let mut cut = vec![0; limit];
    let encoded = decoded.message.encode_truncated(&mut cut).ok()?;
    cut.truncate(encoded.len);
    Some(cut)
}

fn lookup_in(cache: &Cache, query: &[u8], now: u32, stale: StalePolicy, out: &mut [u8]) -> Lookup {
    cache.lookup(&Query::read(query).expect("a query"), now, stale, out)
}

proptest! {
    #[test]
    fn a_truncated_hit_is_the_response_encoded_into_the_buffer(
        answer in records(),
        authority in records(),
        additional in records(),
        per_mille in 0_usize..=1000,
        expired in any::<bool>(),
    ) {
        let cache = Cache::new(dedens_cache::Config::default()).unwrap();
        let q = query(9, "www.example", RecordType::A);
        // The answer holds an A for the question, so the response is positive.
        let mut answers = vec![a("www.example", 60, 0)];
        answers.extend(built(&answer, 60));
        let wire = {
            let mut message = Message::decode(&response(
                "www.example",
                RecordType::A,
                Rcode::NOERROR,
                answers,
                built(&authority, 60),
            ))
            .unwrap()
            .message
            .into_owned();
            message.additional = built(&additional, 60);
            message.to_vec().unwrap()
        };
        insert(&cache, &q, &wire, T0).unwrap();
        let (now, stale) = if expired {
            (T0 + 61, StalePolicy::Always)
        } else {
            (T0, StalePolicy::Never)
        };
        // A stale hit leaves `STALE_ROOM` bytes of the buffer free to a query with EDNS, as `query` is.
        let room = if expired { Cache::STALE_ROOM } else { 0 };
        let mut full = vec![0; 65_535];
        let Lookup::Hit(whole) = lookup_in(&cache, &q, now, stale, &mut full) else {
            panic!("a hit");
        };
        prop_assert!(!whole.truncated);
        let full = &full[..whole.len];
        // From the least buffer to one that takes the whole response.
        let span = whole.len + room + 1 - Cache::MIN_OUT.min(whole.len + room);
        let size = Cache::MIN_OUT + span * per_mille / 1000;
        let mut out = vec![0; size];
        let found = lookup_in(&cache, &q, now, stale, &mut out);
        match expected(full, size - room) {
            None => prop_assert_eq!(found, Lookup::Miss),
            Some(cut) => {
                let Lookup::Hit(Hit { len, truncated, .. }) = found else {
                    panic!("expected a hit, got {found:?}");
                };
                prop_assert_eq!(&out[..len], &cut[..]);
                prop_assert_eq!(truncated, cut.len() < full.len());
            }
        }
    }
}

/// Responses captured from public servers (`testdata/proto` and `testdata/dnssec`): for every buffer size, from
/// the least to one that takes all, the hit is the response encoded into it, so the cuts stored with real answers,
/// referrals and signed responses are the ones `encode_truncated` makes.
#[test]
fn a_truncated_hit_of_a_captured_response_is_the_response_encoded_into_the_buffer() {
    let (mut stored, mut cut, mut tc_set, mut tc_clear) = (0, 0, 0, 0);
    for set in ["proto", "dnssec"] {
        for entry in fs::read_dir(dedens_testkit::path(set)).expect("testdata directory") {
            let path = entry.expect("an entry").path();
            if path.extension().is_none_or(|ext| ext != "bin") {
                continue;
            }
            let bytes = fs::read(&path).expect("a capture");
            let Ok(decoded) = Message::decode(&bytes) else {
                continue;
            };
            let Some(question) = decoded.message.questions.first() else {
                continue;
            };
            let signed = decoded
                .message
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags.contains(EdnsFlags::DO));
            let mut ask = Message::query(9, question.clone());
            ask.edns = Some(Edns {
                flags: if signed {
                    EdnsFlags::DO
                } else {
                    EdnsFlags::default()
                },
                ..Edns::default()
            });
            let q = ask.to_vec().expect("a query fits");
            let cache = Cache::new(dedens_cache::Config::default()).unwrap();
            // Captures a cache refuses (SERVFAIL, TTL 0, ...) have no hit to cut.
            if insert(&cache, &q, &bytes, T0).is_err() {
                continue;
            }
            stored += 1;
            let mut full = vec![0; 65_535];
            let Lookup::Hit(whole) = lookup_in(&cache, &q, T0, StalePolicy::Never, &mut full)
            else {
                panic!("{}: a hit", path.display());
            };
            let full = &full[..whole.len];
            for size in Cache::MIN_OUT..whole.len {
                let mut out = vec![0; size];
                let found = lookup_in(&cache, &q, T0, StalePolicy::Never, &mut out);
                match expected(full, size) {
                    None => assert_eq!(found, Lookup::Miss, "{}: {size}", path.display()),
                    Some(want) => {
                        let Lookup::Hit(Hit { len, truncated, .. }) = found else {
                            panic!("{}: {size}: expected a hit, got {found:?}", path.display());
                        };
                        assert_eq!(&out[..len], &want[..], "{}: {size}", path.display());
                        assert_eq!(truncated, want.len() < full.len());
                        cut += 1;
                        if Message::decode(&out[..len])
                            .unwrap()
                            .message
                            .header
                            .flags
                            .contains(dedens_proto::Flags::TC)
                        {
                            tc_set += 1;
                        } else if truncated {
                            tc_clear += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(stored >= 20, "{stored} captures stored");
    assert!(
        tc_set > 0 && tc_clear > 0,
        "{cut} cuts: {tc_set} with TC, {tc_clear} without"
    );
}

/// More than eight additional records, each an `RRset` of its own: every count of them is a whole cut, kept in the
/// bytes of the stored cuts past the first, so a buffer holding some of them gets as many as `encode_truncated` keeps.
#[test]
fn a_cut_past_the_eighth_additional_record_is_where_encode_truncated_cuts() {
    let cache = Cache::new(dedens_cache::Config::default()).unwrap();
    let q = query(9, "www.example", RecordType::A);
    let mut message = Message::decode(&response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("www.example", 60, 0)],
        vec![],
    ))
    .unwrap()
    .message
    .into_owned();
    message.additional = (0..100)
        .map(|i| a(&format!("host{i}.example"), 60, i))
        .collect();
    let wire = message.to_vec().unwrap();
    insert(&cache, &q, &wire, T0).unwrap();
    let mut full = vec![0; 65_535];
    let Lookup::Hit(whole) = lookup_in(&cache, &q, T0, StalePolicy::Never, &mut full) else {
        panic!("a hit");
    };
    let full = &full[..whole.len];
    let mut kept = Vec::new();
    for size in Cache::MIN_OUT..whole.len {
        let mut out = vec![0; size];
        let found = lookup_in(&cache, &q, T0, StalePolicy::Never, &mut out);
        let want = expected(full, size).expect("a response that fits the least buffer");
        let Lookup::Hit(Hit { len, truncated, .. }) = found else {
            panic!("{size}: expected a hit, got {found:?}");
        };
        assert_eq!(&out[..len], &want[..], "{size}");
        assert!(truncated);
        kept.push(
            Message::decode(&out[..len])
                .unwrap()
                .message
                .additional
                .len(),
        );
    }
    assert!(kept.iter().any(|&count| count > 8), "kept {kept:?}");
}
