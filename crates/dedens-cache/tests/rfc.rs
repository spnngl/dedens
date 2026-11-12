//! The cache's RFCs: truncation, negative caching and TTLs, serve-stale, and failures.

mod truncation {
    //! RFC 2181 §9: a hit larger than the client's buffer is cut where D10 says `Message::encode_truncated` cuts the
    //! full response, whatever the sizes, sections, `RRsets` and freshness (D116).

    use std::fs;

    use dedens_cache::{Cache, Hit, Lookup, StalePolicy};
    use dedens_proto::edns::{Edns, EdnsFlags};
    use dedens_proto::rdata::RData;
    use dedens_proto::{Message, Query, Rcode, Record, RecordType};
    use dedens_testkit::dns;
    use proptest::prelude::*;

    use crate::util::{T0, a, insert, query, record, response};

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

    fn lookup_in(
        cache: &Cache,
        query: &[u8],
        now: u32,
        stale: StalePolicy,
        out: &mut [u8],
    ) -> Lookup {
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
}

mod negative {
    //! RFC 2308 negative caching, and the TTL rules of RFC 1035 §3.2.1 and RFC 2181 §8.

    use dedens_cache::{Cache, Config, ConfigError, Lookup, NotCached, StalePolicy};
    use dedens_proto::rdata::RData;
    use dedens_proto::{Flags, Message, Rcode, RecordType, Ttl};
    use dedens_testkit::captured;

    use crate::util::{
        T0, a, insert, lookup, min_cache, query, query_of, record, response, retimed, small_cache,
        small_config, soa, ttls,
    };

    const NEVER: StalePolicy = StalePolicy::Never;

    /// RFC 2181 §5.2: the records of an `RRset` whose TTLs differ live as long as the least of them.
    #[test]
    fn positive_answer_lives_as_long_as_its_shortest_ttl() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            vec![a("www.example", 300, 1), a("www.example", 100, 2)],
            vec![],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0 + 40, NEVER);
        assert_eq!(ttls(&served.unwrap()), [60, 60]);
        assert_eq!(lookup(&cache, &q, T0 + 100, NEVER).0, Lookup::Expired);
    }

    /// §5: the negative TTL is the lesser of the SOA's TTL and its MINIMUM.
    #[test]
    fn nxdomain_lives_as_long_as_the_soa_allows() {
        let cache = small_cache();
        let q = query(1, "nope.example", RecordType::A);
        let r = response(
            "nope.example",
            RecordType::A,
            Rcode::NXDOMAIN,
            vec![],
            vec![soa("example", 3600, 60)],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0 + 10, NEVER);
        let served = served.unwrap();
        assert_eq!(served.rcode(), Rcode::NXDOMAIN);
        assert_eq!(ttls(&served), [50]);
        assert_eq!(lookup(&cache, &q, T0 + 60, NEVER).0, Lookup::Expired);
    }

    /// §2.2 NODATA: NOERROR, no answer, SOA in authority.
    #[test]
    fn nodata_is_cached_like_nxdomain() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::AAAA);
        let r = response(
            "www.example",
            RecordType::AAAA,
            Rcode::NOERROR,
            vec![],
            vec![soa("example", 120, 900)],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        assert_eq!(ttls(&served.unwrap()), [120]);
    }

    /// §5: "Negative responses without SOA records SHOULD NOT be cached"; a referral is one too.
    #[test]
    fn negative_answer_without_soa_is_not_cached() {
        let cache = small_cache();
        let q = query(1, "nope.example", RecordType::A);
        let r = response(
            "nope.example",
            RecordType::A,
            Rcode::NXDOMAIN,
            vec![],
            vec![],
        );
        assert_eq!(insert(&cache, &q, &r, T0), Err(NotCached::NoSoa));
    }

    /// §5: negative TTLs capped, 1 to 3 hours recommended.
    #[test]
    fn negative_ttl_is_capped() {
        let cache = small_cache();
        let q = query(1, "nope.example", RecordType::A);
        let r = response(
            "nope.example",
            RecordType::A,
            Rcode::NXDOMAIN,
            vec![],
            vec![soa("example", 86_400, 86_400)],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        assert_eq!(ttls(&served.unwrap()), [cache.config().max_negative_ttl]);
    }

    /// D124: the smallest TTL of a captured answer (`a.bin`, 29 s) is raised to the minimum, and clients see TTLs
    /// counting down from it; a record that lived longer than the raised lifetime is served with the same TTL
    /// (`cname_chain.bin`: a CNAME of 3557 s with an A of 17 s).
    #[test]
    fn a_short_ttl_is_raised_to_the_minimum_and_counts_down() {
        for case in ["a", "cname_chain"] {
            let cache = min_cache(60);
            let wire = captured(case);
            let q = query_of(case);
            insert(&cache, &q, &wire, T0).unwrap();
            let (_, served) = lookup(&cache, &q, T0, NEVER);
            assert_eq!(ttls(&served.unwrap()), [60, 60], "{case}");
            let (_, served) = lookup(&cache, &q, T0 + 45, NEVER);
            assert_eq!(ttls(&served.unwrap()), [15, 15], "{case}");
            assert_eq!(lookup(&cache, &q, T0 + 60, NEVER).0, Lookup::Expired);
        }
    }

    /// A minimum of 0 is off: the answer lives as long as the zone said.
    #[test]
    fn a_minimum_of_zero_keeps_the_ttl_of_the_zone() {
        let cache = min_cache(0);
        let wire = captured("a");
        let q = query_of("a");
        insert(&cache, &q, &wire, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        assert_eq!(ttls(&served.unwrap()), [29, 29]);
        assert_eq!(lookup(&cache, &q, T0 + 29, NEVER).0, Lookup::Expired);
    }

    /// A TTL above the minimum is left alone.
    #[test]
    fn a_ttl_above_the_minimum_is_kept() {
        let cache = min_cache(60);
        let wire = captured("ns");
        let q = query_of("ns");
        insert(&cache, &q, &wire, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        assert_eq!(ttls(&served.unwrap()), [81_811, 81_811]);
    }

    /// RFC 1035 §3.2.1, RFC 2181 §8: TTL 0 is for the transaction in hand; the minimum raises only nonzero TTLs, so
    /// a zero among the others, or an SOA that says 0, still keeps the answer out.
    #[test]
    fn the_minimum_does_not_raise_ttl_zero() {
        let cache = min_cache(60);
        let wire = captured("a");
        let q = query_of("a");
        let zero = retimed(&wire, 0, |m| &mut m.answer);
        assert_eq!(insert(&cache, &q, &zero, T0), Err(NotCached::ZeroTtl));

        let mut one_zero = Message::decode(&wire).unwrap().message;
        one_zero.answer[1].ttl = Ttl::new(0).unwrap();
        assert_eq!(
            insert(&cache, &q, &one_zero.to_vec().unwrap(), T0),
            Err(NotCached::ZeroTtl)
        );

        let nodata = captured("nodata");
        let q = query_of("nodata");
        let zero = retimed(&nodata, 0, |m| &mut m.authority);
        assert_eq!(insert(&cache, &q, &zero, T0), Err(NotCached::ZeroTtl));
        assert!(cache.is_empty());
    }

    /// §5: a negative answer is raised too, and still held by `max_negative_ttl`: a captured NODATA (SOA of 1800 s) to
    /// 2 hours, a captured NXDOMAIN (SOA of a day) to the 3 hours of the cap.
    #[test]
    fn the_minimum_raises_negative_answers_within_the_negative_cap() {
        let cache = Cache::new(Config {
            min_ttl: 7_200,
            ..small_config()
        })
        .unwrap();
        let nodata = captured("nodata");
        let q = query_of("nodata");
        insert(&cache, &q, &nodata, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        assert_eq!(ttls(&served.unwrap()), [7_200]);

        let nxdomain = captured("nxdomain_soa");
        let q = query_of("nxdomain_soa");
        insert(&cache, &q, &nxdomain, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        let served = served.unwrap();
        assert_eq!(served.rcode(), Rcode::NXDOMAIN);
        assert_eq!(ttls(&served), [cache.config().max_negative_ttl]);
    }

    #[test]
    fn positive_ttl_is_capped() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            vec![a("www.example", 0x7FFF_FFFF, 1)],
            vec![],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        assert_eq!(ttls(&served.unwrap()), [2 * 86_400]);
    }

    /// RFC 2181 §8: a TTL with its top bit set reads as 0, so a setting that a served TTL may take is at most
    /// 2^31 - 1; the minimum and the insecure cap are within `max_ttl`.
    #[test]
    fn ttl_settings_above_2_pow_31_minus_1_are_refused() {
        let most = Ttl::MAX.get();
        let over = most + 1;
        let base = Config::default;
        for config in [
            Config {
                max_ttl: over,
                ..base()
            },
            Config {
                max_negative_ttl: over,
                ..base()
            },
            Config {
                stale_answer_ttl: over,
                ..base()
            },
            Config {
                bogus_ttl: over,
                ..base()
            },
        ] {
            assert_eq!(config.validate(), Err(ConfigError::Ttl(over)), "{config:?}");
        }
        let largest = Config {
            min_ttl: most,
            max_ttl: most,
            max_negative_ttl: most,
            stale_answer_ttl: most,
            bogus_ttl: most,
            max_insecure_ttl: Some(most),
            ..base()
        };
        assert_eq!(largest.validate(), Ok(()));
    }

    /// RFC 1035 §3.2.1: TTL 0 means use for this transaction only.
    #[test]
    fn ttl_zero_is_not_cached() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            vec![a("www.example", 0, 1)],
            vec![],
        );
        assert_eq!(insert(&cache, &q, &r, T0), Err(NotCached::ZeroTtl));
    }

    #[test]
    fn failures_and_unusable_responses_are_refused() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let answer = || vec![a("www.example", 60, 1)];

        let servfail = response(
            "www.example",
            RecordType::A,
            Rcode::SERVFAIL,
            vec![],
            vec![],
        );
        assert_eq!(
            insert(&cache, &q, &servfail, T0),
            Err(NotCached::Rcode(Rcode::SERVFAIL))
        );

        let other = response(
            "other.example",
            RecordType::A,
            Rcode::NOERROR,
            answer(),
            vec![],
        );
        assert_eq!(
            insert(&cache, &q, &other, T0),
            Err(NotCached::OtherQuestion)
        );

        let other_type = response(
            "www.example",
            RecordType::AAAA,
            Rcode::NOERROR,
            answer(),
            vec![],
        );
        assert_eq!(
            insert(&cache, &q, &other_type, T0),
            Err(NotCached::OtherQuestion)
        );

        let fine = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            answer(),
            vec![],
        );
        let mut truncated = Message::decode(&fine).unwrap().message;
        truncated.header.flags = truncated.header.flags.with(Flags::TC);
        assert_eq!(
            insert(&cache, &q, &truncated.to_vec().unwrap(), T0),
            Err(NotCached::Truncated)
        );

        assert_eq!(insert(&cache, &q, &q, T0), Err(NotCached::NotResponse));
        assert!(cache.is_empty());
    }

    fn cname(owner: &str, ttl: u32, target: &str) -> dedens_proto::Record<'static> {
        record(owner, ttl, &RData::Cname(dedens_testkit::dns(target)))
    }

    /// §2.2 NODATA after a CNAME chain: the chain and the denial live as long as the SOA allows, not the chain's TTL.
    #[test]
    fn nodata_after_a_cname_is_negative() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::AAAA);
        let r = response(
            "www.example",
            RecordType::AAAA,
            Rcode::NOERROR,
            vec![cname("www.example", 3600, "host.example")],
            vec![soa("example", 3600, 60)],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        let served = served.unwrap();
        assert_eq!(served.answer.len(), 1);
        assert_eq!(ttls(&served), [60, 60]);
        assert_eq!(lookup(&cache, &q, T0 + 60, NEVER).0, Lookup::Expired);
    }

    /// §2.1: NXDOMAIN at the end of a chain is denied by the zone of the chain's last name.
    #[test]
    fn nxdomain_after_a_cname_into_another_zone() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NXDOMAIN,
            vec![cname("www.example", 3600, "gone.other.test")],
            vec![soa("other.test", 3600, 30)],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        assert_eq!(ttls(&served.unwrap()), [30, 30]);
    }

    /// §2.1, §2.2: an SOA neither at nor above the denied name is not of the zone that denies it.
    #[test]
    fn an_soa_of_another_zone_does_not_deny() {
        let cache = small_cache();
        let q = query(1, "nope.example", RecordType::A);
        for zone in ["other.test", "sub.nope.example", "xample"] {
            let r = response(
                "nope.example",
                RecordType::A,
                Rcode::NXDOMAIN,
                vec![],
                vec![soa(zone, 3600, 60)],
            );
            assert_eq!(insert(&cache, &q, &r, T0), Err(NotCached::NoSoa), "{zone}");
        }
        let r = response(
            "nope.example",
            RecordType::A,
            Rcode::NXDOMAIN,
            vec![],
            vec![soa("EXAMPLE", 3600, 60)],
        );
        insert(&cache, &q, &r, T0).unwrap();
    }

    /// §2.2: a record of the type asked at a name the chain does not end at is no relevant answer: the response is
    /// NODATA, cached only with its SOA and within the negative cap.
    #[test]
    fn a_record_off_the_chain_is_no_answer() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let answer = || {
            vec![
                cname("www.example", 86_400, "host.example"),
                a("other.example", 86_400, 1),
            ]
        };
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            answer(),
            vec![],
        );
        assert_eq!(insert(&cache, &q, &r, T0), Err(NotCached::NoSoa));
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            answer(),
            vec![soa("example", 86_400, 86_400)],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let (_, served) = lookup(&cache, &q, T0, NEVER);
        let most = cache.config().max_negative_ttl;
        assert_eq!(ttls(&served.unwrap()), [most, most, most]);
    }

    /// RFC 1034 §4.3.2 step 3a: the chain ends where its CNAME records lead, in whatever order they come; a question
    /// for CNAME is answered by the first.
    #[test]
    fn the_chain_is_followed_in_any_order_and_a_cname_answers_its_question() {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            vec![
                a("host.example", 600, 1),
                cname("alias.example", 600, "host.example"),
                cname("www.example", 600, "alias.example"),
            ],
            vec![],
        );
        insert(&cache, &q, &r, T0).unwrap();
        let q = query(1, "www.example", RecordType::CNAME);
        let r = response(
            "www.example",
            RecordType::CNAME,
            Rcode::NOERROR,
            vec![cname("www.example", 600, "alias.example")],
            vec![],
        );
        insert(&cache, &q, &r, T0).unwrap();
    }
}

mod stale {
    //! RFC 8767 serve-stale.

    use dedens_cache::{Freshness, Hit, Lookup, StalePolicy};
    use dedens_proto::{Rcode, RecordType};
    use dedens_testkit::captured;

    use crate::util::{
        T0, a, insert, key_of, lookup, min_cache, query, query_of, response, small_cache, ttls,
    };

    fn cached() -> (dedens_cache::Cache, Vec<u8>) {
        let cache = small_cache();
        let q = query(1, "www.example", RecordType::A);
        let r = response(
            "www.example",
            RecordType::A,
            Rcode::NOERROR,
            vec![a("www.example", 60, 1)],
            vec![],
        );
        insert(&cache, &q, &r, T0).expect("a cacheable answer");
        (cache, q)
    }

    fn freshness(found: Lookup) -> Option<Freshness> {
        match found {
            Lookup::Hit(Hit { freshness, .. }) => Some(freshness),
            _ => None,
        }
    }

    #[test]
    fn expired_data_answers_only_when_allowed() {
        let (cache, q) = cached();
        let later = T0 + 61;
        // Kept, not served: the caller resolves, and may answer with it once the client's timer runs out.
        assert_eq!(
            lookup(&cache, &q, later, StalePolicy::Never).0,
            Lookup::Expired
        );
        assert_eq!(
            lookup(&cache, &q, later, StalePolicy::IfFailing).0,
            Lookup::Expired
        );
        let (found, served) = lookup(&cache, &q, later, StalePolicy::Always);
        assert_eq!(freshness(found), Some(Freshness::Stale));
        // §4: stale records carry a short TTL, 30 seconds recommended.
        assert_eq!(ttls(&served.unwrap()), [30]);
    }

    /// §5: when resolution fails, stale data answers.
    #[test]
    fn stale_data_answers_while_resolution_fails() {
        let (cache, q) = cached();
        let later = T0 + 61;
        let hold = cache.fail(&key_of(&q), later);
        // §5 failure recheck timer: no new attempt for 30 seconds.
        assert_eq!(hold, 30);
        let (found, _) = lookup(&cache, &q, later + 1, StalePolicy::IfFailing);
        assert_eq!(freshness(found), Some(Freshness::Stale));
        // Without stale allowed, the hold still forbids resolving.
        assert_eq!(
            lookup(&cache, &q, later + 1, StalePolicy::Never).0,
            Lookup::Failed
        );
        assert_eq!(
            lookup(&cache, &q, later + 30, StalePolicy::IfFailing).0,
            Lookup::Expired
        );
    }

    /// §5: expired data is kept for a bounded time, 1 to 3 days recommended.
    #[test]
    fn stale_data_is_dropped_after_max_stale() {
        let (cache, q) = cached();
        let end = T0 + 60 + cache.config().max_stale;
        assert!(freshness(lookup(&cache, &q, end - 1, StalePolicy::Always).0).is_some());
        assert_eq!(lookup(&cache, &q, end, StalePolicy::Always).0, Lookup::Miss);
    }

    /// D124: a captured answer of 29 s, raised to 60 s, is fresh for 60 and then kept stale for `max_stale` from there.
    #[test]
    fn stale_data_starts_where_the_raised_lifetime_ends() {
        let cache = min_cache(60);
        let wire = captured("a");
        let q = query_of("a");
        insert(&cache, &q, &wire, T0).expect("a cacheable answer");
        let (found, served) = lookup(&cache, &q, T0 + 59, StalePolicy::Always);
        assert_eq!(freshness(found), Some(Freshness::Fresh { prefetch: true }));
        assert_eq!(ttls(&served.unwrap()), [1, 1]);
        let (found, served) = lookup(&cache, &q, T0 + 60, StalePolicy::Always);
        assert_eq!(freshness(found), Some(Freshness::Stale));
        assert_eq!(ttls(&served.unwrap()), [30, 30]);
        let end = T0 + 60 + cache.config().max_stale;
        assert!(freshness(lookup(&cache, &q, end - 1, StalePolicy::Always).0).is_some());
        assert_eq!(lookup(&cache, &q, end, StalePolicy::Always).0, Lookup::Miss);
    }

    #[test]
    fn fresh_data_is_never_stale() {
        let (cache, q) = cached();
        let (found, _) = lookup(&cache, &q, T0 + 10, StalePolicy::Always);
        assert_eq!(freshness(found), Some(Freshness::Fresh { prefetch: false }));
    }
}

mod failures {
    //! RFC 9520 §3: caching resolution failures.

    use dedens_cache::{Cache, Key, Lookup, StalePolicy};
    use dedens_proto::{Rcode, RecordType};

    use crate::util::{T0, a, insert, key_of, lookup, query, response, small_cache};

    const NEVER: StalePolicy = StalePolicy::Never;

    fn down() -> Key {
        key_of(&query(1, "down.example", RecordType::A))
    }

    /// Fails `key` `times` in a row, each as the previous hold ends; returns the holds and when the last one ends.
    fn fail_in_a_row(cache: &Cache, key: &Key, times: usize) -> (Vec<u32>, u32) {
        let mut now = T0;
        let holds = (0..times)
            .map(|_| {
                let hold = cache.fail(key, now);
                now += hold;
                hold
            })
            .collect();
        (holds, now)
    }

    #[test]
    fn a_failure_holds_the_key() {
        let cache = small_cache();
        let q = query(1, "down.example", RecordType::A);
        assert_eq!(cache.fail(&key_of(&q), T0), 5);
        assert_eq!(lookup(&cache, &q, T0, NEVER).0, Lookup::Failed);
        assert_eq!(lookup(&cache, &q, T0 + 4, NEVER).0, Lookup::Failed);
        assert_eq!(lookup(&cache, &q, T0 + 5, NEVER).0, Lookup::Miss);
    }

    /// §3.2: back off exponentially on repeated failures, holding at most 5 minutes.
    #[test]
    fn holds_double_up_to_five_minutes() {
        let cache = small_cache();
        let (holds, _) = fail_in_a_row(&cache, &down(), 9);
        assert_eq!(holds, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
    }

    /// A failure reported during a hold, by a resolution started before it, neither counts nor extends the hold.
    #[test]
    fn a_failure_during_the_hold_is_not_counted() {
        let cache = small_cache();
        let key = down();
        assert_eq!(cache.fail(&key, T0), 5);
        assert_eq!(cache.fail(&key, T0 + 2), 3);
        assert_eq!(cache.fail(&key, T0 + 4), 1);
        assert_eq!(cache.fail(&key, T0 + 5), 10);
    }

    /// Failures stop being in a row once the key has resolved, or not been tried, for longer than the longest hold.
    #[test]
    fn failures_long_apart_start_over() {
        let cache = small_cache();
        let key = down();
        let (_, end) = fail_in_a_row(&cache, &key, 4);
        let longest = cache.config().failure_max;
        assert_eq!(cache.fail(&key, end + longest), 80);
        assert_eq!(cache.fail(&key, end + 80 + longest + longest + 1), 5);
    }

    /// A hold set before the clock went back lasts no longer than the longest hold from now.
    #[test]
    fn a_clock_going_back_does_not_extend_a_hold() {
        let cache = small_cache();
        let q = query(1, "down.example", RecordType::A);
        let key = key_of(&q);
        let _ = cache.fail(&key, T0 + 10_000);
        assert_eq!(lookup(&cache, &q, T0, NEVER).0, Lookup::Miss);
        // Still in a row: the second failure.
        assert_eq!(cache.fail(&key, T0), 10);
        assert_eq!(lookup(&cache, &q, T0, NEVER).0, Lookup::Failed);
    }

    #[test]
    fn an_answer_ends_the_hold() {
        let cache = small_cache();
        let q = query(1, "down.example", RecordType::A);
        let key = key_of(&q);
        let (_, now) = fail_in_a_row(&cache, &key, 6);
        let _ = cache.fail(&key, now);
        let r = response(
            "down.example",
            RecordType::A,
            Rcode::NOERROR,
            vec![a("down.example", 60, 1)],
            vec![],
        );
        insert(&cache, &q, &r, now).unwrap();
        assert!(matches!(lookup(&cache, &q, now, NEVER).0, Lookup::Hit(_)));
        // Counted from one again: the first hold, raised to the RFC 8767 recheck time as stale data now exists.
        assert_eq!(cache.fail(&key, now + 60), 30);
    }

    /// The RFC 8767 recheck time holds only while the stale data may still be served.
    #[test]
    fn the_recheck_time_ends_with_the_stale_data() {
        let q = query(1, "down.example", RecordType::A);
        let key = key_of(&q);
        let r = response(
            "down.example",
            RecordType::A,
            Rcode::NOERROR,
            vec![a("down.example", 60, 1)],
            vec![],
        );
        for (late, hold) in [(0, 30), (1, 5)] {
            let cache = small_cache();
            insert(&cache, &q, &r, T0).unwrap();
            let stale_until = T0 + 60 + cache.config().max_stale;
            assert_eq!(cache.fail(&key, stale_until - 1 + late), hold);
        }
    }
}
