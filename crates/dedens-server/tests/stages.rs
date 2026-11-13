//! The stages of the pipeline: forwarding, the cache, plugins, queries without RD, and the checks on upstream
//! responses.

mod forward {
    //! The forward stage (D41): what goes upstream, and the client's question case kept in the reply (RFC 4343 §4).

    use std::borrow::Cow;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use dedens_proto::edns::{ClientSubnet, Cookie, Edns, EdnsOption};
    use dedens_proto::{Flags, Message, Transport};
    use dedens_server::{Forward, Pipeline, Server, Stage, Step, Via};
    use dedens_testkit::{captured, dns, query};

    use crate::util::{decode, forwarder, run, wire};

    #[test]
    fn upstream_gets_the_question_and_our_edns_without_the_clients_options() {
        let response = captured("a");
        let mut query = query("a", 7);
        query.edns = Some(Edns {
            udp_payload: 4096,
            options: vec![
                EdnsOption::ClientSubnet(
                    ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 0)
                        .expect("a valid subnet"),
                ),
                EdnsOption::Cookie(Cookie::new([1; 8], None).expect("a client cookie")),
                EdnsOption::Nsid(Cow::Borrowed(b"")),
            ],
            ..Edns::default()
        });
        let done = run(
            &forwarder(),
            &wire(&query),
            Transport::Udp,
            &[Some(&response)],
        );
        let request = &done.requests[0];
        assert_eq!(request.questions, query.questions);
        assert_eq!(request.header.flags, Flags::RD);
        assert_eq!(request.edns, Some(Edns::default()));
        assert_eq!(
            (&request.answer, &request.authority, &request.additional),
            (&vec![], &vec![], &vec![])
        );
    }

    #[test]
    fn the_reply_has_the_question_in_the_clients_case() {
        let response = captured("a");
        let mut query = query("a", 7);
        let upper = query.questions[0].name.to_string().to_ascii_uppercase();
        query.questions[0].name = dns(&upper);
        let done = run(
            &forwarder(),
            &wire(&query),
            Transport::Udp,
            &[Some(&response)],
        );
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.questions[0].name.to_string(), upper);
        let upstream = Message::decode(&response).expect("decodes").message;
        assert_ne!(upstream.questions[0].name.to_string(), upper);
    }

    #[test]
    fn a_forward_stage_has_a_server() {
        assert!(Forward::new(Vec::<SocketAddr>::new()).is_none());
    }

    /// D65: each server is asked over its own transport, handed to the caller as configured, and printed so.
    #[test]
    fn servers_go_upstream_as_configured() {
        let addr: SocketAddr = "192.0.2.1:853".parse().expect("an address");
        let tls = Server {
            addr,
            via: Via::Tls(Some("dns.example".into())),
        };
        let quic = Server {
            addr,
            via: Via::Quic(None),
        };
        let pipeline = Pipeline::new(vec![Stage::Forward(
            Forward::new([tls.clone(), quic.clone()]).expect("servers"),
        )]);
        let mut out = vec![0; 65535];
        let query = query("a", 7);
        let Step::Upstream(first) = pipeline.query(
            &wire(&query),
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            0,
            &mut out,
        ) else {
            unreachable!("a forwarder sends the query upstream");
        };
        assert_eq!(first.server(), &tls);
        let Step::Upstream(second) = pipeline.receive(first, None, 0, &mut out) else {
            unreachable!("the next server is asked");
        };
        assert_eq!(second.server(), &quic);
        assert_eq!(Server::from(addr).to_string(), "192.0.2.1:853");
        assert_eq!(tls.to_string(), "tls://192.0.2.1:853#dns.example");
        assert_eq!(quic.to_string(), "quic://192.0.2.1:853");
        let https = Server {
            addr: "192.0.2.1:443".parse().expect("an address"),
            via: Via::Https {
                name: Some("dns.example".into()),
                path: "/dns-query".into(),
            },
        };
        assert_eq!(
            https.to_string(),
            "https://192.0.2.1:443/dns-query#dns.example"
        );
        let dnscrypt = Server {
            addr: "94.140.14.14:5443".parse().expect("an address"),
            via: Via::Dnscrypt("sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20".into()),
        };
        assert_eq!(
            dnscrypt.to_string(),
            "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20"
        );
    }
}

mod cache {
    //! The cache stage (D43): answers from stored responses with TTLs counted down (RFC 1035 §7.4, RFC 2181 §8),
    //! failure holds (RFC 9520 §3.2), expired data while upstream fails or once the client response timer ran out,
    //! with EDE 3 or 19 (RFC 8767 §4-5, RFC 8914 §4.4), and refresh of entries near their end.

    use std::borrow::Cow;
    use std::net::Ipv4Addr;
    use std::num::NonZeroU8;
    use std::sync::Arc;
    use std::time::Duration;

    use dedens_cache::{Cache, Config};
    use dedens_proto::edns::{Edns, EdnsOption, ExtendedError, InfoCode};
    use dedens_proto::{Flags, Message, Rcode, Transport};
    use dedens_server::{Forward, Pipeline, Stage, Step, Upstream};
    use dedens_testkit::{captured, query};

    use crate::util::{caching, decode, run_at, servers, wire, with_flags};

    /// The reply at `now` to `query`, upstream answering `responses` in turn, and the servers asked.
    fn ask(
        pipeline: &Pipeline,
        query: &Message<'_>,
        now: u32,
        responses: &[Option<&[u8]>],
    ) -> (Message<'static>, usize) {
        let run = run_at(pipeline, &wire(query), Transport::Udp, now, responses);
        let reply = decode(&run.reply.expect("a reply")).into_owned();
        (reply, run.asked.len())
    }

    fn ttls(message: &Message<'_>) -> Vec<u32> {
        message
            .answer
            .iter()
            .map(|record| record.ttl.get())
            .collect()
    }

    /// Our OPT record with an extended error of `code`.
    fn stale(code: InfoCode) -> Edns<'static> {
        Edns {
            options: vec![EdnsOption::Ede(ExtendedError {
                code,
                text: Cow::Borrowed(""),
            })],
            ..Edns::default()
        }
    }

    #[test]
    fn a_second_query_is_answered_from_the_cache() {
        let response = captured("a");
        let pipeline = caching();
        let mut query = query("a", 7);
        let (first, asked) = ask(&pipeline, &query, 0, &[Some(&response)]);
        assert_eq!(asked, 1);
        query.header.id = 8;
        let (second, asked) = ask(&pipeline, &query, 2, &[]);
        assert_eq!(asked, 0);
        assert_eq!((second.header.id, second.rcode()), (8, Rcode::NOERROR));
        assert_eq!(second.header.flags, first.header.flags);
        assert!(!second.header.flags.contains(Flags::AA));
        assert!(second.header.flags.contains(Flags::RA));
        assert_eq!(second.questions, first.questions);
        assert_eq!(second.edns, Some(Edns::default()));
        let counted_down: Vec<_> = ttls(&first).iter().map(|ttl| ttl - 2).collect();
        assert_eq!(ttls(&second), counted_down);
    }

    /// A fresh hit keeps no room for the EDE option only a stale one carries: one that just fits the client's size
    /// goes out whole (RFC 2181 §9: TC only when records are dropped).
    #[test]
    fn a_fresh_hit_that_just_fits_is_whole() {
        let response = captured("txt_large");
        let pipeline = caching();
        let mut query = query("txt_large", 7);
        let _ = ask(&pipeline, &query, 0, &[Some(&response)]);
        let whole = run_at(&pipeline, &wire(&query), Transport::Udp, 0, &[])
            .reply
            .expect("a hit");
        let whole_answer = decode(&whole).answer.len();
        let fits = u16::try_from(whole.len()).expect("a UDP size");
        assert!(fits > 512, "a size the client may ask for");
        query.edns.as_mut().expect("EDNS").udp_payload = fits;
        let (reply, asked) = ask(&pipeline, &query, 0, &[]);
        assert_eq!(asked, 0);
        assert!(!reply.header.flags.contains(Flags::TC));
        assert_eq!(reply.answer.len(), whole_answer);
        // A byte less, and the room kept for our OPT record leaves records out: still a hit, with TC.
        query.edns.as_mut().expect("EDNS").udp_payload = fits - 1;
        let (reply, asked) = ask(&pipeline, &query, 0, &[]);
        assert_eq!(asked, 0);
        assert!(reply.header.flags.contains(Flags::TC));
        assert!(reply.answer.len() < whole_answer);
    }

    #[test]
    fn a_query_without_edns_gets_no_opt_record_from_the_cache() {
        let response = captured("a");
        let pipeline = caching();
        let mut query = query("a", 7);
        query.edns = None;
        let _ = ask(&pipeline, &query, 0, &[Some(&response)]);
        let (reply, asked) = ask(&pipeline, &query, 0, &[]);
        assert_eq!((asked, &reply.edns), (0, &None));
        assert_eq!(reply.rcode(), Rcode::NOERROR);
    }

    #[test]
    fn failures_are_held() {
        let pipeline = caching();
        let query = query("a", 7);
        let (reply, asked) = ask(&pipeline, &query, 0, &[None, None]);
        assert_eq!((reply.rcode(), asked), (Rcode::SERVFAIL, 2));
        // The first hold lasts 5 seconds (RFC 9520 §3.2, at least 1).
        let (reply, asked) = ask(&pipeline, &query, 4, &[]);
        assert_eq!((reply.rcode(), asked), (Rcode::SERVFAIL, 0));
        let (reply, asked) = ask(&pipeline, &query, 5, &[None, None]);
        assert_eq!((reply.rcode(), asked), (Rcode::SERVFAIL, 2));
    }

    /// A hit carries the flags of the query it answers (RFC 1035 §4.1.1), not those of the one that stored it: RD
    /// only when asked, and no AD even for a client that asks for it, the response having had AD upstream but not been
    /// validated (RFC 6840 §5.8, D114).
    #[test]
    fn a_hit_carries_the_flags_of_its_query() {
        let response = with_flags(captured("a"), Flags::QR | Flags::RD | Flags::RA | Flags::AD);
        let pipeline = caching();
        let mut query = query("a", 7);
        query.header.flags = Flags::RD | Flags::AD;
        let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
        assert_eq!(first.header.flags, Flags::QR | Flags::RD | Flags::RA);
        query.header.flags = Flags::AD;
        let (reply, asked) = ask(&pipeline, &query, 0, &[]);
        assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 0));
        assert_eq!(reply.header.flags, Flags::QR | Flags::RA);
    }

    /// A held failure answers recursive queries only: one without RD is refused, as when nothing is cached.
    #[test]
    fn a_held_failure_answers_recursive_queries_only() {
        let pipeline = caching();
        let mut query = query("a", 7);
        let _ = ask(&pipeline, &query, 0, &[None, None]);
        query.header.flags = Flags::default();
        let (reply, asked) = ask(&pipeline, &query, 1, &[]);
        assert_eq!((reply.rcode(), asked), (Rcode::REFUSED, 0));
    }

    #[test]
    fn expired_data_answers_while_upstream_fails() {
        let response = captured("a");
        let pipeline = caching();
        let query = query("a", 7);
        let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
        let expired = ttls(&first).into_iter().min().expect("an answer") + 1;
        let (reply, asked) = ask(&pipeline, &query, expired, &[None, None]);
        assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 2));
        assert_eq!(reply.answer.len(), first.answer.len());
        // Stale records go out with 30 seconds (RFC 8767 §4), and stale data answers through the hold untried.
        assert!(ttls(&reply).iter().all(|&ttl| ttl == 30));
        assert_eq!(reply.edns, Some(stale(InfoCode::STALE_ANSWER)));
        let (again, asked) = ask(&pipeline, &query, expired + 1, &[]);
        assert_eq!((again.rcode(), asked), (Rcode::NOERROR, 0));
        assert_eq!(again.edns, Some(stale(InfoCode::STALE_ANSWER)));
    }

    #[test]
    fn an_expired_nxdomain_is_a_stale_nxdomain_answer() {
        let response = captured("nxdomain_soa");
        let pipeline = caching();
        let query = query("nxdomain_soa", 7);
        let _ = ask(&pipeline, &query, 0, &[Some(&response)]);
        // Past the longest negative TTL (RFC 2308 §5: 3 hours by default).
        let (reply, _) = ask(&pipeline, &query, 3 * 3600 + 1, &[None, None]);
        assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
        assert_eq!(reply.edns, Some(stale(InfoCode::STALE_NXDOMAIN_ANSWER)));
    }

    #[test]
    fn expired_data_does_not_answer_when_upstream_does() {
        let response = captured("a");
        let pipeline = caching();
        let query = query("a", 7);
        let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
        let expired = ttls(&first).into_iter().min().expect("an answer") + 1;
        let (reply, asked) = ask(&pipeline, &query, expired, &[Some(&response)]);
        assert_eq!((asked, &reply.edns), (1, &Some(Edns::default())));
        assert_eq!(ttls(&reply), ttls(&first));
    }

    #[test]
    fn entries_near_their_end_are_refreshed_once() {
        let response = captured("a");
        let pipeline = caching();
        let query = query("a", 7);
        let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
        let ttl = ttls(&first).into_iter().min().expect("an answer");
        assert!(ttl >= 20, "a TTL of {ttl} leaves no time to refresh");
        // Under 10% of the TTL left: the reply comes from the cache and upstream is asked once in the background.
        let late = ttl - ttl / 20;
        let (reply, asked) = ask(&pipeline, &query, late, &[Some(&response)]);
        assert_eq!((asked, ttls(&reply)[0]), (1, ttl - late));
        // The refresh stored the response anew.
        let (refreshed, asked) = ask(&pipeline, &query, late, &[]);
        assert_eq!((asked, ttls(&refreshed)), (0, ttls(&first)));
    }

    /// The upstream query `query` gets at `now`.
    fn upstream_of(pipeline: &Pipeline, query: &Message<'_>, now: u32) -> Box<Upstream> {
        let mut out = vec![0; 65535];
        match pipeline.query(
            &wire(query),
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            now,
            &mut out,
        ) {
            Step::Upstream(upstream) => upstream,
            step => unreachable!("an upstream query, not {step:?}"),
        }
    }

    /// A cached `a` response and the time it has expired by.
    fn expired_a(pipeline: &Pipeline) -> (Vec<u8>, Message<'static>, u32) {
        let response = captured("a");
        let query = query("a", 7);
        let (first, _) = ask(pipeline, &query, 0, &[Some(&response)]);
        let expired = ttls(&first).into_iter().min().expect("an answer") + 1;
        (response, first, expired)
    }

    #[test]
    fn expired_data_answers_once_the_client_timer_runs_out_and_resolution_goes_on() {
        let pipeline = caching();
        let (response, first, expired) = expired_a(&pipeline);
        let query = query("a", 7);
        let mut upstream = upstream_of(&pipeline, &query, expired);
        // RFC 8767 §5 suggests 1.8 seconds.
        assert_eq!(upstream.stale_after(), Some(Duration::from_millis(1800)));
        let mut out = vec![0; 65535];
        let len = pipeline
            .stale(&mut upstream, expired, &mut out)
            .expect("expired data");
        let reply = decode(&out[..len]);
        assert_eq!((reply.header.id, reply.rcode()), (7, Rcode::NOERROR));
        assert!(ttls(&reply).iter().all(|&ttl| ttl == 30));
        assert_eq!(reply.edns, Some(stale(InfoCode::STALE_ANSWER)));
        assert_eq!(
            pipeline.stale(&mut upstream, expired, &mut out),
            None,
            "one reply"
        );
        // The response only refreshes the cache: the next query has it fresh.
        let step = pipeline.receive(upstream, Some(&response), expired, &mut out);
        assert!(matches!(step, Step::Drop), "{step:?}");
        let (fresh, asked) = ask(&pipeline, &query, expired, &[]);
        assert_eq!((asked, ttls(&fresh)), (0, ttls(&first)));
    }

    #[test]
    fn a_failure_after_a_stale_answer_is_held_without_another_reply() {
        let pipeline = caching();
        let (_, _, expired) = expired_a(&pipeline);
        let query = query("a", 7);
        let mut upstream = upstream_of(&pipeline, &query, expired);
        let mut out = vec![0; 65535];
        assert!(pipeline.stale(&mut upstream, expired, &mut out).is_some());
        let Step::Upstream(next) = pipeline.receive(upstream, None, expired, &mut out) else {
            panic!("the second server");
        };
        let step = pipeline.receive(next, None, expired, &mut out);
        assert!(matches!(step, Step::Drop), "{step:?}");
        // Held: expired data answers at once, upstream untried.
        let (reply, asked) = ask(&pipeline, &query, expired + 1, &[]);
        assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 0));
        assert_eq!(reply.edns, Some(stale(InfoCode::STALE_ANSWER)));
    }

    #[test]
    fn a_failure_of_ours_is_servfail_without_a_hold() {
        let pipeline = caching();
        let response = captured("a");
        let query = query("a", 7);
        let upstream = upstream_of(&pipeline, &query, 0);
        let mut out = vec![0; 65535];
        let Step::Reply(len) = pipeline.abandon(&upstream, &mut out) else {
            unreachable!("a reply");
        };
        assert_eq!(decode(&out[..len]).rcode(), Rcode::SERVFAIL);
        let (reply, asked) = ask(&pipeline, &query, 0, &[Some(&response)]);
        assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 1));
    }

    #[test]
    fn without_expired_data_the_client_waits_for_resolution() {
        let pipeline = caching();
        let response = captured("a");
        let mut upstream = upstream_of(&pipeline, &query("a", 7), 0);
        // No timer to wait for: nothing could answer when it ran out.
        assert_eq!(upstream.stale_after(), None);
        let mut out = vec![0; 65535];
        assert_eq!(pipeline.stale(&mut upstream, 0, &mut out), None);
        let step = pipeline.receive(upstream, Some(&response), 0, &mut out);
        assert!(matches!(step, Step::Reply(_)), "{step:?}");
    }

    #[test]
    fn the_timer_is_the_cache_stages_and_the_patience_the_forward_stages() {
        let query = query("a", 7);
        let forward = Forward::new(servers()).expect("servers");
        let alone = Pipeline::new(vec![Stage::Forward(forward.clone())]);
        let upstream = upstream_of(&alone, &query, 0);
        assert_eq!(upstream.stale_after(), None);
        assert_eq!(
            upstream.patience(),
            (Duration::from_secs(3), NonZeroU8::MIN.saturating_add(1))
        );
        let config = Config {
            stale_answer_after_ms: 0,
            ..Config::default()
        };
        let tries = NonZeroU8::MIN;
        let patient = Pipeline::new(vec![
            Stage::Cache(Arc::new(Cache::new(config).expect("valid settings"))),
            Stage::Forward(
                forward
                    .with_timeout(Duration::from_millis(500))
                    .with_tries(tries),
            ),
        ]);
        // A timer of 0 ms is none, even with expired data to answer.
        let (_, _, expired) = expired_a(&patient);
        let upstream = upstream_of(&patient, &query, expired);
        assert_eq!(upstream.stale_after(), None);
        assert_eq!(upstream.patience(), (Duration::from_millis(500), tries));
    }
}

mod plugin {
    //! Plugin stages (D54): an answer is written after the client's question, with AA when the plugin is
    //! authoritative; a query the plugin passes on goes to the next stage.

    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use dedens_cache::{Cache, Config};
    use dedens_dnssec::{Limits, TrustAnchors, Validator};
    use dedens_proto::edns::{Edns, EdnsOption, InfoCode};
    use dedens_proto::rdata::RData;
    use dedens_proto::{
        Class, Flags, Message, Name, Opcode, Query, Question, Rcode, Record, RecordType, Transport,
        Ttl,
    };
    use dedens_server::{Answer, Forward, Pipeline, Plugin, Records, Reviewer, Stage, Validating};
    use dedens_testkit::dns;

    use crate::util::{decode, run, servers, wire};

    /// Answers A queries for `local.test.` with `count` addresses, and blocks `blocked.test.`.
    #[derive(Debug)]
    struct Local {
        records: Records,
    }

    impl Local {
        fn new(count: u8) -> Self {
            let name = dns("local.test");
            let records: Vec<_> = (0..count)
                .map(|i| {
                    let data = RData::A(Ipv4Addr::new(192, 0, 2, i));
                    Record::new(name.clone(), Class::IN, Ttl::from_wire(60), &data)
                })
                .collect();
            Self {
                records: Records::new(&name, &records).expect("the records fit"),
            }
        }
    }

    impl Plugin for Local {
        fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
            let question = query.question()?;
            if question.name == dns("blocked.test") {
                return Some(Answer {
                    rcode: Rcode::NXDOMAIN,
                    records: None,
                    authoritative: false,
                    error: Some(InfoCode::BLOCKED),
                });
            }
            (question.name == dns("local.test")).then_some(Answer {
                rcode: Rcode::NOERROR,
                records: (question.qtype == RecordType::A).then_some(&self.records),
                authoritative: true,
                error: None,
            })
        }
    }

    fn pipeline(count: u8) -> Pipeline {
        Pipeline::new(vec![
            Stage::Plugin(Box::new(Local::new(count))),
            Stage::Forward(Forward::new(servers()).expect("servers")),
        ])
    }

    fn query(name: &str, qtype: RecordType, edns: bool) -> Vec<u8> {
        let name: Name<'static> = name.parse().expect("a name");
        let mut query = Message::query(7, Question::new(name, qtype));
        if !edns {
            query.edns = None;
        }
        wire(&query)
    }

    /// RFC 1035 §4.1.1: AA, the plugin holding the name; the answer owned by the question's name, in its case
    /// (RFC 4343 §4), the OPT record after the records (RFC 6891 §7).
    #[test]
    fn an_answer_follows_the_question_in_its_case() {
        let done = run(
            &pipeline(2),
            &query("LoCaL.TeSt.", RecordType::A, true),
            Transport::Udp,
            &[],
        );
        assert_eq!(done.asked, []);
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!((reply.header.id, reply.header.opcode), (7, Opcode::QUERY));
        assert_eq!(
            reply.header.flags,
            Flags::QR | Flags::AA | Flags::RD | Flags::RA
        );
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert_eq!(reply.questions[0].name.to_string(), "LoCaL.TeSt.");
        let owners: Vec<_> = reply.answer.iter().map(|r| r.name.to_string()).collect();
        assert_eq!(owners, ["LoCaL.TeSt.", "LoCaL.TeSt."]);
        let data: Vec<_> = reply.answer.iter().map(Record::data).collect();
        assert_eq!(
            data,
            [
                RData::A(Ipv4Addr::new(192, 0, 2, 0)),
                RData::A(Ipv4Addr::new(192, 0, 2, 1))
            ]
        );
        assert_eq!(reply.edns, Some(Edns::default()));
    }

    /// RFC 2308 §2.2: no data, NOERROR with an empty answer.
    #[test]
    fn a_name_without_records_of_the_type_has_no_data() {
        let wire = run(
            &pipeline(1),
            &query("local.test.", RecordType::MX, false),
            Transport::Udp,
            &[],
        )
        .reply
        .expect("a reply");
        let reply = decode(&wire);
        assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NOERROR, 0));
        assert!(reply.header.flags.contains(Flags::AA));
    }

    /// RFC 8914 §4.16: Blocked; AA clear, the plugin being no authority.
    #[test]
    fn an_error_goes_in_our_opt_record() {
        let wire = run(
            &pipeline(1),
            &query("blocked.test.", RecordType::A, true),
            Transport::Udp,
            &[],
        )
        .reply
        .expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
        assert!(!reply.header.flags.contains(Flags::AA));
        let options = reply.edns.expect("our OPT record").options;
        assert!(
            matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
            "{options:?}"
        );
    }

    /// RFC 2181 §9: records that do not fit 512 bytes are left out, with TC.
    #[test]
    fn records_too_large_for_the_client_set_tc() {
        let wire = run(
            &pipeline(40),
            &query("local.test.", RecordType::A, false),
            Transport::Udp,
            &[],
        )
        .reply
        .expect("a reply");
        let reply = decode(&wire);
        assert!(reply.header.flags.contains(Flags::TC));
        assert_eq!(reply.answer.len(), 0);
        let tcp = run(
            &pipeline(40),
            &query("local.test.", RecordType::A, false),
            Transport::Tcp,
            &[],
        )
        .reply
        .expect("a reply");
        assert_eq!(decode(&tcp).answer.len(), 40);
    }

    #[test]
    fn a_query_passed_on_goes_upstream() {
        let done = run(
            &pipeline(1),
            &query("example.com.", RecordType::A, true),
            Transport::Udp,
            &[],
        );
        assert_eq!(done.asked, servers());
    }

    /// A plugin answers without RD: its data is local, no recursion (RFC 1034 §4.3.1).
    #[test]
    fn a_plugin_answers_without_recursion_desired() {
        let mut message = Message::query(
            7,
            Question::new("local.test.".parse().expect("a name"), RecordType::A),
        );
        message.header.flags = Flags::default();
        let wire = run(
            &pipeline(1),
            &crate::util::wire(&message),
            Transport::Udp,
            &[],
        )
        .reply
        .expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.answer.len(), 1);
        assert_eq!(reply.header.flags, Flags::QR | Flags::AA | Flags::RA);
    }

    /// Answers every query with its fields.
    #[derive(Debug)]
    struct Fixed {
        rcode: Rcode,
        records: Option<Records>,
        error: Option<InfoCode>,
    }

    impl Fixed {
        /// A pipeline of this plugin alone, answering `records` of `local.test.`, none when empty.
        fn pipeline(rcode: Rcode, records: &[&str], error: Option<InfoCode>) -> Pipeline {
            let records: Vec<Record<'static>> = records
                .iter()
                .map(|text| text.parse().expect("a record"))
                .collect();
            let records = (!records.is_empty())
                .then(|| Records::new(&dns("local.test"), &records).expect("the records fit"));
            Pipeline::new(vec![Stage::Plugin(Box::new(Self {
                rcode,
                records,
                error,
            }))])
        }
    }

    impl Plugin for Fixed {
        fn answer(&self, _: &Query<'_>) -> Option<Answer<'_>> {
            Some(Answer {
                rcode: self.rcode,
                records: self.records.as_ref(),
                authoritative: true,
                error: self.error,
            })
        }
    }

    /// RFC 6891 §6.1.3: an RCODE past 4 bits needs an OPT record; a client without one gets SERVFAIL. RCODE 15 fits.
    #[test]
    fn an_extended_rcode_goes_to_edns_clients_only() {
        for (rcode, edns, sent) in [(16_u16, true, 16_u16), (16, false, 2), (15, false, 15)] {
            let pipeline = Fixed::pipeline(Rcode::from(rcode), &[], None);
            let wire = run(
                &pipeline,
                &query("local.test.", RecordType::A, edns),
                Transport::Udp,
                &[],
            )
            .reply
            .expect("a reply");
            assert_eq!(decode(&wire).rcode(), Rcode::from(sent), "{rcode} {edns}");
        }
    }

    /// RFC 2181 §9: records filling the client's UDP size to the byte go out whole, with an extended error (RFC 8914);
    /// a byte less, they are left out with TC.
    #[test]
    fn records_that_just_fit_go_out_whole() {
        let records: Vec<String> = (0..40)
            .map(|i| format!("local.test. 60 IN A 192.0.2.{i}"))
            .collect();
        let records: Vec<&str> = records.iter().map(String::as_str).collect();
        let pipeline = Fixed::pipeline(Rcode::NOERROR, &records, Some(InfoCode::BLOCKED));
        let mut query = Message::query(7, Question::new(dns("local.test"), RecordType::A));
        let whole = run(&pipeline, &wire(&query), Transport::Tcp, &[])
            .reply
            .expect("a reply");
        let size = u16::try_from(whole.len()).expect("a UDP size");
        assert!(size > 512, "{size}");
        for (payload, count) in [(size, 40), (size - 1, 0)] {
            query.edns.as_mut().expect("EDNS").udp_payload = payload;
            let wire = run(&pipeline, &wire(&query), Transport::Udp, &[])
                .reply
                .expect("a reply");
            let reply = decode(&wire);
            assert_eq!(reply.answer.len(), count, "{payload}");
            assert_eq!(
                reply.header.flags.contains(Flags::TC),
                count == 0,
                "{payload}"
            );
            let options = reply.edns.expect("our OPT record").options;
            assert!(matches!(&options[..], [EdnsOption::Ede(_)]), "{options:?}");
        }
    }

    /// RFC 8467 §4.1: an answer to a padded query over TLS is padded to the next multiple of 468 bytes, whatever its
    /// length.
    #[test]
    fn answers_are_padded_to_the_next_block() {
        let long = "a".repeat(255);
        for n in 150..=170 {
            let record = format!("local.test. 60 IN TXT \"{long}\" \"{}\"", "b".repeat(n));
            let pipeline = Fixed::pipeline(Rcode::NOERROR, &[&record], None);
            let len = |padded: bool| {
                let mut query =
                    Message::query(7, Question::new(dns("local.test"), RecordType::TXT));
                if padded {
                    query.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Padding(0)];
                }
                let reply = run(&pipeline, &wire(&query), Transport::Tls, &[]).reply;
                reply.expect("a reply").len()
            };
            let plain = len(false);
            assert_eq!(len(true), (plain + 4).next_multiple_of(468), "{n}");
        }
    }

    /// Blocks, in review, a response whose answer has a CNAME to `target` (D118); answers `own.test.` itself, with no
    /// records. Counts the responses it reviews.
    #[derive(Debug)]
    struct Gate {
        target: Name<'static>,
        reviews: Arc<AtomicUsize>,
    }

    impl Gate {
        fn new(target: &str) -> (Self, Arc<AtomicUsize>) {
            let reviews = Arc::new(AtomicUsize::new(0));
            let gate = Self {
                target: dns(target),
                reviews: Arc::clone(&reviews),
            };
            (gate, reviews)
        }
    }

    impl Plugin for Gate {
        fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
            let own = query.question()?.name == dns("own.test");
            own.then_some(Answer {
                rcode: Rcode::NOERROR,
                records: None,
                authoritative: true,
                error: None,
            })
        }

        fn reviewer(&self) -> Option<&dyn Reviewer> {
            Some(self)
        }
    }

    impl Reviewer for Gate {
        fn review(&self, _query: &Query<'_>, response: &Message<'_>) -> Option<Answer<'_>> {
            self.reviews.fetch_add(1, Ordering::Relaxed);
            response
                .answer
                .iter()
                .any(|r| matches!(r.data(), RData::Cname(target) if target == self.target))
                .then_some(Answer {
                    rcode: Rcode::NXDOMAIN,
                    records: None,
                    authoritative: false,
                    error: Some(InfoCode::BLOCKED),
                })
        }
    }

    /// The captured response to `www.ripe.net. A`: a CNAME to `www.ripe.net.edgekey.net.`, to
    /// `e337066.dscb.akamaiedge.net.`, and its addresses.
    fn ripe() -> Vec<u8> {
        dedens_testkit::dnssec::capture("cname_to_insecure")
    }

    /// A pipeline of the gate, a cache and a forward stage; `cache` is shared to be kept across pipelines.
    fn gated(target: &str, cache: &Arc<Cache>) -> (Pipeline, Arc<AtomicUsize>) {
        let (gate, reviews) = Gate::new(target);
        let pipeline = Pipeline::new(vec![
            Stage::Plugin(Box::new(gate)),
            Stage::Cache(Arc::clone(cache)),
            Stage::Forward(Forward::new(servers()).expect("servers")),
        ]);
        (pipeline, reviews)
    }

    fn cache() -> Arc<Cache> {
        Arc::new(Cache::new(Config::default()).expect("the default settings"))
    }

    fn assert_blocked(wire: &[u8]) {
        let reply = decode(wire);
        assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NXDOMAIN, 0));
        assert!(!reply.header.flags.contains(Flags::AA));
        assert!(!reply.header.flags.contains(Flags::AD));
        let options = reply.edns.expect("our OPT record").options;
        assert!(
            matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
            "{options:?}"
        );
    }

    /// D118: a response from upstream whose chain a plugin refuses is answered as that plugin answers. It is stored, not
    /// its replacement, and refused again by the hit: a repeat does not go upstream.
    #[test]
    fn a_response_a_plugin_replaces_is_stored_and_refused_on_a_hit() {
        let (pipeline, reviews) = gated("e337066.dscb.akamaiedge.net", &cache());
        let query = query("www.ripe.net.", RecordType::A, true);
        let response = ripe();
        let first = run(&pipeline, &query, Transport::Udp, &[Some(&response)]);
        assert_eq!(first.asked.len(), 1);
        assert_blocked(&first.reply.expect("a reply"));
        let second = run(&pipeline, &query, Transport::Udp, &[]);
        assert_eq!(second.asked, []);
        assert_blocked(&second.reply.expect("a reply"));
        assert_eq!(reviews.load(Ordering::Relaxed), 2);
    }

    /// A plugin after the cache stage cannot refuse what the cache serves: its refusal is not stored.
    #[test]
    fn a_response_a_plugin_after_the_cache_replaces_is_not_stored() {
        let (gate, _) = Gate::new("e337066.dscb.akamaiedge.net");
        let pipeline = Pipeline::new(vec![
            Stage::Cache(cache()),
            Stage::Plugin(Box::new(gate)),
            Stage::Forward(Forward::new(servers()).expect("servers")),
        ]);
        let query = query("www.ripe.net.", RecordType::A, true);
        let response = ripe();
        for _ in 0..2 {
            let done = run(&pipeline, &query, Transport::Udp, &[Some(&response)]);
            assert_eq!(done.asked.len(), 1, "upstream is asked again");
            assert_blocked(&done.reply.expect("a reply"));
        }
    }

    /// The same response, its chain accepted, is stored and served: the first reply is the response, the second a hit.
    /// The pipeline reviewed it when it came, and does not decode the hit: one review.
    #[test]
    fn a_response_no_plugin_replaces_is_cached_and_reviewed_once() {
        let (pipeline, reviews) = gated("nothing.example", &cache());
        let query = query("www.ripe.net.", RecordType::A, true);
        let response = ripe();
        let first = run(&pipeline, &query, Transport::Udp, &[Some(&response)]);
        assert_eq!(decode(&first.reply.expect("a reply")).answer.len(), 5);
        for _ in 0..2 {
            let hit = run(&pipeline, &query, Transport::Udp, &[]);
            assert_eq!(hit.asked, []);
            assert_eq!(decode(&hit.reply.expect("a reply")).answer.len(), 5);
        }
        assert_eq!(reviews.load(Ordering::Relaxed), 1);
    }

    /// D118: a pipeline built on reload reviews an entry of the old one, once: the mark of the old is not its own.
    #[test]
    fn a_reload_reviews_an_entry_again_once() {
        let cache = cache();
        let query = query("www.ripe.net.", RecordType::A, true);
        let (old, _) = gated("nothing.example", &cache);
        let _ = run(&old, &query, Transport::Udp, &[Some(&ripe())]);
        let (new, reviews) = gated("nothing.example", &cache);
        for _ in 0..3 {
            let hit = run(&new, &query, Transport::Udp, &[]);
            assert_eq!(decode(&hit.reply.expect("a reply")).answer.len(), 5);
        }
        assert_eq!(reviews.load(Ordering::Relaxed), 1);
    }

    /// D55: a reload keeps the cache, so a response stored before a name was listed must not be served: a hit is
    /// reviewed by the plugins before the cache stage.
    #[test]
    fn a_cached_response_is_reviewed_on_a_hit() {
        let cache = cache();
        let query = query("www.ripe.net.", RecordType::A, true);
        let before = Pipeline::new(vec![
            Stage::Cache(Arc::clone(&cache)),
            Stage::Forward(Forward::new(servers()).expect("servers")),
        ]);
        let stored = run(&before, &query, Transport::Udp, &[Some(&ripe())]);
        assert_eq!(decode(&stored.reply.expect("a reply")).answer.len(), 5);
        let (after, _) = gated("e337066.dscb.akamaiedge.net", &cache);
        let done = run(&after, &query, Transport::Udp, &[]);
        assert_eq!(done.asked, []);
        assert_blocked(&done.reply.expect("a reply"));
    }

    /// D54, D118: what a plugin answers itself is its own data, not reviewed; a response from upstream is.
    #[test]
    fn a_plugin_does_not_review_its_own_answers() {
        let (pipeline, reviews) = gated("nothing.example", &cache());
        let done = run(
            &pipeline,
            &query("own.test.", RecordType::A, true),
            Transport::Udp,
            &[],
        );
        assert_eq!(done.asked, []);
        assert_eq!(
            decode(&done.reply.expect("a reply")).rcode(),
            Rcode::NOERROR
        );
        assert_eq!(reviews.load(Ordering::Relaxed), 0);
        let _ = run(
            &pipeline,
            &query("www.ripe.net.", RecordType::A, true),
            Transport::Udp,
            &[Some(&ripe())],
        );
        assert_eq!(reviews.load(Ordering::Relaxed), 1);
    }

    /// A plugin after the stage that produced the response does not review it: plugins review for the stages after
    /// them, as they answer queries for them (D23).
    #[test]
    fn a_plugin_after_the_forward_stage_is_not_asked() {
        let (gate, reviews) = Gate::new("e337066.dscb.akamaiedge.net");
        let pipeline = Pipeline::new(vec![
            Stage::Forward(Forward::new(servers()).expect("servers")),
            Stage::Plugin(Box::new(gate)),
        ]);
        let done = run(
            &pipeline,
            &query("www.ripe.net.", RecordType::A, true),
            Transport::Udp,
            &[Some(&ripe())],
        );
        assert_eq!(decode(&done.reply.expect("a reply")).answer.len(), 5);
        assert_eq!(reviews.load(Ordering::Relaxed), 0);
    }

    /// A validating stage reviews the first response before it asks a question of the validation, and stores nothing
    /// when it is replaced (D118): the chain of the captured `www.icann.org. A` crosses zones, `org` to `cloudflare.net`.
    #[test]
    fn a_validated_response_is_reviewed() {
        let (gate, reviews) = Gate::new("www.icann.org.cdn.cloudflare.net");
        let validator = Validator::new(TrustAnchors::root(), Limits::default());
        let validating = Validating::new(validator, Arc::new(crate::util::captured_at));
        let pipeline = Pipeline::new(vec![
            Stage::Plugin(Box::new(gate)),
            Stage::Cache(cache()),
            Stage::Forward(
                Forward::new(servers())
                    .expect("servers")
                    .validating(validating),
            ),
        ]);
        let query = crate::util::client_query("www.icann.org.", RecordType::A, Flags::NONE, true);
        let captures = dedens_testkit::dnssec::Captures::new();
        for _ in 0..2 {
            let done = crate::util::run_captured(&pipeline, &query, 0, &captures);
            assert_eq!(
                done.asked.len(),
                1,
                "no question of the validation, nothing stored"
            );
            assert_blocked(&done.reply.expect("a reply"));
        }
        assert_eq!(reviews.load(Ordering::Relaxed), 2);
    }
}

mod recursion_desired {
    //! Queries without RD (RFC 1034 §4.3.1): answered from fresh cached data only, never asked upstream, never with
    //! expired data (RFC 8767 §5), REFUSED with EDE 20 (Not Authoritative, RFC 8914 §4.21) otherwise.

    use std::borrow::Cow;

    use dedens_proto::edns::{Edns, EdnsOption, ExtendedError, InfoCode};
    use dedens_proto::{Flags, Message, Rcode, Transport};
    use dedens_server::Pipeline;
    use dedens_testkit::{captured, query};

    use crate::util::{caching, decode, forwarder, run_at, wire};

    /// `query` without RD.
    fn norec(mut query: Message<'static>) -> Message<'static> {
        query.header.flags = Flags::NONE;
        query
    }

    /// The reply at `now` to `query` and how many servers were asked.
    fn ask(
        pipeline: &Pipeline,
        query: &Message<'_>,
        now: u32,
        responses: &[Option<&[u8]>],
    ) -> (Message<'static>, usize) {
        let run = run_at(pipeline, &wire(query), Transport::Udp, now, responses);
        (
            decode(&run.reply.expect("a reply")).into_owned(),
            run.asked.len(),
        )
    }

    fn not_authoritative() -> Edns<'static> {
        Edns {
            options: vec![EdnsOption::Ede(ExtendedError {
                code: InfoCode::NOT_AUTHORITATIVE,
                text: Cow::Borrowed(""),
            })],
            ..Edns::default()
        }
    }

    #[test]
    fn a_miss_is_refused_without_asking_upstream() {
        let response = captured("a");
        let query = norec(query("a", 7));
        for pipeline in [forwarder(), caching()] {
            let (reply, asked) = ask(&pipeline, &query, 0, &[Some(&response)]);
            assert_eq!((reply.rcode(), asked), (Rcode::REFUSED, 0));
            assert_eq!(reply.edns, Some(not_authoritative()));
            assert!(!reply.header.flags.contains(Flags::RD));
        }
    }

    #[test]
    fn fresh_cached_data_answers() {
        let response = captured("a");
        let pipeline = caching();
        let query = query("a", 7);
        let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
        let (reply, asked) = ask(&pipeline, &norec(query), 1, &[]);
        assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 0));
        assert_eq!(reply.answer.len(), first.answer.len());
        assert_eq!(reply.edns, Some(Edns::default()));
    }

    #[test]
    fn expired_data_does_not_answer_and_nothing_is_held() {
        let response = captured("a");
        let pipeline = caching();
        let query = query("a", 7);
        let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
        let expired = first
            .answer
            .iter()
            .map(|record| record.ttl.get())
            .min()
            .expect("an answer")
            + 1;
        let (reply, asked) = ask(&pipeline, &norec(query.clone()), expired, &[]);
        assert_eq!((reply.rcode(), asked), (Rcode::REFUSED, 0));
        assert_eq!(reply.edns, Some(not_authoritative()));
        // A client asking for recursion gets upstream's answer, not a hold.
        let (reply, asked) = ask(&pipeline, &query, expired, &[Some(&response)]);
        assert_eq!(
            (reply.rcode(), asked, reply.edns),
            (Rcode::NOERROR, 1, Some(Edns::default()))
        );
    }

    #[test]
    fn a_refresh_asks_for_recursion() {
        let response = captured("a");
        let pipeline = caching();
        let query = query("a", 7);
        let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
        let ttl = first
            .answer
            .iter()
            .map(|record| record.ttl.get())
            .min()
            .expect("an answer");
        let late = ttl - ttl / 20;
        let run = run_at(
            &pipeline,
            &wire(&norec(query)),
            Transport::Udp,
            late,
            &[Some(&response)],
        );
        assert_eq!(run.requests.len(), 1, "a refresh");
        assert!(run.requests[0].header.flags.contains(Flags::RD));
        assert!(
            !decode(&run.reply.expect("a reply"))
                .header
                .flags
                .contains(Flags::RD)
        );
    }
}

mod upstream {
    //! RFC 5452 §9.1 in the server core (D111): `Pipeline::receive` takes an upstream response for the one asked only
    //! when QR is set, the opcode is QUERY and the question is the one sent, in any case (RFC 4343 §4); another
    //! response is that server failing, as a timeout, and the next is asked (RFC 1035 §7.3). Upstream answers are the
    //! captures of `dedens-proto`, each altered in the checked field alone. The ID is the transport's to check
    //! (D27): the core never sees it.

    use std::net::Ipv4Addr;

    use dedens_cache::Config;
    use dedens_proto::{Class, Flags, Message, Opcode, Rcode, RecordType, Transport};
    use dedens_server::Step;
    use dedens_testkit::dnssec::{Captures, capture};
    use dedens_testkit::{captured, dns, query};

    use crate::util::{
        caching_with, client_query, decode, forwarder, run, servers, validating, wire,
    };

    /// The capture `case` with `alter` applied.
    fn altered(case: &str, alter: impl FnOnce(&mut Message<'static>)) -> Vec<u8> {
        let mut message = Message::decode(&captured(case))
            .expect("a captured response decodes")
            .message
            .into_owned();
        alter(&mut message);
        wire(&message)
    }

    /// `bad` from the first server, the capture `a` from the second: the second is asked and its answer comes back.
    fn assert_next_server_asked(bad: &[u8], what: &str) {
        let good = captured("a");
        let done = run(
            &forwarder(),
            &wire(&query("a", 7)),
            Transport::Udp,
            &[Some(bad), Some(&good)],
        );
        assert_eq!(done.asked, servers(), "{what}");
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::NOERROR, "{what}");
        assert_eq!(
            reply.answer,
            Message::decode(&good).expect("decodes").message.answer,
            "{what}"
        );
    }

    /// §9.1: a query is no response to a query.
    #[test]
    fn a_message_without_qr_is_not_the_response() {
        let bad = altered("a", |message| {
            message.header.flags = message.header.flags.without(Flags::QR);
        });
        assert_next_server_asked(&bad, "QR clear");
    }

    /// §9.1: the opcode of the response is the query's, QUERY.
    #[test]
    fn a_response_of_another_opcode_is_not_the_response() {
        for opcode in [Opcode::NOTIFY, Opcode::UPDATE] {
            let bad = altered("a", |message| message.header.opcode = opcode);
            assert_next_server_asked(&bad, &format!("{opcode:?}"));
        }
    }

    /// §9.1: the question is the one asked: name, type and class.
    #[test]
    fn a_response_to_another_question_is_not_the_response() {
        let name = altered("a", |message| {
            message.questions[0].name = dns("other.example.");
        });
        assert_next_server_asked(&name, "another name");
        let qtype = altered("a", |message| message.questions[0].qtype = RecordType::TXT);
        assert_next_server_asked(&qtype, "another type");
        let qclass = altered("a", |message| message.questions[0].qclass = Class::CH);
        assert_next_server_asked(&qclass, "another class");
        let missing = altered("a", |message| message.questions.clear());
        assert_next_server_asked(&missing, "no question");
        let two = altered("a", |message| {
            let again = message.questions[0].clone();
            message.questions.push(again);
        });
        assert_next_server_asked(&two, "two questions");
    }

    /// RFC 4343 §4: the case of the name in the response is the server's; `0x20` randomization (D27) depends on it
    /// being kept, and a server that lowercases it is no other server.
    #[test]
    fn the_question_matches_in_any_case() {
        let upper = altered("a", |message| {
            let name = message.questions[0].name.to_string().to_ascii_uppercase();
            message.questions[0].name = dns(&name);
        });
        let done = run(
            &forwarder(),
            &wire(&query("a", 7)),
            Transport::Udp,
            &[Some(&upper), None],
        );
        assert_eq!(done.asked, servers()[..1]);
        assert_eq!(
            decode(&done.reply.expect("a reply")).rcode(),
            Rcode::NOERROR
        );
    }

    /// §9.1 with RFC 1035 §7.3: after the last server, the failure is SERVFAIL, whatever the response was.
    #[test]
    fn a_mismatch_from_every_server_is_servfail() {
        let bad = altered("a", |message| {
            message.questions[0].name = dns("other.example.");
        });
        let done = run(
            &forwarder(),
            &wire(&query("a", 7)),
            Transport::Udp,
            &[Some(&bad), Some(&bad)],
        );
        assert_eq!(done.asked, servers());
        assert_eq!(
            decode(&done.reply.expect("a reply")).rcode(),
            Rcode::SERVFAIL
        );
    }

    /// D111: a mismatch is a failure like a timeout, so it is never stored: the next query asks again.
    #[test]
    fn a_mismatch_is_not_cached() {
        let good = captured("a");
        let bad = altered("a", |message| {
            message.questions[0].name = dns("other.example.");
        });
        // The records come back as captured: no minimum TTL raises them.
        let pipeline = caching_with(Config {
            min_ttl: 0,
            ..Config::default()
        });
        let query = wire(&query("a", 7));
        let first = run(
            &pipeline,
            &query,
            Transport::Udp,
            &[Some(&bad), Some(&good)],
        );
        assert_eq!(first.asked, servers());
        let again = run(&pipeline, &query, Transport::Udp, &[]);
        // Answered from the cache: the second server's answer was stored, not the first's.
        assert_eq!(again.asked, []);
        assert_eq!(
            decode(&again.reply.expect("a reply")).answer,
            Message::decode(&good).expect("decodes").message.answer
        );
    }

    /// D111: the validator's questions are checked against what the validator asked, not the client's: a response to
    /// the client's question, sent for its first question, is a failure of that server.
    #[test]
    fn a_validators_question_is_checked_against_its_own() {
        let pipeline = validating();
        let captures = Captures::new();
        let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
        let wrong = capture("alg13_a");
        let mut out = vec![0; 65535];
        let mut asked = Vec::new();
        let mut step = pipeline.query(
            &query,
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            0,
            &mut out,
        );
        let reply = loop {
            match step {
                Step::Reply(len) => break out[..len].to_vec(),
                Step::Upstream(upstream) => {
                    asked.push(upstream.server().addr);
                    let request = upstream.request();
                    let response = if asked.len() == 2 {
                        assert_ne!(request.questions[0].qtype, RecordType::A);
                        Some(wrong.as_slice())
                    } else {
                        captures.answer(&request)
                    };
                    step = pipeline.receive(upstream, response, 0, &mut out);
                }
                Step::Drop | Step::Refresh(..) => unreachable!("a reply comes"),
            }
        };
        assert_eq!(asked[..3], [servers()[0], servers()[0], servers()[1]]);
        let reply = decode(&reply);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AD));
    }
}
