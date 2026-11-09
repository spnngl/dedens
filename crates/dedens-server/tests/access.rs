//! Who the server answers, and how much: access lists, the rate limit, and DNS cookies.

mod networks {
    //! RFC 5358 in the server core (D91): a server answers the networks it is told to, so that it is no reflector for
    //! forged sources (§4). The longest network holding the client decides, `deny` wins a tie, a client in no network is
    //! denied, an IPv4-mapped address is the IPv4 one; a denied client gets REFUSED with EDE 18 (RFC 8914 §4.19) or
    //! nothing.

    use std::net::{IpAddr, Ipv4Addr};

    use dedens_proto::edns::{EdnsOption, InfoCode};
    use dedens_proto::{Flags, Rcode, Transport};
    use dedens_server::{Access, Denial, Network, NetworkError, Pipeline, Step};
    use dedens_testkit::{captured, query};

    use crate::util::{decode, forwarder, wire};

    fn nets<const N: usize>(texts: [&str; N]) -> [Network; N] {
        texts.map(|text| text.parse().expect("a network"))
    }

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// A forwarder answering the clients `access` permits.
    fn serving(access: Access) -> Pipeline {
        forwarder().with_access(access)
    }

    /// Whether the pipeline answers a query of the `a` capture from `from`: it goes upstream, or is replied to by a
    /// stage, unlike a denied client's.
    fn permitted(pipeline: &Pipeline, from: &str) -> bool {
        let query = wire(&query("a", 7));
        let mut out = vec![0; 65535];
        match pipeline.query(&query, Transport::Udp, addr(from), 0, &mut out) {
            Step::Upstream(_) => true,
            Step::Reply(len) => decode(&out[..len]).rcode() != Rcode::REFUSED,
            Step::Drop => false,
            step @ Step::Refresh(..) => unreachable!("{step:?}"),
        }
    }

    #[test]
    fn a_denied_client_gets_refused_with_prohibited() {
        let pipeline = serving(Access::new(nets(["10.0.0.0/8"]), [], Denial::Refuse));
        let query = query("a", 7);
        let mut out = vec![0; 65535];
        let Step::Reply(len) = pipeline.query(
            &wire(&query),
            Transport::Udp,
            addr("192.0.2.1"),
            0,
            &mut out,
        ) else {
            unreachable!("a reply");
        };
        let reply = decode(&out[..len]);
        assert_eq!(reply.rcode(), Rcode::REFUSED);
        assert_eq!(reply.header.id, query.header.id);
        assert_eq!(reply.questions, query.questions);
        assert!(reply.header.flags.contains(Flags::QR));
        let options = reply.edns.expect("our OPT record").options;
        assert!(
            matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::PROHIBITED),
            "{options:?}"
        );
        assert!(permitted(&pipeline, "10.1.2.3"));
    }

    #[test]
    fn a_denied_client_gets_nothing_when_the_action_is_drop() {
        let pipeline = serving(Access::new(nets(["10.0.0.0/8"]), [], Denial::Drop));
        assert!(!permitted(&pipeline, "192.0.2.1"));
        let mut out = vec![0; 65535];
        let query = wire(&query("a", 7));
        let step = pipeline.query(&query, Transport::Tcp, addr("192.0.2.1"), 0, &mut out);
        assert!(matches!(step, Step::Drop), "{step:?}");
        assert!(permitted(&pipeline, "10.1.2.3"));
    }

    #[test]
    fn a_denied_response_or_stub_is_not_answered() {
        let pipeline = serving(Access::new([], [], Denial::Refuse));
        let mut out = vec![0; 65535];
        let from = addr("192.0.2.1");
        // A response is never answered, whatever its sender (RFC 1035 §4.1.1).
        let response = captured("a");
        let step = pipeline.query(&response, Transport::Udp, from, 0, &mut out);
        assert!(matches!(step, Step::Drop), "{step:?}");
        let query = wire(&query("a", 7));
        // Fewer bytes than a header cannot be answered either.
        let step = pipeline.query(&query[..11], Transport::Udp, from, 0, &mut out);
        assert!(matches!(step, Step::Drop), "{step:?}");
        // A header alone is a query that does not read, and is refused as it would be answered FORMERR.
        let Step::Reply(len) = pipeline.query(&query[..12], Transport::Udp, from, 0, &mut out)
        else {
            unreachable!("a reply");
        };
        let reply = decode(&out[..len]);
        assert_eq!(reply.rcode(), Rcode::REFUSED);
        assert_eq!(reply.header.id, decode(&query).header.id);
        assert_eq!(reply.questions.len(), 0);
    }

    /// What the pipeline says of a client, to a caller that serves it something else than a query (D91): `denial` tells the
    /// action of a denied client, `drops` whether it gets nothing, `denies` whether it is denied at all.
    #[test]
    fn the_access_lists_tell_what_is_done_to_a_client() {
        let denied = addr("192.0.2.1");
        let allowed = addr("10.1.2.3");
        let said = |denial| {
            let pipeline = serving(Access::new(nets(["10.0.0.0/8"]), [], denial));
            [denied, allowed].map(|from| {
                (
                    pipeline.denial(from),
                    pipeline.drops(from),
                    pipeline.denies(from),
                )
            })
        };
        assert_eq!(
            said(Denial::Refuse),
            [(Some(Denial::Refuse), false, true), (None, false, false)]
        );
        assert_eq!(
            said(Denial::Drop),
            [(Some(Denial::Drop), true, true), (None, false, false)]
        );
        let open = Pipeline::default();
        assert_eq!(
            (open.denial(denied), open.drops(denied), open.denies(denied)),
            (None, false, false)
        );
    }

    #[test]
    fn a_pipeline_without_access_answers_everyone() {
        let pipeline = Pipeline::default();
        let query = wire(&query("a", 7));
        let mut out = vec![0; 65535];
        let step = pipeline.query(&query, Transport::Udp, addr("192.0.2.1"), 0, &mut out);
        let Step::Reply(len) = step else {
            unreachable!("{step:?}");
        };
        // REFUSED as no stage answers, with no Prohibited.
        let reply = decode(&out[..len]);
        let options = reply.edns.map(|edns| edns.options).unwrap_or_default();
        assert!(
            !options
                .iter()
                .any(|o| matches!(o, EdnsOption::Ede(e) if e.code == InfoCode::PROHIBITED)),
            "{options:?}"
        );
    }

    #[test]
    fn an_address_in_no_network_is_denied() {
        let access = Access::new(nets(["10.0.0.0/8", "2001:db8::/32"]), [], Denial::Refuse);
        assert!(access.permits(addr("10.255.255.255")));
        assert!(access.permits(addr("2001:db8::1")));
        assert!(!access.permits(addr("11.0.0.0")));
        assert!(!access.permits(addr("2001:db9::1")));
        assert!(!Access::new([], [], Denial::Refuse).permits(addr("10.0.0.1")));
    }

    #[test]
    fn the_longest_network_holding_the_address_decides() {
        let access = Access::new(
            nets(["10.0.0.0/8", "10.9.9.0/24"]),
            nets(["10.9.0.0/16", "0.0.0.0/0"]),
            Denial::Refuse,
        );
        assert!(access.permits(addr("10.1.1.1")), "/8 beats /0");
        assert!(!access.permits(addr("10.9.1.1")), "/16 beats /8");
        assert!(access.permits(addr("10.9.9.9")), "/24 beats /16");
        assert!(!access.permits(addr("8.8.8.8")), "/0");
    }

    #[test]
    fn deny_wins_a_tie() {
        let both = ["10.0.0.0/8", "::1/128"];
        let access = Access::new(nets(both), nets(both), Denial::Refuse);
        assert!(!access.permits(addr("10.1.1.1")));
        assert!(!access.permits(addr("::1")));
    }

    #[test]
    fn an_ipv4_mapped_address_is_the_ipv4_one() {
        let access = Access::new(nets(["10.0.0.0/8"]), nets(["10.9.0.0/16"]), Denial::Refuse);
        assert!(access.permits(addr("::ffff:10.1.1.1")));
        assert!(!access.permits(addr("::ffff:10.9.1.1")));
        assert!(!access.permits(addr("::ffff:192.0.2.1")));
        // And an IPv6 network holds no IPv4 client.
        let access = Access::new(nets(["::/0"]), [], Denial::Refuse);
        assert!(access.permits(addr("2001:db8::1")));
        assert!(!access.permits(addr("192.0.2.1")));
        assert!(!access.permits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn by_default_loopback_private_and_link_local_networks_are_answered() {
        let access = Access::local(Denial::Refuse);
        for text in [
            "127.0.0.1",
            "127.255.255.255",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(access.permits(addr(text)), "{text}");
        }
        for text in [
            "0.0.0.0",
            "8.8.8.8",
            "172.15.255.255",
            "172.32.0.1",
            "192.0.2.1",
            "100.64.0.1",
            "::",
            "2001:db8::1",
            "fec0::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!access.permits(addr(text)), "{text}");
        }
    }

    #[test]
    fn networks_have_no_bits_past_their_length() {
        for text in ["192.0.2.0/24", "0.0.0.0/0", "192.0.2.1/32", "2001:db8::/32"] {
            assert_eq!(
                text.parse::<Network>().expect("a network").to_string(),
                text
            );
        }
        let Err(NetworkError::HostBits { meant, .. }) = "192.0.2.1/24".parse::<Network>() else {
            unreachable!("bits set");
        };
        assert_eq!(meant.to_string(), "192.0.2.0/24");
        let error = "2001:db8::1/32".parse::<Network>().unwrap_err();
        assert!(error.to_string().contains("`2001:db8::/32`"), "{error}");
    }

    #[test]
    fn text_that_is_no_network_is_refused() {
        for text in [
            "",
            "192.0.2.0",
            "192.0.2.0/33",
            "192.0.2.0/",
            "/24",
            "example.org/24",
            "::/129",
            "10.0.0.0/8 ",
        ] {
            assert_eq!(
                text.parse::<Network>(),
                Err(NetworkError::Malformed(text.to_owned())),
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_ipv6_network_starting_in_the_mapped_range_is_refused() {
        for text in ["::ffff:0:0/95", "::ffff:0:0/80", "::ffff:10.0.0.0/64"] {
            let error = text.parse::<Network>().unwrap_err();
            assert_eq!(error, NetworkError::MappedRange(text.to_owned()), "{text}");
            assert!(error.to_string().contains("::ffff:0:0/96"), "{error}");
        }
        // `::/0` starts outside it, and holds IPv6 clients only.
        assert!("::/0".parse::<Network>().is_ok());
    }

    #[test]
    fn an_ipv4_network_written_as_ipv6_is_refused_for_the_ipv4_one() {
        let error = "::ffff:192.0.2.0/120".parse::<Network>().unwrap_err();
        assert!(
            matches!(&error, NetworkError::Mapped { meant, .. } if meant.to_string() == "192.0.2.0/24"),
            "{error}"
        );
        assert!(error.to_string().contains("`192.0.2.0/24`"), "{error}");
    }
}

mod rrl {
    //! Response rate limiting in the server core (D113, audit S1): over UDP a source network over its rate gets TC=1
    //! or nothing, one in `slip` answered; a valid Server Cookie, and every other transport, are not limited; the
    //! table is of fixed size.

    use std::net::IpAddr;
    use std::sync::Arc;

    use dedens_proto::edns::{Cookie, Edns, EdnsOption};
    use dedens_proto::{Flags, Rcode, Transport};
    use dedens_server::{
        Access, Admission, Clock, Cookies, Denial, Network, Pipeline, Rate, RateLimit,
        RateLimitConfig, RateLimitError, Secret, Secrets, Step,
    };
    use dedens_testkit::{captured, query};

    use crate::util::{decode, forwarder, wire};

    /// What the pipeline did with a query.
    #[derive(Debug, PartialEq, Eq)]
    enum Fate {
        /// Went on to the stages: answered, as far as the limit goes.
        Passed,
        /// Replied TC=1 with no answer.
        Truncated,
        /// Replied BADCOOKIE.
        BadCookie,
        /// Replied REFUSED, as to a client the access lists deny.
        Refused,
        /// Replied FORMERR, as to a query that cannot be read.
        FormErr,
        /// Sent nothing.
        Dropped,
    }

    const BURST: u32 = 3;

    fn config(slip: u8) -> RateLimitConfig {
        RateLimitConfig {
            ipv4: Rate {
                prefix: 24,
                per_second: 2,
                burst: BURST,
            },
            ipv6: Rate {
                prefix: 56,
                per_second: 2,
                burst: BURST,
            },
            slip,
            // A million buckets, keyed at random: two networks of a test share one once in a million runs, not once in
            // a thousand.
            table: 1 << 20,
            exempt: RateLimitConfig::default().exempt,
        }
    }

    fn limited(slip: u8) -> Pipeline {
        forwarder().with_rate_limit(RateLimit::new(config(slip)).expect("a valid limit"))
    }

    fn send(pipeline: &Pipeline, wire: &[u8], transport: Transport, from: &str, now: u32) -> Fate {
        let from: IpAddr = from.parse().expect("an address");
        let mut out = vec![0; 65535];
        match pipeline.query(wire, transport, from, now, &mut out) {
            Step::Upstream(_) => Fate::Passed,
            Step::Drop => Fate::Dropped,
            Step::Reply(len) => {
                let reply = decode(&out[..len]);
                match reply.rcode() {
                    // The reply to a query with a Client Cookie carries a Server Cookie, 16 bytes more.
                    Rcode::BADCOOKIE => {
                        assert!(len <= wire.len() + 16, "{len} bytes to {}", wire.len());
                        Fate::BadCookie
                    }
                    Rcode::REFUSED => Fate::Refused,
                    Rcode::FORMERR => Fate::FormErr,
                    _ if reply.header.flags.contains(Flags::TC) => {
                        assert!(reply.answer.is_empty(), "a truncated reply has no answer");
                        assert_eq!(reply.header.id, 7, "it answers the query");
                        // No larger than the query: a spoofer gets no amplification from it (D113).
                        assert!(len <= wire.len(), "{len} bytes to {}", wire.len());
                        Fate::Truncated
                    }
                    rcode => unreachable!("a reply of {rcode:?}"),
                }
            }
            step @ Step::Refresh(..) => unreachable!("{step:?}"),
        }
    }

    fn udp(pipeline: &Pipeline, from: &str, now: u32) -> Fate {
        send(pipeline, &wire(&query("a", 7)), Transport::Udp, from, now)
    }

    /// The trigger of S1: a source over its rate gets TC=1 or nothing; of the queries over it, one in two (the slip)
    /// is truncated.
    #[test]
    fn a_source_over_its_rate_gets_tc_or_nothing() {
        use Fate::{Dropped, Passed, Truncated};
        let pipeline = limited(2);
        let fates: Vec<_> = (0..8).map(|_| udp(&pipeline, "198.51.100.7", 10)).collect();
        assert_eq!(
            fates,
            [
                Passed, Passed, Passed, Dropped, Truncated, Dropped, Truncated, Dropped
            ]
        );
    }

    #[test]
    fn slip_zero_drops_every_limited_query_and_one_truncates_every_one() {
        use Fate::{Dropped, Passed, Truncated};
        let fates = |slip| -> Vec<_> {
            let pipeline = limited(slip);
            (0..5).map(|_| udp(&pipeline, "198.51.100.7", 10)).collect()
        };
        assert_eq!(fates(0), [Passed, Passed, Passed, Dropped, Dropped]);
        assert_eq!(fates(1), [Passed, Passed, Passed, Truncated, Truncated]);
    }

    /// The limit is of the network: another address of the /24 shares the bucket, an address of another /24 does not.
    #[test]
    fn the_limit_is_per_network() {
        use Fate::{Dropped, Passed};
        let pipeline = limited(0);
        for _ in 0..BURST {
            assert_eq!(udp(&pipeline, "198.51.100.7", 10), Passed);
        }
        assert_eq!(udp(&pipeline, "198.51.100.200", 10), Dropped);
        assert_eq!(udp(&pipeline, "198.51.101.7", 10), Passed);
        // An IPv4-mapped IPv6 address is the IPv4 one.
        assert_eq!(udp(&pipeline, "::ffff:198.51.100.9", 10), Dropped);
    }

    #[test]
    fn an_ipv6_network_is_a_56() {
        use Fate::{Dropped, Passed};
        let pipeline = limited(0);
        for _ in 0..BURST {
            assert_eq!(udp(&pipeline, "2001:db8:0:ab00::1", 10), Passed);
        }
        // The same /56, another /64.
        assert_eq!(udp(&pipeline, "2001:db8:0:abff::9", 10), Dropped);
        // The next /56.
        assert_eq!(udp(&pipeline, "2001:db8:0:ac00::1", 10), Passed);
    }

    /// The bucket refills at the rate: two queries a second.
    #[test]
    fn a_quiet_source_is_answered_again() {
        use Fate::{Dropped, Passed};
        let pipeline = limited(0);
        for _ in 0..BURST {
            assert_eq!(udp(&pipeline, "198.51.100.7", 10), Passed);
        }
        assert_eq!(udp(&pipeline, "198.51.100.7", 10), Dropped);
        assert_eq!(udp(&pipeline, "198.51.100.7", 11), Passed);
        assert_eq!(udp(&pipeline, "198.51.100.7", 11), Passed);
        assert_eq!(udp(&pipeline, "198.51.100.7", 11), Dropped);
        assert_eq!(udp(&pipeline, "198.51.100.7", 100), Passed);
    }

    /// A client that retries over TCP when truncated gets its answer: the other transports are not limited, their
    /// clients having proved their addresses.
    #[test]
    fn connections_are_not_limited() {
        use Fate::{Dropped, Passed};
        let pipeline = limited(0);
        for _ in 0..BURST {
            assert_eq!(udp(&pipeline, "198.51.100.7", 10), Passed);
        }
        assert_eq!(udp(&pipeline, "198.51.100.7", 10), Dropped);
        for transport in [
            Transport::Tcp,
            Transport::Tls,
            Transport::Quic,
            Transport::Https,
        ] {
            for _ in 0..10 {
                let fate = send(
                    &pipeline,
                    &wire(&query("a", 7)),
                    transport,
                    "198.51.100.7",
                    10,
                );
                assert_eq!(fate, Passed, "{transport:?}");
            }
        }
    }

    /// `DoC` is CoAP over UDP and amplifies as DNS over UDP does, but has no TC: `Pipeline::limits` says to drop.
    #[test]
    fn coap_over_its_rate_is_dropped() {
        let pipeline = limited(2);
        let from: IpAddr = "198.51.100.7".parse().expect("an address");
        let limits: Vec<_> = (0..5).map(|_| pipeline.limits(from, 10)).collect();
        assert_eq!(limits, [false, false, false, true, true]);
        // The same network over DNS has spent the bucket too, and no query of it slips to TC after.
        assert_eq!(udp(&pipeline, "198.51.100.7", 10), Fate::Dropped);
    }

    /// The local resolver's queries, and the daemon's own, are not for a spoofer to forge from outside.
    #[test]
    fn loopback_is_not_limited() {
        let pipeline = limited(0);
        for _ in 0..20 {
            assert_eq!(udp(&pipeline, "127.0.0.1", 10), Fate::Passed);
            assert_eq!(udp(&pipeline, "::1", 10), Fate::Passed);
        }
    }

    /// A proxy on another address hides its clients behind its own: the operator exempts it, and loopback no longer.
    /// The pipeline's limit tells the two apart.
    #[test]
    fn only_the_exempt_networks_are_not_limited() {
        let mut config = config(0);
        config.exempt = vec!["203.0.113.0/24".parse::<Network>().expect("a network")];
        let pipeline = forwarder().with_rate_limit(RateLimit::new(config).expect("a limit"));
        for _ in 0..20 {
            assert_eq!(udp(&pipeline, "203.0.113.9", 10), Fate::Passed);
        }
        for _ in 0..BURST {
            assert_eq!(udp(&pipeline, "127.0.0.1", 10), Fate::Passed);
        }
        assert_eq!(udp(&pipeline, "127.0.0.1", 10), Fate::Dropped);
        let limit = pipeline.rate_limit().expect("its rate limit");
        let exempts = |from: &str| limit.exempts(from.parse().expect("an address"));
        assert!(exempts("203.0.113.9"));
        assert!(!exempts("127.0.0.1"));
    }

    /// The default access lists deny every Internet source, so a spoofed one would get a REFUSED each time: the
    /// REFUSED over UDP is limited like an answer, and over TCP it is not.
    #[test]
    fn a_refusal_over_udp_is_limited() {
        use Fate::{Dropped, Refused};
        let pipeline = limited(2).with_access(Access::local(Denial::Refuse));
        let from = "198.51.100.7";
        let fates: Vec<_> = (0..6).map(|_| udp(&pipeline, from, 10)).collect();
        assert_eq!(
            fates,
            [Refused, Refused, Refused, Dropped, Dropped, Dropped]
        );
        for _ in 0..10 {
            assert_eq!(
                send(&pipeline, &wire(&query("a", 7)), Transport::Tcp, from, 10),
                Refused
            );
        }
    }

    /// A UDP query counts before it is read, so the FORMERR to one that cannot be read is limited too (D113).
    #[test]
    fn an_unreadable_query_over_udp_is_limited() {
        use Fate::{Dropped, FormErr, Truncated};
        let pipeline = limited(2);
        let mut unreadable = wire(&query("a", 7));
        unreadable.truncate(15);
        let fates: Vec<_> = (0..6)
            .map(|_| send(&pipeline, &unreadable, Transport::Udp, "198.51.100.7", 10))
            .collect();
        assert_eq!(
            fates,
            [FormErr, FormErr, FormErr, Dropped, Truncated, Dropped]
        );
    }

    #[test]
    fn a_pipeline_without_a_limit_answers_everyone() {
        let pipeline = forwarder();
        for _ in 0..50 {
            assert_eq!(udp(&pipeline, "198.51.100.7", 10), Fate::Passed);
        }
    }

    /// A response is dropped before the limit: forged responses do not use a victim's bucket.
    #[test]
    fn responses_do_not_count() {
        let pipeline = limited(0);
        let response = captured("a");
        for _ in 0..20 {
            let fate = send(&pipeline, &response, Transport::Udp, "198.51.100.7", 10);
            assert_eq!(fate, Fate::Dropped);
        }
        assert_eq!(udp(&pipeline, "198.51.100.7", 10), Fate::Passed);
    }

    fn cookies() -> Cookies {
        let clock: Clock = Arc::new(|| 1_559_731_985);
        let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
            .parse()
            .expect("a secret");
        Cookies::new(Secrets::new(secret, vec![]), clock)
    }

    fn cookie_query(cookie: &Cookie) -> Vec<u8> {
        let mut query = query("a", 7);
        query.edns = Some(Edns {
            options: vec![EdnsOption::Cookie(*cookie)],
            ..Edns::default()
        });
        wire(&query)
    }

    /// RFC 7873 §5.2: a query with a valid Server Cookie comes from where it says, so it is not limited; one over its
    /// rate with only a Client Cookie slips as BADCOOKIE with a Server Cookie, to retry with: a real client is then
    /// served at once, a spoofer never sees it.
    #[test]
    fn a_valid_server_cookie_is_not_limited() {
        use Fate::{BadCookie, Passed};
        let from = "198.51.100.7";
        let pipeline = forwarder()
            .with_rate_limit(RateLimit::new(config(1)).expect("a limit"))
            .with_cookies(cookies());
        for _ in 0..BURST {
            assert_eq!(udp(&pipeline, from, 10), Passed);
        }
        let client = [1, 2, 3, 4, 5, 6, 7, 8];
        let only = Cookie::new(client, None).expect("a cookie");
        let sent = cookie_query(&only);
        assert_eq!(send(&pipeline, &sent, Transport::Udp, from, 10), BadCookie);
        // What the BADCOOKIE carries.
        let mut out = vec![0; 65535];
        let Step::Reply(len) = pipeline.query(
            &sent,
            Transport::Udp,
            from.parse().expect("ip"),
            10,
            &mut out,
        ) else {
            unreachable!("a reply");
        };
        let Some(EdnsOption::Cookie(fresh)) = decode(&out[..len])
            .edns
            .and_then(|edns| edns.options.into_iter().next())
        else {
            unreachable!("a cookie");
        };
        assert!(fresh.server().is_some());
        // The query with a fresh cookie passes the limit, any number of times; one without is limited.
        let retried = cookie_query(&fresh);
        for _ in 0..20 {
            assert_eq!(send(&pipeline, &retried, Transport::Udp, from, 10), Passed);
        }
        assert_eq!(udp(&pipeline, from, 10), Fate::Truncated);
        // A cookie is for the address it was made for, not its neighbour in the /24.
        let neighbour = send(&pipeline, &retried, Transport::Udp, "198.51.100.99", 10);
        assert_eq!(neighbour, BadCookie);
    }

    /// Over its rate, a query without a Client Cookie has TC=1 even if the pipeline makes cookies.
    #[test]
    fn a_query_without_a_cookie_is_truncated_not_badcookie() {
        let pipeline = forwarder()
            .with_rate_limit(RateLimit::new(config(1)).expect("a limit"))
            .with_cookies(cookies());
        for _ in 0..BURST {
            assert_eq!(udp(&pipeline, "198.51.100.7", 10), Fate::Passed);
        }
        assert_eq!(udp(&pipeline, "198.51.100.7", 10), Fate::Truncated);
    }

    #[test]
    fn a_config_out_of_bounds_makes_no_limit() {
        let bad = |edit: fn(&mut RateLimitConfig)| {
            let mut config = RateLimitConfig::default();
            edit(&mut config);
            RateLimit::new(config).expect_err("out of bounds")
        };
        assert!(matches!(
            bad(|c| c.ipv4.prefix = 0),
            RateLimitError::Prefix { .. }
        ));
        assert!(matches!(
            bad(|c| c.ipv4.prefix = 33),
            RateLimitError::Prefix { .. }
        ));
        assert!(matches!(
            bad(|c| c.ipv6.prefix = 129),
            RateLimitError::Prefix { .. }
        ));
        assert!(matches!(
            bad(|c| c.ipv6.per_second = 0),
            RateLimitError::Rate(_)
        ));
        assert!(matches!(
            bad(|c| c.ipv4.burst = 0),
            RateLimitError::Burst { .. }
        ));
        // The bucket refills by whole seconds: a burst under the rate would hold the rate under it.
        assert!(matches!(
            bad(|c| c.ipv6.burst = c.ipv6.per_second - 1),
            RateLimitError::Burst { .. }
        ));
        assert!(matches!(
            bad(|c| c.ipv4.burst = 1 << 24),
            RateLimitError::Burst { .. }
        ));
        assert!(matches!(bad(|c| c.slip = 11), RateLimitError::Slip(11)));
        assert!(matches!(bad(|c| c.table = 0), RateLimitError::Table(0)));
        assert!(RateLimit::new(RateLimitConfig::default()).is_ok());
        let mut equal = RateLimitConfig::default();
        equal.ipv4.burst = equal.ipv4.per_second;
        assert!(
            RateLimit::new(equal).is_ok(),
            "a burst equal to the rate is allowed"
        );
    }

    /// The table is of fixed size: sources of a million networks do not grow it, they share buckets.
    #[test]
    fn a_flood_from_many_networks_shares_a_fixed_table() {
        let mut config = config(0);
        config.table = 8;
        let limit = RateLimit::new(config).expect("a limit");
        let mut passed = 0;
        for network in 0..200_000_u32 {
            let [a, b, c, _] = network.to_be_bytes();
            let from = IpAddr::from([10 + (a % 100), b, c, 1]);
            if limit.check(from, 10, true) == Admission::Pass {
                passed += 1;
            }
        }
        // At most 8 buckets of `BURST`.
        assert!(passed <= 8 * BURST, "{passed} passed");
    }
}

mod cookies {
    //! RFC 7873 §5.2 and §5.4 in the server core (D113): a query with a Client Cookie is answered with a Server Cookie
    //! (made as RFC 9018 says, `server_cookies`), on every transport and from the cache; an invalid Server Cookie is
    //! treated as none, so the query is answered; a query without a question but with a cookie is a request for one.

    use std::net::IpAddr;
    use std::sync::Arc;

    use dedens_proto::edns::{Cookie, Edns, EdnsOption};
    use dedens_proto::{Message, Rcode, Transport};
    use dedens_server::{Clock, Cookies, Secret, Secrets, Standing};
    use dedens_testkit::{captured, hex, query};

    use crate::util::{caching, decode, forwarder, reply, run, wire};

    const CLIENT: [u8; 8] = [0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57];
    const NOW: u64 = 1_559_731_985;
    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn cookies() -> Cookies {
        let clock: Clock = Arc::new(|| NOW);
        let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
            .parse()
            .expect("a secret");
        Cookies::new(Secrets::new(secret, vec![]), clock)
    }

    /// `query` asking with `cookie`.
    fn with_cookie(mut query: Message<'static>, cookie: &Cookie) -> Vec<u8> {
        query.edns = Some(Edns {
            options: vec![EdnsOption::Cookie(*cookie)],
            ..Edns::default()
        });
        wire(&query)
    }

    fn client_only() -> Cookie {
        Cookie::new(CLIENT, None).expect("a client cookie")
    }

    /// The cookie of the reply's OPT record, if any.
    fn cookie_of(reply: &[u8]) -> Option<Cookie> {
        decode(reply)
            .edns?
            .options
            .into_iter()
            .find_map(|option| match option {
                EdnsOption::Cookie(cookie) => Some(cookie),
                _ => None,
            })
    }

    /// A query with a Client Cookie alone gets its own Client Cookie back and a Server Cookie of RFC 9018 §4: 16 bytes,
    /// version 1, the timestamp of now.
    #[test]
    fn a_client_cookie_is_answered_with_a_server_cookie() {
        let pipeline = forwarder().with_cookies(cookies());
        let query = query("a", 7);
        let sent = with_cookie(query, &client_only());
        for transport in [Transport::Udp, Transport::Tcp, Transport::Https] {
            let answer = reply(&pipeline, &sent, transport, Some(&captured("a")));
            let cookie = cookie_of(&answer).expect("a cookie");
            assert_eq!(cookie.client(), CLIENT);
            let server = cookie.server().expect("a Server Cookie");
            assert_eq!(&server[..4], [1, 0, 0, 0]);
            assert_eq!(
                server[4..8],
                u32::try_from(NOW).expect("a timestamp").to_be_bytes()
            );
            assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
        }
    }

    /// §5.2.1: a query without a cookie is answered without one; so is any query to a pipeline without cookies.
    #[test]
    fn no_cookie_asked_none_given() {
        let query = wire(&query("a", 7));
        let pipeline = forwarder().with_cookies(cookies());
        assert_eq!(
            cookie_of(&reply(
                &pipeline,
                &query,
                Transport::Udp,
                Some(&captured("a"))
            )),
            None
        );
        let sent = with_cookie(dedens_testkit::query("a", 7), &client_only());
        let bare = forwarder();
        assert_eq!(
            cookie_of(&reply(&bare, &sent, Transport::Udp, Some(&captured("a")))),
            None
        );
    }

    /// §5.2.5: the reply to a query with a valid Server Cookie has one, fresh, from the cache or upstream alike.
    #[test]
    fn a_valid_server_cookie_is_answered_and_renewed_from_the_cache_too() {
        let pipeline = caching().with_cookies(cookies());
        let issued = cookies().issue(CLIENT, LOOPBACK);
        let sent = with_cookie(query("a", 7), &issued);
        let first = run(&pipeline, &sent, Transport::Udp, &[Some(&captured("a"))]);
        assert_eq!(first.asked.len(), 1);
        let cached = run(&pipeline, &sent, Transport::Udp, &[]);
        assert_eq!(cached.asked.len(), 0, "the cache answers");
        for answer in [first.reply, cached.reply] {
            let answer = answer.expect("a reply");
            assert_eq!(
                cookie_of(&answer),
                Some(issued),
                "the same time, the same cookie"
            );
            assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
        }
    }

    /// §5.2.3, §5.2.4: our policy answers a query whose Server Cookie is invalid as one with a Client Cookie alone: the
    /// answer is the real one, with a valid Server Cookie to use next, not BADCOOKIE (D113).
    #[test]
    fn an_invalid_server_cookie_is_answered_with_a_fresh_one() {
        let pipeline = forwarder().with_cookies(cookies());
        let stale =
            Cookie::new(CLIENT, Some(&hex("010000005cf79f11ffffffffffffffff"))).expect("a cookie");
        let sent = with_cookie(query("a", 7), &stale);
        let answer = reply(&pipeline, &sent, Transport::Udp, Some(&captured("a")));
        assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
        assert!(!decode(&answer).answer.is_empty(), "the real answer");
        let fresh = cookie_of(&answer).expect("a cookie");
        let verified = pipeline
            .cookies()
            .map(|cookies| cookies.verify(Some(&fresh), LOOPBACK));
        assert_eq!(verified, Some(Standing::Valid));
    }

    /// §5.2.2: a query that breaks a rule, here two questions (RFC 9619 §4), is FORMERR with no cookie, though its
    /// own is well-formed.
    #[test]
    fn a_query_breaking_a_rule_is_formerr_without_a_cookie() {
        let pipeline = forwarder().with_cookies(cookies());
        let mut query = query("a", 7);
        query.questions.push(query.questions[0].clone());
        let answer = reply(
            &pipeline,
            &with_cookie(query, &client_only()),
            Transport::Udp,
            None,
        );
        assert_eq!(decode(&answer).rcode(), Rcode::FORMERR);
        assert_eq!(cookie_of(&answer), None);
    }

    /// The request sent upstream carries no cookie of ours or the client's: they are for the hop they were made for.
    #[test]
    fn the_cookie_is_not_forwarded() {
        let pipeline = forwarder().with_cookies(cookies());
        let sent = with_cookie(query("a", 7), &client_only());
        let ran = run(&pipeline, &sent, Transport::Udp, &[Some(&captured("a"))]);
        let request = ran.requests.first().expect("a request");
        let options = request.edns.as_ref().map(|edns| edns.options.clone());
        assert!(
            options
                .unwrap_or_default()
                .iter()
                .all(|option| !matches!(option, EdnsOption::Cookie(_)))
        );
    }

    /// §5.4: a query with no question and a cookie asks for a cookie: NOERROR with one, BADCOOKIE when the Server
    /// Cookie it sent is invalid, with a valid one to retry with. Without a cookie it is FORMERR (RFC 9619).
    #[test]
    fn a_query_without_a_question_asks_for_a_cookie() {
        let pipeline = forwarder().with_cookies(cookies());
        let empty = || {
            let mut query = Message::default();
            query.header.id = 9;
            query
        };
        let bad =
            Cookie::new(CLIENT, Some(&hex("010000005cf79f11ffffffffffffffff"))).expect("cookie");
        let good = cookies().issue(CLIENT, LOOPBACK);
        for (cookie, rcode) in [
            (client_only(), Rcode::NOERROR),
            (good, Rcode::NOERROR),
            (bad, Rcode::BADCOOKIE),
        ] {
            let answer = reply(
                &pipeline,
                &with_cookie(empty(), &cookie),
                Transport::Udp,
                None,
            );
            assert_eq!(decode(&answer).rcode(), rcode, "{cookie:?}");
            let fresh = cookie_of(&answer).expect("a cookie");
            assert_eq!(cookies().verify(Some(&fresh), LOOPBACK), Standing::Valid);
        }
        let mut bare = empty();
        bare.edns = Some(Edns::default());
        let answer = reply(&pipeline, &wire(&bare), Transport::Udp, None);
        assert_eq!(decode(&answer).rcode(), Rcode::FORMERR);
    }

    /// A query with an empty OPT record followed by COOKIE options of `lengths` bytes of data each.
    fn with_cookie_options(lengths: &[usize]) -> Vec<u8> {
        let mut sent = wire(&{
            let mut query = query("a", 7);
            query.edns = Some(Edns::default());
            query
        });
        // The OPT record is last: its RDLENGTH, the two bytes before the end, now holds the options.
        let options: usize = lengths.iter().map(|length| 4 + length).sum();
        let rdlength = sent.len() - 2;
        sent[rdlength..].copy_from_slice(&u16::try_from(options).expect("fits").to_be_bytes());
        for &length in lengths {
            sent.extend_from_slice(&10_u16.to_be_bytes());
            sent.extend_from_slice(&u16::try_from(length).expect("fits").to_be_bytes());
            sent.extend_from_slice(&vec![7; length]);
        }
        sent
    }

    /// §5.2.2: a COOKIE option of a length other than 8, or 16 to 40, is FORMERR, with no cookie in the reply; those
    /// lengths are answered, with a Server Cookie.
    #[test]
    fn a_cookie_of_the_wrong_length_is_formerr() {
        let pipeline = forwarder().with_cookies(cookies());
        for length in [0, 7, 9, 12, 15, 41] {
            let answer = reply(
                &pipeline,
                &with_cookie_options(&[length]),
                Transport::Udp,
                None,
            );
            assert_eq!(decode(&answer).rcode(), Rcode::FORMERR, "{length} bytes");
            assert_eq!(cookie_of(&answer), None, "{length} bytes");
        }
        for length in [8, 16, 24, 40] {
            let sent = with_cookie_options(&[length]);
            let answer = reply(&pipeline, &sent, Transport::Udp, Some(&captured("a")));
            assert_eq!(decode(&answer).rcode(), Rcode::NOERROR, "{length} bytes");
            let fresh = cookie_of(&answer).expect("a cookie");
            assert_eq!(fresh.client(), [7; 8], "{length} bytes");
            assert_eq!(cookies().verify(Some(&fresh), LOOPBACK), Standing::Valid);
        }
    }

    /// §5.2: a COOKIE option after the first is ignored, a malformed one too.
    #[test]
    fn the_cookie_options_after_the_first_are_ignored() {
        let pipeline = forwarder().with_cookies(cookies());
        let sent = with_cookie_options(&[8, 12, 41]);
        let answer = reply(&pipeline, &sent, Transport::Udp, Some(&captured("a")));
        assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
        assert_eq!(cookie_of(&answer).expect("a cookie").client(), [7; 8]);
    }
}

mod server_cookies {
    //! RFC 9018 in the server cookies (D113): the interoperable Server Cookie of version 1, SipHash-2-4, checked against
    //! the examples of Appendix A, whose secrets, addresses and timestamps are used as written, and the timestamp
    //! window of §4.3 and the secret rollover of §5.

    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use dedens_proto::edns::Cookie;
    use dedens_server::{Clock, Cookies, Secret, Secrets, Standing};
    use dedens_testkit::hex;

    const SECRET: &str = "e5e973e5a6b2a43f48e7dc849e37bfcf";
    const OLD: &str = "dd3bdf9344b678b185a6f5cb60fca715";
    const NEW: &str = "445536bcd2513298075a5d379663c962";
    const CLIENT: &str = "2464c4abcf10c957";

    fn secret(text: &str) -> Secret {
        text.parse().expect("a secret")
    }

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// A clock a test sets.
    fn clock(start: u64) -> (Arc<AtomicU64>, Clock) {
        let time = Arc::new(AtomicU64::new(start));
        let reading = Arc::clone(&time);
        (time, Arc::new(move || reading.load(Ordering::Relaxed)))
    }

    fn cookies(secrets: Secrets, now: u64) -> Cookies {
        Cookies::new(secrets, clock(now).1)
    }

    fn fixed(current: &str, accepted: &[&str]) -> Secrets {
        Secrets::new(
            secret(current),
            accepted.iter().map(|text| secret(text)).collect(),
        )
    }

    /// The cookie of the hexadecimal `text`: 8 bytes of client cookie, the rest the server's.
    fn cookie(text: &str) -> Cookie {
        let bytes = hex(text);
        let (client, server) = bytes.split_at(8);
        Cookie::new(
            client.try_into().expect("8 bytes"),
            (!server.is_empty()).then_some(server),
        )
        .expect("a cookie")
    }

    fn client_cookie(text: &str) -> [u8; 8] {
        hex(text).try_into().expect("8 bytes")
    }

    /// The examples of Appendix A: a cookie the server issues for a client cookie at a time.
    #[test]
    fn the_examples_of_appendix_a_are_issued() {
        for (secrets, client, from, now, expected) in [
            // A.1: a client cookie only.
            (
                fixed(SECRET, &[]),
                CLIENT,
                "198.51.100.100",
                1_559_731_985,
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480",
            ),
            // A.2: the client uses the cookie of A.1 later: a new timestamp, a new hash.
            (
                fixed(SECRET, &[]),
                CLIENT,
                "198.51.100.100",
                1_559_734_385,
                "2464c4abcf10c957010000005cf7a871d4a564a1442aca77",
            ),
            // A.3: another client; its request had reserved bytes of abcdef, the reply has zeros.
            (
                fixed(SECRET, &[]),
                "fc93fc62807ddb86",
                "203.0.113.203",
                1_559_734_700,
                "fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e",
            ),
            // A.4: an IPv6 client, the new secret of a rollover.
            (
                fixed(NEW, &[OLD]),
                "22681ab97d52c298",
                "2001:db8:220:1:59de:d0f4:8769:82b8",
                1_559_741_961,
                "22681ab97d52c298010000005cf7c609a6bb79d16625507a",
            ),
        ] {
            let issued = cookies(secrets, now).issue(client_cookie(client), addr(from));
            assert_eq!(issued, cookie(expected), "{from} at {now}");
        }
    }

    /// The requests of A.3 and A.4 verify, reserved bytes and all (§4.2: they are not required to be zero).
    #[test]
    fn the_requests_of_appendix_a_verify() {
        for (secrets, from, now, request) in [
            (
                fixed(SECRET, &[]),
                "203.0.113.203",
                // A.3's request is a few seconds old, not the hours of its reply.
                1_559_727_985 + 10,
                "fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5",
            ),
            (
                // A.4: the request has the old secret; the server is at stage 2 of §5: new secret, old accepted.
                fixed(NEW, &[OLD]),
                "2001:db8:220:1:59de:d0f4:8769:82b8",
                1_559_741_961,
                "22681ab97d52c298010000005cf7c57926556bd0934c72f8",
            ),
            (
                // The reply of A.4, to a server of stage 1: old secret, new accepted.
                fixed(OLD, &[NEW]),
                "2001:db8:220:1:59de:d0f4:8769:82b8",
                1_559_741_961,
                "22681ab97d52c298010000005cf7c609a6bb79d16625507a",
            ),
        ] {
            let standing = cookies(secrets, now).verify(Some(&cookie(request)), addr(from));
            assert_eq!(standing, Standing::Valid, "{request}");
        }
    }

    #[test]
    fn a_secret_the_server_does_not_have_does_not_verify() {
        let request = cookie("22681ab97d52c298010000005cf7c57926556bd0934c72f8");
        let from = addr("2001:db8:220:1:59de:d0f4:8769:82b8");
        // Stage 3 of §5: the old secret is gone.
        let after = cookies(fixed(NEW, &[]), 1_559_741_961);
        assert_eq!(after.verify(Some(&request), from), Standing::Invalid);
        let before = cookies(fixed(OLD, &[]), 1_559_741_961);
        assert_eq!(before.verify(Some(&request), from), Standing::Valid);
    }

    /// §4.4: the hash covers the client's address and the client cookie.
    #[test]
    fn a_cookie_is_for_one_address_and_one_client_cookie() {
        let cookies = cookies(fixed(SECRET, &[]), 1_559_731_985);
        let issued = cookies.issue(client_cookie(CLIENT), addr("198.51.100.100"));
        assert_eq!(
            cookies.verify(Some(&issued), addr("198.51.100.100")),
            Standing::Valid
        );
        assert_eq!(
            cookies.verify(Some(&issued), addr("198.51.100.101")),
            Standing::Invalid
        );
        // An IPv4-mapped address is the IPv4 one (D91).
        assert_eq!(
            cookies.verify(Some(&issued), addr("::ffff:198.51.100.100")),
            Standing::Valid
        );
        let other =
            Cookie::new(client_cookie("2464c4abcf10c958"), issued.server()).expect("a cookie");
        assert_eq!(
            cookies.verify(Some(&other), addr("198.51.100.100")),
            Standing::Invalid
        );
    }

    /// §4.3: a cookie is good for an hour from its timestamp, and a timestamp may be five minutes ahead of the clock
    /// (the skew of an anycast set).
    #[test]
    fn a_timestamp_must_be_within_an_hour_past_and_five_minutes_ahead() {
        let from = addr("198.51.100.100");
        let (time, reading) = clock(1_559_731_985);
        let cookies = Cookies::new(fixed(SECRET, &[]), reading);
        let issued = cookies.issue(client_cookie(CLIENT), from);
        for (now, expected) in [
            (1_559_731_985 - 300, Standing::Valid),
            (1_559_731_985 - 301, Standing::Invalid),
            (1_559_731_985 + 3600, Standing::Valid),
            (1_559_731_985 + 3601, Standing::Invalid),
        ] {
            time.store(now, Ordering::Relaxed);
            assert_eq!(cookies.verify(Some(&issued), from), expected, "at {now}");
        }
    }

    /// §4.3: timestamps are 32 bits compared as serial numbers (RFC 1982), so that they wrap.
    #[test]
    fn timestamps_wrap_at_2_pow_32() {
        let from = addr("198.51.100.100");
        let before_wrap = u64::from(u32::MAX) - 10;
        let (time, reading) = clock(before_wrap);
        let cookies = Cookies::new(fixed(SECRET, &[]), reading);
        let issued = cookies.issue(client_cookie(CLIENT), from);
        // 100 seconds on, the clock is past 2^32 and the timestamp small again.
        time.store(before_wrap + 100, Ordering::Relaxed);
        assert_eq!(cookies.verify(Some(&issued), from), Standing::Valid);
    }

    /// §4.1: only version 1 is checked here; a version 1 cookie is 16 bytes.
    #[test]
    fn another_version_or_length_is_invalid() {
        let from = addr("198.51.100.100");
        let cookies = cookies(fixed(SECRET, &[]), 1_559_731_985);
        for server in [
            "020000005cf79f111f8130c3eee29480",
            "010000005cf79f111f8130c3eee294",
            "010000005cf79f111f8130c3eee29480ff",
            "0100000000000000",
        ] {
            let sent = cookie(&format!("{CLIENT}{server}"));
            assert_eq!(
                cookies.verify(Some(&sent), from),
                Standing::Invalid,
                "{server}"
            );
        }
    }

    #[test]
    fn what_the_query_carries_is_its_standing() {
        let from = addr("198.51.100.100");
        let cookies = cookies(fixed(SECRET, &[]), 1_559_731_985);
        assert_eq!(cookies.verify(None, from), Standing::NoCookie);
        assert_eq!(
            cookies.verify(Some(&cookie(CLIENT)), from),
            Standing::ClientOnly
        );
    }

    #[test]
    fn a_secret_is_32_hexadecimal_digits_and_never_printed() {
        for bad in ["", "e5e973", &"zz".repeat(16), &format!("{SECRET}00")] {
            assert!(bad.parse::<Secret>().is_err(), "{bad}");
        }
        let shown = format!("{:?}", fixed(SECRET, &[OLD]));
        assert!(
            !shown.contains("e5e9") && !shown.contains("dd3b"),
            "{shown}"
        );
    }
}
