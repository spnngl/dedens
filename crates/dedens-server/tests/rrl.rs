//! Response rate limiting in the server core (D113, audit S1): over UDP a source network over its rate gets TC=1
//! or nothing, one in `slip` answered; a valid Server Cookie, and every other transport, are not limited; the
//! table is of fixed size.

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use common::{captured, decode, forwarder, query_for, wire};
use dedens_proto::edns::{Cookie, Edns, EdnsOption};
use dedens_proto::{Flags, Rcode, Transport};
use dedens_server::{
    Access, Admission, Clock, Cookies, Denial, Network, Pipeline, Rate, RateLimit, RateLimitConfig,
    RateLimitError, Secret, Secrets, Step,
};

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

fn query() -> Vec<u8> {
    wire(&query_for(&captured("a")))
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
    send(pipeline, &query(), Transport::Udp, from, now)
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
            let fate = send(&pipeline, &query(), transport, "198.51.100.7", 10);
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
        assert_eq!(send(&pipeline, &query(), Transport::Tcp, from, 10), Refused);
    }
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
    let mut query = query_for(&captured("a"));
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
