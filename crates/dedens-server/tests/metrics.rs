//! The counters of the `metrics` feature (D30, D91, D113).

use std::net::IpAddr;
use std::sync::Arc;

use dedens_dnssec::{Limits, TrustAnchors, Validator};
use dedens_proto::edns::{Cookie, Edns, EdnsOption};
use dedens_proto::{Flags, RecordType, Transport};
use dedens_server::{
    Access, Budget, Budgets, Clock, Cookies, Denial, Network, Rate, RateLimit, RateLimitConfig,
    Secret, Secrets, Validating,
};
use dedens_testkit::dnssec::Captures;
use dedens_testkit::query;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

use crate::util::{captured_at, client_query, forwarder, run_captured, validating_under, wire};

/// The counter `dedensd_access_denied_total{action}` counts the queries a denied client sent, by action.
#[test]
fn denied_queries_are_counted_by_action() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let allowed: Network = "10.0.0.0/8".parse().expect("a network");
    let query = wire(&query("a", 7));
    let mut out = vec![0; 65535];
    for (denial, denied, permitted, expected) in [
        (Denial::Refuse, 2, 1, "refuse"),
        (Denial::Drop, 3, 1, "drop"),
    ] {
        let pipeline = metrics::with_local_recorder(&recorder, || {
            forwarder().with_access(Access::new([allowed], [], denial))
        });
        for (count, from) in [(denied, "192.0.2.1"), (permitted, "10.0.0.1")] {
            let from: IpAddr = from.parse().expect("an address");
            for _ in 0..count {
                let _ = pipeline.query(&query, Transport::Udp, from, 0, &mut out);
            }
        }
        let counted: Vec<_> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, _, value)| {
                let DebugValue::Counter(n) = value else {
                    return None;
                };
                let (_, key) = key.into_parts();
                let action = key
                    .labels()
                    .find(|l| l.key() == "action")?
                    .value()
                    .to_owned();
                (key.name() == "dedensd_access_denied_total" && n > 0).then_some((action, n))
            })
            .collect();
        assert_eq!(counted, [(expected.to_owned(), denied)]);
    }
}

/// The values of the counter `name`, by the label `label`, that are not zero.
fn counted(
    snapshotter: &metrics_util::debugging::Snapshotter,
    name: &str,
    label: &str,
) -> Vec<(String, u64)> {
    let mut counted: Vec<_> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let DebugValue::Counter(n) = value else {
                return None;
            };
            let (_, key) = key.into_parts();
            let value = key.labels().find(|l| l.key() == label)?.value().to_owned();
            (key.name() == name && n > 0).then_some((value, n))
        })
        .collect();
    counted.sort();
    counted
}

/// `dedensd_rrl_limited_total{action}` counts the UDP queries over the rate, by slip (TC) and drop; the queries
/// within it and the queries over TCP count nothing.
#[test]
fn limited_queries_are_counted_by_action() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let config = RateLimitConfig {
        ipv4: Rate {
            prefix: 24,
            per_second: 1,
            burst: 2,
        },
        slip: 2,
        ..RateLimitConfig::default()
    };
    let pipeline = metrics::with_local_recorder(&recorder, || {
        forwarder().with_rate_limit(RateLimit::new(config).expect("a limit"))
    });
    let query = wire(&query("a", 7));
    let mut out = vec![0; 65535];
    let from: IpAddr = "198.51.100.7".parse().expect("an address");
    // 2 within the burst, then 3 over: drop, slip, drop.
    for _ in 0..5 {
        let _ = pipeline.query(&query, Transport::Udp, from, 0, &mut out);
    }
    let _ = pipeline.query(&query, Transport::Tcp, from, 0, &mut out);
    assert_eq!(
        counted(&snapshotter, "dedensd_rrl_limited_total", "action"),
        [("drop".to_owned(), 2), ("slip".to_owned(), 1)]
    );
}

/// `dedensd_cookies_total{outcome}` counts the queries by what they carry.
#[test]
fn cookies_are_counted_by_outcome() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let clock: Clock = Arc::new(|| 1_559_731_985);
    let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
        .parse()
        .expect("a secret");
    let issuer = Cookies::new(Secrets::new(secret.clone(), vec![]), Arc::clone(&clock));
    let pipeline = metrics::with_local_recorder(&recorder, || {
        forwarder().with_cookies(Cookies::new(Secrets::new(secret, vec![]), clock))
    });
    let from: IpAddr = "198.51.100.7".parse().expect("an address");
    let valid = issuer.issue([1; 8], from);
    let ask = |cookie: Option<Cookie>| {
        let mut query = query("a", 7);
        query.edns = Some(Edns {
            options: cookie.map(EdnsOption::Cookie).into_iter().collect(),
            ..Edns::default()
        });
        let mut out = vec![0; 65535];
        let _ = pipeline.query(&wire(&query), Transport::Udp, from, 0, &mut out);
    };
    let wrong = Cookie::new([1; 8], Some(&[9; 16])).expect("a cookie");
    for cookie in [
        None,
        Some(Cookie::new([1; 8], None).expect("a cookie")),
        Some(wrong),
        Some(valid),
        Some(valid),
    ] {
        ask(cookie);
    }
    assert_eq!(
        counted(&snapshotter, "dedensd_cookies_total", "outcome"),
        [
            ("client_only".to_owned(), 1),
            ("invalid".to_owned(), 1),
            ("none".to_owned(), 1),
            ("valid".to_owned(), 2),
        ]
    );
}

/// `dedens_validations_total{verdict}` counts the responses validated by verdict: a cold validation costs more than
/// a share of 2 units, so it stops once the share is in debt, and the next query of the network finds it so (D117).
#[test]
fn a_query_over_its_share_is_counted_as_shed_by_the_share() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let limits = Limits {
        key_cache: 0,
        ..Limits::default()
    };
    let validating = metrics::with_local_recorder(&recorder, || {
        Validating::new(
            Validator::new(TrustAnchors::root(), limits),
            Arc::new(captured_at),
        )
        .sharing(
            Budgets::new(Budget {
                per_second: 1,
                burst: 2,
                table: 1 << 8,
            })
            .expect("a share in bounds"),
        )
    });
    let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
    for _ in 0..2 {
        // A fresh cache each time: nothing is held between the two.
        drop(run_captured(
            &validating_under(validating.clone()),
            &query,
            0,
            &Captures::new(),
        ));
    }
    assert_eq!(
        counted(&snapshotter, "dedens_validations_total", "verdict"),
        [("shed_share".to_owned(), 2)]
    );
}
