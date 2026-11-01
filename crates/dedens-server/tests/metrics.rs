//! The counters of the `metrics` feature (D30, D91).

#![cfg(feature = "metrics")]

mod common;

use std::net::IpAddr;

use common::{captured, forwarder, query_for, wire};
use dedens_server::{Access, Denial, Network, Transport};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

/// The counter `dedensd_access_denied_total{action}` counts the queries a denied client sent, by action.
#[test]
fn denied_queries_are_counted_by_action() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let allowed: Network = "10.0.0.0/8".parse().expect("a network");
    let query = wire(&query_for(&captured("a")));
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
