//! What the families share: the seeds of `just check`, the timeouts of the stub and of a forward stage, the
//! upstream servers most scenarios ask, and the counts of their events most scenarios check.

use std::net::IpAddr;
use std::time::Duration;

use dedens_proto::Transport;
use dedens_sim::trace::{Event, What};
use dedens_sim::upstream::Answers;

/// The seeds of `just check`; `DEDENS_SIM_SEED` and `DEDENS_SIM_RUNS` replace them.
pub(crate) const SEEDS: &[u64] = &[0, 1, 7, 42, 2026];

/// The hash key of the rate limits' and the budgets' tables: fixed, so that a run replays in any process (D133).
pub(crate) const TABLE_KEY: [u8; 16] = *b"dedens-sim table";

/// A second of simulated time.
pub(crate) const SECOND: Duration = Duration::from_secs(1);

/// How long the stub waits for a response to each try, and how many tries it makes (D27).
pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TRIES: u32 = 3;

/// How long a forward stage waits for a response to each try, and how many tries it makes of one server (D45).
pub(crate) const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const FORWARD_TRIES: u32 = 2;

/// An upstream server holding `example.com A`.
pub(crate) fn answers() -> Answers {
    Answers::new().captured("a")
}

/// [`answers`], and `google.com TXT`: truncated over UDP, whole over TCP.
pub(crate) fn answers_and_txt() -> Answers {
    answers().truncating("truncated", "txt_large")
}

/// Responses the upstream servers sent, over any transport.
pub(crate) fn served(events: &[Event]) -> usize {
    count(events, |event| matches!(event.what, What::Served { .. }))
}

/// Responses the upstream servers sent over `over`.
pub(crate) fn served_over(events: &[Event], over: Transport) -> usize {
    count(
        events,
        |event| matches!(event.what, What::Served { transport, .. } if transport == over),
    )
}

/// Responses the upstream server at `host` sent.
pub(crate) fn served_by(events: &[Event], host: IpAddr) -> usize {
    count(events, |event| {
        event.host == host && matches!(event.what, What::Served { .. })
    })
}

/// Times the resolver started asking an upstream server, over any transport.
pub(crate) fn forwarded(events: &[Event]) -> usize {
    count(events, |event| matches!(event.what, What::Forwarded { .. }))
}

/// How many of `events` `what` picks.
fn count(events: &[Event], what: impl Fn(&Event) -> bool) -> usize {
    events.iter().filter(|event| what(event)).count()
}
