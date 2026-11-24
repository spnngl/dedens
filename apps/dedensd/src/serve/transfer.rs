//! Zone transfers out over TCP and TLS (D214): their bounds, for all threads, and their metric. The stream itself
//! is the connection's ([`super::tcp`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::sync::{Mutex, PoisonError};

/// Transfers at once, for all threads: BIND's `transfers-out` default (its reference manual). Past them a request is
/// answered SERVFAIL (RFC 9103 §6.3.3). Knot and NSD bound them only by their TCP connections (Knot's
/// `tcp-max-clients`, `src/knot/conf/schema.c`; NSD's `tcp-count`, `options.c`).
pub(crate) const TRANSFERS: usize = 10;

/// Transfers at once to one client address: the most BIND asks of one primary as a secondary (`transfers-per-ns`,
/// its reference manual), so that one client leaves room for the others.
pub(crate) const TRANSFERS_PER_CLIENT: usize = 2;

/// How long a transfer may take: BIND's `max-transfer-time-out` default (its reference manual), 120 minutes. Past
/// it the connection closes. A client that reads nothing loses it sooner, at [`super::tcp::TCP_WRITE`].
pub(crate) const TRANSFER_TIME: Duration = Duration::from_mins(120);

/// Transfers counted by `type`, `axfr` or `ixfr` (as sent: an IXFR answered with the zone is `axfr`), and
/// `outcome`: `done`, `refused` (over [`TRANSFERS`] or [`TRANSFERS_PER_CLIENT`]), or `cut` (closed before its
/// end: a revoked key, [`TRANSFER_TIME`], the client gone).
pub(crate) const TRANSFERS_TOTAL: &str = "dedensd_authoritative_transfers_total";

/// Describes the metric of transfers.
pub(crate) fn describe() {
    metrics::describe_counter!(
        TRANSFERS_TOTAL,
        "Zone transfers out, by type: axfr or ixfr, and outcome: done, refused (too many at once), or cut (D214)."
    );
}

/// The transfers running, for all threads and across reloads.
#[derive(Debug, Default)]
pub(crate) struct Transfers(Mutex<Running>);

/// The transfers running, and to whom.
#[derive(Debug, Default)]
struct Running {
    total: usize,
    clients: HashMap<IpAddr, usize>,
}

impl Transfers {
    /// A place for a transfer to `client`, given back when dropped; `None` past [`TRANSFERS`] or
    /// [`TRANSFERS_PER_CLIENT`].
    pub(crate) fn take(&self, client: IpAddr) -> Option<Turn<'_>> {
        let mut running = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if running.total >= TRANSFERS {
            return None;
        }
        let count = running.clients.entry(client).or_default();
        if *count >= TRANSFERS_PER_CLIENT {
            return None;
        }
        *count += 1;
        running.total += 1;
        Some(Turn {
            transfers: self,
            client,
        })
    }
}

/// A transfer's place, given back when dropped.
#[derive(Debug)]
pub(crate) struct Turn<'t> {
    transfers: &'t Transfers,
    client: IpAddr,
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut running = (self.transfers.0)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        running.total -= 1;
        if let Some(count) = running.clients.get_mut(&self.client) {
            *count -= 1;
            if *count == 0 {
                running.clients.remove(&self.client);
            }
        }
    }
}

// Loom's locks run inside a model only (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
mod tests {
    use std::net::IpAddr;

    use super::{TRANSFERS, TRANSFERS_PER_CLIENT, Transfers};

    fn client(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    #[test]
    fn s6_3_3_transfers_are_bounded_per_client_and_in_all() {
        let transfers = Transfers::default();
        let first: Vec<_> = (0..TRANSFERS_PER_CLIENT)
            .map(|_| transfers.take(client(0)).expect("a place"))
            .collect();
        assert!(transfers.take(client(0)).is_none());
        let others: Vec<_> = (1..).map_while(|n| transfers.take(client(n))).collect();
        assert_eq!(first.len() + others.len(), TRANSFERS);
        drop(first);
        assert!(transfers.take(client(0)).is_some());
        drop(others);
        let running = transfers.0.lock().expect("unpoisoned");
        assert_eq!((running.total, running.clients.len()), (0, 0));
    }

    #[test]
    fn the_metric_of_transfers_is_described() {
        use metrics_util::debugging::DebuggingRecorder;

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            super::describe();
            metrics::counter!(super::TRANSFERS_TOTAL, "type" => "axfr", "outcome" => "done")
                .increment(1);
        });
        let snapshot = snapshotter.snapshot().into_vec();
        let described: Vec<_> = snapshot
            .iter()
            .map(|(key, _, help, _)| (key.key().name(), help.is_some()))
            .collect();
        assert_eq!(described, [(super::TRANSFERS_TOTAL, true)]);
    }
}
