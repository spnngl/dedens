//! The byte budget of HTTP/3 connections (D119). h3 0.0.8 reads a stream into memory while it waits for the end of
//! a frame whose length the peer declared, and so returns the QUIC credit: what a connection holds is bounded by
//! the bytes it received and by nothing else. So a connection that received [`BUDGET`] bytes is sent `GOAWAY` (RFC 9114
//! §5.2): its client opens another and its memory is freed, as the rotation of a long connection. One that goes on
//! to [`BUDGET`] plus [`RECEIVE_WINDOW`], or does not end within [`DRAIN`] of `GOAWAY`, is closed with
//! `H3_EXCESSIVE_LOAD` (§8.1, §10.5).
//!
//! One task per thread, [`sweep`], checks its connections every [`CHECK`] while it has any: quinn has no event for
//! bytes received. Bytes are those of the UDP datagrams, counted before they are decrypted (quinn-proto's
//! `udp_rx`): junk on the path in the name of a connection can make it rotate, which costs its client a handshake.

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

use compio::quic::{Connection, VarInt};
use compio::runtime::spawn;
use dedens_net::https::H3_EXCESSIVE_LOAD;
use dedens_net::quic::RECEIVE_WINDOW;

use crate::serve::TCP_IDLE;

/// The bytes an HTTP/3 connection may receive before `GOAWAY`: 4 MiB, some 25 000 `DoH` GETs of 170 bytes (measured
/// in `tests/rfc9114.rs`), so a client at 1 000 queries a second changes connection every 25 s. It is the memory an
/// attacker may make one connection hold for as long as it stays under it, and `TCP_CONNECTIONS` times that is
/// what a thread accepts (1 GiB): a smaller budget rotates honest clients more often, a larger one costs memory (D119).
pub(crate) const BUDGET: u64 = 4 << 20;

/// The time between two checks: 50 a second per thread, whatever the number of connections. A peer that returns its
/// credit at once sends [`RECEIVE_WINDOW`] bytes a round trip, so a connection holds at most [`BUDGET`] plus
/// [`RECEIVE_WINDOW`] times (1 + [`CHECK`] over its round trip) before it is closed: 9.25 MiB at a round trip of 1 ms,
/// 4.5 MiB at 20 ms.
const CHECK: Duration = Duration::from_millis(20);

/// How long a connection may last after `GOAWAY`: its requests in flight are answered within [`TCP_IDLE`] or given up
/// (D47).
const DRAIN: Duration = TCP_IDLE;

/// The state of one HTTP/3 connection's budget.
pub(crate) struct Budget {
    connection: Connection,
    peer: SocketAddr,
    /// When the connection passed [`BUDGET`]: it is being sent `GOAWAY`.
    passed: Cell<Option<Instant>>,
    /// Requests being answered, each holding a [`Flight`].
    flights: Cell<usize>,
}

impl Budget {
    /// Whether the connection received [`BUDGET`] bytes: no request is to be taken on it.
    pub(crate) fn passed(&self) -> bool {
        self.passed.get().is_some()
    }

    /// Whether no request is being answered.
    pub(crate) fn quiet(&self) -> bool {
        self.flights.get() == 0
    }

    /// A request taken: held until it is answered, it keeps the budget checked.
    pub(crate) fn fly(self: &Rc<Self>) -> Flight {
        self.flights.set(self.flights.get() + 1);
        Flight(Rc::clone(self))
    }

    /// Looks at the connection once; `false` when it is closed, or this closes it.
    fn check(&self, now: Instant) -> bool {
        if self.connection.close_reason().is_some() {
            return false;
        }
        let received = self.connection.stats().udp_rx.bytes;
        let late = self.passed.get().is_some_and(|since| now - since > DRAIN);
        if late || received >= BUDGET + u64::from(RECEIVE_WINDOW) {
            tracing::debug!(peer = %self.peer, received, "HTTP/3 connection over its byte budget: closed");
            let code = VarInt::from_u64(H3_EXCESSIVE_LOAD).unwrap_or(VarInt::MAX);
            self.connection.close(code, b"");
            return false;
        }
        if received >= BUDGET && self.passed.get().is_none() {
            tracing::info!(peer = %self.peer, received, "HTTP/3 connection over its byte budget: GOAWAY");
            self.passed.set(Some(now));
        }
        true
    }
}

/// A request being answered on a connection with a [`Budget`].
pub(crate) struct Flight(Rc<Budget>);

impl Drop for Flight {
    fn drop(&mut self) {
        self.0.flights.set(self.0.flights.get() - 1);
    }
}

/// The HTTP/3 connections of one thread that are checked.
#[derive(Default)]
pub(crate) struct Connections {
    /// Weak: the budget lives as long as the connection's service and its requests, and no longer.
    list: RefCell<Vec<Weak<Budget>>>,
    /// Whether [`sweep`] runs; it ends when the list is empty.
    sweeping: Cell<bool>,
}

impl Connections {
    /// Starts checking `connection` from `peer`; the check ends with the returned budget's last holder.
    pub(crate) fn register(
        self: &Rc<Self>,
        connection: Connection,
        peer: SocketAddr,
    ) -> Rc<Budget> {
        let budget = Rc::new(Budget {
            connection,
            peer,
            passed: Cell::new(None),
            flights: Cell::new(0),
        });
        self.list.borrow_mut().push(Rc::downgrade(&budget));
        if !self.sweeping.replace(true) {
            spawn(sweep(Rc::clone(self))).detach();
        }
        budget
    }
}

/// Checks the connections of `connections` every [`CHECK`] until none is left.
async fn sweep(connections: Rc<Connections>) {
    loop {
        compio::time::sleep(CHECK).await;
        let now = Instant::now();
        let mut list = connections.list.borrow_mut();
        list.retain(|budget| budget.upgrade().is_some_and(|budget| budget.check(now)));
        if list.is_empty() {
            connections.sweeping.set(false);
            return;
        }
    }
}
