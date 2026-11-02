//! The synchronization types of `Current` (`reload.rs`) and `Flights` (`flights.rs`), the two places where threads
//! share state by a protocol of their own: std's and flume's in the server, loom's under `--cfg dedens_loom`, so that
//! the loom tests beside those two try every interleaving of their threads (D135, `just loom`). Everything else in
//! `dedensd` takes its own.

pub(crate) use std::sync::PoisonError;

#[cfg(dedens_loom)]
mod loom_slot;

#[cfg(not(dedens_loom))]
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(dedens_loom))]
pub(crate) use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(not(dedens_loom))]
pub(crate) use flume::{Receiver, Sender, TrySendError};
#[cfg(dedens_loom)]
pub(crate) use loom::sync::atomic::{AtomicU64, Ordering};
#[cfg(dedens_loom)]
pub(crate) use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(dedens_loom)]
pub(crate) use loom_slot::{Receiver, Sender, TrySendError, slot};

/// A channel holding one message at most: a wake-up (`Sender::try_send`, never blocking; `Receiver::recv_async`) or
/// the one response of a flight. `flume::bounded(1)` in the server.
#[cfg(not(dedens_loom))]
pub(crate) fn slot<T>() -> (Sender<T>, Receiver<T>) {
    flume::bounded(1)
}
