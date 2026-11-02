//! [`slot`] for loom: the channel of one that `flume::bounded(1)` is in the server, for the calls `dedensd` makes on it.
//! A message sent is received even after the sender is dropped, then the receiver sees the channel closed; a send
//! fails once the receiver is dropped, and when a message is waiting. Loom has no channel with a `Future` to receive
//! from, so this one is a loom `Mutex` around the message and the waker of the task receiving: a wake-up the task
//! misses is a deadlock loom reports.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use loom::sync::{Arc, Mutex, MutexGuard};

use super::PoisonError;

#[derive(Debug)]
struct State<T> {
    message: Option<T>,
    /// The task waiting for a message, to wake when one comes or the sender goes.
    waker: Option<Waker>,
    sender: bool,
    receiver: bool,
}

type Shared<T> = Arc<Mutex<State<T>>>;

fn lock<T>(shared: &Shared<T>) -> MutexGuard<'_, State<T>> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Wakes `waker`, once the lock is released.
fn wake(waker: Option<Waker>) {
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// A channel of one message.
pub(crate) fn slot<T>() -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Mutex::new(State {
        message: None,
        waker: None,
        sender: true,
        receiver: true,
    }));
    (Sender(Arc::clone(&shared)), Receiver(shared))
}

#[derive(Debug)]
pub(crate) struct Sender<T>(Shared<T>);

#[derive(Debug)]
pub(crate) enum TrySendError<T> {
    /// A message is waiting.
    Full(T),
    /// The receiver is gone.
    Disconnected(T),
}

impl<T> Sender<T> {
    pub(crate) fn try_send(&self, message: T) -> Result<(), TrySendError<T>> {
        let waker = {
            let mut state = lock(&self.0);
            if !state.receiver {
                return Err(TrySendError::Disconnected(message));
            }
            if state.message.is_some() {
                return Err(TrySendError::Full(message));
            }
            state.message = Some(message);
            state.waker.take()
        };
        wake(waker);
        Ok(())
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let waker = {
            let mut state = lock(&self.0);
            state.sender = false;
            state.waker.take()
        };
        wake(waker);
    }
}

#[derive(Debug)]
pub(crate) struct Receiver<T>(Shared<T>);

/// The sender is gone and no message is left.
#[derive(Debug)]
pub(crate) struct RecvError;

impl<T> Receiver<T> {
    pub(crate) const fn recv_async(&self) -> RecvFut<'_, T> {
        RecvFut(&self.0)
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let (message, waker) = {
            let mut state = lock(&self.0);
            state.receiver = false;
            (state.message.take(), state.waker.take())
        };
        drop((message, waker));
    }
}

/// [`Receiver::recv_async`].
#[derive(Debug)]
pub(crate) struct RecvFut<'a, T>(&'a Shared<T>);

impl<T> Future for RecvFut<'_, T> {
    type Output = Result<T, RecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock(self.0);
        if let Some(message) = state.message.take() {
            return Poll::Ready(Ok(message));
        }
        if !state.sender {
            return Poll::Ready(Err(RecvError));
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
