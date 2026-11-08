//! Failures kept where they happen (D121): a task that panics ends alone, and a listener whose loop ended starts
//! again, so one bug, or one dependency's panic reachable from the network (D89), does not end the process.
//!
//! The runtime already catches a panic in any task, but a detached task then ends in silence. [`Origin::spawn`] logs
//! and counts it; [`supervise`] restarts the loop of a listener, with a pause that doubles. A panic of the runtime
//! itself ends its thread, and the process with it (D121): only `main` sees that.

use std::any::Any;
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe, PanicHookInfo, catch_unwind};
use std::pin::pin;
use std::rc::Rc;
use std::time::{Duration, Instant};
use std::{fmt, io, thread};

use compio::runtime::JoinHandle;
use futures_util::FutureExt;

/// Counts the panics of tasks, by listener.
const PANICS: &str = "dedensd_task_panics_total";

/// Counts the restarts of listener loops, by listener.
const RESTARTS: &str = "dedensd_listener_restarts_total";

/// A listener logs a panic at most this often, and says how many it left out: a client sending what panics at line
/// rate would otherwise fill the log. The counter has them all.
const LOG_EVERY: Duration = Duration::from_secs(1);

/// Describes the metrics of this module.
pub(crate) fn describe() {
    metrics::describe_counter!(
        PANICS,
        "Tasks that panicked, caught and dropped: a query, a connection or a listener loop."
    );
    metrics::describe_counter!(
        RESTARTS,
        "Listener loops started again after they ended or panicked."
    );
}

thread_local! {
    /// Whether the code running on this thread is under a catch of ours: its panic is logged by [`Origin::panicked`],
    /// with the listener and the client, so the hook of [`hook`] keeps quiet ([`Hooked::Kept`]).
    static CAUGHT: Cell<bool> = const { Cell::new(false) };
    /// Where the last caught panic happened, from the hook to the log of the catch.
    static AT: Cell<Option<String>> = const { Cell::new(None) };
}

/// Marks the thread as under a catch until dropped.
struct Caught(bool);

impl Caught {
    fn enter() -> Self {
        Self(CAUGHT.replace(true))
    }
}

impl Drop for Caught {
    fn drop(&mut self) {
        CAUGHT.set(self.0);
    }
}

/// Sets the panic hook, which does what [`Hooked`] says (D121). Without a hook, the default one writes each panic to
/// stderr. Process-wide, so no test sets it: a test of [`Hooked::new`] stands for it.
pub(crate) fn hook() {
    panic::set_hook(Box::new(|info: &PanicHookInfo<'_>| {
        let thread = thread::current();
        let at = info.location().map(ToString::to_string);
        match Hooked::new(CAUGHT.get(), thread.name(), at, info.payload()) {
            Hooked::Kept { at } => AT.set(at),
            Hooked::Logged { thread, at, panic } => {
                tracing::error!(thread, at = at.as_deref(), panic, "panic");
            }
        }
    }));
}

/// What the panic hook does with a panic (D121).
#[derive(Debug, PartialEq, Eq)]
enum Hooked<'a> {
    /// A catch of ours has it, and logs it with the listener and the client, rate-limited: the hook keeps where it
    /// happened, for that log.
    Kept { at: Option<String> },
    /// No catch has it: the hook logs it through `tracing` with its thread and place, as the last words of the thread
    /// (`main` ends the process).
    Logged {
        thread: &'a str,
        at: Option<String>,
        panic: &'a str,
    },
}

impl<'a> Hooked<'a> {
    /// What the hook does with a panic at `at` saying `payload`, on the thread named `thread`, under a catch of ours
    /// if `caught`.
    fn new(
        caught: bool,
        thread: Option<&'a str>,
        at: Option<String>,
        payload: &'a (dyn Any + Send),
    ) -> Self {
        if caught {
            Self::Kept { at }
        } else {
            Self::Logged {
                thread: thread.unwrap_or("unnamed"),
                at,
                panic: message(payload),
            }
        }
    }
}

/// Runs `step`, which is not to await, under a catch.
///
/// Unwind safe: a panic leaves nothing the next task cannot use. The standard `Mutex`es recover from poisoning
/// (`PoisonError::into_inner`: the cache, the validator's cache, the flights, the reload, the certificate); the rate
/// limits and the budgets (D113, D117) are atomic leaky buckets, whose token leaked by a panic refills; a flight's
/// leader that panics releases its followers as it drops; the thread's buffer is a `RefCell` whose borrow ends
/// as the stack unwinds, and a reply is written into a buffer of fixed length. A `Mutex::lock().unwrap()` or a
/// shared update in several steps added later breaks this: keep it true.
fn caught_now<T>(step: impl FnOnce() -> T) -> Result<T, Box<dyn Any + Send>> {
    let _caught = Caught::enter();
    catch_unwind(AssertUnwindSafe(step))
}

/// Polls `task` under a catch (see [`caught_now`] for why this is unwind safe), marking the thread only while it
/// polls: the other tasks of the thread run in between.
async fn caught<T>(task: impl Future<Output = T>) -> Result<T, Box<dyn Any + Send>> {
    let mut task = pin!(task);
    AssertUnwindSafe(poll_fn(move |cx| {
        let _caught = Caught::enter();
        task.as_mut().poll(cx)
    }))
    .catch_unwind()
    .await
}

/// What the listener a task serves is: named by its scheme and address, `udp://127.0.0.1:53`, the `listener` label;
/// and how long ago it logged a panic.
#[derive(Debug)]
struct Named {
    name: Box<str>,
    logged: Cell<Option<Instant>>,
    /// The panics not logged since.
    suppressed: Cell<u64>,
}

/// The listener a task serves, shared by its tasks.
#[derive(Clone, Debug)]
pub(super) struct Listener(Rc<Named>);

impl Listener {
    /// The listener of `scheme` on `addr`, if known.
    pub(super) fn new(scheme: &str, addr: Option<SocketAddr>) -> Self {
        let name = match addr {
            Some(addr) => format!("{scheme}://{addr}"),
            None => format!("{scheme}://"),
        };
        Self(Rc::new(Named {
            name: name.into(),
            logged: Cell::new(None),
            suppressed: Cell::new(0),
        }))
    }

    /// Counts a panic of one of its tasks.
    fn count_panic(&self) {
        metrics::counter!(PANICS, "listener" => self.0.name.to_string()).increment(1);
    }

    /// Whether a panic at `now` is logged: the first, then one a [`LOG_EVERY`]; with it, the number left out since.
    fn admit(&self, now: Instant) -> Option<u64> {
        let due = self
            .0
            .logged
            .get()
            .is_none_or(|at| now.saturating_duration_since(at) >= LOG_EVERY);
        if due {
            self.0.logged.set(Some(now));
            Some(self.0.suppressed.take())
        } else {
            self.0.suppressed.set(self.0.suppressed.get() + 1);
            None
        }
    }

    /// Counts and logs a panic of a task for the client at `peer`, if any.
    fn panicked(&self, peer: Option<SocketAddr>, payload: &(dyn Any + Send)) {
        self.count_panic();
        let at = AT.take();
        if let Some(suppressed) = self.admit(Instant::now()) {
            tracing::error!(
                listener = %self,
                peer = peer.map(|peer| peer.to_string()),
                panic = message(payload),
                at,
                suppressed,
                "task panicked: dropped, the listener goes on"
            );
        }
    }

    /// Runs `step`, which is not to await, for the client at `peer`: `None` if it panicked, the panic logged and
    /// counted.
    pub(super) fn guard<T>(&self, peer: SocketAddr, step: impl FnOnce() -> T) -> Option<T> {
        caught_now(step)
            .map_err(|payload| self.panicked(Some(peer), &*payload))
            .ok()
    }

    /// As [`Listener::guard`], for a step that awaits.
    pub(super) async fn guard_async<T>(
        &self,
        peer: SocketAddr,
        step: impl Future<Output = T>,
    ) -> Option<T> {
        caught(step)
            .await
            .map_err(|payload| self.panicked(Some(peer), &*payload))
            .ok()
    }
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.name)
    }
}

/// Where a task comes from: the listener it serves and the client it answers.
#[derive(Clone, Debug)]
pub(super) struct Origin {
    listener: Listener,
    pub(super) peer: SocketAddr,
}

impl Origin {
    pub(super) fn listener(&self) -> &Listener {
        &self.listener
    }

    pub(super) fn new(listener: &Listener, peer: SocketAddr) -> Self {
        Self {
            listener: listener.clone(),
            peer,
        }
    }

    /// Runs `task` alone on the thread's runtime, not waited for: if it panics, that is logged and counted, and
    /// nothing else ends. Dropping the task on the way gives back what it held, as slots.
    pub(super) fn spawn(self, task: impl Future<Output = ()> + 'static) {
        self.run(task).detach();
    }

    /// As [`Origin::spawn`], but dropping the handle ends the task.
    pub(super) fn spawn_joinable(
        &self,
        task: impl Future<Output = ()> + 'static,
    ) -> JoinHandle<()> {
        self.clone().run(task)
    }

    fn run(self, task: impl Future<Output = ()> + 'static) -> JoinHandle<()> {
        compio::runtime::spawn(async move {
            if let Err(payload) = caught(task).await {
                self.listener.panicked(Some(self.peer), &*payload);
            }
        })
    }
}

/// What a panic said, if it said a string.
fn message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("not a string")
}

/// The error of a thread that panicked outside any catch: its runtime's or its driver's. The process ends with it, for
/// its supervisor to start it again (D121).
pub(crate) fn fatal(payload: &(dyn Any + Send)) -> io::Error {
    io::Error::other(format!(
        "a thread panicked: {}; the process ends, for its supervisor to start it again",
        message(payload)
    ))
}

/// How long a listener waits before it starts again.
#[derive(Clone, Copy, Debug)]
pub(super) struct Backoff {
    /// The first pause.
    pub(super) first: Duration,
    /// The pause never grows past this.
    pub(super) max: Duration,
    /// A run this long is healthy: the next pause is the first again.
    pub(super) healthy: Duration,
}

/// The pauses of a listener: 10 ms, doubling up to 5 s, the first again after a minute of service (D121).
pub(super) const BACKOFF: Backoff = Backoff {
    first: Duration::from_millis(10),
    max: Duration::from_secs(5),
    healthy: Duration::from_secs(60),
};

impl Backoff {
    /// The pause after a run of `ran`, `last` being the pause before it, if it followed one.
    fn pause(&self, last: Option<Duration>, ran: Duration) -> Duration {
        match last {
            Some(last) if ran < self.healthy => last.saturating_mul(2).min(self.max),
            _ => self.first,
        }
    }
}

/// Runs the loop `start` makes, and again each time it ends or panics, after a pause of `backoff`; never ends. A
/// restart is logged and counted. What a loop holds that outlives it, its socket, is `start`'s to keep: a panic
/// leaves it as it was.
pub(super) async fn supervise<F: Future<Output = ()>>(
    listener: &Listener,
    backoff: Backoff,
    mut start: impl FnMut() -> F,
) {
    let mut last = None;
    loop {
        let began = Instant::now();
        match caught(start()).await {
            Ok(()) => tracing::error!(%listener, "listener ended"),
            Err(payload) => listener.panicked(None, &*payload),
        }
        let pause = backoff.pause(last, began.elapsed());
        last = Some(pause);
        tracing::warn!(%listener, ?pause, "listener restarts");
        metrics::counter!(RESTARTS, "listener" => listener.0.name.to_string()).increment(1);
        compio::time::sleep(pause).await;
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::cell::Cell;
    use std::panic::panic_any;
    use std::pin::pin;

    use futures_util::future::select;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;

    const MS: Backoff = Backoff {
        first: Duration::from_millis(1),
        max: Duration::from_millis(4),
        healthy: Duration::from_millis(50),
    };

    fn listener() -> Listener {
        Listener::new("udp", Some(SocketAddr::from(([127, 0, 0, 1], 53))))
    }

    const PEER: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        4,
    );

    /// The panics and restarts counted, as (metric, listener, count), from what `recorder` saw: one snapshot, as it
    /// takes the counts.
    pub(in crate::serve) fn counted(recorder: &DebuggingRecorder) -> Vec<(String, String, u64)> {
        let mut counts: Vec<_> = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, ..)| [PANICS, RESTARTS].contains(&key.key().name()))
            .filter_map(|(key, _, _, value)| match value {
                DebugValue::Counter(count) if count > 0 => Some((
                    key.key().name().to_owned(),
                    key.key()
                        .labels()
                        .map(|label| label.value().to_owned())
                        .collect(),
                    count,
                )),
                _ => None,
            })
            .collect();
        counts.sort();
        counts
    }

    #[test]
    fn the_pause_doubles_to_its_limit_and_starts_over_after_service() {
        let (short, long) = (Duration::ZERO, Duration::from_secs(60));
        let mut last = None;
        let mut pauses = Vec::new();
        for _ in 0..5 {
            let pause = BACKOFF.pause(last, short);
            pauses.push(pause);
            last = Some(pause);
        }
        let ms = |ms| Duration::from_millis(ms);
        assert_eq!(pauses, [ms(10), ms(20), ms(40), ms(80), ms(160)]);
        let capped = BACKOFF.pause(Some(Duration::from_secs(4)), short);
        assert_eq!(capped, BACKOFF.max);
        assert_eq!(BACKOFF.pause(Some(capped), short), BACKOFF.max);
        assert_eq!(BACKOFF.pause(Some(capped), long), BACKOFF.first);
    }

    #[test]
    fn a_listener_is_named_by_its_scheme_and_address() {
        assert_eq!(listener().to_string(), "udp://127.0.0.1:53");
        assert_eq!(Listener::new("coap", None).to_string(), "coap://");
    }

    #[test]
    fn the_counters_are_described() {
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            describe();
            metrics::counter!(PANICS).increment(1);
            metrics::counter!(RESTARTS).increment(1);
        });
        let mut described: Vec<_> = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, description, _)| (key.key().name().to_owned(), description.is_some()))
            .collect();
        described.sort();
        assert_eq!(
            described,
            [(RESTARTS.to_owned(), true), (PANICS.to_owned(), true)]
        );
    }

    /// D121: the hook logs a panic no catch has, with its thread and place; one a catch has is the catch's to log,
    /// the hook keeping only where it happened.
    #[test]
    fn the_hook_logs_the_panics_no_catch_has() {
        let at = || Some("src/main.rs:1:1".to_owned());
        let payload: &(dyn Any + Send) = &"a bug";
        assert_eq!(
            Hooked::new(true, Some("main"), at(), payload),
            Hooked::Kept { at: at() }
        );
        assert_eq!(
            Hooked::new(false, Some("main"), at(), payload),
            Hooked::Logged {
                thread: "main",
                at: at(),
                panic: "a bug"
            }
        );
        assert_eq!(
            Hooked::new(false, None, None, payload),
            Hooked::Logged {
                thread: "unnamed",
                at: None,
                panic: "a bug"
            }
        );
    }

    /// D121: a thread is under a catch only while it runs one, panicking or not, so the hook leaves the catch only
    /// the panics it has.
    #[test]
    fn a_thread_is_under_a_catch_while_it_runs_one() {
        let listener = listener();
        assert_eq!(listener.guard(PEER, || CAUGHT.get()), Some(true));
        assert!(!CAUGHT.get());
        assert_eq!(
            listener.guard(PEER, || panic_any::<&str>("a bug")),
            None::<()>
        );
        assert!(!CAUGHT.get());
    }

    #[test]
    fn a_panic_says_its_string() {
        assert_eq!(message(&*Box::new("a bug")), "a bug");
        assert_eq!(message(&*Box::new(String::from("a bug"))), "a bug");
        assert_eq!(message(&*Box::new(7)), "not a string");
    }

    /// A listener logs its first panic, then one a second, counting the others.
    #[test]
    fn a_listener_logs_a_panic_a_second_and_counts_the_rest() {
        let listener = listener();
        let start = Instant::now();
        let ms = |ms| start + Duration::from_millis(ms);
        assert_eq!(listener.admit(ms(0)), Some(0));
        assert_eq!(listener.admit(ms(1)), None);
        assert_eq!(listener.admit(ms(999)), None);
        assert_eq!(listener.admit(ms(1000)), Some(2));
        assert_eq!(listener.admit(ms(2500)), Some(0));
    }

    #[test]
    fn a_task_that_panics_is_counted_and_the_next_runs() {
        let recorder = DebuggingRecorder::new();
        let ran = Rc::new(Cell::new(false));
        metrics::with_local_recorder(&recorder, || {
            compio::runtime::Runtime::new()
                .expect("a runtime")
                .block_on(async {
                    let origin = Origin::new(&listener(), PEER);
                    origin
                        .spawn_joinable(async { panic_any("a bug") })
                        .await
                        .expect("the panic is caught");
                    let flag = Rc::clone(&ran);
                    origin
                        .spawn_joinable(async move { flag.set(true) })
                        .await
                        .expect("the next task runs");
                });
        });
        assert!(ran.get());
        assert_eq!(
            counted(&recorder),
            [(PANICS.to_owned(), "udp://127.0.0.1:53".to_owned(), 1)]
        );
    }

    #[test]
    fn a_step_that_panics_gives_none_and_is_counted() {
        let recorder = DebuggingRecorder::new();
        let (bad, late, good) = metrics::with_local_recorder(&recorder, || {
            compio::runtime::Runtime::new()
                .expect("a runtime")
                .block_on(async {
                    let listener = listener();
                    (
                        listener.guard(PEER, || panic_any::<&str>("a bug")),
                        listener
                            .guard_async(PEER, async {
                                compio::time::sleep(Duration::from_millis(1)).await;
                                panic_any::<&str>("a bug")
                            })
                            .await,
                        listener.guard(PEER, || 7),
                    )
                })
        });
        assert_eq!((bad, late, good), (None::<()>, None::<()>, Some(7)));
        assert_eq!(
            counted(&recorder),
            [(PANICS.to_owned(), "udp://127.0.0.1:53".to_owned(), 2)]
        );
    }

    /// A loop that panics, then returns, then serves: started three times, the panic and two restarts counted.
    #[test]
    fn a_listener_that_panics_or_ends_is_started_again() {
        let recorder = DebuggingRecorder::new();
        let started = Rc::new(Cell::new(0));
        metrics::with_local_recorder(&recorder, || {
            compio::runtime::Runtime::new()
                .expect("a runtime")
                .block_on(async {
                    let (serving, wait) = flume::bounded(1);
                    let turns = Rc::clone(&started);
                    let name = listener();
                    let supervising = supervise(&name, MS, || {
                        turns.set(turns.get() + 1);
                        let turn = turns.get();
                        let serving = serving.clone();
                        async move {
                            match turn {
                                1 => panic_any("a bug"),
                                2 => {}
                                _ => {
                                    let _ = serving.send(());
                                    std::future::pending::<()>().await;
                                }
                            }
                        }
                    });
                    let wait = pin!(wait.recv_async());
                    select(pin!(supervising), wait).await;
                });
        });
        assert_eq!(started.get(), 3);
        assert_eq!(
            counted(&recorder),
            [
                (RESTARTS.to_owned(), "udp://127.0.0.1:53".to_owned(), 2),
                (PANICS.to_owned(), "udp://127.0.0.1:53".to_owned(), 1),
            ]
        );
    }
}
