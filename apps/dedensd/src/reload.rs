//! Replacing the pipeline, on SIGHUP (D55) or once downloaded lists changed (D57): queries in flight end on the one
//! they started on, and a configuration that does not read leaves the running one in place.

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use std::{io, thread};

use dedens_net::tls::{Presented, Trust};
use dedens_server::Pipeline;

use crate::config::{Downloads, Listen};
use crate::download::{Fetched, Fetcher, sweep};
use crate::flights::Flights;
use crate::lists::Store;
use crate::privileges::Identity;
use crate::sync::{self, AtomicU64, Mutex, Ordering, PoisonError};

/// The pipeline in use. Serving threads ask [`Current::newer`] before each query: one atomic load, and the new
/// pipeline under the lock only when the generation changed; a reload wakes them too, so that
/// an idle thread takes it without a query (D107).
#[derive(Debug)]
pub(crate) struct Current {
    generation: AtomicU64,
    pipeline: Mutex<sync::Arc<Pipeline>>,
    /// The wake-up of each serving thread, sent by [`Current::replace`]; see [`Current::follow`].
    followers: Mutex<Vec<sync::Sender<()>>>,
    /// The validator's questions in flight, for all threads and across reloads (D86).
    flights: Flights,
}

impl Current {
    pub(crate) fn new(pipeline: Pipeline) -> Self {
        Self {
            generation: AtomicU64::new(0),
            pipeline: Mutex::new(sync::Arc::new(pipeline)),
            followers: Mutex::default(),
            flights: Flights::default(),
        }
    }

    pub(crate) const fn flights(&self) -> &Flights {
        &self.flights
    }

    /// Bumped by each [`Current::replace`], after the pipeline is.
    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// What a thread holding generation `held` takes before a query: `None` while a reload has not replaced the
    /// pipeline since, else the generation read, with the pipeline of that generation or a later one.
    pub(crate) fn newer(&self, held: u64) -> Option<(u64, sync::Arc<Pipeline>)> {
        let generation = self.generation();
        (generation != held).then(|| (generation, self.get()))
    }

    /// The pipeline in use: of [`Current::generation`] or a later one.
    pub(crate) fn get(&self) -> sync::Arc<Pipeline> {
        sync::Arc::clone(&self.pipeline.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// What a serving thread starts from: a channel with a message once [`Current::replace`] ran since the last one
    /// taken from it, so that a thread no query reaches still takes the new pipeline and lets go of the old one
    /// (D107), with the generation and the pipeline in use. In that order, so that a replacement is never missed: one
    /// after the subscription is heard, one before it is in the pipeline, and a generation read before the pipeline
    /// can only be older than it.
    pub(crate) fn follow(&self) -> (sync::Receiver<()>, u64, sync::Arc<Pipeline>) {
        let (follower, wake) = sync::slot();
        self.followers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(follower);
        (wake, self.generation(), self.get())
    }

    pub(crate) fn replace(&self, pipeline: Pipeline) {
        *self.pipeline.lock().unwrap_or_else(PoisonError::into_inner) = sync::Arc::new(pipeline);
        self.generation.fetch_add(1, Ordering::Release);
        // A full channel holds a wake-up not yet taken, which says as much; one whose thread is gone is dropped.
        self.followers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|follower| {
                !matches!(
                    follower.try_send(()),
                    Err(sync::TrySendError::Disconnected(()))
                )
            });
    }
}

/// What a reload cannot change: the sockets are bound and the threads started.
#[derive(Debug)]
pub(crate) struct Fixed {
    pub(crate) listen: Vec<Listen>,
    pub(crate) threads: usize,
    /// Who the process dropped to (D122): a reload cannot go back to root to become another user.
    pub(crate) user: Option<Identity>,
    /// What upstream servers are checked against: each thread's client holds it.
    pub(crate) trust: Trust,
    /// The certificate presented over TLS and QUIC, which a reload replaces (D66).
    pub(crate) presented: Option<Arc<Presented>>,
    /// The Oblivious `DoH` target's settings: its key is read at start (D79).
    #[cfg(feature = "odoh")]
    pub(crate) odoh: Option<crate::odoh::Section>,
}

/// The first wait after a failed download or reload; each failure in a row doubles it, up to the refresh interval.
const RETRY: Duration = Duration::from_secs(60);

/// What the thread keeps from one fetch to the next (D104).
#[derive(Debug)]
struct Ticks {
    /// The wait after the next failure.
    retry: Duration,
    /// A downloaded list changed and no reload served it yet. The list and its `ETag` are saved before the reload,
    /// so the next fetch finds it unchanged (304): only this remembers that the pipeline is behind the lists.
    pending: bool,
}

impl Ticks {
    const fn new() -> Self {
        Self {
            retry: RETRY,
            pending: false,
        }
    }

    /// A reload built from the lists on disk served, a SIGHUP's included: nothing is pending, and a failure waits
    /// the first time again.
    const fn served(&mut self) {
        self.pending = false;
        self.retry = RETRY;
    }

    /// How long to wait after a fetch that found `fetched`, `refresh` being the interval of the downloads in use.
    /// `reload` builds the pipeline again from the lists on disk, returning the interval of the downloads it built,
    /// `None` when it failed: it runs when a list changed, and again after each fetch until it succeeds.
    fn wait(
        &mut self,
        fetched: Fetched,
        mut refresh: Duration,
        reload: impl FnOnce() -> Option<Duration>,
    ) -> Duration {
        self.pending |= fetched.changed;
        if self.pending
            && let Some(new) = reload()
        {
            self.pending = false;
            refresh = new;
        }
        if fetched.failed || self.pending {
            let wait = self.retry.min(refresh);
            self.retry = self.retry.saturating_mul(2);
            wait
        } else {
            self.retry = RETRY;
            refresh
        }
    }
}

/// Starts the thread that replaces the pipeline: on each SIGHUP, reading `file` again (D55), and once the lists of
/// `downloads` changed, fetched at once, after each SIGHUP, then every refresh interval (D57), building `text`, the
/// configuration last loaded, again without reading `file`. One thread for both, so a refresh never replaces the
/// pipeline of a reload with an older one. A panic while fetching or reloading is logged and counts as a failure;
/// the thread goes on, and a reload that failed after the lists changed is tried again on the next tick (D104). The
/// SIGHUP handler is installed before this returns: a SIGHUP once the server logged that it serves never ends the
/// process.
///
/// # Errors
///
/// A handler the OS refuses, or a thread it does not start.
pub(crate) fn control(
    file: PathBuf,
    mut text: String,
    current: Arc<Current>,
    fixed: Fixed,
    mut downloads: Downloads,
    mut store: Store,
) -> io::Result<()> {
    let (hangup, hangups) = mpsc::channel::<()>();
    #[cfg(unix)]
    {
        let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])?;
        let hangup = hangup.clone();
        thread::Builder::new()
            .name("dedensd-hangups".to_owned())
            .spawn(move || {
                for _ in signals.forever() {
                    let _ = hangup.send(());
                }
            })?;
    }
    thread::Builder::new()
        .name("dedensd-reload".to_owned())
        .spawn(move || {
            // Held here, so `hangups` is never disconnected, SIGHUP or not.
            let _hangup = hangup;
            let client = Fetcher::new();
            guarded("leftover sweep", || sweep(&downloads.urls, &downloads.dir));
            let mut ticks = Ticks::new();
            loop {
                let wait = if downloads.urls.is_empty() {
                    Duration::MAX
                } else {
                    let fetched = guarded("list download", || {
                        client.fetch(&downloads.urls, &downloads.dir, &mut store)
                    })
                    // A panic may have come after a list was saved: reload, which costs little when nothing changed.
                    .unwrap_or(Fetched {
                        changed: true,
                        failed: true,
                    });
                    ticks.wait(fetched, downloads.refresh, || {
                        let new =
                            reload(&file, Read::Last, &mut text, &current, &fixed, &mut store)?;
                        let refresh = new.refresh;
                        downloads = new;
                        Some(refresh)
                    })
                };
                // A SIGHUP reloads, then fetches again at once: its lists may have changed with it.
                if hangups.recv_timeout(wait).is_ok() {
                    // Those queued meanwhile ask for what this one does (D104).
                    while hangups.try_recv().is_ok() {}
                    if let Some(new) =
                        reload(&file, Read::File, &mut text, &current, &fixed, &mut store)
                    {
                        downloads = new;
                        // Built from the lists on disk, the pending reload included.
                        ticks.served();
                    }
                }
            }
        })?;
    Ok(())
}

/// Which configuration a reload builds.
#[derive(Debug, Clone, Copy)]
enum Read {
    /// The file, read again: a SIGHUP.
    File,
    /// The text last loaded, the file untouched: downloaded lists changed, and the file may be half edited.
    Last,
}

/// Runs `work`; `None`, logged, when it panics, so the thread replacing the pipeline outlives a bug.
fn guarded<T>(what: &str, work: impl FnOnce() -> T) -> Option<T> {
    panic::catch_unwind(AssertUnwindSafe(work))
        .inspect_err(|_| tracing::error!(what, "panicked, trying again later"))
        .ok()
}

/// Builds the configuration `read` says, `text` the one last loaded, and serves its pipeline, keeping the cache
/// when its settings are unchanged; the new downloads, `None` when it fails.
fn reload(
    file: &Path,
    read: Read,
    text: &mut String,
    current: &Current,
    fixed: &Fixed,
    store: &mut Store,
) -> Option<Downloads> {
    let config = file.display();
    let built = guarded("reload", || {
        let new_text = match read {
            Read::File => crate::read(file)?,
            Read::Last => text.clone(),
        };
        let new = crate::build(file, &new_text, &current.get(), store)?;
        *text = new_text;
        anyhow::Ok(new)
    })
    .unwrap_or_else(|| Err(anyhow::anyhow!("the reload panicked")));
    match built {
        Ok(new) => {
            if new.listen != fixed.listen {
                tracing::warn!(%config, "changes to `listen` take a restart");
            }
            if new.threads != fixed.threads {
                tracing::warn!(%config, "changes to `threads` take a restart");
            }
            if new.user != fixed.user {
                tracing::warn!(%config, "changes to `user` and `group` take a restart");
            }
            if new.trust != fixed.trust {
                tracing::warn!(%config, "changes to `upstream_ca` take a restart");
            }
            #[cfg(feature = "odoh")]
            if new.odoh != fixed.odoh {
                tracing::warn!(%config, "changes to `odoh` take a restart");
            }
            new.warn_access(&fixed.listen);
            if let (Some(presented), Some(new)) = (&fixed.presented, new.presented) {
                presented.replace(new);
            }
            current.replace(new.pipeline);
            metrics::counter!(RELOADS, "result" => "ok").increment(1);
            tracing::info!(%config, "reloaded");
            Some(new.downloads)
        }
        Err(error) => {
            metrics::counter!(RELOADS, "result" => "error").increment(1);
            tracing::error!(%config, error = format!("{error:#}"), "reload failed, serving the previous configuration");
            None
        }
    }
}

/// Reloads by result, `ok` or `error`.
const RELOADS: &str = "dedensd_reloads_total";

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{RETRY, Ticks, guarded};
    use crate::download::Fetched;

    /// D64: a panic in a reload or a download is logged, and the reload thread goes on.
    #[test]
    fn a_panic_is_contained() {
        assert_eq!(guarded("work", || 7), Some(7));
        assert_eq!(guarded("work", || -> u8 { panic!("a bug") }), None);
    }

    /// S15.a: a reload that failed after the list was saved is tried again, though the next fetch finds the list
    /// unchanged.
    #[test]
    fn a_failed_reload_is_retried_on_the_next_tick() {
        let refresh = Duration::from_hours(24);
        let mut ticks = Ticks::new();
        let changed = Fetched {
            changed: true,
            failed: false,
        };
        assert_eq!(ticks.wait(changed, refresh, || None), RETRY);
        // Still failing: the wait doubles, as after a failed download.
        assert_eq!(ticks.wait(Fetched::default(), refresh, || None), RETRY * 2);
        // The fetch finds the list unchanged (304), the reload serves it.
        let mut reloads = 0;
        let wait = ticks.wait(Fetched::default(), refresh, || {
            reloads += 1;
            Some(refresh)
        });
        assert_eq!((reloads, wait), (1, refresh));
        // Nothing is pending any more: no reload, and the next failure waits the first time again.
        let wait = ticks.wait(Fetched::default(), refresh, || panic!("reloaded"));
        assert_eq!(wait, refresh);
        let failed = Fetched {
            changed: false,
            failed: true,
        };
        assert_eq!(ticks.wait(failed, refresh, || panic!("reloaded")), RETRY);
    }

    /// A SIGHUP's reload serves the lists on disk: nothing stays pending and the backoff starts again.
    #[test]
    fn a_served_reload_clears_the_backoff() {
        let refresh = Duration::from_hours(24);
        let mut ticks = Ticks::new();
        let changed = Fetched {
            changed: true,
            failed: false,
        };
        ticks.wait(changed, refresh, || None);
        ticks.wait(Fetched::default(), refresh, || None);
        ticks.served();
        assert_eq!(ticks.wait(changed, refresh, || None), RETRY);
    }

    /// The interval of the downloads a reload built is the next wait.
    #[test]
    fn a_reload_gives_the_new_refresh_interval() {
        let mut ticks = Ticks::new();
        let changed = Fetched {
            changed: true,
            failed: false,
        };
        let new = Duration::from_hours(1);
        let wait = ticks.wait(changed, Duration::from_hours(24), || Some(new));
        assert_eq!(wait, new);
    }
}

/// Every interleaving of a reload with the threads that follow it (D135, `just loom`): a serving thread ends up
/// holding the last pipeline, however the generation it reads, the pipeline it takes and the wake-up it hears fall
/// among the steps of [`Current::replace`].
#[cfg(test)]
#[cfg(dedens_loom)]
mod loom_tests {
    use loom::future::block_on;
    use loom::thread;

    use super::*;
    use crate::sync::{Arc, model};

    /// What a serving thread holds: `Thread` in `serve/mod.rs`.
    struct Serving {
        current: Arc<Current>,
        wake: sync::Receiver<()>,
        generation: u64,
        pipeline: sync::Arc<Pipeline>,
    }

    impl Serving {
        fn new(current: &Arc<Current>) -> Self {
            let (wake, generation, pipeline) = current.follow();
            Self {
                current: Arc::clone(current),
                wake,
                generation,
                pipeline,
            }
        }

        /// What a query does first, as `Thread::pipeline` in `serve/mod.rs`: takes the pipeline of a newer generation.
        fn query(&mut self) {
            if let Some((generation, pipeline)) = self.current.newer(self.generation) {
                (self.generation, self.pipeline) = (generation, pipeline);
            }
        }

        /// The `follow` task of `serve/mod.rs`, which ends here once the thread holds generation `last`: no query comes, a
        /// wake-up is the only way to the new pipeline. A wake-up that never comes is a deadlock loom reports.
        fn follow(&mut self, last: u64) {
            while self.generation < last {
                block_on(self.wake.recv_async()).expect("`current` keeps the sender");
                self.query();
            }
        }

        fn holds_the_last(&self) -> bool {
            sync::Arc::ptr_eq(&self.pipeline, &self.current.get())
        }
    }

    /// A thread replacing the pipeline `times` times.
    fn reload(current: &Arc<Current>, times: usize) -> thread::JoinHandle<()> {
        let current = Arc::clone(current);
        thread::spawn(move || {
            for _ in 0..times {
                current.replace(Pipeline::default());
            }
        })
    }

    /// A follower that starts while the pipeline is replaced reads a generation and a pipeline that fit: a query
    /// then takes the last one, whichever read the replacement fell between.
    #[test]
    fn a_query_finds_the_last_pipeline_after_a_follow_racing_a_replace() {
        model(|| {
            let current = Arc::new(Current::new(Pipeline::default()));
            let reloading = reload(&current, 1);
            let mut serving = Serving::new(&current);
            reloading.join().expect("no panic");
            serving.query();
            assert!(serving.holds_the_last());
        });
    }

    /// A thread no query reaches holds the last pipeline once woken: the wake-up is there when the replacement came
    /// after the subscription, and the generation read says so when it came before.
    #[test]
    fn an_idle_follower_takes_the_pipeline_by_its_wake_up() {
        model(|| {
            let current = Arc::new(Current::new(Pipeline::default()));
            let reloading = reload(&current, 1);
            let mut serving = Serving::new(&current);
            serving.follow(1);
            reloading.join().expect("no panic");
            assert!(serving.holds_the_last());
        });
    }

    /// Two replacements one after the other: the wake-ups may be one, as a full slot holds the second's, and the
    /// follower still ends on the last pipeline.
    #[test]
    fn an_idle_follower_ends_on_the_last_of_two_replaces() {
        model(|| {
            let current = Arc::new(Current::new(Pipeline::default()));
            let reloading = reload(&current, 2);
            let mut serving = Serving::new(&current);
            serving.follow(2);
            reloading.join().expect("no panic");
            assert!(serving.holds_the_last());
        });
    }

    /// A follower that goes while a replacement runs, with its old pipeline: the replacement does not fail, the
    /// follower that stays hears it, and the next replacement forgets the one that went.
    #[test]
    fn a_dropped_follower_does_not_cost_the_others_their_wake_up() {
        model(|| {
            let current = Arc::new(Current::new(Pipeline::default()));
            let reloading = reload(&current, 1);
            let leaving = {
                let current = Arc::clone(&current);
                thread::spawn(move || drop(Serving::new(&current)))
            };
            let mut staying = Serving::new(&current);
            staying.follow(1);
            reloading.join().expect("no panic");
            leaving.join().expect("no panic");
            assert!(staying.holds_the_last());
            current.replace(Pipeline::default());
            let followers = current
                .followers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            assert_eq!(followers.len(), 1, "the follower that went is forgotten");
        });
    }
}
