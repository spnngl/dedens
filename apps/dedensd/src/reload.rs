//! Replacing the pipeline, on SIGHUP (D55) or once downloaded lists changed (D57): queries in flight end on the one
//! they started on, and a configuration that does not read leaves the running one in place.

use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;
use std::{io, thread};

use dedens_net::tls::{Presented, Trust};
use dedens_server::Pipeline;

use crate::config::{Downloads, Listen};
use crate::download::Fetcher;
use crate::flights::Flights;

/// The pipeline in use. Serving threads compare [`Current::generation`] with the one they hold before each query,
/// one atomic load, and take the new pipeline under the lock only when it changed.
#[derive(Debug)]
pub(crate) struct Current {
    generation: AtomicU64,
    pipeline: Mutex<Arc<Pipeline>>,
    /// The validator's questions in flight, for all threads and across reloads (D86).
    flights: Flights,
}

impl Current {
    pub(crate) fn new(pipeline: Pipeline) -> Self {
        Self {
            generation: AtomicU64::new(0),
            pipeline: Mutex::new(Arc::new(pipeline)),
            flights: Flights::default(),
        }
    }

    pub(crate) const fn flights(&self) -> &Flights {
        &self.flights
    }

    /// Bumped by each [`Current::replace`], after the pipeline is.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The pipeline in use: of [`Current::generation`] or a later one.
    pub(crate) fn get(&self) -> Arc<Pipeline> {
        Arc::clone(&self.pipeline.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn replace(&self, pipeline: Pipeline) {
        *self.pipeline.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(pipeline);
        self.generation.fetch_add(1, Ordering::Release);
    }
}

/// What a reload cannot change: the sockets are bound and the threads started.
#[derive(Debug)]
pub(crate) struct Fixed {
    pub(crate) listen: Vec<Listen>,
    /// What upstream servers are checked against: each thread's client holds it.
    pub(crate) trust: Trust,
    /// The certificate presented over TLS and QUIC, which a reload replaces (D66).
    pub(crate) presented: Option<Arc<Presented>>,
    /// The Oblivious `DoH` target's settings: its key is read at start (D79).
    #[cfg(feature = "odoh")]
    pub(crate) odoh: Option<crate::odoh::Section>,
}

/// The first wait after a failed download; each failure in a row doubles it, up to the refresh interval.
const RETRY: Duration = Duration::from_secs(60);

/// Starts the thread that replaces the pipeline: on each SIGHUP, reading `file` again (D55), and once the lists of
/// `downloads` changed, fetched at once, after each SIGHUP, then every refresh interval (D57), building `text`, the
/// configuration last loaded, again without reading `file`. One thread for both, so a refresh never replaces the
/// pipeline of a reload with an older one. A panic while fetching or reloading is logged and counts as a failure;
/// the thread goes on. The SIGHUP handler is installed before this returns: a SIGHUP once the server logged that
/// it serves never ends the process.
///
/// # Errors
///
/// A handler the OS refuses.
pub(crate) fn control(
    file: PathBuf,
    mut text: String,
    current: Arc<Current>,
    fixed: Fixed,
    mut downloads: Downloads,
) -> io::Result<()> {
    let (hangup, hangups) = mpsc::channel::<()>();
    #[cfg(unix)]
    {
        let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])?;
        let hangup = hangup.clone();
        thread::spawn(move || {
            for _ in signals.forever() {
                let _ = hangup.send(());
            }
        });
    }
    thread::spawn(move || {
        // Held here, so `hangups` is never disconnected, SIGHUP or not.
        let _hangup = hangup;
        let client = Fetcher::new();
        let mut retry = RETRY;
        loop {
            let wait = if downloads.urls.is_empty() {
                Duration::MAX
            } else {
                let fetched = guarded("list download", || {
                    client.fetch(&downloads.urls, &downloads.dir)
                });
                if fetched.is_some_and(|fetched| fetched.changed)
                    && let Some(new) = reload(&file, Read::Last, &mut text, &current, &fixed)
                {
                    downloads = new;
                }
                if fetched.is_none_or(|fetched| fetched.failed) {
                    let next = retry.min(downloads.refresh);
                    retry = retry.saturating_mul(2);
                    next
                } else {
                    retry = RETRY;
                    downloads.refresh
                }
            };
            // A SIGHUP reloads, then fetches again at once: its lists may have changed with it.
            if hangups.recv_timeout(wait).is_ok()
                && let Some(new) = reload(&file, Read::File, &mut text, &current, &fixed)
            {
                downloads = new;
            }
        }
    });
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
) -> Option<Downloads> {
    let config = file.display();
    let built = guarded("reload", || {
        let new_text = match read {
            Read::File => crate::read(file)?,
            Read::Last => text.clone(),
        };
        let new = crate::build(file, &new_text, &current.get())?;
        *text = new_text;
        anyhow::Ok(new)
    })
    .unwrap_or_else(|| Err(anyhow::anyhow!("the reload panicked")));
    match built {
        Ok(new) => {
            if new.listen != fixed.listen {
                tracing::warn!(%config, "changes to `listen` take a restart");
            }
            if new.trust != fixed.trust {
                tracing::warn!(%config, "changes to `upstream_ca` take a restart");
            }
            #[cfg(feature = "odoh")]
            if new.odoh != fixed.odoh {
                tracing::warn!(%config, "changes to `odoh` take a restart");
            }
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
    use super::guarded;

    /// D64: a panic in a reload or a download is logged, and the reload thread goes on.
    #[test]
    fn a_panic_is_contained() {
        assert_eq!(guarded("work", || 7), Some(7));
        assert_eq!(guarded("work", || -> u8 { panic!("a bug") }), None);
    }
}
