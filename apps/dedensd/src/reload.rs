//! Replacing the pipeline, on SIGHUP (D55) or once downloaded lists changed (D57): queries in flight end on the one
//! they started on, and a configuration that does not read leaves the running one in place.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;
use std::{io, thread};

use dedens_server::Pipeline;

use crate::config::Downloads;
use crate::download::Fetcher;

/// The pipeline in use. Serving threads compare [`Current::generation`] with the one they hold before each query,
/// one atomic load, and take the new pipeline under the lock only when it changed.
#[derive(Debug)]
pub(crate) struct Current {
    generation: AtomicU64,
    pipeline: Mutex<Arc<Pipeline>>,
}

impl Current {
    pub(crate) fn new(pipeline: Pipeline) -> Self {
        Self {
            generation: AtomicU64::new(0),
            pipeline: Mutex::new(Arc::new(pipeline)),
        }
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
    pub(crate) listen: Vec<SocketAddr>,
    pub(crate) zero_buffers: bool,
}

/// The first wait after a failed download; each failure in a row doubles it, up to the refresh interval.
const RETRY: Duration = Duration::from_secs(60);

/// Starts the thread that replaces the pipeline: on each SIGHUP, reading `file` again (D55), and once the lists of
/// `downloads` changed, fetched at once then every refresh interval (D57). One thread for both, so a refresh never
/// replaces the pipeline of a reload with an older one. The SIGHUP handler is installed before this returns: a
/// SIGHUP once the server logged that it serves never ends the process.
///
/// # Errors
///
/// A handler the OS refuses.
pub(crate) fn control(
    file: PathBuf,
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
                let fetched = client.fetch(&downloads.urls, &downloads.dir);
                if fetched.changed
                    && let Some(new) = reload(&file, &current, &fixed)
                {
                    downloads = new;
                }
                if fetched.failed {
                    let next = retry.min(downloads.refresh);
                    retry = retry.saturating_mul(2);
                    next
                } else {
                    retry = RETRY;
                    downloads.refresh
                }
            };
            // A SIGHUP reloads, then fetches again: its lists may have changed with it.
            if hangups.recv_timeout(wait).is_ok()
                && let Some(new) = reload(&file, &current, &fixed)
            {
                downloads = new;
            }
        }
    });
    Ok(())
}

/// Reads `file` again and serves its pipeline, keeping the cache when its settings are unchanged; the new
/// downloads, `None` when it fails.
fn reload(file: &Path, current: &Current, fixed: &Fixed) -> Option<Downloads> {
    let config = file.display();
    match crate::load(file, &current.get()) {
        Ok(new) => {
            if new.listen != fixed.listen || new.zero_buffers != fixed.zero_buffers {
                tracing::warn!(%config, "changes to `listen` and `zero_buffers` take a restart");
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
