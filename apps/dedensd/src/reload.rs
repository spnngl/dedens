//! Reloading the configuration file on SIGHUP (D55): the pipeline is replaced, queries in flight end on the one
//! they started on, and a configuration that does not read leaves the running one in place.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use dedens_server::Pipeline;

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

/// Reloads `file` into `current` on each SIGHUP, from a thread of its own. The handler is installed before this
/// returns: a SIGHUP once the server logged that it serves never ends the process.
///
/// # Errors
///
/// A handler the OS refuses.
#[cfg(unix)]
pub(crate) fn on_hangup(file: PathBuf, current: Arc<Current>, fixed: Fixed) -> std::io::Result<()> {
    let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])?;
    std::thread::spawn(move || {
        for _ in signals.forever() {
            reload(&file, &current, &fixed);
        }
    });
    Ok(())
}

/// Reads `file` again and serves its pipeline, keeping the cache when its settings are unchanged.
fn reload(file: &std::path::Path, current: &Current, fixed: &Fixed) {
    let config = file.display();
    match crate::load(file, &current.get()) {
        Ok(new) => {
            if new.listen != fixed.listen || new.zero_buffers != fixed.zero_buffers {
                tracing::warn!(%config, "changes to `listen` and `zero_buffers` take a restart");
            }
            current.replace(new.pipeline);
            metrics::counter!(RELOADS, "result" => "ok").increment(1);
            tracing::info!(%config, "reloaded");
        }
        Err(error) => {
            metrics::counter!(RELOADS, "result" => "error").increment(1);
            tracing::error!(%config, error = format!("{error:#}"), "reload failed, serving the previous configuration");
        }
    }
}

/// Reloads by result, `ok` or `error`.
const RELOADS: &str = "dedensd_reloads_total";
