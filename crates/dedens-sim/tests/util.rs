//! What the families share: the seeds of `just check` and the timeouts of the stub and of a forward stage.

use std::time::Duration;

/// The seeds of `just check`; `DEDENS_SIM_SEED` and `DEDENS_SIM_RUNS` replace them.
pub(crate) const SEEDS: &[u64] = &[0, 1, 7, 42, 2026];

/// A second of simulated time.
pub(crate) const SECOND: Duration = Duration::from_secs(1);

/// How long the stub waits for a response to each try, and how many tries it makes (D27).
pub(crate) const TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const TRIES: u32 = 3;

/// How long a forward stage waits for a response to each try, and how many tries it makes of one server (D45).
pub(crate) const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const FORWARD_TRIES: u32 = 2;
