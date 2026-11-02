//! Seeds: every random choice of a run follows from one, so a failing run replays.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

/// The variable that replays one seed: `DEDENS_SIM_SEED=7 cargo test -p dedens-sim`.
pub const SEED_VAR: &str = "DEDENS_SIM_SEED";

/// The variable that runs that many random seeds (`just sim`).
pub const RUNS_VAR: &str = "DEDENS_SIM_RUNS";

/// The seed of one run: turmoil's network (latencies, losses, order of hosts) and the IDs of the queries follow
/// from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seed(pub u64);

/// A variable that does not hold what it should.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SeedError {
    /// [`SEED_VAR`] is not a number.
    #[error("{SEED_VAR} is not a 64-bit number: {0:?}")]
    Seed(String),
    /// [`RUNS_VAR`] is not a number.
    #[error("{RUNS_VAR} is not a number: {0:?}")]
    Runs(String),
}

impl Seed {
    /// The seeds a scenario runs under: [`SEED_VAR`] alone, else [`RUNS_VAR`] random ones, else `fixed`, the
    /// seeds of `just check`.
    ///
    /// # Errors
    ///
    /// [`SeedError`] when a variable is set but is not a number.
    pub fn chosen(fixed: &[u64]) -> Result<Vec<Self>, SeedError> {
        Self::choose(
            fixed,
            std::env::var(SEED_VAR).ok().as_deref(),
            std::env::var(RUNS_VAR).ok().as_deref(),
            random,
        )
    }

    fn choose(
        fixed: &[u64],
        seed: Option<&str>,
        runs: Option<&str>,
        mut draw: impl FnMut() -> u64,
    ) -> Result<Vec<Self>, SeedError> {
        if let Some(seed) = seed {
            let seed = seed
                .trim()
                .parse()
                .map_err(|_| SeedError::Seed(seed.to_owned()))?;
            return Ok(vec![Self(seed)]);
        }
        if let Some(runs) = runs {
            let runs: usize = runs
                .trim()
                .parse()
                .map_err(|_| SeedError::Runs(runs.to_owned()))?;
            return Ok((0..runs).map(|_| Self(draw())).collect());
        }
        Ok(fixed.iter().copied().map(Self).collect())
    }
}

fn random() -> u64 {
    getrandom::u64().expect("the operating system has entropy")
}

/// Runs `scenario` once for each of [`Seed::chosen`]. A failure prints `DEDENS_SIM_SEED=<n>`, which replays it,
/// and stops the runs.
///
/// # Panics
///
/// When a variable is no number, and as `scenario` does.
#[expect(
    clippy::print_stderr,
    reason = "the seed of a failure is for whoever replays it; cargo test shows it with the failure"
)]
pub fn each(fixed: &[u64], scenario: impl Fn(Seed)) {
    for seed in Seed::chosen(fixed).expect("the variables hold numbers") {
        if let Err(failure) = catch_unwind(AssertUnwindSafe(|| scenario(seed))) {
            eprintln!("{SEED_VAR}={}", seed.0);
            resume_unwind(failure);
        }
    }
}

/// A generator of numbers from a seed (SplitMix64): the IDs and cookies of the queries of a host, and the times
/// and places of faults. Shared between the runs of a host that crashed and restarted, so its queries go on with
/// new IDs.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// The generator of `stream`, one for each host of a run: another stream, another numbers.
    #[must_use]
    pub fn new(seed: Seed, stream: u64) -> Self {
        Self(seed.0 ^ stream.wrapping_mul(0xD1B5_4A32_D192_ED03))
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number below `bound`, 0 when `bound` is 0. The modulo bias does not matter to a simulation.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64().checked_rem(bound).unwrap_or(0)
    }

    /// The next 16 bits: a query ID.
    pub fn next_u16(&mut self) -> u16 {
        let [high, low, ..] = self.next_u64().to_be_bytes();
        u16::from_be_bytes([high, low])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_replays_alone() {
        let chosen = Seed::choose(&[1, 2], Some(" 9 "), Some("5"), || 0);
        assert_eq!(chosen, Ok(vec![Seed(9)]));
    }

    #[test]
    fn runs_draw_random_seeds() {
        let mut next = 0;
        let chosen = Seed::choose(&[1], None, Some("3"), || {
            next += 1;
            next
        });
        assert_eq!(chosen, Ok(vec![Seed(1), Seed(2), Seed(3)]));
    }

    #[test]
    fn the_fixed_seeds_run_by_default() {
        let chosen = Seed::choose(&[4, 5], None, None, || 0);
        assert_eq!(chosen, Ok(vec![Seed(4), Seed(5)]));
    }

    #[test]
    fn a_variable_that_is_no_number_is_an_error() {
        assert_eq!(
            Seed::choose(&[], Some("x"), None, || 0),
            Err(SeedError::Seed("x".to_owned()))
        );
        assert_eq!(
            Seed::choose(&[], None, Some("-1"), || 0),
            Err(SeedError::Runs("-1".to_owned()))
        );
    }

    #[test]
    fn streams_and_seeds_change_the_numbers() {
        let first = Rng::new(Seed(1), 0).next_u64();
        assert_eq!(first, Rng::new(Seed(1), 0).next_u64());
        assert_ne!(first, Rng::new(Seed(1), 1).next_u64());
        assert_ne!(first, Rng::new(Seed(2), 0).next_u64());
    }

    #[test]
    fn the_generator_is_splitmix64() {
        // The first output of SplitMix64 from state 0.
        let first = 0xE220_A839_7B1D_CDAF_u64;
        assert_eq!(Rng::new(Seed(0), 0).next_u64(), first);
        assert_eq!(Rng::new(Seed(0), 0).next_u16(), 0xE220);
        assert_eq!(Rng::new(Seed(0), 0).below(1000), first % 1000);
    }

    #[test]
    fn below_stays_below() {
        let mut rng = Rng::new(Seed(3), 0);
        assert!((0..100).all(|_| rng.below(7) < 7));
        assert_eq!(rng.below(0), 0);
    }

    #[test]
    fn each_runs_every_seed_and_lets_a_failure_through() {
        let seen = std::cell::RefCell::new(Vec::new());
        each(&[1, 2], |seed| seen.borrow_mut().push(seed));
        // The variables of `just sim` or a replay choose other seeds, but always some.
        assert!(!seen.borrow().is_empty());
        let failed = catch_unwind(|| each(&[3], |_| unreachable!("a failing scenario")));
        assert!(failed.is_err());
    }
}
