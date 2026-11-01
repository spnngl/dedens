//! The work one validation may do (`KeyTrap`, CVE-2023-50387; RFC 9276 §3.2).

use thiserror::Error;

/// Which counter of a [`Budget`] ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BudgetExhausted {
    /// Too many signature verifications.
    #[error("signature verification budget exhausted")]
    Verifications,
    /// Too many NSEC3 hashes.
    #[error("NSEC3 hash budget exhausted")]
    Nsec3Hashes,
}

/// The CPU an attacker can make one validation spend, bounded by counting it before it is done.
///
/// A zone full of colliding key tags and signatures makes a naive validator verify every pair (`KeyTrap`,
/// CVE-2023-50387), and a response full of NSEC3 records at the iteration limit makes it hash for as long
/// (RFC 9276 §3.2). The caller (04, 05) spends before each [`verify`](super::verify()) and
/// [`nsec3_hash`](super::nsec3_hash()), and stops the validation on [`BudgetExhausted`]: the answer is
/// bogus, not retried. One `Budget` serves a whole validation, its chain of trust included (06).
///
/// An exhausted counter stays at zero: a later, cheaper spend does not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    verifications: u32,
    nsec3_hashes: u32,
}

impl Budget {
    /// Signature verifications one validation may do: `DEFAULT_VERIFICATIONS` of D71, sized from
    /// `docs/benchmarks.md`.
    pub const DEFAULT_VERIFICATIONS: u32 = 64;

    /// NSEC3 hashes (one per iteration, plus the first) one validation may compute: D71, sized from
    /// `docs/benchmarks.md`.
    pub const DEFAULT_NSEC3_HASHES: u32 = 8192;

    /// A budget of `verifications` signature checks and `nsec3_hashes` SHA-1 computations.
    #[must_use]
    pub const fn new(verifications: u32, nsec3_hashes: u32) -> Self {
        Self {
            verifications,
            nsec3_hashes,
        }
    }

    /// Spends one signature verification.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted::Verifications`] when none is left.
    pub const fn spend_verification(&mut self) -> Result<(), BudgetExhausted> {
        match self.verifications.checked_sub(1) {
            Some(left) => {
                self.verifications = left;
                Ok(())
            }
            None => Err(BudgetExhausted::Verifications),
        }
    }

    /// Spends the hashes of one [`nsec3_hash`](super::nsec3_hash) call: `iterations + 1`.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted::Nsec3Hashes`] when fewer are left; the counter is then zero.
    pub fn spend_nsec3_hash(&mut self, iterations: u16) -> Result<(), BudgetExhausted> {
        let cost = u32::from(iterations) + 1;
        if let Some(left) = self.nsec3_hashes.checked_sub(cost) {
            self.nsec3_hashes = left;
            Ok(())
        } else {
            self.nsec3_hashes = 0;
            Err(BudgetExhausted::Nsec3Hashes)
        }
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(Self::DEFAULT_VERIFICATIONS, Self::DEFAULT_NSEC3_HASHES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifications_run_out() {
        let mut budget = Budget::new(2, 0);
        assert_eq!(budget.spend_verification(), Ok(()));
        assert_eq!(budget.spend_verification(), Ok(()));
        assert_eq!(
            budget.spend_verification(),
            Err(BudgetExhausted::Verifications)
        );
        assert_eq!(
            budget.spend_verification(),
            Err(BudgetExhausted::Verifications)
        );
    }

    #[test]
    fn an_nsec3_call_costs_its_iterations_plus_one() {
        let mut budget = Budget::new(0, 13);
        assert_eq!(budget.spend_nsec3_hash(0), Ok(()));
        assert_eq!(budget.spend_nsec3_hash(11), Ok(()));
        assert_eq!(
            budget.spend_nsec3_hash(0),
            Err(BudgetExhausted::Nsec3Hashes)
        );
    }

    #[test]
    fn the_largest_count_does_not_overflow() {
        let mut budget = Budget::new(0, u32::MAX);
        assert_eq!(budget.spend_nsec3_hash(u16::MAX), Ok(()));
        assert_eq!(budget.nsec3_hashes, u32::MAX - 65_536);
    }

    #[test]
    fn an_exhausted_nsec3_counter_refuses_a_later_cheap_spend() {
        let mut budget = Budget::new(0, 10);
        assert_eq!(
            budget.spend_nsec3_hash(20),
            Err(BudgetExhausted::Nsec3Hashes)
        );
        assert_eq!(
            budget.spend_nsec3_hash(0),
            Err(BudgetExhausted::Nsec3Hashes)
        );
    }

    #[test]
    fn the_counters_are_independent() {
        let mut budget = Budget::new(1, 1);
        assert_eq!(
            budget.spend_nsec3_hash(5),
            Err(BudgetExhausted::Nsec3Hashes)
        );
        assert_eq!(budget.spend_verification(), Ok(()));
    }
}
