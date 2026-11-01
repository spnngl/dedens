//! The work one validation may do (`KeyTrap`, CVE-2023-50387; RFC 9276 §3.2).

use thiserror::Error;

/// A number of signature verifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Verifications(pub u32);

/// A number of NSEC3 hashes: one SHA-1 computation each, `iterations + 1` per name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nsec3Hashes(pub u32);

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
/// [`nsec3_hash`](super::nsec3_hash()), and stops on [`BudgetExhausted`]. What an exhausted budget means is
/// the caller's verdict, not this type's: for signatures the `KeyTrap` guidance is to fail the validation
/// (bogus, SERVFAIL); for NSEC3 hashes RFC 9276 §3.2 allows treating the response as insecure or answering
/// SERVFAIL. One `Budget` serves a whole validation, its chain of trust included (06).
///
/// An exhausted counter stays at zero: a later, cheaper spend does not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    verifications: Verifications,
    nsec3_hashes: Nsec3Hashes,
}

impl Budget {
    /// Signature verifications one validation may do: D71, sized from `docs/benchmarks.md`.
    pub const DEFAULT_VERIFICATIONS: Verifications = Verifications(64);

    /// NSEC3 hashes one validation may compute: D71, sized from `docs/benchmarks.md`.
    pub const DEFAULT_NSEC3_HASHES: Nsec3Hashes = Nsec3Hashes(8192);

    /// A budget of `verifications` signature checks and `nsec3_hashes` SHA-1 computations.
    #[must_use]
    pub const fn new(verifications: Verifications, nsec3_hashes: Nsec3Hashes) -> Self {
        Self {
            verifications,
            nsec3_hashes,
        }
    }

    /// The signature verifications left.
    #[must_use]
    pub const fn verifications_left(&self) -> Verifications {
        self.verifications
    }

    /// The NSEC3 hashes left.
    #[must_use]
    pub const fn nsec3_hashes_left(&self) -> Nsec3Hashes {
        self.nsec3_hashes
    }

    /// Spends one signature verification.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted::Verifications`] when none is left.
    pub const fn spend_verification(&mut self) -> Result<(), BudgetExhausted> {
        match self.verifications.0.checked_sub(1) {
            Some(left) => {
                self.verifications = Verifications(left);
                Ok(())
            }
            None => Err(BudgetExhausted::Verifications),
        }
    }

    /// Spends the hashes of one [`nsec3_hash`](super::nsec3_hash()) call: `iterations + 1`.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted::Nsec3Hashes`] when fewer are left; the counter is then zero.
    pub fn spend_nsec3_hash(&mut self, iterations: u16) -> Result<(), BudgetExhausted> {
        let cost = u32::from(iterations) + 1;
        if let Some(left) = self.nsec3_hashes.0.checked_sub(cost) {
            self.nsec3_hashes = Nsec3Hashes(left);
            Ok(())
        } else {
            self.nsec3_hashes = Nsec3Hashes(0);
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
        let mut budget = Budget::new(Verifications(2), Nsec3Hashes(0));
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
        let mut budget = Budget::new(Verifications(0), Nsec3Hashes(13));
        assert_eq!(budget.spend_nsec3_hash(0), Ok(()));
        assert_eq!(budget.spend_nsec3_hash(11), Ok(()));
        assert_eq!(
            budget.spend_nsec3_hash(0),
            Err(BudgetExhausted::Nsec3Hashes)
        );
    }

    #[test]
    fn the_largest_count_does_not_overflow() {
        let mut budget = Budget::new(Verifications(0), Nsec3Hashes(u32::MAX));
        assert_eq!(budget.spend_nsec3_hash(u16::MAX), Ok(()));
        assert_eq!(budget.nsec3_hashes_left(), Nsec3Hashes(u32::MAX - 65_536));
    }

    #[test]
    fn an_exhausted_nsec3_counter_refuses_a_later_cheap_spend() {
        let mut budget = Budget::new(Verifications(0), Nsec3Hashes(10));
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
        let mut budget = Budget::new(Verifications(1), Nsec3Hashes(1));
        assert_eq!(
            budget.spend_nsec3_hash(5),
            Err(BudgetExhausted::Nsec3Hashes)
        );
        assert_eq!(budget.spend_verification(), Ok(()));
        assert_eq!(budget.verifications_left(), Verifications(0));
        assert_eq!(budget.nsec3_hashes_left(), Nsec3Hashes(0));
    }
}
