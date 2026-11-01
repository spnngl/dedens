//! The work one validation may do (`KeyTrap`, CVE-2023-50387; RFC 9276 §3.2).

use dedens_proto::Name;
use thiserror::Error;

use super::digest::nsec3_sha1;

/// Octets of message one SHA-1 block compresses (FIPS 180-4 §5.1.1).
const BLOCK_LEN: usize = 64;

/// Octets SHA-1 pads a message with: one `0x80` and the 64-bit length (FIPS 180-4 §5.1.1).
const PADDING_LEN: usize = 9;

/// The length of a SHA-1 hash, the input of every iteration but the first (RFC 5155 §5).
const HASH_LEN: usize = 20;

/// The SHA-1 blocks compressed to hash a message of `len` octets, padding included.
fn blocks(len: usize) -> u32 {
    u32::try_from((len + PADDING_LEN).div_ceil(BLOCK_LEN)).unwrap_or(u32::MAX)
}

/// A number of signature verifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Verifications(pub u32);

/// A number of SHA-1 blocks computed for NSEC3 hashes (D106): a name's hash is `iterations + 1` SHA-1 computations,
/// each of one or more blocks, as many as the salt and the owner name make it (RFC 5155 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nsec3Blocks(pub u32);

/// Which counter of a [`Budget`] ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BudgetExhausted {
    /// Too many signature verifications.
    #[error("signature verification budget exhausted")]
    Verifications,
    /// Too much NSEC3 hashing.
    #[error("NSEC3 hash budget exhausted")]
    Nsec3Blocks,
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
    nsec3_blocks: Nsec3Blocks,
}

impl Budget {
    /// Signature verifications one validation may do: D71, sized from `docs/benchmarks.md`.
    pub const DEFAULT_VERIFICATIONS: Verifications = Verifications(64);

    /// SHA-1 blocks of NSEC3 hashing one validation may compute: D71, counted in blocks by D106, sized from
    /// `docs/benchmarks.md`: a hash of a short name with no salt is one block per iteration.
    pub const DEFAULT_NSEC3_BLOCKS: Nsec3Blocks = Nsec3Blocks(8192);

    /// A budget of `verifications` signature checks and `nsec3_blocks` SHA-1 blocks.
    #[must_use]
    pub const fn new(verifications: Verifications, nsec3_blocks: Nsec3Blocks) -> Self {
        Self {
            verifications,
            nsec3_blocks,
        }
    }

    /// The signature verifications left.
    #[must_use]
    pub const fn verifications_left(&self) -> Verifications {
        self.verifications
    }

    /// The SHA-1 blocks of NSEC3 hashing left.
    #[must_use]
    pub const fn nsec3_blocks_left(&self) -> Nsec3Blocks {
        self.nsec3_blocks
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

    /// The NSEC3 hash of `owner` (RFC 5155 §5, SHA-1: [`nsec3_hash`](super::nsec3_hash()) with that algorithm),
    /// paid for first, the only way to hash with a budget.
    ///
    /// It spends the SHA-1 blocks the hash compresses: the first computation hashes the owner name in wire form
    /// and the salt, each of the `iterations` after it the previous hash and the salt. A salt of 255 octets
    /// therefore makes each of 150 iterations 5 blocks, not 1.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted::Nsec3Blocks`] when fewer are left, with nothing hashed; the counter is then zero.
    pub fn nsec3_hash(
        &mut self,
        salt: &[u8],
        iterations: u16,
        owner: &Name<'_>,
    ) -> Result<[u8; 20], BudgetExhausted> {
        self.spend_nsec3_blocks(salt, iterations, owner)?;
        Ok(nsec3_sha1(salt, iterations, owner))
    }

    fn spend_nsec3_blocks(
        &mut self,
        salt: &[u8],
        iterations: u16,
        owner: &Name<'_>,
    ) -> Result<(), BudgetExhausted> {
        let first = blocks(owner.wire_len() + salt.len());
        let each = blocks(HASH_LEN + salt.len());
        let cost = first.saturating_add(u32::from(iterations).saturating_mul(each));
        if let Some(left) = self.nsec3_blocks.0.checked_sub(cost) {
            self.nsec3_blocks = Nsec3Blocks(left);
            Ok(())
        } else {
            self.nsec3_blocks = Nsec3Blocks(0);
            Err(BudgetExhausted::Nsec3Blocks)
        }
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(Self::DEFAULT_VERIFICATIONS, Self::DEFAULT_NSEC3_BLOCKS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name<'static> {
        text.parse().expect("a name")
    }

    /// What one call spends, from a budget no call exhausts.
    fn spent(salt: &[u8], iterations: u16, owner: &str) -> u32 {
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(u32::MAX));
        budget
            .spend_nsec3_blocks(salt, iterations, &name(owner))
            .expect("enough");
        u32::MAX - budget.nsec3_blocks_left().0
    }

    /// The paid hash is the hash, and a refused one is not computed: the counter is zero and there is no hash.
    #[test]
    fn the_paid_hash_is_the_hash_and_a_refused_one_is_none() {
        use dedens_proto::codes::Nsec3HashAlgorithm;
        let owner = name("a.c.x.w.example.");
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(13));
        assert_eq!(
            budget.nsec3_hash(&salt, 12, &owner),
            Ok(
                super::super::nsec3_hash(Nsec3HashAlgorithm::SHA1, &salt, 12, &owner)
                    .expect("SHA-1")
            )
        );
        assert_eq!(budget.nsec3_blocks_left(), Nsec3Blocks(0));
        assert_eq!(
            budget.nsec3_hash(&salt, 0, &owner),
            Err(BudgetExhausted::Nsec3Blocks)
        );
    }

    #[test]
    fn verifications_run_out() {
        let mut budget = Budget::new(Verifications(2), Nsec3Blocks(0));
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

    /// A short name and no salt is one block a computation: `iterations + 1`, as before D106.
    #[test]
    fn an_nsec3_call_without_salt_costs_its_iterations_plus_one() {
        let owner = name("a.c.x.w.example.");
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(13));
        assert_eq!(budget.spend_nsec3_blocks(&[], 0, &owner), Ok(()));
        assert_eq!(budget.spend_nsec3_blocks(&[], 11, &owner), Ok(()));
        assert_eq!(
            budget.spend_nsec3_blocks(&[], 0, &owner),
            Err(BudgetExhausted::Nsec3Blocks)
        );
    }

    /// RFC 5155 §5: the first computation hashes the owner and the salt, the others a 20-octet hash and the
    /// salt. A block holds 55 octets of message before the padding, so the cost steps at 55 and 56.
    #[test]
    fn the_cost_is_the_sha1_blocks_of_the_owner_the_hash_and_the_salt() {
        // Appendix A's `a.c.x.w.example.` is 17 octets on the wire, its salt 4.
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        assert_eq!(spent(&salt, 12, "a.c.x.w.example."), 13);
        // The longest salt: 17 + 255 and 20 + 255 octets are 5 blocks each.
        assert_eq!(spent(&[0; 255], 0, "a.c.x.w.example."), 5);
        assert_eq!(spent(&[0; 255], 150, "a.c.x.w.example."), 5 + 150 * 5);
        // `example.` is 9 octets: 46 of salt make 55, one block, and 47 make 56, two. Each later computation
        // is 20 octets and the salt: 35 of salt make 55, 36 make 56.
        assert_eq!(spent(&[0; 46], 0, "example."), 1);
        assert_eq!(spent(&[0; 47], 0, "example."), 2);
        assert_eq!(spent(&[0; 35], 1, "example."), 1 + 1);
        assert_eq!(spent(&[0; 36], 1, "example."), 1 + 2);
        // A name of 255 octets alone is 5 blocks, and 9 with the longest salt (510 octets).
        let label = "a".repeat(63);
        let longest = format!("{label}.{label}.{label}.{}.", "a".repeat(61));
        assert_eq!(name(&longest).wire_len(), 255);
        assert_eq!(spent(&[], 0, &longest), 5);
        assert_eq!(spent(&[0; 255], 0, &longest), 9);
    }

    #[test]
    fn the_largest_count_does_not_overflow() {
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(u32::MAX));
        assert_eq!(
            budget.spend_nsec3_blocks(&[], u16::MAX, &name("example.")),
            Ok(())
        );
        assert_eq!(budget.nsec3_blocks_left(), Nsec3Blocks(u32::MAX - 65_536));
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(u32::MAX));
        assert_eq!(
            budget.spend_nsec3_blocks(&[0; 255], u16::MAX, &name("example.")),
            Ok(())
        );
        assert_eq!(
            budget.nsec3_blocks_left(),
            Nsec3Blocks(u32::MAX - 5 * 65_536)
        );
    }

    #[test]
    fn an_exhausted_nsec3_counter_refuses_a_later_cheap_spend() {
        let owner = name("example.");
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(10));
        assert_eq!(
            budget.spend_nsec3_blocks(&[], 20, &owner),
            Err(BudgetExhausted::Nsec3Blocks)
        );
        assert_eq!(
            budget.spend_nsec3_blocks(&[], 0, &owner),
            Err(BudgetExhausted::Nsec3Blocks)
        );
    }

    #[test]
    fn the_counters_are_independent() {
        let mut budget = Budget::new(Verifications(1), Nsec3Blocks(1));
        assert_eq!(
            budget.spend_nsec3_blocks(&[], 5, &name("example.")),
            Err(BudgetExhausted::Nsec3Blocks)
        );
        assert_eq!(budget.spend_verification(), Ok(()));
        assert_eq!(budget.verifications_left(), Verifications(0));
        assert_eq!(budget.nsec3_blocks_left(), Nsec3Blocks(0));
    }
}
