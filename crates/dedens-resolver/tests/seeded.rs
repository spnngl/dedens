//! `SplitMix64` from a fixed seed, so that a draw replays: the tests' and `examples/capture_minimisation.rs`'
//! (D198), which draws as the tests replay.

use std::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// `SplitMix64` from a fixed seed, so that a draw replays: a CSPRNG by marker only, for tests.
pub(crate) struct Seeded(pub(crate) u64);

impl TryRng for Seeded {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::try_from(self.try_next_u64()? >> 32).unwrap_or_default())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Seeded {}
