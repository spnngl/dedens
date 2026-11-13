//! Shared by the tests: keys from counting bytes, and randomness that replays given bytes.

use std::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// `len` bytes counting up from `first`, the pattern of the draft's pinned inputs (`00 01 02 ...`).
pub(crate) fn seq(first: u8, len: u8) -> Vec<u8> {
    (first..first + len).collect()
}

/// `bytes` as an array of `N`.
#[track_caller]
pub(crate) fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("N bytes")
}

/// "Randomness" that replays given bytes, so the resolver nonce and the padding are known.
///
/// A CSPRNG by marker only, for tests: it panics when the bytes run out.
pub(crate) struct Replay {
    bytes: Vec<u8>,
    taken: usize,
}

impl Replay {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            taken: 0,
        }
    }
}

impl TryRng for Replay {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut word = [0; 4];
        self.try_fill_bytes(&mut word)?;
        Ok(u32::from_le_bytes(word))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut word = [0; 8];
        self.try_fill_bytes(&mut word)?;
        Ok(u64::from_le_bytes(word))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self.taken + dst.len();
        dst.copy_from_slice(
            self.bytes
                .get(self.taken..end)
                .expect("the test gave enough bytes"),
        );
        self.taken = end;
        Ok(())
    }
}

impl TryCryptoRng for Replay {}
