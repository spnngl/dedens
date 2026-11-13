//! The random bytes of one encryption, drawn before it so that no randomness fails inside it (D79, D98).

use core::convert::Infallible;
use std::io;

use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroizing;

use crate::io::Io;

/// The bytes one encryption draws: for Oblivious `DoH`, the ephemeral key of a query and the nonce of a response, 32 and 16
/// (RFC 9180 §7.1.3, RFC 9230 §6.2); for `DNSCrypt`, a client key, a nonce and a byte of padding, 32, 12 and 1; with
/// room to spare.
pub(crate) const ENTROPY: usize = 64;

/// Random bytes for one encryption (Oblivious `DoH`: `dedens_odoh::encrypt_query` and `encrypt_response`; `DNSCrypt`: a
/// query), drawn when made, so that a failing generator is an error where the exchange starts and not a panic where the encryption
/// draws. One per encryption: a second would reuse the bytes.
///
/// A draw past the bytes, which no encryption makes, gets zeros and is no panic: [`Entropy::finish`] says so, and
/// what was encrypted is then dropped.
pub struct Entropy {
    bytes: Zeroizing<[u8; ENTROPY]>,
    pub(crate) used: usize,
    /// A draw found too few bytes left.
    exhausted: bool,
}

impl Entropy {
    /// Draws the bytes.
    ///
    /// # Errors
    ///
    /// [`getrandom::Error`] when the system has none.
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0; ENTROPY]);
        getrandom::fill(bytes.as_mut_slice())?;
        Ok(Self {
            bytes,
            used: 0,
            exhausted: false,
        })
    }

    /// Draws the bytes from `io`, the seam of randomness that tests replace.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when `io` has none to give.
    pub fn from_io(io: &impl Io) -> io::Result<Self> {
        let mut bytes = Zeroizing::new([0; ENTROPY]);
        io.random(bytes.as_mut_slice())?;
        Ok(Self {
            bytes,
            used: 0,
            exhausted: false,
        })
    }

    /// Whether every draw got random bytes: to be asked once the encryption is done, before its output is used.
    ///
    /// # Errors
    ///
    /// [`getrandom::Error::UNEXPECTED`] when a draw found too few bytes left.
    pub fn finish(self) -> Result<(), getrandom::Error> {
        if self.exhausted {
            Err(getrandom::Error::UNEXPECTED)
        } else {
            Ok(())
        }
    }

    /// Fills `dst` with the next bytes, or with zeros when there are too few.
    fn fill(&mut self, dst: &mut [u8]) {
        let taken = self
            .used
            .checked_add(dst.len())
            .and_then(|end| Some((self.bytes.get(self.used..end)?, end)));
        if let Some((bytes, end)) = taken {
            dst.copy_from_slice(bytes);
            self.used = end;
        } else {
            dst.fill(0);
            self.exhausted = true;
        }
    }
}

impl TryRng for Entropy {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for Entropy {}
