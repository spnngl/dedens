//! TLS-style reading and writing (RFC 8446 §3): big-endian integers and byte strings behind a two-byte length.

use crate::error::WireError;

/// The largest field a two-byte length carries.
pub(crate) const MAX_FIELD: usize = 0xFFFF;

/// A cursor over the bytes of a structure; every read is bounds-checked.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let (head, rest) = self
            .rest
            .split_at_checked(len)
            .ok_or(WireError::Truncated)?;
        self.rest = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| WireError::Truncated)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        self.array().map(u8::from_be_bytes)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        self.array().map(u16::from_be_bytes)
    }

    /// A byte string behind its two-byte length.
    pub(crate) fn vec16(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    /// Ends the structure: nothing may follow it.
    pub(crate) fn finish(self) -> Result<(), WireError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// Checks `bytes` against the bounds `<min..2^16-1>` of the field `name`.
pub(crate) fn check_vec16(name: &'static str, bytes: &[u8], min: usize) -> Result<(), WireError> {
    if bytes.len() < min {
        Err(WireError::EmptyField(name))
    } else if bytes.len() > MAX_FIELD {
        Err(WireError::FieldTooLong(name))
    } else {
        Ok(())
    }
}

/// Writes `bytes` behind their two-byte length.
///
/// The bound is checked when the structure is built ([`check_vec16`]), so writing cannot fail.
pub(crate) fn put_vec16(out: &mut Vec<u8>, bytes: &[u8]) {
    let len =
        u16::try_from(bytes.len()).expect("field length checked when the structure was built");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}
