//! TLS-style reading and writing (RFC 8446 §3): big-endian integers and byte strings behind a two-byte length.

use crate::error::WireError;

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

/// A byte string of a `<min..2^16-1>` field. Its length fits the two-byte prefix, checked when it is built, so
/// writing cannot fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    len: u16,
    bytes: Vec<u8>,
}

impl Field {
    /// The field `name` of `bytes`, which are at least `min` and at most 65535.
    pub(crate) fn new(name: &'static str, bytes: Vec<u8>, min: usize) -> Result<Self, WireError> {
        if bytes.len() < min {
            return Err(WireError::EmptyField(name));
        }
        let len = u16::try_from(bytes.len()).map_err(|_| WireError::FieldTooLong(name))?;
        Ok(Self { len, bytes })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Writes the length prefix, then the bytes.
    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.len.to_be_bytes());
        out.extend_from_slice(&self.bytes);
    }
}
