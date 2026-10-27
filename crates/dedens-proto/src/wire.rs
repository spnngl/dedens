//! Byte cursors: [`Reader`] decodes, [`Writer`] encodes, neither allocates.

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};

/// Largest DNS message: the 16-bit length prefix of TCP (RFC 1035 §4.2.2) bounds it.
pub const MAX_MESSAGE_LEN: usize = 65535;

/// A bounds-checked cursor over a message.
///
/// A reader made by [`Reader::sub`] is limited to a field (RDATA) but still sees the whole message, so a
/// compression pointer inside the field can point before it (RFC 1035 §4.1.4).
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `msg`.
    #[must_use]
    pub const fn new(msg: &'a [u8]) -> Self {
        Self {
            msg,
            pos: 0,
            end: msg.len(),
        }
    }

    /// The whole message, for following compression pointers.
    #[must_use]
    pub const fn message(&self) -> &'a [u8] {
        self.msg
    }

    /// Offset of the next byte to read.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Offset one past the last byte this reader may read.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.end
    }

    /// Bytes left in this reader.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.end - self.pos
    }

    /// Whether every byte was read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos == self.end
    }

    /// An error of `kind` at the current offset.
    #[must_use]
    pub const fn error(&self, kind: DecodeErrorKind) -> DecodeError {
        DecodeError {
            offset: self.pos,
            kind,
        }
    }

    /// Moves to `pos`, which `Name` decoding has already checked to be inside the message.
    pub(crate) const fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Reads `n` bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than `n` bytes are left.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).filter(|&end| end <= self.end);
        let slice = end.and_then(|end| self.msg.get(self.pos..end));
        let Some(slice) = slice else {
            return Err(self.error(DecodeErrorKind::UnexpectedEnd));
        };
        self.pos += n;
        Ok(slice)
    }

    /// Reads `N` bytes as an array.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than `N` bytes are left.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] at the end of the reader.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than 2 bytes are left.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than 4 bytes are left.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads everything left.
    pub fn rest(&mut self) -> &'a [u8] {
        let slice = self.msg.get(self.pos..self.end).unwrap_or_default();
        self.pos = self.end;
        slice
    }

    /// Splits off the next `len` bytes as a reader limited to them, and moves past them.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than `len` bytes are left.
    pub fn sub(&mut self, len: usize) -> Result<Self, DecodeError> {
        let start = self.pos;
        self.bytes(len)?;
        Ok(Self {
            msg: self.msg,
            pos: start,
            end: self.pos,
        })
    }
}

/// A cursor writing into a caller-provided buffer, at most [`MAX_MESSAGE_LEN`] bytes of it.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    /// A writer at the start of `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let cap = buf.len().min(MAX_MESSAGE_LEN);
        let (buf, _) = buf.split_at_mut(cap);
        Self { buf, len: 0 }
    }

    /// Bytes written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing was written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes still available.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.len
    }

    /// What was written.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }

    /// Appends `bytes`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when they do not fit; nothing is written then.
    pub fn put_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self.len + bytes.len();
        let dst = self
            .buf
            .get_mut(self.len..end)
            .ok_or(EncodeError::BufferFull)?;
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    /// Appends `n` zero bytes.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when they do not fit; nothing is written then.
    pub fn put_zeros(&mut self, n: usize) -> Result<(), EncodeError> {
        let end = self.len + n;
        let dst = self
            .buf
            .get_mut(self.len..end)
            .ok_or(EncodeError::BufferFull)?;
        dst.fill(0);
        self.len = end;
        Ok(())
    }

    /// Appends one byte.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn put_u8(&mut self, v: u8) -> Result<(), EncodeError> {
        self.put_bytes(&[v])
    }

    /// Appends a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn put_u16(&mut self, v: u16) -> Result<(), EncodeError> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Appends a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn put_u32(&mut self, v: u32) -> Result<(), EncodeError> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Appends a zeroed `u16` to fill in later with [`Writer::patch_u16`] (a count, an RDLENGTH), and returns its
    /// offset.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn reserve_u16(&mut self) -> Result<usize, EncodeError> {
        let at = self.len;
        self.put_u16(0)?;
        Ok(at)
    }

    /// Overwrites the `u16` at `at`, an offset [`Writer::reserve_u16`] returned.
    pub fn patch_u16(&mut self, at: usize, v: u16) {
        if let Some(dst) = self.buf.get_mut(at..at + 2) {
            dst.copy_from_slice(&v.to_be_bytes());
        } else {
            debug_assert!(false, "patch_u16 outside the written bytes");
        }
    }

    /// Drops everything written after `len`, to roll back a partial record.
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_stops_at_its_end() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16().unwrap(), 0x0102);
        assert_eq!(r.u16().unwrap_err().kind, DecodeErrorKind::UnexpectedEnd);
        assert_eq!(r.u8().unwrap(), 3);
        assert!(r.is_empty());
    }

    #[test]
    fn sub_reader_is_bounded_but_sees_the_message() {
        let mut r = Reader::new(&[1, 2, 3, 4]);
        r.u8().unwrap();
        let mut sub = r.sub(2).unwrap();
        assert_eq!(r.position(), 3);
        assert_eq!(sub.remaining(), 2);
        assert_eq!(sub.message().len(), 4);
        assert_eq!(sub.rest(), &[2, 3]);
    }

    #[test]
    fn writer_never_exceeds_its_buffer() {
        let mut buf = [0; 3];
        let mut w = Writer::new(&mut buf);
        w.put_u16(0xabcd).unwrap();
        assert_eq!(w.put_u16(1), Err(EncodeError::BufferFull));
        assert_eq!(w.written(), &[0xab, 0xcd]);
        let at = w.len();
        w.put_u8(0).unwrap();
        w.truncate(at);
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn patch_fills_a_reserved_u16() {
        let mut buf = [0; 4];
        let mut w = Writer::new(&mut buf);
        let at = w.reserve_u16().unwrap();
        w.put_u16(7).unwrap();
        w.patch_u16(at, 0x0102);
        assert_eq!(w.written(), &[1, 2, 0, 7]);
    }
}
