//! Byte cursors: [`Reader`] decodes, [`Writer`] encodes, neither allocates.

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::{MAX_NAME_LEN, Name};

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

    /// A reader of `msg` from `pos` to `end`, offsets a previous pass found inside it.
    pub(crate) const fn range(msg: &'a [u8], pos: usize, end: usize) -> Self {
        Self { msg, pos, end }
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

/// Compression pointers hold 14 bits of offset (RFC 1035 §4.1.4).
const POINTER_LIMIT: usize = 0x4000;

/// Slots of the name table: a power of two.
const TABLE_SLOTS: usize = 256;

/// How many name offsets a [`Writer`] remembers, 3/4 of the slots so probes stay short; a message with more
/// distinct names compresses the later ones less.
const TABLE_CAPACITY: usize = TABLE_SLOTS / 4 * 3;

/// Offsets of the names written so far, to point to them (RFC 1035 §4.1.4).
///
/// An open-addressing hash table of offsets, linear probing, keyed on the first label and the length of a name:
/// fixed capacity, so no allocation (D10), and 512 bytes to clear per message. Names are matched byte for byte
/// against the written message, so each keeps its own case (RFC 4343 §4).
#[derive(Debug)]
struct NameTable {
    /// Offset + 1 of a name; 0 is an empty slot.
    slots: [u16; TABLE_SLOTS],
    len: usize,
}

impl NameTable {
    const fn new() -> Self {
        Self {
            slots: [0; TABLE_SLOTS],
            len: 0,
        }
    }

    /// The first slot to probe for the wire-form name `suffix`.
    fn home(suffix: &[u8]) -> usize {
        let label = suffix
            .split_first()
            .and_then(|(&len, rest)| rest.get(..usize::from(len)))
            .unwrap_or_default();
        // FNV-1a over the first label, then the length.
        let mut hash: u32 = 0x811C_9DC5;
        for &b in label {
            hash = (hash ^ u32::from(b)).wrapping_mul(0x0100_0193);
        }
        hash = (hash ^ u32::try_from(suffix.len()).unwrap_or_default()).wrapping_mul(0x0100_0193);
        usize::try_from(hash >> 24).unwrap_or_default() % TABLE_SLOTS
    }

    /// Slot indexes from the home of `suffix` on, wrapping around.
    fn probe(suffix: &[u8]) -> impl Iterator<Item = usize> {
        let home = Self::home(suffix);
        (home..TABLE_SLOTS).chain(0..home)
    }

    /// Remembers that the name `suffix` starts at `offset`; ignored when it cannot be pointed to or the table is
    /// full.
    fn add(&mut self, offset: usize, suffix: &[u8]) {
        let Ok(stored) = u16::try_from(offset + 1) else {
            return;
        };
        if offset >= POINTER_LIMIT || self.len >= TABLE_CAPACITY {
            return;
        }
        let empty = Self::probe(suffix).find(|&i| self.slots.get(i) == Some(&0));
        if let Some(slot) = empty.and_then(|i| self.slots.get_mut(i)) {
            *slot = stored;
            self.len += 1;
        }
    }

    /// Forgets the names starting at or after `len`.
    ///
    /// They are the last ones added, so no name left behind was probed past their slots: emptying them keeps
    /// every probe sequence whole.
    fn truncate(&mut self, len: usize) {
        for slot in &mut self.slots {
            if usize::from(*slot) > len {
                *slot = 0;
                self.len -= 1;
            }
        }
    }

    /// The offset of an earlier name equal to `suffix` (wire form, root included), if any.
    fn find(&self, written: &[u8], suffix: &[u8]) -> Option<u16> {
        Self::probe(suffix)
            .map_while(|i| self.slots.get(i).and_then(|&s| s.checked_sub(1)))
            .find(|&offset| name_matches(written, usize::from(offset), suffix))
    }
}

/// Whether the name at `offset` in `written`, following its pointers, is the wire-form name `suffix`.
///
/// Pointers in `written` were made by [`Writer::put_name_compressed`] and point backwards; one that does not ends
/// the match, so this always ends.
fn name_matches(written: &[u8], mut offset: usize, mut suffix: &[u8]) -> bool {
    loop {
        let Some(&len) = written.get(offset) else {
            return false;
        };
        match len {
            0 => return suffix == [0],
            l if l & 0xC0 == 0xC0 => {
                let Some(&low) = written.get(offset + 1) else {
                    return false;
                };
                let target = usize::from(l & 0x3F) << 8 | usize::from(low);
                if target >= offset {
                    return false;
                }
                offset = target;
            }
            l => {
                let end = offset + 1 + usize::from(l);
                let Some(label) = written.get(offset..end) else {
                    return false;
                };
                let Some(rest) = suffix.strip_prefix(label) else {
                    return false;
                };
                suffix = rest;
                offset = end;
            }
        }
    }
}

/// A cursor writing into a caller-provided buffer, at most [`MAX_MESSAGE_LEN`] bytes of it.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
    /// Writes stop here, short of `buf.len()` while a tail is held back.
    limit: usize,
    names: NameTable,
    /// Whether [`Writer::put_name_compressed`] compresses; off for RDATA written on its own.
    compress: bool,
}

impl<'a> Writer<'a> {
    /// A writer at the start of `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let cap = buf.len().min(MAX_MESSAGE_LEN);
        let (buf, _) = buf.split_at_mut(cap);
        let limit = buf.len();
        Self {
            buf,
            len: 0,
            limit,
            names: NameTable::new(),
            compress: true,
        }
    }

    /// A writer that never compresses names, for RDATA outside a message (RFC 3597 §5).
    pub(crate) fn uncompressed(buf: &'a mut [u8]) -> Self {
        Self {
            compress: false,
            ..Self::new(buf)
        }
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
        self.limit - self.len
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
            .get_mut(self.len..end.min(self.limit))
            .filter(|dst| dst.len() == bytes.len())
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
            .get_mut(self.len..end.min(self.limit))
            .filter(|dst| dst.len() == n)
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
    pub(crate) fn reserve_u16(&mut self) -> Result<usize, EncodeError> {
        let at = self.len;
        self.put_u16(0)?;
        Ok(at)
    }

    /// The `u16` at `at`, if it is within what was written.
    #[must_use]
    pub(crate) fn u16_at(&self, at: usize) -> Option<u16> {
        let bytes = self.written().get(at..at.checked_add(2)?)?;
        Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
    }

    /// Overwrites the `u16` at `at`, an offset [`Writer::reserve_u16`] returned.
    pub(crate) fn patch_u16(&mut self, at: usize, v: u16) {
        let end = at.saturating_add(2).min(self.len);
        if let Some(dst) = self.buf.get_mut(at..end).filter(|dst| dst.len() == 2) {
            dst.copy_from_slice(&v.to_be_bytes());
        } else {
            debug_assert!(false, "patch_u16 outside the written bytes");
        }
    }

    /// Writes `name`, ending in a pointer to the longest earlier name it ends with, and remembers it for the
    /// names after it (RFC 1035 §4.1.4). Only for names of types RFC 1035 defines (RFC 3597 §4); others are
    /// written with [`Name::encode`].
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit; nothing is written then.
    pub fn put_name_compressed(&mut self, name: &Name<'_>) -> Result<(), EncodeError> {
        // Only a name decoded with compression pointers is copied, and only its runs of labels.
        let mut buf;
        let wire = if let Some(wire) = name.flat() {
            wire
        } else {
            buf = [0; MAX_NAME_LEN];
            name.to_wire(&mut buf)
        };
        if !self.compress {
            return self.put_bytes(wire);
        }
        // `inline` is how many bytes of `wire` are labels to write; the rest is a name already written.
        let mut inline = 0;
        let mut pointer = None;
        while let Some(&label_len) = wire.get(inline).filter(|&&l| l != 0) {
            let suffix = wire.get(inline..).unwrap_or_default();
            if let Some(target) = self.names.find(self.written(), suffix) {
                pointer = Some(target);
                break;
            }
            inline += 1 + usize::from(label_len);
        }
        let first = self.len;
        let tail = if pointer.is_some() { 2 } else { 1 };
        if self.remaining() < inline + tail {
            return Err(EncodeError::BufferFull);
        }
        self.put_bytes(wire.get(..inline).unwrap_or_default())?;
        match pointer {
            Some(target) => self.put_u16(0xC000 | target)?,
            None => self.put_u8(0)?,
        }
        let mut at = 0;
        while let Some(&label_len) = wire.get(at).filter(|&&l| l != 0).filter(|_| at < inline) {
            self.names
                .add(first + at, wire.get(at..).unwrap_or_default());
            at += 1 + usize::from(label_len);
        }
        Ok(())
    }

    /// Keeps the last `n` bytes of the buffer free for what is written after [`Writer::release_tail`].
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when fewer than `n` bytes are left.
    pub(crate) fn hold_back(&mut self, n: usize) -> Result<(), EncodeError> {
        if self.remaining() < n {
            return Err(EncodeError::BufferFull);
        }
        self.limit -= n;
        Ok(())
    }

    /// Makes the bytes kept by [`Writer::hold_back`] writable.
    pub(crate) fn release_tail(&mut self) {
        self.limit = self.buf.len();
    }

    /// Drops everything written after `len`, to roll back a partial record.
    pub(crate) fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
        self.names.truncate(self.len);
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
