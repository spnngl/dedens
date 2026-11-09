//! The message size limit, and the crate's byte cursors: `Reader` decodes, `Writer` encodes, neither allocates.
//! `name_table` holds the table `Writer` compresses names with.

mod name_table;

use name_table::{NameTable, Suffix, suffix_hashes};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::header::HEADER_LEN;
use crate::name::{MAX_NAME_LEN, Name};

/// Largest DNS message: the 16-bit length prefix of TCP (RFC 1035 §4.2.2) bounds it.
pub const MAX_MESSAGE_LEN: usize = 65535;

/// A bounds-checked cursor over a message.
///
/// A reader made by [`Reader::sub`] is limited to a field (RDATA) but still sees the whole message, so a
/// compression pointer inside the field can point before it (RFC 1035 §4.1.4).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `msg`.
    #[must_use]
    pub(crate) const fn new(msg: &'a [u8]) -> Self {
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
    pub(crate) const fn message(&self) -> &'a [u8] {
        self.msg
    }

    /// Offset of the next byte to read.
    #[must_use]
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Offset one past the last byte this reader may read.
    #[must_use]
    pub(crate) const fn end(&self) -> usize {
        self.end
    }

    /// Bytes left in this reader.
    #[must_use]
    pub(crate) const fn remaining(&self) -> usize {
        self.end - self.pos
    }

    /// Whether every byte was read.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.pos == self.end
    }

    /// An error of `kind` at the current offset.
    #[must_use]
    pub(crate) const fn error(&self, kind: DecodeErrorKind) -> DecodeError {
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
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
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
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// Reads a fixed layout in place, one bounds check for all its fields.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer bytes than its size are left.
    pub(crate) fn fields<T: FromBytes + KnownLayout + Immutable + Unaligned>(
        &mut self,
    ) -> Result<&'a T, DecodeError> {
        let left = self.msg.get(self.pos..self.end).unwrap_or_default();
        let Ok((fields, _)) = T::ref_from_prefix(left) else {
            return Err(self.error(DecodeErrorKind::UnexpectedEnd));
        };
        self.pos += size_of::<T>();
        Ok(fields)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] at the end of the reader.
    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than 2 bytes are left.
    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than 4 bytes are left.
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads everything left.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let slice = self.msg.get(self.pos..self.end).unwrap_or_default();
        self.pos = self.end;
        slice
    }

    /// Splits off the next `len` bytes as a reader limited to them, and moves past them.
    ///
    /// # Errors
    ///
    /// [`DecodeErrorKind::UnexpectedEnd`] when fewer than `len` bytes are left.
    pub(crate) fn sub(&mut self, len: usize) -> Result<Self, DecodeError> {
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

/// Most labels of a name: a 255-byte wire form of one-byte labels, each with its length byte, and the root.
const MAX_LABELS: usize = 127;

/// Labels of the names most messages hold: their hashes are kept in a small array, 32 bytes to clear.
const FEW_LABELS: usize = 8;

/// Suffixes looked up longest first before the search narrows in on the longest one held (see
/// [`Writer::put_name_found`]): names of up to this many labels, nearly all of them, match as soon as they can.
const LONGEST_FIRST: usize = 8;

/// A cursor writing into a caller-provided buffer, at most [`MAX_MESSAGE_LEN`] bytes of it.
#[derive(Debug)]
pub(crate) struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
    /// Writes stop here, short of `buf.len()` while a tail is held back.
    limit: usize,
    /// The names to point to; `None` for RDATA written on its own, whose names are never compressed.
    names: Option<NameTable>,
}

impl<'a> Writer<'a> {
    /// A writer at the start of `buf`.
    #[must_use]
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self::with_names(buf, Some(NameTable::new()))
    }

    /// A writer that never compresses names, for RDATA outside a message (RFC 3597 §5) and an OPT record after
    /// one: it has no name table to clear.
    pub(crate) fn uncompressed(buf: &'a mut [u8]) -> Self {
        Self::with_names(buf, None)
    }

    fn with_names(buf: &'a mut [u8], names: Option<NameTable>) -> Self {
        let cap = buf.len().min(MAX_MESSAGE_LEN);
        let (buf, _) = buf.split_at_mut(cap);
        let limit = buf.len();
        Self {
            buf,
            len: 0,
            limit,
            names,
        }
    }

    /// Bytes written so far.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Bytes still available.
    #[must_use]
    pub(crate) const fn remaining(&self) -> usize {
        self.limit - self.len
    }

    /// What was written.
    #[must_use]
    pub(crate) fn written(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }

    /// Appends `bytes`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when they do not fit; nothing is written then.
    pub(crate) fn put_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
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
    pub(crate) fn put_zeros(&mut self, n: usize) -> Result<(), EncodeError> {
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
    pub(crate) fn put_u8(&mut self, v: u8) -> Result<(), EncodeError> {
        self.put_bytes(&[v])
    }

    /// Appends a big-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub(crate) fn put_u16(&mut self, v: u16) -> Result<(), EncodeError> {
        self.put_bytes(&v.to_be_bytes())
    }

    /// Appends a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub(crate) fn put_u32(&mut self, v: u32) -> Result<(), EncodeError> {
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
    pub(crate) fn put_name_compressed(&mut self, name: &Name<'_>) -> Result<(), EncodeError> {
        self.put_name_found(name).map(drop)
    }

    /// Writes the owner of a record: a pointer to `previous` when given, the offset where the previous record's
    /// owner can be found, if it is the same name; otherwise as [`Writer::put_name_compressed`] does. Returns the
    /// offset to give for the next record, so a record set's owner is looked up once, as Unbound does.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit; nothing is written then.
    pub(crate) fn put_owner(
        &mut self,
        name: &Name<'_>,
        previous: Option<u16>,
    ) -> Result<Option<u16>, EncodeError> {
        match previous {
            Some(target) if self.names.is_some() => {
                self.put_u16(0xC000 | target)?;
                Ok(Some(target))
            }
            _ => self.put_name_found(name),
        }
    }

    /// [`Writer::put_name_compressed`], returning an offset a pointer to the name can use: where its first label
    /// was written, or what the pointer written for all of it points to. `None` for the root, whose one byte is
    /// shorter than a pointer, and for names past what a pointer reaches.
    fn put_name_found(&mut self, name: &Name<'_>) -> Result<Option<u16>, EncodeError> {
        // Only a name decoded with compression pointers is copied, and only its runs of labels.
        let mut buf;
        let wire = if let Some(wire) = name.flat() {
            wire
        } else {
            buf = [0; MAX_NAME_LEN];
            name.to_wire(&mut buf)
        };
        let Some(names) = &self.names else {
            return self.put_bytes(wire).map(|()| None);
        };
        let seed = names.seed;
        let mut few = [Suffix::default(); FEW_LABELS];
        let mut many;
        let hashes = if let Some(hashes) = suffix_hashes(wire, seed, &mut few) {
            hashes
        } else {
            many = [Suffix::default(); MAX_LABELS];
            suffix_hashes(wire, seed, &mut many).unwrap_or_default()
        };
        let written = self.written();
        let find = |suffix: Suffix| {
            names.find(
                written,
                wire.get(suffix.start()..).unwrap_or_default(),
                suffix.hash(),
            )
        };
        // The longest earlier suffix of the name: its first `fresh` labels, `inline` bytes of `wire`, are to
        // write, and the rest is a name already written.
        let head = hashes.len().min(LONGEST_FIRST);
        let mut found = hashes
            .iter()
            .take(head)
            .enumerate()
            .find_map(|(i, &suffix)| find(suffix).map(|target| (i, suffix.start(), target)));
        if found.is_none() {
            // The table holds every suffix of a name it holds (see below), so the suffixes held are the last
            // ones: a binary search finds the first, and a name of a hundred labels costs a few lookups. By hand:
            // `partition_point` makes two lookups more (docs/benchmarks.md).
            let (mut low, mut high) = (head, hashes.len());
            while low < high {
                let mid = low + (high - low) / 2;
                let suffix = hashes.get(mid).copied().unwrap_or_default();
                if let Some(target) = find(suffix) {
                    found = Some((mid, suffix.start(), target));
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
        }
        let (fresh, inline, pointer) = match found {
            Some((i, start, target)) => (i, start, Some(target)),
            None => (hashes.len(), wire.len().saturating_sub(1), None),
        };
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
        if let Some(names) = &mut self.names {
            // The shortest suffix first: when the table or a group is full, the longest go and the shortest stay,
            // so what is held stays closed under taking a suffix.
            let fresh = hashes.get(..fresh).unwrap_or_default();
            for &suffix in fresh.iter().rev() {
                let offset = first + suffix.start();
                if !(HEADER_LEN..POINTER_LIMIT).contains(&offset) {
                    continue;
                }
                if !u16::try_from(offset).is_ok_and(|offset| names.add(offset, suffix.hash())) {
                    break;
                }
            }
        }
        Ok(match pointer {
            Some(target) if inline == 0 => Some(target),
            _ if inline == 0 => None,
            _ => u16::try_from(first)
                .ok()
                .filter(|_| (HEADER_LEN..POINTER_LIMIT).contains(&first)),
        })
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
        if let Some(names) = &mut self.names {
            names.truncate(self.len);
        }
    }

    /// Runs `write`, rolling back what it wrote if it fails, so that a public encoder never leaves a partial
    /// entry behind.
    pub(crate) fn all_or_nothing<T>(
        &mut self,
        write: impl FnOnce(&mut Self) -> Result<T, EncodeError>,
    ) -> Result<T, EncodeError> {
        let start = self.len;
        write(self).inspect_err(|_| self.truncate(start))
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

    /// A record or question that does not fit leaves the writer as it was, compression table included.
    #[test]
    fn failed_encoding_writes_nothing() {
        use crate::rdata::RData;
        use crate::{Class, Question, Record, RecordType, Ttl};

        let owner: Name<'static> = "abcdefgh.example".parse().unwrap();
        let record = Record::new(
            owner.clone(),
            Class::IN,
            Ttl::ZERO,
            &RData::A([192, 0, 2, 1].into()),
        );
        let question = Question::new(owner, RecordType::A);
        let mut buf = [0; 41];
        let mut w = Writer::new(&mut buf);
        // A header: names are never in it, so never pointed to.
        w.put_bytes(&[7; 12]).unwrap();
        assert!(record.encode_after(&mut w, None).is_err());
        assert_eq!(w.len(), 12);
        question.encode(&mut w).expect("fits: 18 + 4 bytes");
        assert_eq!(w.len(), 34);
        assert!(
            question.encode(&mut w).is_ok(),
            "a pointer to the first one"
        );
        assert_eq!(w.len(), 40);
        assert!(question.encode(&mut w).is_err());
        assert_eq!(w.len(), 40);
    }

    /// A name ending in a pointer (RFC 1035 §4.1.4) fits in exactly the room its labels and pointer take; in a
    /// byte less, nothing of it is written.
    #[test]
    fn a_compressed_name_fits_in_exactly_its_room() {
        let base: Name<'static> = "example".parse().unwrap();
        let name: Name<'static> = "www.example".parse().unwrap();
        let room = HEADER_LEN + 9 + 4 + 2;
        for (size, fits) in [(room, true), (room - 1, false)] {
            let mut buf = vec![0; size];
            let mut w = Writer::new(&mut buf);
            w.put_bytes(&[0; HEADER_LEN]).unwrap();
            w.put_name_compressed(&base).unwrap();
            let at = w.len();
            assert_eq!(w.put_name_compressed(&name).is_ok(), fits, "{size} bytes");
            let written = if fits { &b"\x03www\xC0\x0C"[..] } else { &[] };
            assert_eq!(w.written().get(at..), Some(written), "{size} bytes");
        }
    }

    /// An owner looked up returns where the next record's owner may point to (RFC 1035 §4.1.4): its own offset when
    /// it starts with labels, its target when it is only a pointer, and none for the root, whose one byte a pointer
    /// would not shorten.
    #[test]
    fn an_owner_returns_where_to_point_to() {
        let name: Name<'static> = "example".parse().unwrap();
        let mut buf = [0; 64];
        let mut w = Writer::new(&mut buf);
        w.put_bytes(&[0; HEADER_LEN]).unwrap();
        assert_eq!(w.put_owner(&name, None), Ok(Some(12)));
        assert_eq!(w.put_owner(&name, None), Ok(Some(12)));
        assert_eq!(w.put_owner(&Name::root(), None), Ok(None));
        assert_eq!(
            w.written().get(HEADER_LEN..),
            Some(&b"\x07example\x00\xC0\x0C\x00"[..])
        );
    }

    /// [`Writer::hold_back`], the room of the OPT record (RFC 6891 §7), keeps all of what is left, but not a byte
    /// more.
    #[test]
    fn holding_back_keeps_up_to_what_is_left() {
        let mut buf = [0; 11];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.hold_back(12), Err(EncodeError::BufferFull));
        assert_eq!(w.hold_back(11), Ok(()));
        assert_eq!(w.put_u8(0), Err(EncodeError::BufferFull));
    }

    /// A writer that never compresses names writes an owner in full, whatever offset it is given to point to.
    #[test]
    fn an_uncompressed_owner_is_written_in_full() {
        let owner: Name<'static> = "example".parse().unwrap();
        let mut buf = [0; 16];
        let mut w = Writer::uncompressed(&mut buf);
        assert_eq!(w.put_owner(&owner, Some(0)), Ok(None));
        assert_eq!(w.written(), b"\x07example\x00");
    }

    /// The owner of a record set's second record points to the first's (RFC 1035 §4.1.4) by the offset
    /// [`Writer::put_owner`] returned, also when the name table was full and could not remember it.
    #[test]
    fn an_owner_past_a_full_table_points_to_the_previous_one() {
        let mut buf = [0; 4096];
        let mut w = Writer::new(&mut buf);
        w.put_bytes(&[0; HEADER_LEN]).unwrap();
        for i in 0..256 {
            let name: Name<'static> = format!("n{i}").parse().unwrap();
            w.put_name_compressed(&name).unwrap();
        }
        let owner: Name<'static> = "example".parse().unwrap();
        let previous = w.put_owner(&owner, None).unwrap();
        assert!(previous.is_some());
        let at = w.len();
        assert_eq!(w.put_owner(&owner, previous), Ok(previous));
        assert_eq!(w.len() - at, 2, "a pointer");
        let at = w.len();
        w.put_name_compressed(&owner).unwrap();
        assert_eq!(w.len() - at, 9, "not in the full table: written in full");
    }
}
