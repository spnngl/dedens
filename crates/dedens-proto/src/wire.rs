//! The message size limit, and the crate's byte cursors: `Reader` decodes, `Writer` encodes, neither allocates.

use std::hash::{BuildHasher, RandomState};
use std::sync::OnceLock;

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

/// Slots of the name table: a power of two, a multiple of [`GROUP`].
const TABLE_SLOTS: usize = 256;

/// Slots a probe reads at once: their 8 tags fit a word.
const GROUP: usize = 8;

/// Groups of the name table.
const GROUPS: usize = TABLE_SLOTS / GROUP;

/// Names of one tag that a lookup compares with the message before it gives up: names chosen to share a tag lose
/// their own compression, not the encoder's time (D112).
const MAX_COMPARES: usize = 4;

/// How many suffixes a [`Writer`] remembers, 3/4 of the slots so probes stay short; a message with more
/// distinct names compresses the later ones less.
const TABLE_CAPACITY: usize = TABLE_SLOTS / 4 * 3;

/// Most labels of a name: a 255-byte wire form of one-byte labels, each with its length byte, and the root.
const MAX_LABELS: usize = 127;

/// Labels of the names most messages hold: their hashes are kept in a small array, 32 bytes to clear.
const FEW_LABELS: usize = 8;

/// Suffixes looked up longest first before the search narrows in on the longest one held (see
/// [`Writer::put_name_found`]): names of up to this many labels, nearly all of them, match as soon as they can.
const LONGEST_FIRST: usize = 8;

/// A suffix of a name, as [`suffix_hashes`] lists it: where it starts in the wire-form name, at most 253, and
/// the top 32 bits of its hash but for the 8 that hold the start.
#[derive(Debug, Clone, Copy, Default)]
struct Suffix(u32);

impl Suffix {
    const START: u32 = 0xFF;

    /// The suffix of the name that starts at `start`, of `hash`.
    fn new(start: usize, hash: u64) -> Self {
        let hash = u32::try_from(hash >> 32).unwrap_or_default();
        Self(hash & !Self::START | u32::try_from(start).unwrap_or_default() & Self::START)
    }

    /// Where the suffix starts in the wire-form name.
    fn start(self) -> usize {
        usize::try_from(self.0 & Self::START).unwrap_or_default()
    }

    /// The bits of the hash the name table uses: the same for every name with this suffix.
    const fn hash(self) -> u32 {
        self.0
    }
}

/// Fills `hashes` with a [`Suffix`] for each suffix of the wire-form name `wire` that starts at a label, longest
/// first, and returns them; `None` when the name has more labels than `hashes` holds. Folded from the root,
/// each byte of the name is hashed once, however many suffixes there are. The hash starts from `seed` and
/// keeps case: names are matched byte for byte (D10).
fn suffix_hashes<'h, const N: usize>(
    wire: &[u8],
    seed: u64,
    hashes: &'h mut [Suffix; N],
) -> Option<&'h [Suffix]> {
    // Each entry holds where its label starts, until the hash is put above it.
    let mut count = 0;
    let mut at = 0;
    while let Some(&len) = wire.get(at).filter(|&&len| len != 0) {
        *hashes.get_mut(count)? = Suffix::new(at, 0);
        count += 1;
        at += 1 + usize::from(len);
    }
    let mut hash = seed;
    for suffix in hashes.iter_mut().take(count).rev() {
        let start = suffix.start();
        let len = usize::from(wire.get(start).copied().unwrap_or_default());
        hash = fold(hash, wire, start, start + 1 + len);
        *suffix = Suffix::new(start, hash);
    }
    hashes.get(..count)
}

/// One step of the hash: the product of `hash` and `word`, as wide as the registers twice over, folded in two.
/// Every input bit reaches every output bit, which `FxHash`'s multiplication by a constant does not do: bits
/// of two words can be flipped so that they cancel, whatever `hash` held.
fn mix(hash: u64, word: u64) -> u64 {
    let product = u128::from(hash ^ word) * 0x9E37_79B9_7F4A_7C15;
    // Both halves of the product, so the high bits do not have to carry the whole result.
    let folded = product >> 64 ^ product & u128::from(u64::MAX);
    u64::try_from(folded).unwrap_or_default()
}

/// Mixes the label at `wire[start..end]`, its length byte first, into `hash`, a word at a time. Reads the
/// bytes before `start` for a label of up to 8 bytes, but not into the hash.
fn fold(mut hash: u64, wire: &[u8], start: usize, end: usize) -> u64 {
    let word = |at: usize| {
        let bytes = wire.get(at..at + 8).unwrap_or_default();
        u64::from_le_bytes(<[u8; 8]>::try_from(bytes).unwrap_or_default())
    };
    let len = end - start;
    if len > 8 {
        let mut at = start;
        while at + 8 < end {
            hash = mix(hash, word(at));
            at += 8;
        }
        // The last word overlaps the one before it, so no byte of the label is left out.
        mix(hash, word(end - 8))
    } else if end >= 8 {
        // The label is the last bytes of the word before `end`: shifted down, they start it.
        mix(hash, word(end - 8) >> (8 * (8 - len)))
    } else {
        // Zeros past the end cannot make two labels equal: the length byte differs.
        let tail = wire.get(start..end).unwrap_or_default();
        mix(
            hash,
            tail.iter().rev().fold(0, |w, &b| w << 8 | u64::from(b)),
        )
    }
}

/// Offsets of the names written so far, to point to them (RFC 1035 §4.1.4).
///
/// An open-addressing hash table of offsets keyed on [`suffix_hashes`]: fixed capacity, so no allocation (D10),
/// and 768 bytes to clear per message. Beside its offset a slot has an 8-bit tag of its hash, 0 for an empty
/// slot; a probe reads the tags of a group of slots in one word and compares a name with the written message
/// only where the tag agrees, and gives up after a few (D112). Names are matched byte for byte against the
/// written message, so each keeps its own case (RFC 4343 §4).
#[derive(Debug)]
struct NameTable {
    /// Offset of the name in each slot; meaningless while the slot is empty.
    offsets: [u16; TABLE_SLOTS],
    /// The tags of the slots, a group in each word, the first slot in the low byte; a tag is 1 to 255, 0 is an
    /// empty slot.
    tags: [u64; GROUPS],
    len: usize,
    /// Where [`suffix_hashes`] starts: random for each process, so that names cannot be chosen to share a group.
    seed: u64,
}

impl NameTable {
    fn new() -> Self {
        static SEED: OnceLock<u64> = OnceLock::new();
        Self::with_seed(*SEED.get_or_init(|| RandomState::new().hash_one(0_u8)))
    }

    const fn with_seed(seed: u64) -> Self {
        Self {
            offsets: [0; TABLE_SLOTS],
            tags: [0; GROUPS],
            len: 0,
            seed,
        }
    }

    /// The groups to look in for a name of `hash`, from its home, its top 5 bits, on.
    fn probe(hash: u32) -> impl Iterator<Item = usize> {
        let home = usize::try_from(hash >> 27).unwrap_or_default();
        (0..GROUPS).map(move |step| (home + step) % GROUPS)
    }

    /// The tag of a name of `hash`: 8 bits under its home's, never 0.
    fn tag(hash: u32) -> u8 {
        u8::try_from(hash >> 19 & 0xFF).unwrap_or_default().max(1)
    }

    /// The tags of the slots of `group`.
    fn group(&self, group: usize) -> u64 {
        self.tags.get(group).copied().unwrap_or_default()
    }

    /// Remembers that the name of `hash` starts at `offset`, which a pointer can reach; `false` when the table
    /// is full.
    fn add(&mut self, offset: u16, hash: u32) -> bool {
        if self.len >= TABLE_CAPACITY {
            return false;
        }
        for group in Self::probe(hash) {
            let empties = zero_bytes(self.group(group));
            if empties == 0 {
                continue;
            }
            let first = empties.trailing_zeros() / 8;
            let slot = group * GROUP + usize::try_from(first).unwrap_or_default();
            if let (Some(tags), Some(stored)) =
                (self.tags.get_mut(group), self.offsets.get_mut(slot))
            {
                *tags |= u64::from(Self::tag(hash)) << (8 * first);
                *stored = offset;
                self.len += 1;
                return true;
            }
        }
        false
    }

    /// Forgets the names starting at or after `len`.
    ///
    /// They are the last ones added, so no name left behind was probed past their slots: emptying them keeps
    /// every probe sequence whole.
    fn truncate(&mut self, len: usize) {
        for (group, tags) in self.tags.iter_mut().enumerate() {
            for slot in 0..GROUP {
                let shift = 8 * slot;
                let at = group * GROUP + slot;
                let offset = self.offsets.get(at).copied().unwrap_or_default();
                if *tags >> shift & 0xFF != 0 && usize::from(offset) >= len {
                    *tags &= !(0xFF << shift);
                    self.len -= 1;
                }
            }
        }
    }

    /// The offset of an earlier name equal to `suffix` (wire form, root included, of `hash`), if any.
    fn find(&self, written: &[u8], suffix: &[u8], hash: u32) -> Option<u16> {
        let tag = u64::from(Self::tag(hash)) * 0x0101_0101_0101_0101;
        let mut compares = 0;
        for group in Self::probe(hash) {
            let tags = self.group(group);
            let mut hits = zero_bytes(tags ^ tag);
            while hits != 0 {
                if compares == MAX_COMPARES {
                    return None;
                }
                compares += 1;
                let first = usize::try_from(hits.trailing_zeros() / 8).unwrap_or_default();
                let offset = *self.offsets.get(group * GROUP + first)?;
                if name_matches(written, usize::from(offset), suffix) {
                    return Some(offset);
                }
                hits &= hits - 1;
            }
            // A group with room left ends the probe: a name that overflowed it would have filled it.
            if zero_bytes(tags) != 0 {
                return None;
            }
        }
        None
    }
}

/// `0x80` in each byte of `word` that is 0, `0` in the others, with no false positives.
const fn zero_bytes(word: u64) -> u64 {
    const LOW: u64 = 0x7F7F_7F7F_7F7F_7F7F;
    !((word & LOW).wrapping_add(LOW) | word | LOW)
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
            // ones: a binary search finds the first, and a name of a hundred labels costs a few lookups.
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
        use crate::{Class, Question, RData, Record, RecordType, Ttl};

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

    /// The name of `labels`.
    fn name_of(labels: &[&[u8]]) -> Name<'static> {
        Name::from_labels(labels.iter().copied()).unwrap()
    }

    /// The wire form of `name`.
    fn wire_of(name: &Name<'_>) -> Vec<u8> {
        name.to_wire(&mut [0; MAX_NAME_LEN]).to_vec()
    }

    /// The hash the table keys the whole of `name` on.
    fn hash_of(name: &Name<'_>, seed: u64) -> u32 {
        let mut hashes = [Suffix::default(); MAX_LABELS];
        suffix_hashes(&wire_of(name), seed, &mut hashes).unwrap()[0].hash()
    }

    /// Writes `names` after a header, compressed, and returns what was written past it.
    fn compressed(names: &[Name<'_>]) -> Vec<u8> {
        let mut buf = [0; 2048];
        let mut w = Writer::new(&mut buf);
        w.put_bytes(&[0; HEADER_LEN]).unwrap();
        for name in names {
            w.put_name_compressed(name).unwrap();
        }
        w.written().get(HEADER_LEN..).unwrap().to_vec()
    }

    /// Names whose hashes agree on the group and the tag share a probe sequence and are told apart by the
    /// comparison with the message, not by the tag; a lookup compares at most [`MAX_COMPARES`] of them, so the
    /// next one is not found, and one that was never added is not found either.
    #[test]
    fn names_of_one_tag_are_compared_in_full_up_to_a_cap() {
        const SEED: u64 = 1;
        let mut buckets = std::collections::HashMap::<u32, Vec<Name<'static>>>::new();
        let same = (0..)
            .find_map(|i| {
                let name = name_of(&[format!("n{i}").as_bytes()]);
                let bucket = buckets.entry(hash_of(&name, SEED) >> 19).or_default();
                bucket.push(name);
                (bucket.len() == MAX_COMPARES + 2).then(|| bucket.clone())
            })
            .unwrap();
        let mut written = vec![0; HEADER_LEN];
        let mut table = NameTable::with_seed(SEED);
        let mut offsets = Vec::new();
        for name in &same[..=MAX_COMPARES] {
            let offset = u16::try_from(written.len()).unwrap();
            assert!(table.add(offset, hash_of(name, SEED)));
            offsets.push(offset);
            written.extend(wire_of(name));
        }
        let find = |name: &Name<'_>| table.find(&written, &wire_of(name), hash_of(name, SEED));
        for (name, &offset) in same.iter().zip(&offsets).take(MAX_COMPARES) {
            assert_eq!(find(name), Some(offset));
        }
        assert_eq!(find(&same[MAX_COMPARES]), None, "held, past the cap");
        assert_eq!(find(&same[MAX_COMPARES + 1]), None, "never added");
    }

    /// A table of `names`, added in turn as if written one after the other after a header, and what was written.
    fn table_of(names: &[Name<'_>], seed: u64) -> (NameTable, Vec<u8>) {
        let mut written = vec![0; HEADER_LEN];
        let mut table = NameTable::with_seed(seed);
        for name in names {
            let offset = u16::try_from(written.len()).unwrap();
            assert!(table.add(offset, hash_of(name, seed)));
            written.extend(wire_of(name));
        }
        (table, written)
    }

    /// The names `n0.`, `n1.`... and the hashes the table keys them on.
    fn numbered(seed: u64) -> impl Iterator<Item = (Name<'static>, u32)> {
        (0..).map(move |i| {
            let name = name_of(&[format!("n{i}").as_bytes()]);
            let hash = hash_of(&name, seed);
            (name, hash)
        })
    }

    /// Names past a full group go to the next one, from the last group round to the first, and are found there.
    #[test]
    fn names_past_a_full_group_are_found_in_the_next() {
        const SEED: u64 = 1;
        // The last group: the top 5 bits of the hash all set.
        let names: Vec<_> = numbered(SEED)
            .filter(|&(_, hash)| hash >> 27 == u32::MAX >> 27)
            .map(|(name, _)| name)
            .take(GROUP + 2)
            .collect();
        let (table, written) = table_of(&names, SEED);
        for name in &names {
            let found = table.find(&written, &wire_of(name), hash_of(name, SEED));
            assert!(found.is_some(), "{name}");
        }
    }

    /// Names of one tag and of other homes are each found in their own group, more of them than a lookup compares.
    #[test]
    fn names_of_one_tag_in_other_groups_are_each_found() {
        const SEED: u64 = 1;
        let mut buckets = std::collections::HashMap::<u8, Vec<(u32, Name<'static>)>>::new();
        let names = numbered(SEED)
            .find_map(|(name, hash)| {
                // The home: the top 5 bits of the hash.
                let home = hash >> 27;
                let bucket = buckets.entry(NameTable::tag(hash)).or_default();
                if bucket.iter().all(|&(other, _)| other != home) {
                    bucket.push((home, name));
                }
                (bucket.len() > MAX_COMPARES).then(|| {
                    bucket
                        .iter()
                        .map(|(_, name)| name.clone())
                        .collect::<Vec<_>>()
                })
            })
            .unwrap();
        let (table, written) = table_of(&names, SEED);
        for name in &names {
            let found = table.find(&written, &wire_of(name), hash_of(name, SEED));
            assert!(found.is_some(), "{name}");
        }
    }

    /// Labels longer than a word that differ only in their last byte hash apart: written again, each is a pointer.
    #[test]
    fn long_labels_that_differ_at_their_end_are_each_pointed_to() {
        let names: Vec<_> = (0..=MAX_COMPARES)
            .map(|i| name_of(&[format!("abcdefghij{i}").as_bytes()]))
            .collect();
        let once = compressed(&names).len();
        let twice = compressed(&[names.clone(), names.clone()].concat()).len();
        assert_eq!(twice - once, 2 * names.len());
    }

    /// A rolled-back name is forgotten and frees its room in the table; the names before the cut stay found.
    #[test]
    fn a_rolled_back_name_frees_its_room() {
        const SEED: u64 = 1;
        let names: Vec<_> = numbered(SEED).map(|(name, _)| name).take(220).collect();
        let (kept, cut, after) = (&names[..50], &names[50..100], &names[100..]);
        assert!(kept.len() + cut.len() + after.len() > TABLE_CAPACITY);
        assert!(kept.len() + after.len() <= TABLE_CAPACITY);
        let mut buf = [0; 4096];
        let mut w = Writer::with_names(&mut buf, Some(NameTable::with_seed(SEED)));
        w.put_bytes(&[0; HEADER_LEN]).unwrap();
        for name in kept {
            w.put_name_compressed(name).unwrap();
        }
        let at = w.len();
        for name in cut {
            w.put_name_compressed(name).unwrap();
        }
        w.truncate(at);
        for name in after {
            w.put_name_compressed(name).unwrap();
        }
        let before = w.len();
        for name in kept.iter().chain(after) {
            w.put_name_compressed(name).unwrap();
        }
        assert_eq!(
            w.len() - before,
            2 * (kept.len() + after.len()),
            "a pointer each"
        );
    }

    /// Labels that differ by bits chosen to cancel in a multiplicative hash of the words of a name (the
    /// shape `flips` of the `message` bench has) hash apart, whatever the seed.
    #[test]
    fn flipped_bits_do_not_cancel() {
        for seed in [0, 1, 0x9E37_79B9_7F4A_7C15] {
            let hashes: std::collections::HashSet<u32> = (0..128_u32)
                .map(|variant| {
                    let mut label = [b'x'; 63];
                    for pair in (0..7).filter(|pair| variant >> pair & 1 == 1) {
                        label[8 * pair + 6] ^= 0x80;
                        label[8 * pair + 7] ^= 0x10;
                    }
                    hash_of(&name_of(&[label.as_slice(), b"example", b"com"]), seed)
                })
                .collect();
            assert_eq!(hashes.len(), 128, "seed {seed}");
        }
    }

    /// A name that has more labels before the shared ones than are looked up longest first still finds its
    /// longest suffix, by the search over the rest.
    #[test]
    fn deep_names_find_their_longest_suffix() {
        let shared: Vec<&[u8]> = [b"a".as_slice()]
            .repeat(30)
            .into_iter()
            .chain([b"com".as_slice()])
            .collect();
        let base = name_of(&shared);
        let base_len = wire_of(&base).len();
        for fresh in [1, LONGEST_FIRST, LONGEST_FIRST + 1, 12, 60] {
            let labels: Vec<&[u8]> = [b"bb".as_slice()]
                .repeat(fresh)
                .into_iter()
                .chain(shared.iter().copied())
                .collect();
            let written = compressed(&[base.clone(), name_of(&labels)]);
            assert_eq!(written.len(), base_len + 3 * fresh + 2, "{fresh} fresh");
            assert_eq!(
                written.get(written.len() - 2..),
                Some(&[0xC0, u8::try_from(HEADER_LEN).unwrap()][..]),
                "{fresh} fresh"
            );
        }
    }

    /// Past the table's capacity the suffixes kept are the shortest of a name, so those found last stay found.
    #[test]
    fn a_full_table_keeps_the_shortest_suffixes() {
        let deep = |label: &[u8]| name_of(&[label].repeat(127));
        let tail = name_of(&[b"b".as_slice()].repeat(50));
        let (a, b) = (deep(b"a"), deep(b"b"));
        let before = compressed(&[a.clone(), b.clone()]).len();
        let after = compressed(&[a, b, tail]).len();
        assert_eq!(
            after - before,
            2,
            "a pointer to the last 50 labels of the second"
        );
    }

    /// A name that starts where a pointer reaches and ends past it is remembered by its suffixes that a pointer
    /// reaches; one that starts past it is not remembered.
    #[test]
    fn names_past_what_a_pointer_reaches_are_not_remembered() {
        let name = name_of(&[b"cccc".as_slice()].repeat(10));
        let other = name_of(&[b"dddd".as_slice()].repeat(3));
        let (len, other_len) = (wire_of(&name).len(), wire_of(&other).len());
        let before = POINTER_LIMIT - 40;
        let mut buf = vec![0; POINTER_LIMIT + 200];
        let mut w = Writer::new(&mut buf);
        w.put_bytes(&vec![0; before]).unwrap();
        w.put_name_compressed(&name).unwrap();
        assert_eq!(
            w.len(),
            before + len,
            "8 of its 10 suffixes start below the limit"
        );
        w.put_name_compressed(&name).unwrap();
        assert_eq!(w.len(), before + len + 2, "a pointer to the first");
        let after = w.len();
        w.put_name_compressed(&other).unwrap();
        w.put_name_compressed(&other).unwrap();
        assert_eq!(w.len(), after + 2 * other_len, "written in full both times");
    }
}
