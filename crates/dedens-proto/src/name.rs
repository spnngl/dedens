//! Domain names (RFC 1035 §3.1, §4.1.4; RFC 4343).

use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::header::HEADER_LEN;
use crate::text::{self, TextError, TextErrorKind};
use crate::wire::{Reader, Writer};

/// Longest name in wire form, length bytes and root label included (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;
/// Longest label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;
/// Most compression pointers followed in one name: one per label of the longest name.
const MAX_POINTERS: usize = 127;

/// A label that cannot be part of a [`Name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// A label with no byte; only the root label is empty, and it is implicit.
    #[error("empty label")]
    EmptyLabel,
    /// A label longer than 63 bytes.
    #[error("label longer than 63 bytes")]
    LabelTooLong,
    /// A name longer than 255 bytes in wire form.
    #[error("name longer than 255 bytes")]
    NameTooLong,
}

/// An absolute domain name, borrowed from the message it was decoded from or owned (D7).
///
/// Labels are arbitrary bytes (RFC 2181 §11) and keep the case they were written in; equality and hashing ignore
/// ASCII case (RFC 4343 §3), whatever the representation. The name is always valid: labels of 1 to 63 bytes, at
/// most 255 bytes in total uncompressed, ending in the root label.
#[derive(Clone)]
pub struct Name<'a>(Repr<'a>);

#[derive(Clone)]
enum Repr<'a> {
    /// The uncompressed wire form, a slice of a message or a constant.
    Slice(&'a [u8]),
    /// The uncompressed wire form, built or copied.
    Owned(Box<[u8]>),
    /// A name with compression pointers starting at `start` in `msg`, checked when it was decoded; `len` is the
    /// length of its uncompressed wire form.
    Packed { msg: &'a [u8], start: u16, len: u8 },
}

impl<'a> Name<'a> {
    /// The root, `.`.
    #[must_use]
    pub const fn root() -> Self {
        Self(Repr::Slice(&[0]))
    }

    /// A name from its labels, most specific first, without the root label.
    ///
    /// # Errors
    ///
    /// [`NameError`] when a label is empty or longer than 63 bytes, or the name longer than 255 bytes.
    pub fn from_labels<'l, I>(labels: I) -> Result<Name<'static>, NameError>
    where
        I: IntoIterator<Item = &'l [u8]>,
    {
        let mut wire = Vec::new();
        for label in labels {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            let len = u8::try_from(label.len())
                .ok()
                .filter(|&len| usize::from(len) <= MAX_LABEL_LEN)
                .ok_or(NameError::LabelTooLong)?;
            if wire.len() + label.len() + 2 > MAX_NAME_LEN {
                return Err(NameError::NameTooLong);
            }
            wire.push(len);
            wire.extend_from_slice(label);
        }
        wire.push(0);
        Ok(Name(Repr::Owned(wire.into_boxed_slice())))
    }

    /// The uncompressed wire form, ending in the root label: the bytes the name holds, or, for a name decoded
    /// with compression pointers, a copy into `buf`.
    #[must_use]
    pub fn to_wire<'s>(&'s self, buf: &'s mut [u8; MAX_NAME_LEN]) -> &'s [u8] {
        let (msg, start) = match &self.0 {
            Repr::Slice(wire) => return wire,
            Repr::Owned(wire) => return wire,
            Repr::Packed { msg, start, .. } => (*msg, usize::from(*start)),
        };
        unpack(msg, start, buf)
    }

    /// The uncompressed wire form when it is stored as is.
    pub(crate) fn flat(&self) -> Option<&[u8]> {
        match &self.0 {
            Repr::Slice(wire) => Some(wire),
            Repr::Owned(wire) => Some(wire),
            Repr::Packed { .. } => None,
        }
    }

    /// Whether both names have the same uncompressed wire form, case included: `==` ignores case (RFC 4343), name
    /// compression must not (D10).
    pub(crate) fn same_wire(&self, other: &Name<'_>) -> bool {
        match (&self.0, &other.0) {
            // Two names whose labels start at the same place of the same message: the owners of one RRset in a
            // decoded message, each a pointer to the same name.
            (
                Repr::Packed { msg, start, .. },
                Repr::Packed {
                    msg: m, start: s, ..
                },
            ) if core::ptr::eq(*msg, *m) && first_label(msg, *start) == first_label(m, *s) => true,
            _ => match (self.flat(), other.flat()) {
                (Some(a), Some(b)) => a == b,
                _ => self.wire_len() == other.wire_len() && self.labels().eq(other.labels()),
            },
        }
    }

    /// Whether the name was decoded with compression pointers, so it borrows labels from elsewhere in its message.
    pub(crate) const fn is_packed(&self) -> bool {
        matches!(self.0, Repr::Packed { .. })
    }

    /// Length of the uncompressed wire form.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        match &self.0 {
            Repr::Slice(wire) => wire.len(),
            Repr::Owned(wire) => wire.len(),
            Repr::Packed { len, .. } => usize::from(*len),
        }
    }

    /// Whether this is the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.wire_len() == 1
    }

    /// The labels, most specific first, without the root label.
    #[must_use]
    pub fn labels(&self) -> Labels<'_> {
        match &self.0 {
            Repr::Slice(wire) => Labels::new(wire, 0),
            Repr::Owned(wire) => Labels::new(wire, 0),
            Repr::Packed { msg, start, .. } => Labels::new(msg, usize::from(*start)),
        }
    }

    /// Number of labels, without the root label.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// The same name, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Name<'static> {
        match self.0 {
            Repr::Owned(wire) => Name(Repr::Owned(wire)),
            _ if self.is_root() => Name::root(),
            _ => Name(Repr::Owned(Box::from(self.to_wire(&mut [0; MAX_NAME_LEN])))),
        }
    }

    /// Reads a name at the reader's position, following compression pointers (RFC 1035 §4.1.4); the name borrows
    /// from the message.
    ///
    /// The reader ends after the name's first pointer, or after its root label when it has none. A pointer must
    /// point strictly before the start of the name being read, and each pointer strictly before the previous
    /// target: that rules out loops without a counter.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the name runs past the reader, is longer than 255 bytes, has a pointer that does not
    /// point backwards, or a reserved label type.
    pub fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Self::decode_with(r, true)
    }

    /// Reads a name that must not be compressed, as in new RDATA types (RFC 3597 §4, RFC 9460 §2.2).
    ///
    /// # Errors
    ///
    /// [`DecodeError`] as [`Name::decode`], and for any compression pointer.
    pub fn decode_uncompressed(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Self::decode_with(r, false)
    }

    fn decode_with(r: &mut Reader<'a>, pointers: bool) -> Result<Self, DecodeError> {
        let msg = r.message();
        let start = r.position();
        let mut limit = r.end();
        let mut bound = start;
        let mut pos = start;
        // Where the reader resumes, set at the first pointer.
        let mut resume = None;
        let mut len = 0;
        let mut hops = 0;
        let at = |offset, kind| DecodeError { offset, kind };
        // Past `limit`: the end of the input, or, after a pointer, of the prior name it points to.
        let past = |resume: Option<usize>, pos| {
            let kind = if resume.is_some() {
                DecodeErrorKind::BadPointer
            } else {
                DecodeErrorKind::UnexpectedEnd
            };
            at(pos, kind)
        };
        loop {
            let first = match msg.get(pos) {
                Some(&b) if pos < limit => b,
                _ => return Err(past(resume, pos)),
            };
            match first & 0xC0 {
                0x00 => {
                    let end = pos + 1 + usize::from(first);
                    if end > limit {
                        return Err(past(resume, pos));
                    }
                    if first != 0 && len + usize::from(first) + 2 > MAX_NAME_LEN {
                        return Err(at(pos, DecodeErrorKind::NameTooLong));
                    }
                    len += end - pos;
                    pos = end;
                    if first == 0 {
                        break;
                    }
                }
                0xC0 if !pointers => {
                    let kind = DecodeErrorKind::Invalid(
                        "compression pointer in a name that must not be compressed",
                    );
                    return Err(at(pos, kind));
                }
                0xC0 => {
                    let second = match msg.get(pos + 1) {
                        Some(&b) if pos + 1 < limit => b,
                        _ => return Err(past(resume, pos)),
                    };
                    let target = usize::from(u16::from_be_bytes([first & 0x3F, second]));
                    // Backward pointers rule out loops, the hop count rules out long chains of them: a name
                    // has at most 127 labels, each worth at most one pointer. Offsets count from the start of
                    // the message, so a name is never in its 12-byte header.
                    hops += 1;
                    if target < HEADER_LEN || target >= bound || hops > MAX_POINTERS {
                        return Err(at(pos, DecodeErrorKind::BadPointer));
                    }
                    resume.get_or_insert(pos + 2);
                    // The name pointed to was written before this one, so it ends where this one starts: it
                    // cannot run into the bytes that point to it.
                    limit = bound;
                    bound = target;
                    pos = target;
                }
                _ => return Err(at(pos, DecodeErrorKind::ReservedLabelType)),
            }
        }
        let repr = if let Some(resume) = resume {
            r.set_position(resume);
            let len = u8::try_from(len).map_err(|_| at(start, DecodeErrorKind::NameTooLong))?;
            match u16::try_from(start) {
                Ok(start) => Repr::Packed { msg, start, len },
                // Only past the 65535 bytes of a DNS message, in a larger buffer: copied out.
                Err(_) => Repr::Owned(Box::from(unpack(msg, start, &mut [0; MAX_NAME_LEN]))),
            }
        } else {
            r.set_position(pos);
            Repr::Slice(msg.get(start..pos).unwrap_or_default())
        };
        Ok(Self(repr))
    }

    /// Writes the name uncompressed; see [`Writer::put_name_compressed`] for the names RFC 1035 allows to compress.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(self.to_wire(&mut [0; MAX_NAME_LEN]))
    }
}

/// Where the first label of the name at `start` in `msg` lies, past the pointers it starts with; decoding
/// checked that each points before the previous one.
fn first_label(msg: &[u8], start: u16) -> usize {
    let mut pos = usize::from(start);
    while let [high, low, ..] = msg.get(pos..).unwrap_or_default()
        && high & 0xC0 == 0xC0
    {
        let target = usize::from(high & 0x3F) << 8 | usize::from(*low);
        if target >= pos {
            break;
        }
        pos = target;
    }
    pos
}

/// The uncompressed wire form of the name with compression pointers at `start` in `msg`, decoded and checked
/// before; see [`Name::to_wire`].
fn unpack<'s>(msg: &'s [u8], start: usize, buf: &'s mut [u8; MAX_NAME_LEN]) -> &'s [u8] {
    // The runs of labels between pointers, the last one ending in the root label. A single non-empty run,
    // as for a name that is only a pointer, is returned in place; several are copied into `buf`.
    let mut single: Option<&[u8]> = None;
    let mut len = 0;
    let (mut run, mut pos) = (start, start);
    while let Some(&first) = msg.get(pos) {
        let pointer = first & 0xC0 == 0xC0;
        if first != 0 && !pointer {
            pos += 1 + usize::from(first);
            continue;
        }
        let end = if pointer { pos } else { pos + 1 };
        let labels = msg.get(run..end).unwrap_or_default();
        if !labels.is_empty() {
            if len == 0 && single.is_none() {
                single = Some(labels);
            } else {
                if let Some(first_run) = single.take() {
                    len = append(buf, len, first_run);
                }
                len = append(buf, len, labels);
            }
        }
        if !pointer {
            break;
        }
        // Decoding checked that each pointer points before the previous one.
        let low = msg.get(pos + 1).copied().unwrap_or_default();
        let target = usize::from(first & 0x3F) << 8 | usize::from(low);
        if target >= run.min(pos) {
            break;
        }
        (run, pos) = (target, target);
    }
    match single {
        Some(wire) => wire,
        None => buf.get(..len).filter(|w| !w.is_empty()).unwrap_or(&[0]),
    }
}

/// Copies `part` into `buf` at `len`, returning the new length; a name never overflows `buf`.
fn append(buf: &mut [u8; MAX_NAME_LEN], len: usize, part: &[u8]) -> usize {
    let end = len + part.len();
    if let Some(dst) = buf.get_mut(len..end) {
        dst.copy_from_slice(part);
    }
    end
}

/// Iterator over the labels of a [`Name`], following the compression pointers of a decoded one.
#[derive(Debug, Clone)]
pub struct Labels<'n> {
    buf: &'n [u8],
    pos: usize,
    /// Pointers must go strictly below this, as when decoding, so iteration always ends.
    bound: usize,
}

impl<'n> Labels<'n> {
    const fn new(buf: &'n [u8], start: usize) -> Self {
        Self {
            buf,
            pos: start,
            bound: start,
        }
    }
}

impl<'n> Iterator for Labels<'n> {
    type Item = &'n [u8];

    fn next(&mut self) -> Option<&'n [u8]> {
        loop {
            let &len = self.buf.get(self.pos)?;
            match len & 0xC0 {
                0x00 if len != 0 => {
                    let start = self.pos + 1;
                    let end = start + usize::from(len);
                    let label = self.buf.get(start..end)?;
                    self.pos = end;
                    return Some(label);
                }
                0xC0 => {
                    let &low = self.buf.get(self.pos + 1)?;
                    let target = usize::from(len & 0x3F) << 8 | usize::from(low);
                    if target >= self.bound {
                        return None;
                    }
                    self.bound = target;
                    self.pos = target;
                }
                // The root label, or a reserved type a checked name never holds.
                _ => {
                    self.pos = self.buf.len();
                    return None;
                }
            }
        }
    }
}

impl<'b> PartialEq<Name<'b>> for Name<'_> {
    fn eq(&self, other: &Name<'b>) -> bool {
        if let (Some(a), Some(b)) = (self.flat(), other.flat()) {
            // Length bytes are at most 63, below `A`, so lowercasing the whole wire form only touches letters.
            return a.eq_ignore_ascii_case(b);
        }
        if self.wire_len() != other.wire_len() {
            return false;
        }
        let mut theirs = other.labels();
        self.labels()
            .all(|a| theirs.next().is_some_and(|b| a.eq_ignore_ascii_case(b)))
            && theirs.next().is_none()
    }
}

impl Eq for Name<'_> {}

impl Hash for Name<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = self.to_wire(&mut buf);
        let mut lower = [0_u8; MAX_NAME_LEN];
        let lower = lower.get_mut(..wire.len()).unwrap_or_default();
        lower.copy_from_slice(wire);
        lower.make_ascii_lowercase();
        state.write(lower);
    }
}

/// Presentation form: labels joined by dots, ending in a dot; the special characters `.\"();@$` inside a label
/// are escaped with `\`, and bytes outside printable ASCII written `\DDD` (RFC 1035 §5.1).
impl fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for label in self.labels() {
            text::write_escaped(f, label, 0x21..=0x7E, b".\\\"();@$")?;
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl Name<'_> {
    /// Reads a name in presentation form (RFC 1035 §5.1): labels separated by dots, `\X` and `\DDD` escapes
    /// taken as label bytes; a name not ending in a dot is relative to `origin`, and `@` is `origin`.
    pub(crate) fn from_text(
        raw: &[u8],
        origin: Option<&Name<'_>>,
    ) -> Result<Name<'static>, TextErrorKind> {
        match raw {
            b"." => return Ok(Name::root()),
            b"@" => {
                return origin
                    .map(|o| o.clone().into_owned())
                    .ok_or(TextErrorKind::RelativeName);
            }
            _ => {}
        }
        // Built on the stack, then copied into one allocation of the exact size.
        let mut wire = Stack::default();
        // Offset of the length byte of the label being read.
        let mut label = 0;
        wire.push(0)?;
        let mut absolute = false;
        let mut i = 0;
        while let Some(&b) = raw.get(i) {
            i += 1;
            let byte = match b {
                b'.' => {
                    wire.close_label(label)?;
                    if i == raw.len() {
                        absolute = true;
                        break;
                    }
                    label = wire.len;
                    wire.push(0)?;
                    continue;
                }
                b'\\' => {
                    let (byte, used) = text::escape(raw.get(i..).unwrap_or_default())?;
                    i += used;
                    byte
                }
                // Names are never quoted; BIND refuses a bare quote too.
                b'"' => {
                    return Err(TextErrorKind::Invalid(
                        "domain name: a quote must be escaped",
                    ));
                }
                _ => b,
            };
            // Checked before the name length, so that a long label is reported as such.
            if wire.len - label > MAX_LABEL_LEN {
                return Err(TextErrorKind::Name(NameError::LabelTooLong));
            }
            wire.push(byte)?;
        }
        if absolute {
            wire.push(0)?;
        } else {
            wire.close_label(label)?;
            let origin = origin.ok_or(TextErrorKind::RelativeName)?;
            let mut buf = [0; MAX_NAME_LEN];
            wire.extend(origin.to_wire(&mut buf))?;
        }
        Ok(Name(Repr::Owned(wire.as_slice().into())))
    }
}

/// The wire form of a name being read from text: at most [`MAX_NAME_LEN`] bytes.
struct Stack {
    bytes: [u8; MAX_NAME_LEN],
    len: usize,
}

impl Default for Stack {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_NAME_LEN],
            len: 0,
        }
    }
}

impl Stack {
    const TOO_LONG: TextErrorKind = TextErrorKind::Name(NameError::NameTooLong);

    fn push(&mut self, byte: u8) -> Result<(), TextErrorKind> {
        *self.bytes.get_mut(self.len).ok_or(Self::TOO_LONG)? = byte;
        self.len += 1;
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), TextErrorKind> {
        let end = self.len + bytes.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(Self::TOO_LONG)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// Sets the length byte at `at` for the label after it, which must be 1 to 63 bytes.
    fn close_label(&mut self, at: usize) -> Result<(), TextErrorKind> {
        let len = self.len - at - 1;
        if len == 0 {
            return Err(TextErrorKind::Name(NameError::EmptyLabel));
        }
        let len = u8::try_from(len)
            .ok()
            .filter(|&l| usize::from(l) <= MAX_LABEL_LEN)
            .ok_or(TextErrorKind::Name(NameError::LabelTooLong))?;
        if let Some(byte) = self.bytes.get_mut(at) {
            *byte = len;
        }
        Ok(())
    }
}

/// Reads a name in presentation form; one not ending in a dot is taken as absolute, `@` is the root.
impl FromStr for Name<'static> {
    type Err = TextError;

    fn from_str(s: &str) -> Result<Self, TextError> {
        Name::from_text(s.as_bytes(), Some(&Name::root())).map_err(|kind| TextError {
            line: 1,
            column: 1,
            kind,
        })
    }
}

impl fmt::Debug for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&[u8]]) -> Name<'static> {
        Name::from_labels(labels.iter().copied()).unwrap()
    }

    #[test]
    fn wire_form_ends_in_the_root_label() {
        let mut buf = [0; MAX_NAME_LEN];
        assert_eq!(
            name(&[b"a", b"bc"]).to_wire(&mut buf),
            [1, b'a', 2, b'b', b'c', 0]
        );
        assert_eq!(Name::root().to_wire(&mut buf), [0]);
    }

    #[test]
    fn labels_are_validated() {
        assert_eq!(Name::from_labels([&b""[..]]), Err(NameError::EmptyLabel));
        assert_eq!(
            Name::from_labels([&[b'a'; 64][..]]),
            Err(NameError::LabelTooLong)
        );
        assert!(Name::from_labels([&[b'a'; 63][..]]).is_ok());
    }

    #[test]
    fn name_length_limit_is_255_with_the_root() {
        // 3 labels of 63 bytes = 192, plus one of 61 = 62 bytes of wire form: 254 + root = 255.
        let long = [b'a'; 63];
        let last = [b'a'; 61];
        assert!(Name::from_labels([&long[..], &long, &long, &last]).is_ok());
        let last = [b'a'; 62];
        assert_eq!(
            Name::from_labels([&long[..], &long, &long, &last]),
            Err(NameError::NameTooLong)
        );
    }

    #[test]
    fn display_escapes() {
        assert_eq!(
            name(&[b"www", b"example", b"com"]).to_string(),
            "www.example.com."
        );
        assert_eq!(
            name(&[b"a.b", b"\\", &[0x00, 0xff]]).to_string(),
            "a\\.b.\\\\.\\000\\255."
        );
        assert_eq!(Name::root().to_string(), ".");
    }

    #[test]
    fn decode_reads_one_name_and_stops() {
        let msg = [1, b'a', 0, 9];
        let mut r = Reader::new(&msg);
        assert_eq!(Name::decode(&mut r).unwrap(), name(&[b"a"]));
        assert_eq!(r.position(), 3);
    }

    #[test]
    fn decode_follows_a_pointer_and_resumes_after_it() {
        // 12: "a" root; 15: "b" + pointer to 12.
        let msg = [&[0; 12][..], &[1, b'a', 0, 1, b'b', 0xC0, 12, 7]].concat();
        let mut r = Reader::new(&msg);
        r.bytes(15).unwrap();
        assert_eq!(Name::decode(&mut r).unwrap(), name(&[b"b", b"a"]));
        assert_eq!(r.position(), 19);
    }

    #[test]
    fn a_decoded_name_borrows_and_matches_its_owned_copy() {
        use std::hash::BuildHasher;

        // 12: "a" root; 15: "B" + pointer to 12; 19: "b" "a" root, uncompressed.
        let msg = [
            &[0; 12][..],
            &[1, b'a', 0, 1, b'B', 0xC0, 12, 1, b'b', 1, b'a', 0],
        ]
        .concat();
        let mut r = Reader::new(&msg);
        r.bytes(15).unwrap();
        let packed = Name::decode(&mut r).unwrap();
        let flat = Name::decode(&mut r).unwrap();
        assert!(packed.is_packed() && !flat.is_packed());
        assert_eq!(
            packed.to_wire(&mut [0; MAX_NAME_LEN]),
            [1, b'B', 1, b'a', 0]
        );
        assert_eq!(packed.wire_len(), 5);
        assert_eq!(packed.labels().collect::<Vec<_>>(), [b"B", b"a"]);
        assert_eq!(packed, flat);
        let hasher = std::hash::RandomState::new();
        assert_eq!(hasher.hash_one(&packed), hasher.hash_one(&flat));
        let owned = packed.clone().into_owned();
        assert_eq!(owned, packed);
        assert_eq!(owned.to_string(), "B.a.");
        assert_ne!(packed, name(&[b"b"]));
    }

    #[test]
    fn decode_rejects_pointers_that_do_not_go_back() {
        // A pointer to itself, to later bytes, to a label that points back at it, and into the header.
        for name in [
            &[0xC0, 12][..],
            &[0xC0, 14, 0],
            &[1, b'a', 0xC0, 12],
            &[0xC0, 1],
        ] {
            let msg = [&[0; 12][..], name].concat();
            let mut r = Reader::new(&msg);
            r.bytes(12).unwrap();
            let err = Name::decode(&mut r).unwrap_err();
            assert_eq!(err.kind, DecodeErrorKind::BadPointer, "{msg:?}");
        }
    }

    #[test]
    fn decode_rejects_a_prior_name_running_over_its_pointer() {
        // 12: a 3-byte label holding the name at 13, a pointer back to 12, then "x" and the root.
        let msg = [&[0; 12][..], &[3, 0xC0, 12, b'x', 0]].concat();
        let mut r = Reader::new(&msg);
        r.bytes(13).unwrap();
        let err = Name::decode(&mut r).unwrap_err();
        assert_eq!(err.kind, DecodeErrorKind::BadPointer);
    }

    #[test]
    fn decode_rejects_reserved_label_types_and_truncation() {
        for (msg, kind) in [
            (&[0x40, 0][..], DecodeErrorKind::ReservedLabelType),
            (&[0x80, 0], DecodeErrorKind::ReservedLabelType),
            (&[3, b'a', b'b'], DecodeErrorKind::UnexpectedEnd),
            (&[1, b'a'], DecodeErrorKind::UnexpectedEnd),
            (&[0xC0], DecodeErrorKind::UnexpectedEnd),
        ] {
            let err = Name::decode(&mut Reader::new(msg)).unwrap_err();
            assert_eq!(err.kind, kind, "{msg:?}");
        }
    }

    #[test]
    fn decode_rejects_expanded_names_over_255_bytes() {
        // Each name is a 63-byte label pointing at the one before: 5 of them expand to 320 bytes.
        let mut msg = vec![0];
        let mut last = 0;
        for _ in 0..5 {
            let at = msg.len();
            msg.push(63);
            msg.extend_from_slice(&[b'a'; 63]);
            let [hi, lo] = u16::try_from(last).unwrap().to_be_bytes();
            msg.extend_from_slice(&[0xC0 | hi, lo]);
            last = at;
        }
        let mut r = Reader::new(&msg);
        r.bytes(last).unwrap();
        assert_eq!(
            Name::decode(&mut r).unwrap_err().kind,
            DecodeErrorKind::NameTooLong
        );
    }

    #[test]
    fn a_sub_reader_cannot_read_inline_labels_past_its_end() {
        let msg = [1, b'a', 0];
        let mut r = Reader::new(&msg);
        let mut sub = r.sub(2).unwrap();
        assert_eq!(
            Name::decode(&mut sub).unwrap_err().kind,
            DecodeErrorKind::UnexpectedEnd
        );
    }
}
