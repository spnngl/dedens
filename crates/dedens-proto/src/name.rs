//! Domain names (RFC 1035 §3.1, §4.1.4; RFC 4343).

use core::fmt;
use core::hash::{Hash, Hasher};

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

/// Longest name in wire form, length bytes and root label included (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;
/// Longest label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

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

/// An absolute domain name.
///
/// Labels are arbitrary bytes (RFC 2181 §11) and keep the case they were written in; equality and hashing ignore
/// ASCII case (RFC 4343 §3). The wire form is stored uncompressed and always valid: labels of 1 to 63 bytes, at
/// most 255 bytes in total, ending in the root label.
#[derive(Clone)]
pub struct Name(Box<[u8]>);

impl Name {
    /// The root, `.`.
    #[must_use]
    pub fn root() -> Self {
        Self(Box::new([0]))
    }

    /// A name from its labels, most specific first, without the root label.
    ///
    /// # Errors
    ///
    /// [`NameError`] when a label is empty or longer than 63 bytes, or the name longer than 255 bytes.
    pub fn from_labels<'a, I>(labels: I) -> Result<Self, NameError>
    where
        I: IntoIterator<Item = &'a [u8]>,
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
        Ok(Self(wire.into_boxed_slice()))
    }

    /// The uncompressed wire form, ending in the root label.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.0
    }

    /// Length of the wire form.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// The labels, most specific first, without the root label.
    #[must_use]
    pub fn labels(&self) -> Labels<'_> {
        Labels(&self.0)
    }

    /// Number of labels, without the root label.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Reads a name at the reader's position, following compression pointers (RFC 1035 §4.1.4).
    ///
    /// The reader ends after the name's first pointer, or after its root label when it has none. A pointer must
    /// point strictly before the start of the name being read, and each pointer strictly before the previous
    /// target: that rules out loops without a counter.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the name runs past the reader, is longer than 255 bytes, has a pointer that does not
    /// point backwards, or a reserved label type.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let msg = r.message();
        let mut limit = r.end();
        let mut bound = r.position();
        let mut pos = bound;
        let mut resume = None;
        let mut wire = Vec::with_capacity(32);
        let at = |offset, kind| DecodeError { offset, kind };
        loop {
            let first = match msg.get(pos) {
                Some(&b) if pos < limit => b,
                _ => return Err(at(pos, DecodeErrorKind::UnexpectedEnd)),
            };
            match first & 0xC0 {
                0x00 => {
                    let len = usize::from(first);
                    let end = pos + 1 + len;
                    if end > limit {
                        return Err(at(pos, DecodeErrorKind::UnexpectedEnd));
                    }
                    if len != 0 && wire.len() + len + 2 > MAX_NAME_LEN {
                        return Err(at(pos, DecodeErrorKind::NameTooLong));
                    }
                    let label = msg
                        .get(pos..end)
                        .ok_or(at(pos, DecodeErrorKind::UnexpectedEnd))?;
                    wire.extend_from_slice(label);
                    pos = end;
                    if len == 0 {
                        break;
                    }
                }
                0xC0 => {
                    let second = match msg.get(pos + 1) {
                        Some(&b) if pos + 1 < limit => b,
                        _ => return Err(at(pos, DecodeErrorKind::UnexpectedEnd)),
                    };
                    let target = usize::from(u16::from_be_bytes([first & 0x3F, second]));
                    if target >= bound {
                        return Err(at(pos, DecodeErrorKind::BadPointer));
                    }
                    resume.get_or_insert(pos + 2);
                    bound = target;
                    pos = target;
                    limit = msg.len();
                }
                _ => return Err(at(pos, DecodeErrorKind::ReservedLabelType)),
            }
        }
        r.set_position(resume.unwrap_or(pos));
        Ok(Self(wire.into_boxed_slice()))
    }

    /// Writes the name uncompressed.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&self.0)
    }
}

/// Iterator over the labels of a [`Name`].
#[derive(Debug, Clone)]
pub struct Labels<'a>(&'a [u8]);

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (&len, rest) = self.0.split_first()?;
        if len == 0 {
            self.0 = &[];
            return None;
        }
        let (label, rest) = rest.split_at_checked(usize::from(len))?;
        self.0 = rest;
        Some(label)
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        // Length bytes are at most 63, below `A`, so lowercasing the whole wire form only touches letters.
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in &self.0 {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

/// Presentation form: labels joined by dots, ending in a dot; `.` and `\` inside a label are written `\.` and
/// `\\`, and bytes outside printable ASCII as `\DDD` (RFC 1035 §5.1).
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for label in self.labels() {
            for &b in label {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", char::from(b))?,
                    0x21..=0x7E => write!(f, "{}", char::from(b))?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&[u8]]) -> Name {
        Name::from_labels(labels.iter().copied()).unwrap()
    }

    #[test]
    fn wire_form_ends_in_the_root_label() {
        assert_eq!(name(&[b"a", b"bc"]).as_wire(), &[1, b'a', 2, b'b', b'c', 0]);
        assert_eq!(Name::root().as_wire(), &[0]);
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
        // 0: "a" root; 3: "b" + pointer to 0.
        let msg = [1, b'a', 0, 1, b'b', 0xC0, 0, 7];
        let mut r = Reader::new(&msg);
        r.bytes(3).unwrap();
        assert_eq!(Name::decode(&mut r).unwrap(), name(&[b"b", b"a"]));
        assert_eq!(r.position(), 7);
    }

    #[test]
    fn decode_rejects_pointers_that_do_not_go_back() {
        // A pointer to itself, to later bytes, and to a label that points back at it.
        for msg in [&[0xC0, 0][..], &[0xC0, 2, 0], &[1, b'a', 0xC0, 0]] {
            let mut r = Reader::new(msg);
            let err = Name::decode(&mut r).unwrap_err();
            assert_eq!(err.kind, DecodeErrorKind::BadPointer, "{msg:?}");
        }
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
