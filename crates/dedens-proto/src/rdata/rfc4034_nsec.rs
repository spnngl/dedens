//! NSEC: the next name of a zone and the types of the name it is owned by (RFC 4034 §4), and the type bit maps that
//! NSEC3 shares (RFC 5155 §3.2.1).

use core::fmt;
use std::borrow::Cow;

use crate::codes::RecordType;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::Name;
use crate::text::{Fields, TextError, TextErrorKind};
use crate::wire::{Reader, Writer};

/// Bytes that are not the type bit maps of RFC 4034 §4.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TypeBitmapError {
    /// A window number that does not exceed the one before it.
    #[error("type bit map windows must be in increasing order")]
    WindowOrder,
    /// A window of no bytes, of more than 32, or cut short.
    #[error("type bit map window must hold 1 to 32 bytes")]
    WindowLength,
    /// A window whose last byte is zero.
    #[error("type bit map window ends with a zero byte")]
    TrailingZero,
}

/// The record types present at a name: windows of 256 types, each a bit map of 1 to 32 bytes, in increasing
/// order, without trailing zero bytes (RFC 4034 §4.1.2). Bytes that break these rules are not a `TypeBitmap`, so
/// one set of types has one value and one wire form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeBitmap<'a>(Cow<'a, [u8]>);

impl<'a> TypeBitmap<'a> {
    /// The type bit maps in `wire`, which it borrows.
    ///
    /// # Errors
    ///
    /// [`TypeBitmapError`] when `wire` breaks the rules of RFC 4034 §4.1.2.
    pub fn from_wire(wire: &'a [u8]) -> Result<Self, TypeBitmapError> {
        let mut rest = wire;
        let mut previous = None;
        while let [window, len, tail @ ..] = rest {
            if previous.is_some_and(|p| p >= *window) {
                return Err(TypeBitmapError::WindowOrder);
            }
            previous = Some(*window);
            let len = usize::from(*len);
            let (bits, after) = tail
                .split_at_checked(len)
                .filter(|_| (1..=32).contains(&len))
                .ok_or(TypeBitmapError::WindowLength)?;
            if bits.last() == Some(&0) {
                return Err(TypeBitmapError::TrailingZero);
            }
            rest = after;
        }
        if rest.is_empty() {
            Ok(Self(Cow::Borrowed(wire)))
        } else {
            Err(TypeBitmapError::WindowLength)
        }
    }

    /// The set of `types`, in any order, repeats ignored.
    #[must_use]
    pub fn from_types(types: impl IntoIterator<Item = RecordType>) -> TypeBitmap<'static> {
        let mut types: Vec<u16> = types.into_iter().map(u16::from).collect();
        types.sort_unstable();
        types.dedup();
        let mut wire = Vec::new();
        for group in types.chunk_by(|a, b| a >> 8 == b >> 8) {
            let Some(&first) = group.first() else {
                continue;
            };
            let mut bits = [0_u8; 32];
            let mut used = 0;
            for rtype in group {
                let [_, low] = rtype.to_be_bytes();
                let byte = usize::from(low / 8);
                bits[byte] |= 0x80 >> (low % 8);
                used = used.max(byte + 1);
            }
            wire.push(first.to_be_bytes()[0]);
            wire.push(u8::try_from(used).unwrap_or(32));
            wire.extend_from_slice(&bits[..used]);
        }
        TypeBitmap(Cow::Owned(wire))
    }

    /// The same set, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> TypeBitmap<'static> {
        TypeBitmap(Cow::Owned(self.0.into_owned()))
    }

    /// The wire form: the windows, each `window number, length, bit map`.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.0
    }

    /// Whether `rtype` is in the set.
    #[must_use]
    pub fn contains(&self, rtype: RecordType) -> bool {
        let [window, low] = u16::from(rtype).to_be_bytes();
        self.windows()
            .find(|(number, _)| *number == window)
            .and_then(|(_, bits)| bits.get(usize::from(low / 8)))
            .is_some_and(|byte| byte & (0x80 >> (low % 8)) != 0)
    }

    /// The types in the set, in increasing order.
    pub fn types(&self) -> impl Iterator<Item = RecordType> {
        self.windows().flat_map(|(window, bits)| {
            (0_u16..).zip(bits).flat_map(move |(index, byte)| {
                (0_u16..8)
                    .filter(move |bit| byte & (0x80 >> bit) != 0)
                    .map(move |bit| RecordType((u16::from(window) << 8) | (index * 8 + bit)))
            })
        })
    }

    /// Whether no type is in the set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The windows as `(number, bit map)`; the bytes were checked, so none is cut short.
    fn windows(&self) -> impl Iterator<Item = (u8, &[u8])> {
        let mut rest: &[u8] = &self.0;
        core::iter::from_fn(move || {
            let [window, len, tail @ ..] = rest else {
                return None;
            };
            let (bits, after) = tail.split_at_checked(usize::from(*len))?;
            rest = after;
            Some((*window, bits))
        })
    }

    /// Reads the type bit maps to the end of the RDATA.
    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let wire = r.rest();
        Self::from_wire(wire).map_err(|e| {
            r.error(DecodeErrorKind::Invalid(match e {
                TypeBitmapError::WindowOrder => "type bit map windows out of order",
                TypeBitmapError::WindowLength => "type bit map window of invalid length",
                TypeBitmapError::TrailingZero => "type bit map window ends with a zero byte",
            }))
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&self.0)
    }
}

impl TypeBitmap<'static> {
    /// Reads the type mnemonics (or `TYPEn`) left in the entry, in any order, as a set.
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let mut types = Vec::new();
        while let Some(token) = f.next_opt()? {
            let rtype = str::from_utf8(token.raw)
                .ok()
                .and_then(|s| s.parse::<RecordType>().ok())
                .ok_or(token.error(TextErrorKind::Invalid("type in the type bit map")))?;
            types.push(rtype);
        }
        Ok(Self::from_types(types))
    }
}

/// The types as mnemonics, in increasing order, a blank before each.
impl fmt::Display for TypeBitmap<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.types().try_for_each(|rtype| write!(f, " {rtype}"))
    }
}

/// The next name in the zone, and the types at the owner name: the link of the NSEC chain.
///
/// The next name is never compressed (RFC 4034 §4.1.1, RFC 3597 §4): RDATA with a compression pointer there is
/// kept opaque (D70).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec<'a> {
    /// The next owner name in the canonical order of the zone; the last NSEC of a zone holds the apex.
    pub next: Name<'a>,
    /// The types of the `RRsets` at the owner name.
    pub types: TypeBitmap<'a>,
}

impl<'a> Nsec<'a> {
    /// The same data, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Nsec<'static> {
        Nsec {
            next: self.next.into_owned(),
            types: self.types.into_owned(),
        }
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            next: Name::decode_uncompressed(r)?,
            types: TypeBitmap::decode(r)?,
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        self.next.encode(w)?;
        self.types.encode(w)
    }
}

impl Nsec<'static> {
    /// Reads `next-name type...`.
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        Ok(Self {
            next: f.name("NSEC next name")?,
            types: TypeBitmap::from_text(f)?,
        })
    }
}

/// `next-name type...`, the types as mnemonics.
impl fmt::Display for Nsec<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.next, self.types)
    }
}
