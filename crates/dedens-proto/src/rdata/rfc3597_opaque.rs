//! Unknown and unsupported types: RDATA kept as bytes (RFC 3597 §4-5).

use std::borrow::Cow;

use crate::codes::RecordType;
use crate::error::{DecodeError, EncodeError};
use crate::name::{MAX_NAME_LEN, Name};
use crate::wire::{Reader, Writer};

/// RDATA of a type this crate does not interpret, or whose content is invalid for its type (D9).
///
/// The bytes never hold compression pointers: names in the types that may carry compressed ones are decompressed
/// on decode (RFC 3597 §4), so the bytes keep their meaning outside the message they came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Opaque<'a> {
    rtype: RecordType,
    data: Cow<'a, [u8]>,
}

/// One field of the RDATA of a type that holds names but has no typed form here.
#[derive(Debug, Clone, Copy)]
enum Field {
    Name,
    Bytes(usize),
    CharacterString,
    Rest,
}

impl<'a> Opaque<'a> {
    /// RDATA of `rtype` from its wire bytes, borrowed.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when `rtype` holds names (see [`RData::may_hold_compressed_names`]) and `data` does not
    /// parse as its fields with uncompressed names.
    ///
    /// [`RData::may_hold_compressed_names`]: super::RData::may_hold_compressed_names
    pub fn new(rtype: RecordType, data: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data);
        let opaque = Self::decode_with(rtype, &mut r, Name::decode_uncompressed)?;
        if r.is_empty() {
            Ok(opaque)
        } else {
            Err(r.error(crate::error::DecodeErrorKind::RdataLength))
        }
    }

    /// The record type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// The RDATA bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// RDATA of an invalid record of an interpreted type, kept as received (D9); never one that holds names.
    pub(crate) const fn invalid(rtype: RecordType, data: &'a [u8]) -> Self {
        Self {
            rtype,
            data: Cow::Borrowed(data),
        }
    }

    /// Whether `rtype` is one of the types without a typed form that hold names (see [`layout`]).
    pub(super) const fn holds_names(rtype: RecordType) -> bool {
        layout(rtype).is_some()
    }

    /// Reads RDATA of `rtype`, decompressing the names of the types listed in [`layout`].
    pub(super) fn decode(rtype: RecordType, r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Self::decode_with(rtype, r, Name::decode)
    }

    fn decode_with(
        rtype: RecordType,
        r: &mut Reader<'a>,
        name: NameFn<'a>,
    ) -> Result<Self, DecodeError> {
        let Some(fields) = layout(rtype) else {
            return Ok(Self::invalid(rtype, r.rest()));
        };
        let mut start = *r;
        let data = if read_fields(fields, r, name, None)? {
            // Pointers mean nothing outside the message: copy the fields with the names uncompressed.
            let mut data = Vec::with_capacity(r.position() - start.position());
            read_fields(fields, &mut start, name, Some(&mut data))?;
            Cow::Owned(data)
        } else {
            Cow::Borrowed(start.bytes(r.position() - start.position())?)
        };
        Ok(Self { rtype, data })
    }

    /// The same RDATA, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Opaque<'static> {
        Opaque {
            rtype: self.rtype,
            data: Cow::Owned(self.data.into_owned()),
        }
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&self.data)
    }
}

/// Fields of the types without a typed form whose names receivers decompress: MUST for those of RFC 1035, SHOULD
/// for the others (RFC 3597 §4).
const fn layout(rtype: RecordType) -> Option<&'static [Field]> {
    use Field::{Bytes, CharacterString, Name, Rest};
    Some(match rtype {
        RecordType::MD | RecordType::MF | RecordType::MB | RecordType::MG | RecordType::MR => {
            &[Name]
        }
        RecordType::MINFO | RecordType::RP => &[Name, Name],
        RecordType::AFSDB | RecordType::RT => &[Bytes(2), Name],
        RecordType::PX => &[Bytes(2), Name, Name],
        RecordType::NAPTR => &[
            Bytes(4),
            CharacterString,
            CharacterString,
            CharacterString,
            Name,
        ],
        // Type covered, algorithm, labels, original TTL, expiration, inception, key tag; signer; signature.
        RecordType::SIG => &[Bytes(18), Name, Rest],
        RecordType::NXT => &[Name, Rest],
        _ => return None,
    })
}

/// Reads a name for [`read_fields`]: compressed or not.
type NameFn<'a> = fn(&mut Reader<'a>) -> Result<Name<'a>, DecodeError>;

/// Reads `fields`, and appends them to `copy` when given, names uncompressed; returns whether a name had
/// compression pointers.
fn read_fields<'a>(
    fields: &[Field],
    r: &mut Reader<'a>,
    name: NameFn<'a>,
    mut copy: Option<&mut Vec<u8>>,
) -> Result<bool, DecodeError> {
    let mut packed = false;
    for field in fields {
        let mut start = *r;
        match field {
            Field::Name => {
                let name = name(r)?;
                packed |= name.is_packed();
                if let Some(out) = copy.as_deref_mut() {
                    out.extend_from_slice(name.to_wire(&mut [0; MAX_NAME_LEN]));
                }
                continue;
            }
            Field::Bytes(n) => {
                r.bytes(*n)?;
            }
            Field::CharacterString => {
                let len = r.u8()?;
                r.bytes(usize::from(len))?;
            }
            Field::Rest => {
                r.rest();
            }
        }
        if let Some(out) = copy.as_deref_mut() {
            out.extend_from_slice(start.bytes(r.position() - start.position())?);
        }
    }
    Ok(packed)
}
