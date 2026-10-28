//! The 12-byte message header (RFC 1035 §4.1.1).

use core::fmt;
use core::ops::BitOr;

use crate::codes::{Opcode, Rcode};
use crate::error::{DecodeError, EncodeError};
use crate::wire::{Reader, Writer};

/// Length of the header on the wire.
pub const HEADER_LEN: usize = 12;

/// Adds `contains`, `with`, `without` and `bits` to a set of one-bit flags kept as their bits in a `u16`.
macro_rules! flag_set {
    ($name:ident) => {
        impl $name {
            /// Whether every flag of `other` is set.
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            /// These flags plus those of `other`.
            #[must_use]
            pub const fn with(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }

            /// These flags minus those of `other`.
            #[must_use]
            pub const fn without(self, other: Self) -> Self {
                Self(self.0 & !other.0)
            }

            /// The flags at their bit positions on the wire.
            #[must_use]
            pub const fn bits(self) -> u16 {
                self.0
            }
        }
    };
}

pub(crate) use flag_set;

/// The one-bit header flags: QR, AA, TC, RD, RA, the reserved Z bit, AD and CD (RFC 1035 §4.1.1, RFC 4035 §3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags(u16);

impl Flags {
    /// No flag set.
    pub const NONE: Self = Self(0);
    /// Response, not a query.
    pub const QR: Self = Self(0x8000);
    /// Authoritative answer.
    pub const AA: Self = Self(0x0400);
    /// Truncated (RFC 1035 §4.2.1, RFC 2181 §9).
    pub const TC: Self = Self(0x0200);
    /// Recursion desired.
    pub const RD: Self = Self(0x0100);
    /// Recursion available.
    pub const RA: Self = Self(0x0080);
    /// Reserved, must be zero.
    pub const Z: Self = Self(0x0040);
    /// Authentic data (RFC 4035 §3.2.3).
    pub const AD: Self = Self(0x0020);
    /// Checking disabled (RFC 4035 §3.2.2).
    pub const CD: Self = Self(0x0010);

    const MASK: u16 = 0x8000 | 0x0400 | 0x0200 | 0x0100 | 0x0080 | 0x0040 | 0x0020 | 0x0010;
    const NAMES: [(Self, &str); 8] = [
        (Self::QR, "qr"),
        (Self::AA, "aa"),
        (Self::TC, "tc"),
        (Self::RD, "rd"),
        (Self::RA, "ra"),
        (Self::Z, "z"),
        (Self::AD, "ad"),
        (Self::CD, "cd"),
    ];

    /// Flags from the header's second 16-bit word, ignoring the opcode and rcode bits.
    #[must_use]
    pub const fn from_word(word: u16) -> Self {
        Self(word & Self::MASK)
    }

    /// The names of the set flags, in header order.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |&(flag, _)| self.contains(flag))
            .map(|(_, name)| name)
    }
}

flag_set!(Flags);

impl BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.with(rhs)
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.names()).finish()
    }
}

/// The section counts of a header, which `Message` never stores: they are the lengths
/// of its sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Entries in the question section.
    pub questions: u16,
    /// Records in the answer section.
    pub answers: u16,
    /// Records in the authority section.
    pub authority: u16,
    /// Records in the additional section.
    pub additional: u16,
}

/// A message header without its counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    /// Identifier copied from query to response.
    pub id: u16,
    /// The one-bit flags.
    pub flags: Flags,
    /// Kind of query.
    pub opcode: Opcode,
    /// The low four bits of the response code, 0 to 15; `Message::rcode` adds the upper eight from EDNS, and
    /// `Message::set_rcode` splits a full one.
    pub rcode: Rcode,
}

impl Header {
    /// Reads a header and its counts.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when fewer than 12 bytes are left.
    pub fn decode(r: &mut Reader<'_>) -> Result<(Self, Counts), DecodeError> {
        let id = r.u16()?;
        let [hi, lo] = r.u16()?.to_be_bytes();
        let header = Self {
            id,
            flags: Flags::from_word(u16::from_be_bytes([hi, lo])),
            opcode: Opcode((hi >> 3) & 0x0F),
            rcode: Rcode(u16::from(lo & 0x0F)),
        };
        let counts = Counts {
            questions: r.u16()?,
            answers: r.u16()?,
            authority: r.u16()?,
            additional: r.u16()?,
        };
        Ok((header, counts))
    }

    /// Writes the header with `counts`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::OpcodeOutOfRange`] or [`EncodeError::RcodeOutOfRange`] when the opcode or the rcode does
    /// not fit in its four bits; [`EncodeError::BufferFull`] when the header does not fit.
    pub fn encode(&self, counts: Counts, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let opcode = Some(self.opcode.0)
            .filter(|&op| op <= 0x0F)
            .ok_or(EncodeError::OpcodeOutOfRange)?;
        let rcode = u8::try_from(self.rcode.0)
            .ok()
            .filter(|&rcode| rcode <= 0x0F)
            .ok_or(EncodeError::RcodeOutOfRange)?;
        let [flags_hi, flags_lo] = self.flags.bits().to_be_bytes();
        let hi = flags_hi | (opcode << 3);
        let lo = flags_lo | rcode;
        w.put_u16(self.id)?;
        w.put_bytes(&[hi, lo])?;
        w.put_u16(counts.questions)?;
        w.put_u16(counts.answers)?;
        w.put_u16(counts.authority)?;
        w.put_u16(counts.additional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_and_opcode_and_rcode_share_two_bytes() {
        // id 0x1234, QR RD RA, opcode UPDATE (5), rcode REFUSED (5), counts 1 2 3 4.
        let wire = [0x12, 0x34, 0b1010_1001, 0b1000_0101, 0, 1, 0, 2, 0, 3, 0, 4];
        let (header, counts) = Header::decode(&mut Reader::new(&wire)).unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(header.flags, Flags::QR | Flags::RD | Flags::RA);
        assert_eq!(header.opcode, Opcode::UPDATE);
        assert_eq!(header.rcode, Rcode::REFUSED);
        assert_eq!(
            counts,
            Counts {
                questions: 1,
                answers: 2,
                authority: 3,
                additional: 4
            }
        );

        let mut buf = [0; HEADER_LEN];
        let mut w = Writer::new(&mut buf);
        header.encode(counts, &mut w).unwrap();
        assert_eq!(w.written(), &wire);
    }

    #[test]
    fn short_header_is_an_error() {
        assert!(Header::decode(&mut Reader::new(&[0; 11])).is_err());
    }

    #[test]
    fn flag_names_follow_header_order() {
        let flags = Flags::CD | Flags::QR | Flags::AA;
        assert_eq!(flags.names().collect::<Vec<_>>(), ["qr", "aa", "cd"]);
        assert!(!flags.without(Flags::AA).contains(Flags::AA));
    }
}
