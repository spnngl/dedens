//! The question section (RFC 1035 §4.1.2).

use crate::codes::{Class, RecordType};
use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

/// What is asked: a name, a type and a class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name asked about (QNAME).
    pub name: Name,
    /// The type asked for (QTYPE).
    pub qtype: RecordType,
    /// The class asked in (QCLASS).
    pub qclass: Class,
}

impl Question {
    /// A question in class IN.
    #[must_use]
    pub const fn new(name: Name, qtype: RecordType) -> Self {
        Self {
            name,
            qtype,
            qclass: Class::IN,
        }
    }

    /// Reads a question.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the name or the two 16-bit fields are cut short or broken.
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            name: Name::decode(r)?,
            qtype: RecordType(r.u16()?),
            qclass: Class(r.u16()?),
        })
    }

    /// Writes the question, its name uncompressed.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_name_compressed(&self.name)?;
        w.put_u16(self.qtype.0)?;
        w.put_u16(self.qclass.0)
    }
}
