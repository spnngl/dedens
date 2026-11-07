//! The question section (RFC 1035 §4.1.2).

use zerocopy::IntoBytes;
use zerocopy::network_endian::U16;

use crate::codes::{Class, RecordType};
use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

/// What is asked: a name, a type and a class (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question<'a> {
    /// The name asked about (QNAME).
    pub name: Name<'a>,
    /// The type asked for (QTYPE).
    pub qtype: RecordType,
    /// The class asked in (QCLASS).
    pub qclass: Class,
}

impl<'a> Question<'a> {
    /// A question in class IN.
    #[must_use]
    pub const fn new(name: Name<'a>, qtype: RecordType) -> Self {
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
    pub(crate) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let name = Name::decode(r)?;
        let [qtype, qclass] = r.fields::<[U16; 2]>()?;
        Ok(Self {
            name,
            qtype: RecordType(qtype.get()),
            qclass: Class(qclass.get()),
        })
    }

    /// The same question, owning its name.
    #[must_use]
    pub fn into_owned(self) -> Question<'static> {
        Question {
            name: self.name.into_owned(),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }

    /// Writes the question, its name compressed.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit; the writer is then left as it was.
    pub(crate) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.all_or_nothing(|w| {
            w.put_name_compressed(&self.name)?;
            w.put_bytes([U16::new(self.qtype.0), U16::new(self.qclass.0)].as_bytes())
        })
    }
}
