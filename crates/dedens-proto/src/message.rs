//! A whole DNS message (RFC 1035 §4.1) with its EDNS OPT record lifted out (D8, RFC 6891).

use crate::codes::{Opcode, Rcode, RecordType};
use crate::edns::{Edns, OptionCode};
use crate::error::{DecodeError, EncodeError};
use crate::header::{Counts, Flags, Header};
use crate::question::Question;
use crate::record::Record;
use crate::wire::{MAX_MESSAGE_LEN, Reader, Writer};

/// Smallest wire size of a question (root name, type, class) and of a record (root name, fixed fields), used to
/// bound allocations by what the input can hold rather than by the counts it claims.
const MIN_QUESTION_LEN: usize = 5;
const MIN_RECORD_LEN: usize = 11;

/// The record sections of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    /// Answer (RFC 1035 §4.1.3).
    Answer,
    /// Authority.
    Authority,
    /// Additional.
    Additional,
}

/// A message: header, the four sections, and EDNS.
///
/// The counts of the header are the lengths of the sections, so they are not stored (D8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// The header, without counts; its rcode holds the low 4 bits, see [`Message::rcode`].
    pub header: Header,
    /// The question section; a conforming message has at most one (RFC 9619).
    pub questions: Vec<Question>,
    /// The answer section.
    pub answer: Vec<Record>,
    /// The authority section.
    pub authority: Vec<Record>,
    /// The additional section, without the OPT record.
    pub additional: Vec<Record>,
    /// The OPT record, when the message has one.
    pub edns: Option<Edns>,
}

/// A message that was decoded although it breaks a rule, and what it breaks (D9).
///
/// A client shows these; a server answers FORMERR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Violation {
    /// More than one question (RFC 9619 §4).
    #[error("more than one question")]
    MultipleQuestions,
    /// More than one OPT record (RFC 6891 §6.1.1); the extra ones stay in the additional section as opaque records.
    #[error("more than one OPT record")]
    MultipleOpt,
    /// An OPT record outside the additional section (RFC 6891 §6.1.1); it stays there as an opaque record.
    #[error("OPT record outside the additional section")]
    OptOutsideAdditional,
    /// An OPT record whose owner is not the root (RFC 6891 §6.1.2); it stays as an opaque record.
    #[error("OPT record owner is not the root")]
    OptOwnerNotRoot,
    /// Bytes after the last record.
    #[error("{len} bytes after the last record")]
    TrailingBytes {
        /// How many.
        len: usize,
    },
    /// A record's RDATA is invalid for its type; the record is opaque.
    #[error("invalid RDATA in record {index} of {section:?}: {error}")]
    InvalidRdata {
        /// The section of the record.
        section: Section,
        /// Its index in that section.
        index: usize,
        /// What is wrong.
        error: DecodeError,
    },
    /// The content of an EDNS option is invalid for its code; it is an unknown option.
    #[error("invalid content in EDNS option {code}: {error}")]
    InvalidOption {
        /// The option code.
        code: OptionCode,
        /// What is wrong.
        error: DecodeError,
    },
}

/// The result of [`Message::decode`]: the message and the rules it breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The message.
    pub message: Message,
    /// The rules it breaks, in the order found; empty for a conforming message.
    pub violations: Vec<Violation>,
}

impl Message {
    /// A recursive query for `question`: RD set, and EDNS advertising the default UDP payload (D10).
    #[must_use]
    pub fn query(id: u16, question: Question) -> Self {
        Self {
            header: Header {
                id,
                flags: Flags::RD,
                opcode: Opcode::QUERY,
                rcode: Rcode::NOERROR,
            },
            questions: vec![question],
            edns: Some(Edns::default()),
            ..Self::default()
        }
    }

    /// The 12-bit response code: the header's low 4 bits and the OPT record's upper 8 (RFC 6891 §6.1.3).
    #[must_use]
    pub fn rcode(&self) -> Rcode {
        let ext = self.edns.as_ref().map_or(0, |e| e.ext_rcode);
        Rcode((u16::from(ext) << 4) | (self.header.rcode.0 & 0x0F))
    }

    /// Sets the response code, splitting it between the header and the OPT record.
    ///
    /// # Errors
    ///
    /// [`EncodeError::RcodeNeedsEdns`] when `rcode` is above 15 and the message has no EDNS;
    /// [`EncodeError::RcodeOutOfRange`] when it is above 4095. The message is unchanged then.
    pub fn set_rcode(&mut self, rcode: Rcode) -> Result<(), EncodeError> {
        let ext = u8::try_from(rcode.0 >> 4).map_err(|_| EncodeError::RcodeOutOfRange)?;
        match (&mut self.edns, ext) {
            (Some(edns), _) => edns.ext_rcode = ext,
            (None, 0) => {}
            (None, _) => return Err(EncodeError::RcodeNeedsEdns),
        }
        self.header.rcode = Rcode(rcode.0 & 0x0F);
        Ok(())
    }

    /// Reads a message.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the structure is broken: a section cut short, a bad name or pointer, a RDLENGTH that
    /// overruns the message, broken EDNS option framing, or invalid RDATA of a type with compressible names.
    /// Anything else that is wrong is a [`Violation`] in the result (D9).
    pub fn decode(msg: &[u8]) -> Result<Decoded, DecodeError> {
        let mut r = Reader::new(msg);
        let (header, counts) = Header::decode(&mut r)?;
        let mut violations = Vec::new();

        let mut questions =
            Vec::with_capacity(bounded(counts.questions, r.remaining(), MIN_QUESTION_LEN));
        for _ in 0..counts.questions {
            questions.push(Question::decode(&mut r)?);
        }
        if questions.len() > 1 {
            violations.push(Violation::MultipleQuestions);
        }

        let mut edns = None;
        let mut section =
            |which, count| read_section(&mut r, which, count, &mut edns, &mut violations);
        let answer = section(Section::Answer, counts.answers)?;
        let authority = section(Section::Authority, counts.authority)?;
        let additional = section(Section::Additional, counts.additional)?;

        if !r.is_empty() {
            violations.push(Violation::TrailingBytes { len: r.remaining() });
        }
        let message = Self {
            header,
            questions,
            answer,
            authority,
            additional,
            edns,
        };
        Ok(Decoded {
            message,
            violations,
        })
    }

    /// Writes the message into `buf` (at most 65535 bytes of it are used), names uncompressed.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit, or a section has more than 65535 entries.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        let additional = self.additional.len() + usize::from(self.edns.is_some());
        let counts = Counts {
            questions: count(self.questions.len())?,
            answers: count(self.answer.len())?,
            authority: count(self.authority.len())?,
            additional: count(additional)?,
        };
        self.header.encode(counts, &mut w)?;
        for q in &self.questions {
            q.encode(&mut w)?;
        }
        for record in self
            .answer
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
        {
            record.encode(&mut w)?;
        }
        if let Some(edns) = &self.edns {
            edns.encode(&mut w)?;
        }
        Ok(w.len())
    }

    /// Writes the message into a new vector.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it is longer than 65535 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = vec![0; MAX_MESSAGE_LEN];
        let len = self.encode(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}

fn count(len: usize) -> Result<u16, EncodeError> {
    u16::try_from(len).map_err(|_| EncodeError::BufferFull)
}

/// `claimed` entries, capped by how many of at least `min_len` bytes fit in `remaining`.
fn bounded(claimed: u16, remaining: usize, min_len: usize) -> usize {
    usize::from(claimed).min(remaining / min_len)
}

fn read_section(
    r: &mut Reader<'_>,
    section: Section,
    count: u16,
    edns: &mut Option<Edns>,
    violations: &mut Vec<Violation>,
) -> Result<Vec<Record>, DecodeError> {
    let mut records = Vec::with_capacity(bounded(count, r.remaining(), MIN_RECORD_LEN));
    for _ in 0..count {
        let raw = Record::read_raw(r)?;
        if raw.rtype == RecordType::OPT {
            let reject = if section != Section::Additional {
                Some(Violation::OptOutsideAdditional)
            } else if !raw.name.is_root() {
                Some(Violation::OptOwnerNotRoot)
            } else if edns.is_some() {
                Some(Violation::MultipleOpt)
            } else {
                None
            };
            if let Some(violation) = reject {
                violations.push(violation);
            } else {
                let (parsed, invalid) = Edns::from_opt(raw.class.0, raw.ttl, raw.rdata)?;
                violations.extend(invalid.into_iter().map(|o| Violation::InvalidOption {
                    code: o.code,
                    error: o.error,
                }));
                *edns = Some(parsed);
                continue;
            }
        }
        let decoded = Record::from_raw(raw)?;
        if let Some(error) = decoded.invalid_rdata {
            violations.push(Violation::InvalidRdata {
                section,
                index: records.len(),
                error,
            });
        }
        records.push(decoded.record);
    }
    Ok(records)
}
