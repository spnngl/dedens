//! A whole DNS message (RFC 1035 §4.1) with its EDNS OPT record lifted out (D8, RFC 6891).

use crate::codes::{Opcode, Rcode, RecordType};
use crate::edns::{Edns, OptionCode};
use crate::error::{DecodeError, EncodeError};
use crate::header::{Counts, Flags, HEADER_LEN, Header};
use crate::question::Question;
use crate::record::{RawRecord, Record, Ttl, decode_rdata};
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

impl Section {
    /// The place of the section in a message, from 0 for the answer.
    pub(crate) const fn position(self) -> usize {
        match self {
            Self::Answer => 0,
            Self::Authority => 1,
            Self::Additional => 2,
        }
    }
}

/// A message: header, the four sections, and EDNS.
///
/// The counts of the header are the lengths of the sections, so they are not stored (D8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message<'a> {
    /// The header, without counts; its rcode holds the low 4 bits, see [`Message::rcode`].
    pub header: Header,
    /// The question section; a conforming message has at most one (RFC 9619).
    pub questions: Vec<Question<'a>>,
    /// The answer section.
    pub answer: Vec<Record<'a>>,
    /// The authority section.
    pub authority: Vec<Record<'a>>,
    /// The additional section, without the OPT record.
    pub additional: Vec<Record<'a>>,
    /// The OPT record, when the message has one.
    pub edns: Option<Edns<'a>>,
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

/// How much of a message [`Message::encode_truncated`] wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encoded {
    /// Bytes written.
    pub len: usize,
    /// Whether TC was set because the answer or authority section lost records.
    pub truncated: bool,
    /// Records left out, from any section.
    pub dropped: usize,
}

/// The result of [`Message::decode`]: the message and the rules it breaks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decoded<'a> {
    /// The message.
    pub message: Message<'a>,
    /// The rules it breaks, in the order found; empty for a conforming message.
    pub violations: Vec<Violation>,
}

impl Decoded<'_> {
    /// The same result, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Decoded<'static> {
        Decoded {
            message: self.message.into_owned(),
            violations: self.violations,
        }
    }

    /// Empties the result, keeping the capacity of its vectors for [`Message::decode_reusing`], and frees it from
    /// the input it borrowed.
    #[must_use]
    pub fn recycle(self) -> Decoded<'static> {
        let Message {
            questions,
            answer,
            authority,
            additional,
            ..
        } = self.message;
        Decoded {
            message: Message {
                questions: recycle(questions),
                answer: recycle(answer),
                authority: recycle(authority),
                additional: recycle(additional),
                ..Message::default()
            },
            violations: recycle(self.violations),
        }
    }

    /// Empties the result, keeping the capacity of its vectors.
    fn clear(&mut self) {
        let message = &mut self.message;
        message.questions.clear();
        message.answer.clear();
        message.authority.clear();
        message.additional.clear();
        message.edns = None;
        self.violations.clear();
    }
}

/// An empty vector with the allocation of `v`: `T` and `U` differ only by lifetimes, so they share a layout and
/// the standard library collects in place.
fn recycle<T, U>(mut v: Vec<T>) -> Vec<U> {
    v.clear();
    v.into_iter().filter_map(|_| None).collect()
}

impl<'a> Message<'a> {
    /// A recursive query for `question`: RD set, and EDNS advertising the default UDP payload (D10).
    #[must_use]
    pub fn query(id: u16, question: Question<'a>) -> Self {
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

    /// The same message, owning its bytes, to keep it past the buffer it was decoded from.
    #[must_use]
    pub fn into_owned(self) -> Message<'static> {
        let owned =
            |records: Vec<Record<'a>>| records.into_iter().map(Record::into_owned).collect();
        Message {
            header: self.header,
            questions: self
                .questions
                .into_iter()
                .map(Question::into_owned)
                .collect(),
            answer: owned(self.answer),
            authority: owned(self.authority),
            additional: owned(self.additional),
            edns: self.edns.map(Edns::into_owned),
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
    pub fn decode(msg: &'a [u8]) -> Result<Decoded<'a>, DecodeError> {
        let mut out = Decoded::default();
        decode_into(msg, &mut out)?;
        Ok(out)
    }

    /// Reads a message like [`Message::decode`], into the vectors of `spare` so that decoding message after
    /// message allocates only for one bigger than any before; get `spare` back with [`Decoded::recycle`]. On error,
    /// `spare` keeps its vectors.
    ///
    /// ```
    /// # use dedens_proto::{Decoded, Message};
    /// let mut spare = Decoded::default();
    /// for id in [1, 2] {
    ///     let wire = [0, id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    ///     let decoded = Message::decode_reusing(&wire, &mut spare)?;
    ///     assert_eq!(decoded.message.header.id, u16::from(id));
    ///     spare = decoded.recycle();
    /// }
    /// # Ok::<(), dedens_proto::DecodeError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Message::decode`].
    pub fn decode_reusing(
        msg: &'a [u8],
        spare: &mut Decoded<'static>,
    ) -> Result<Decoded<'a>, DecodeError> {
        // A `Decoded<'static>` is a `Decoded<'a>`: only its contents must go.
        let mut out: Decoded<'a> = core::mem::take(spare);
        out.clear();
        match decode_into(msg, &mut out) {
            Ok(()) => Ok(out),
            Err(error) => {
                *spare = out.recycle();
                Err(error)
            }
        }
    }

    /// Writes the message into `buf` (at most 65535 bytes of it are used), compressing the names RFC 1035
    /// allows to (RFC 1035 §4.1.4, RFC 3597 §4).
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        self.encode_into(buf, false).map(|encoded| encoded.len)
    }

    /// Like [`Message::encode`], but when the records do not fit, writes the ones that do and drops the rest
    /// (D10).
    ///
    /// Dropping starts at the first record that does not fit; the OPT record is always kept (RFC 6891 §7). TC is
    /// set only if the answer or authority section lost records; when only additional data does not fit, TC stays
    /// clear and the whole `RRset` of the first record that does not fit is dropped, so no partial `RRset` is left
    /// (RFC 2181 §9). An `RRset` is a run of consecutive records with the same owner, type and class.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when the header, the questions and the OPT record do not fit.
    pub fn encode_truncated(&self, buf: &mut [u8]) -> Result<Encoded, EncodeError> {
        self.encode_into(buf, true)
    }

    fn encode_into(&self, buf: &mut [u8], may_truncate: bool) -> Result<Encoded, EncodeError> {
        let mut w = Writer::new(buf);
        self.header.encode(Counts::default(), &mut w)?;
        for q in &self.questions {
            q.encode(&mut w)?;
        }
        if let Some(edns) = &self.edns {
            w.hold_back(edns.wire_len())?;
        }
        let mut written = [0_usize; 3];
        let mut tc = false;
        let mut opt_written = false;
        let sections = [&self.answer, &self.authority, &self.additional];
        'sections: for (section, (count, records)) in written.iter_mut().zip(sections).enumerate() {
            if section == 2 {
                // The OPT record opens the additional section, so a decoder lifts it before any stray OPT
                // record kept among the additional records (D9).
                w.release_tail();
                if let Some(edns) = &self.edns {
                    edns.encode(&mut w)?;
                }
                opt_written = true;
            }
            // Start of the run of records of the RRset being written: offset, count, and its first record.
            let mut rrset = (w.len(), 0, None::<&Record<'_>>);
            for record in records {
                // Only truncation needs to know where the RRset started.
                if may_truncate && !rrset.2.is_some_and(|first| same_rrset(first, record)) {
                    rrset = (w.len(), *count, Some(record));
                }
                let before = w.len();
                match record.encode(&mut w) {
                    Ok(()) => *count += 1,
                    Err(EncodeError::BufferFull) if may_truncate => {
                        if section < 2 {
                            // TC tells the client the answer is partial: a partial RRset may stay (RFC 2181 §9).
                            w.truncate(before);
                            tc = true;
                        } else {
                            // Without TC, a partial RRset would be taken for the whole one: drop all of it.
                            w.truncate(rrset.0);
                            *count = rrset.1;
                        }
                        break 'sections;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        if !opt_written {
            w.release_tail();
            if let Some(edns) = &self.edns {
                edns.encode(&mut w)?;
            }
        }
        let [answers, authority, additional] = written;
        let additional = additional + usize::from(self.edns.is_some());
        for (at, n) in [
            (4, self.questions.len()),
            (6, answers),
            (8, authority),
            (10, additional),
        ] {
            w.patch_u16(at, u16::try_from(n).map_err(|_| EncodeError::BufferFull)?);
        }
        if tc {
            w.patch_u16(2, w.u16_at(2).unwrap_or_default() | Flags::TC.bits());
        }
        let total = self.answer.len() + self.authority.len() + self.additional.len();
        Ok(Encoded {
            len: w.len(),
            truncated: tc,
            dropped: total - (answers + authority + written[2]),
        })
    }

    /// Writes the message into a new vector.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it is longer than 65535 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        // Most messages fit in 512 bytes; larger ones are encoded again into a buffer 4 times larger.
        let mut buf = vec![0; 512];
        loop {
            match self.encode(&mut buf) {
                Ok(len) => {
                    buf.truncate(len);
                    return Ok(buf);
                }
                Err(EncodeError::BufferFull) if buf.len() < MAX_MESSAGE_LEN => {
                    buf.resize((buf.len() * 4).min(MAX_MESSAGE_LEN), 0);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Whether two records belong to the same `RRset`: same owner, type and class (RFC 2181 §5).
fn same_rrset(a: &Record<'_>, b: &Record<'_>) -> bool {
    a.name == b.name && a.rtype() == b.rtype() && a.class == b.class
}

/// `claimed` entries, capped by how many of at least `min_len` bytes fit in `remaining`.
fn bounded(claimed: u16, remaining: usize, min_len: usize) -> usize {
    usize::from(claimed).min(remaining / min_len)
}

/// One entry of a message, met by [`walk`] in wire order.
pub(crate) enum Entry<'a> {
    /// The header, met first.
    Header(Header, Counts),
    /// A question.
    Question(Question<'a>, Span),
    /// A record of `Section`.
    Record(Section, RawRecord<'a>, Span),
    /// The OPT record lifted out as EDNS (D8); a misplaced or extra one is a [`Entry::Record`].
    Opt(RawRecord<'a>, Span),
}

/// Where an entry sits in the message: the start of its name, and of the fields after it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Span {
    pub(crate) name: usize,
    pub(crate) fixed: usize,
}

/// Reads the structure of `msg`, handing each entry to `sink` in wire order, and pushes the violations it finds:
/// several questions, a misplaced or extra OPT record, trailing bytes (D9). `sink` reads what it needs of each
/// entry and pushes the violations of RDATA and options.
pub(crate) fn walk<'a>(
    msg: &'a [u8],
    violations: &mut Vec<Violation>,
    mut sink: impl FnMut(Entry<'a>, &mut Vec<Violation>) -> Result<(), DecodeError>,
) -> Result<(), DecodeError> {
    let mut r = Reader::new(msg);
    let (header, counts) = Header::decode(&mut r)?;
    sink(Entry::Header(header, counts), violations)?;
    for _ in 0..counts.questions {
        let name = r.position();
        let question = Question::decode(&mut r)?;
        let fixed = r.position() - 4;
        sink(Entry::Question(question, Span { name, fixed }), violations)?;
    }
    if counts.questions > 1 {
        violations.push(Violation::MultipleQuestions);
    }

    let mut opt_seen = false;
    for (section, count) in [
        (Section::Answer, counts.answers),
        (Section::Authority, counts.authority),
        (Section::Additional, counts.additional),
    ] {
        for _ in 0..count {
            let name = r.position();
            let raw = Record::read_raw(&mut r)?;
            // Type, class, TTL and RDLENGTH: 10 bytes before the RDATA.
            let span = Span {
                name,
                fixed: raw.rdata.position() - 10,
            };
            if raw.rtype == RecordType::OPT {
                let reject = if section != Section::Additional {
                    Some(Violation::OptOutsideAdditional)
                } else if !raw.name.is_root() {
                    Some(Violation::OptOwnerNotRoot)
                } else if opt_seen {
                    Some(Violation::MultipleOpt)
                } else {
                    None
                };
                if let Some(violation) = reject {
                    violations.push(violation);
                } else {
                    opt_seen = true;
                    sink(Entry::Opt(raw, span), violations)?;
                    continue;
                }
            }
            sink(Entry::Record(section, raw, span), violations)?;
        }
    }

    if !r.is_empty() {
        violations.push(Violation::TrailingBytes { len: r.remaining() });
    }
    Ok(())
}

/// Reads a message into the empty vectors of `out`.
fn decode_into<'a>(msg: &'a [u8], out: &mut Decoded<'a>) -> Result<(), DecodeError> {
    let Message {
        header,
        questions,
        answer,
        authority,
        additional,
        edns,
    } = &mut out.message;
    walk(msg, &mut out.violations, |entry, violations| {
        match entry {
            Entry::Header(read, counts) => {
                *header = read;
                // Capped by what the input can hold rather than by the counts it claims.
                let remaining = msg.len() - HEADER_LEN;
                questions.reserve(bounded(counts.questions, remaining, MIN_QUESTION_LEN));
                answer.reserve(bounded(counts.answers, remaining, MIN_RECORD_LEN));
                authority.reserve(bounded(counts.authority, remaining, MIN_RECORD_LEN));
                additional.reserve(bounded(counts.additional, remaining, MIN_RECORD_LEN));
            }
            Entry::Question(question, _) => questions.push(question),
            Entry::Opt(raw, _) => {
                let (parsed, invalid) = Edns::from_opt(raw.class.0, raw.ttl, raw.rdata)?;
                violations.extend(invalid.into_iter().map(|o| Violation::InvalidOption {
                    code: o.code,
                    error: o.error,
                }));
                *edns = Some(parsed);
            }
            Entry::Record(section, raw, _) => {
                let records = match section {
                    Section::Answer => &mut *answer,
                    Section::Authority => &mut *authority,
                    Section::Additional => &mut *additional,
                };
                let (data, invalid) = decode_rdata(raw.rtype, raw.rdata)?;
                if let Some(error) = invalid {
                    violations.push(Violation::InvalidRdata {
                        section,
                        index: records.len(),
                        error,
                    });
                }
                let ttl = Ttl::of_record(raw.rtype, raw.ttl);
                records.push(Record::new(raw.name, raw.class, ttl, data));
            }
        }
        Ok(())
    })
}
