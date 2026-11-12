//! A whole DNS message (RFC 1035 §4.1) with its EDNS OPT record lifted out (D8, RFC 6891).

use std::collections::HashMap;

use crate::codes::{Opcode, Rcode, RecordType};
use crate::edns::{self, Edns, EdnsOption, OptionCode};
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::header::{Counts, Flags, HEADER_LEN, Header};
use crate::name::Name;
use crate::question::Question;
use crate::record::{DecodedRecord, RawRecord, Record};
use crate::wire::{MAX_MESSAGE_LEN, Reader, Writer};

/// Smallest wire size of a question (root name, type, class) and of a record (root name, fixed fields), used to
/// bound allocations by what the input can hold rather than by the counts it claims.
const MIN_QUESTION_LEN: usize = 5;
const MIN_RECORD_LEN: usize = 11;

/// The record sections of a message (RFC 1035 §4.1).
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

/// A message: header, the four sections, and EDNS (RFC 1035 §4.1, RFC 6891 §6.1.1).
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
    /// The OPT record of the additional section whose options do not fill its RDATA: an option's code, length or
    /// data runs past it (RFC 6891 §6.1.2). It stays as an opaque record, its options unread, and is the message's
    /// one OPT record all the same: another is [`Violation::MultipleOpt`].
    #[error("EDNS option running past its OPT record")]
    OptOptionOverrun,
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
    /// Empty, with the allocation of the EDNS options of a message decoded before, for the next one.
    spare_options: Vec<EdnsOption<'a>>,
}

impl Decoded<'_> {
    /// The same result, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Decoded<'static> {
        Decoded {
            message: self.message.into_owned(),
            violations: self.violations,
            spare_options: Vec::new(),
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
            edns,
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
            spare_options: recycle(edns.map_or(self.spare_options, |edns| edns.options)),
        }
    }

    /// Empties the result, keeping the capacity of its vectors.
    fn clear(&mut self) {
        let message = &mut self.message;
        message.questions.clear();
        message.answer.clear();
        message.authority.clear();
        message.additional.clear();
        if let Some(edns) = message.edns.take() {
            self.spare_options = edns.options;
        }
        self.spare_options.clear();
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

    /// The zone a response refers the query down to (RFC 1034 §4.3.2 step 3b): the owner of its first NS record
    /// when it is a referral, NOERROR without answer or AA, its authority holding NS records and no SOA; with a
    /// SOA it is NODATA (RFC 2308 §2.2).
    #[must_use]
    pub fn referral(&self) -> Option<&Name<'a>> {
        if self.rcode() != Rcode::NOERROR
            || !self.answer.is_empty()
            || self.header.flags.contains(Flags::AA)
            || self
                .authority
                .iter()
                .any(|r| r.rdata.rtype() == RecordType::SOA)
        {
            return None;
        }
        self.authority
            .iter()
            .find(|r| r.rdata.rtype() == RecordType::NS)
            .map(|r| &r.name)
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
    /// overruns the message, or invalid RDATA of a type with compressible names; and
    /// [`DecodeErrorKind::Invalid`] for a message longer than 65535 bytes. Anything else that is wrong is a
    /// [`Violation`] in the result (D9).
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
        self.encode_into(buf, false, self.edns.as_ref())
            .map(|encoded| encoded.len)
    }

    /// Like [`Message::encode`], but when the records do not fit, writes the ones that do and drops the rest
    /// (D10).
    ///
    /// Dropping starts at the first record that does not fit; the OPT record is always kept (RFC 6891 §7). TC is
    /// set only if the answer or authority section lost records; when only additional data does not fit, TC stays
    /// clear and only whole `RRsets` stay, even when the records of one are not next to each other, so no partial
    /// `RRset` is taken for the whole one (RFC 2181 §9).
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when the header, the questions and the OPT record do not fit.
    pub fn encode_truncated(&self, buf: &mut [u8]) -> Result<Encoded, EncodeError> {
        self.encode_into(buf, true, self.edns.as_ref())
    }

    /// Writes the message with the OPT record of `edns`, in place of its own.
    fn encode_into(
        &self,
        buf: &mut [u8],
        may_truncate: bool,
        edns: Option<&Edns<'_>>,
    ) -> Result<Encoded, EncodeError> {
        let mut w = Writer::new(buf);
        self.header.encode(Counts::default(), &mut w)?;
        for q in &self.questions {
            q.encode(&mut w)?;
        }
        if let Some(edns) = edns {
            w.hold_back(edns.wire_len())?;
        }
        let mut written = [0_usize; 3];
        let mut tc = false;
        let mut opt_written = false;
        // The previous record, and where a pointer to its owner may point.
        let mut previous = None::<(&Record<'_>, u16)>;
        let sections = [&self.answer, &self.authority, &self.additional];
        'sections: for (section, (count, records)) in written.iter_mut().zip(sections).enumerate() {
            if section == 2 {
                // The OPT record opens the additional section, so a decoder lifts it before any stray OPT
                // record kept among the additional records (D9).
                w.release_tail();
                if let Some(edns) = edns {
                    edns.encode(&mut w)?;
                }
                opt_written = true;
            }
            // Where the section starts, to write it again with fewer records.
            let start = (w.len(), previous);
            for (i, record) in records.iter().enumerate() {
                match put_record(&mut w, record, previous) {
                    Ok(next) => {
                        *count += 1;
                        previous = next;
                    }
                    Err(EncodeError::BufferFull) if may_truncate => {
                        // TC tells the client the answer is partial: a partial RRset may stay (RFC 2181 §9).
                        tc = section < 2;
                        if !tc {
                            // Without TC, a partial RRset would be taken for the whole one: keep only whole
                            // RRsets, writing the section again, the same bytes up to where it stops.
                            w.truncate(start.0);
                            previous = start.1;
                            *count = whole_rrsets(records, i);
                            for record in records.iter().take(*count) {
                                previous = put_record(&mut w, record, previous)?;
                            }
                        }
                        break 'sections;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        if !opt_written {
            w.release_tail();
            if let Some(edns) = edns {
                edns.encode(&mut w)?;
            }
        }
        let [answers, authority, additional] = written;
        let additional = additional + usize::from(edns.is_some());
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
        self.to_vec_with(self.edns.as_ref())
    }

    /// Writes the message without its OPT record into a new vector, as a cache stores a response to add its own
    /// OPT record to each copy it serves.
    ///
    /// # Errors
    ///
    /// As [`Message::to_vec`].
    pub fn to_vec_without_edns(&self) -> Result<Vec<u8>, EncodeError> {
        self.to_vec_with(None)
    }

    fn to_vec_with(&self, edns: Option<&Edns<'_>>) -> Result<Vec<u8>, EncodeError> {
        let encode = |buf: &mut [u8]| self.encode_into(buf, false, edns).map(|e| e.len);
        // Most messages fit in 512 bytes; larger ones are encoded again into a buffer 4 times larger.
        let mut buf = vec![0; 512];
        loop {
            match encode(&mut buf) {
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

/// The record written before, and where a pointer to its owner may point.
type Previous<'r, 'a> = Option<(&'r Record<'a>, u16)>;

/// Writes `record`, its owner a pointer to the owner of `previous` when they are the same; returns what to give
/// the next record.
fn put_record<'r, 'a>(
    w: &mut Writer<'_>,
    record: &'r Record<'a>,
    previous: Previous<'r, 'a>,
) -> Result<Previous<'r, 'a>, EncodeError> {
    let owner = previous
        .filter(|(p, _)| p.name.same_wire(&record.name))
        .map(|(_, at)| at);
    Ok(record.encode_after(w, owner)?.map(|at| (record, at)))
}

/// How many of the first `failed` records to keep, `failed` the first that did not fit, so that no `RRset` has
/// records on both sides of the cut (RFC 2181 §9): the largest such count.
///
/// One hash per record, so that a response with thousands of records cannot make truncation quadratic.
fn whole_rrsets(records: &[Record<'_>], failed: usize) -> usize {
    // The index of the first record of each record's `RRset`: same owner, type and class (RFC 2181 §5).
    let mut first_of = HashMap::with_capacity(records.len());
    let firsts: Vec<usize> = records
        .iter()
        .enumerate()
        .map(|(i, r)| *first_of.entry((&r.name, r.rtype(), r.class)).or_insert(i))
        .collect();
    // A cut is whole when no record after it belongs to an `RRset` that starts before it.
    let mut low = usize::MAX;
    for (keep, &first) in firsts.iter().enumerate().rev() {
        low = low.min(first);
        if keep <= failed && low >= keep {
            return keep;
        }
    }
    0
}

/// One entry of a message, met by [`walk`] in wire order.
pub(crate) enum Entry<'a> {
    /// The header, met first.
    Header(Header, Counts),
    /// A question.
    Question(Question<'a>),
    /// A record of `Section`.
    Record(Section, RawRecord<'a>),
    /// The OPT record lifted out as EDNS (D8); a misplaced or extra one is a [`Entry::Record`].
    Opt(RawRecord<'a>),
}

/// Hands `each` the offsets of the TTL fields of the records of `msg` in wire order, without the OPT record lifted
/// out as EDNS (D8), to rewrite TTLs in a copy of the bytes, as a cache serving them does.
///
/// Reads the structure only: names, fixed fields and RDLENGTH, not the RDATA. A stray OPT record has no offset:
/// its TTL field holds the extended RCODE, version and flags (RFC 6891 §6.1.3).
///
/// # Errors
///
/// [`DecodeError`] when the structure is broken. Unlike [`Message::decode`], it accepts invalid RDATA and EDNS
/// options, which it does not read.
pub fn ttl_offsets(msg: &[u8], mut each: impl FnMut(u16)) -> Result<(), DecodeError> {
    walk(msg, &mut Vec::new(), |entry, _| {
        if let Entry::Record(_, raw) = entry
            && raw.rtype != RecordType::OPT
        {
            // TTL and RDLENGTH: the 6 bytes before the RDATA.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "`walk` reads messages of at most 65535 bytes"
            )]
            each((raw.rdata.position() - 6) as u16);
        }
        Ok(())
    })
}

/// Reads the structure of `msg`, handing each entry to `sink` in wire order, and pushes the violations it finds:
/// several questions, a misplaced or extra OPT record or one whose options overrun it, trailing bytes (D9). `sink`
/// reads what it needs of each entry and pushes the violations of RDATA and options.
pub(crate) fn walk<'a>(
    msg: &'a [u8],
    violations: &mut Vec<Violation>,
    mut sink: impl FnMut(Entry<'a>, &mut Vec<Violation>) -> Result<(), DecodeError>,
) -> Result<(), DecodeError> {
    if msg.len() > MAX_MESSAGE_LEN {
        return Err(DecodeError {
            offset: MAX_MESSAGE_LEN,
            kind: DecodeErrorKind::Invalid("message longer than 65535 bytes"),
        });
    }
    let mut r = Reader::new(msg);
    let (header, counts) = Header::decode(&mut r)?;
    sink(Entry::Header(header, counts), violations)?;
    for _ in 0..counts.questions {
        sink(Entry::Question(Question::decode(&mut r)?), violations)?;
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
            let raw = Record::read_raw(&mut r)?;
            if raw.rtype == RecordType::OPT {
                let reject = if section != Section::Additional {
                    Some(Violation::OptOutsideAdditional)
                } else if !raw.name.is_root() {
                    Some(Violation::OptOwnerNotRoot)
                } else if core::mem::replace(&mut opt_seen, true) {
                    Some(Violation::MultipleOpt)
                } else if !edns::framed(raw.rdata) {
                    Some(Violation::OptOptionOverrun)
                } else {
                    None
                };
                if let Some(violation) = reject {
                    violations.push(violation);
                } else {
                    sink(Entry::Opt(raw), violations)?;
                    continue;
                }
            }
            sink(Entry::Record(section, raw), violations)?;
        }
    }

    if !r.is_empty() {
        violations.push(Violation::TrailingBytes { len: r.remaining() });
    }
    Ok(())
}

/// Reads a message into the empty vectors of `out`.
fn decode_into<'a>(msg: &'a [u8], out: &mut Decoded<'a>) -> Result<(), DecodeError> {
    let Decoded {
        message:
            Message {
                header,
                questions,
                answer,
                authority,
                additional,
                edns,
            },
        violations,
        spare_options,
    } = out;
    walk(msg, violations, |entry, violations| {
        match entry {
            Entry::Header(read, counts) => {
                *header = read;
                // Capped by what the input can hold rather than by the counts it claims, one budget shared by
                // all sections, so a hostile header cannot claim the input several times over.
                let mut remaining = msg.len() - HEADER_LEN;
                let mut take = |claimed: u16, min_len: usize| {
                    let n = usize::from(claimed).min(remaining / min_len);
                    remaining -= n * min_len;
                    n
                };
                questions.reserve(take(counts.questions, MIN_QUESTION_LEN));
                answer.reserve(take(counts.answers, MIN_RECORD_LEN));
                authority.reserve(take(counts.authority, MIN_RECORD_LEN));
                additional.reserve(take(counts.additional, MIN_RECORD_LEN));
            }
            Entry::Question(question) => questions.push(question),
            Entry::Opt(raw) => {
                let options = core::mem::take(spare_options);
                *edns = Some(Edns::from_opt(
                    raw.class.0,
                    raw.ttl,
                    raw.rdata,
                    options,
                    |o| {
                        violations.push(Violation::InvalidOption {
                            code: o.code,
                            error: o.error,
                        });
                    },
                ));
            }
            Entry::Record(section, raw) => {
                let records = match section {
                    Section::Answer => &mut *answer,
                    Section::Authority => &mut *authority,
                    Section::Additional => &mut *additional,
                };
                let DecodedRecord {
                    record,
                    invalid_rdata,
                } = Record::from_raw(raw)?;
                if let Some(error) = invalid_rdata {
                    violations.push(Violation::InvalidRdata {
                        section,
                        index: records.len(),
                        error,
                    });
                }
                records.push(record);
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EDNS options keep their allocation from one decode to the next.
    #[test]
    fn decoding_into_a_spare_reuses_the_edns_options() {
        let message = Message {
            edns: Some(Edns {
                options: vec![EdnsOption::Padding(1), EdnsOption::Keepalive(None)],
                ..Edns::default()
            }),
            ..Message::default()
        };
        let wire = message.to_vec().unwrap();
        let options = |d: &Decoded<'_>| {
            d.message
                .edns
                .as_ref()
                .unwrap()
                .options
                .as_ptr()
                .cast::<u8>()
        };

        let first = Message::decode_reusing(&wire, &mut Decoded::default()).unwrap();
        let allocation = options(&first);
        let mut spare = first.recycle();
        assert_eq!(spare.spare_options, []);
        assert!(spare.spare_options.capacity() >= 2);
        let second = Message::decode_reusing(&wire, &mut spare).unwrap();
        assert_eq!(second.message, message);
        assert_eq!(options(&second), allocation);
    }
}
