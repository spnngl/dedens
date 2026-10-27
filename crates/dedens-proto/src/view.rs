//! A message read in place (D20): one pass checks it as [`Message::decode`] does and notes where each entry
//! starts; fields are then read from the input when asked for, without copying it.
//!
//! [`MessageView`] suits a server that only looks at part of a message, such as the question of a query or the
//! TTLs of a response it caches; [`Message`] suits building or changing one.

use core::slice;

use crate::codes::{Class, RecordType};
use crate::edns::{self, Edns};
use crate::error::{DecodeError, DecodeErrorKind};
use crate::header::{HEADER_LEN, Header};
use crate::message::{self, Decoded, Entry, Message, Section, Violation};
use crate::name::Name;
use crate::question::Question;
use crate::rdata::RData;
use crate::record::{Record, Ttl, decode_rdata};
use crate::wire::{MAX_MESSAGE_LEN, Reader};

/// Most entries (questions and records) a message can hold: each takes at least 5 bytes after the header.
pub const MAX_ENTRIES: usize = (MAX_MESSAGE_LEN - HEADER_LEN) / 5;

/// Type, class, TTL and RDLENGTH: the fields between a record's owner and its RDATA.
const FIXED_LEN: usize = 10;

/// Where an entry sits in the message: the start of its name, and of the fields after it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Span {
    name: u16,
    fixed: u16,
}

impl Span {
    fn new(at: message::Span) -> Self {
        Self {
            name: offset(at.name),
            fixed: offset(at.fixed),
        }
    }
}

/// `at` as a 16-bit offset.
fn offset(at: usize) -> u16 {
    u16::try_from(at).expect("MessageIndex::read takes messages of at most 65535 bytes")
}

/// A value read again from bytes [`MessageIndex::read`] checked.
fn checked<T>(read: Result<T, DecodeError>) -> T {
    read.expect("MessageIndex::read checked these bytes")
}

/// Where the entries of one message at a time start, in a table allocated once at [`MAX_ENTRIES`] so that reading
/// a message never allocates, whatever counts it claims (D20).
#[derive(Debug, Clone)]
pub struct MessageIndex {
    spans: Box<[Span]>,
    violations: Vec<Violation>,
}

impl Default for MessageIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageIndex {
    /// An index, allocating its table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spans: vec![Span::default(); MAX_ENTRIES].into_boxed_slice(),
            violations: Vec::new(),
        }
    }

    /// Checks `msg` as [`Message::decode`] does and notes where its entries start.
    ///
    /// ```
    /// # use dedens_proto::view::MessageIndex;
    /// let mut index = MessageIndex::new();
    /// let wire = [0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    /// let view = index.read(&wire)?;
    /// assert_eq!(view.header().id, 7);
    /// assert_eq!(view.questions().next().map(|q| q.name.is_root()), Some(true));
    /// # Ok::<(), dedens_proto::DecodeError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Message::decode`], and [`DecodeErrorKind::Invalid`] for a message longer than 65535 bytes.
    pub fn read<'a>(&'a mut self, msg: &'a [u8]) -> Result<MessageView<'a>, DecodeError> {
        if msg.len() > MAX_MESSAGE_LEN {
            return Err(DecodeError {
                offset: MAX_MESSAGE_LEN,
                kind: DecodeErrorKind::Invalid("message longer than 65535 bytes"),
            });
        }
        let Self { spans, violations } = self;
        violations.clear();
        let mut header = Header::default();
        // Entries per part: questions, answer, authority, additional.
        let mut lens = [0; 4];
        let mut len = 0;
        let mut opt = None;
        message::walk(msg, violations, |entry, violations| {
            let (part, at) = match entry {
                Entry::Header(read, _) => {
                    header = read;
                    return Ok(());
                }
                Entry::Question(_, at) => (0, at),
                Entry::Opt(raw, at) => {
                    edns::read_options(raw.rdata, |_, invalid| {
                        violations.extend(invalid.map(|o| Violation::InvalidOption {
                            code: o.code,
                            error: o.error,
                        }));
                    })?;
                    opt = Some(Span::new(at));
                    return Ok(());
                }
                Entry::Record(section, raw, at) => {
                    let part = part_of(section);
                    if let (_, Some(error)) = decode_rdata(raw.rtype, raw.rdata)? {
                        violations.push(Violation::InvalidRdata {
                            section,
                            index: lens[part],
                            error,
                        });
                    }
                    (part, at)
                }
            };
            // Each entry takes at least 5 bytes of a message of at most 65535, so `len` stays below MAX_ENTRIES.
            spans[len] = Span::new(at);
            len += 1;
            lens[part] += 1;
            Ok(())
        })?;
        let [questions, answer, authority, _] = lens;
        let ends = [
            questions,
            questions + answer,
            questions + answer + authority,
            len,
        ];
        Ok(MessageView {
            msg,
            header,
            spans: &spans[..len],
            ends,
            opt,
            violations,
        })
    }
}

/// Position of a section among the parts of [`MessageView::spans`], after the questions.
const fn part_of(section: Section) -> usize {
    section.position() + 1
}

/// A message checked by [`MessageIndex::read`], read in place: every accessor parses the bytes it needs and never
/// fails, since they were checked.
#[derive(Debug, Clone, Copy)]
pub struct MessageView<'a> {
    msg: &'a [u8],
    header: Header,
    /// Questions, then answer, authority and additional records, without the OPT record lifted out as EDNS.
    spans: &'a [Span],
    /// Where each part of `spans` ends.
    ends: [usize; 4],
    opt: Option<Span>,
    violations: &'a [Violation],
}

impl<'a> MessageView<'a> {
    /// The message as read.
    #[must_use]
    pub const fn wire(&self) -> &'a [u8] {
        self.msg
    }

    /// The header; its counts are the lengths of [`Self::questions`] and the sections.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The rules the message breaks, as [`Decoded::violations`].
    #[must_use]
    pub const fn violations(&self) -> &'a [Violation] {
        self.violations
    }

    /// The questions.
    #[must_use]
    pub fn questions(&self) -> Questions<'a> {
        Questions {
            msg: self.msg,
            spans: self.part(0).iter(),
        }
    }

    /// The records of `section`; the additional section leaves out the OPT record lifted out as EDNS.
    #[must_use]
    pub fn section(&self, section: Section) -> Records<'a> {
        Records {
            msg: self.msg,
            spans: self.part(part_of(section)).iter(),
        }
    }

    /// The answer section.
    #[must_use]
    pub fn answer(&self) -> Records<'a> {
        self.section(Section::Answer)
    }

    /// The authority section.
    #[must_use]
    pub fn authority(&self) -> Records<'a> {
        self.section(Section::Authority)
    }

    /// The additional section, without the OPT record lifted out as EDNS.
    #[must_use]
    pub fn additional(&self) -> Records<'a> {
        self.section(Section::Additional)
    }

    /// The OPT record lifted out of the additional section (D8), as a record: [`RecordView::ttl_offset`] then
    /// locates the extended RCODE, version and flags.
    #[must_use]
    pub fn opt(&self) -> Option<RecordView<'a>> {
        self.opt.map(|span| RecordView {
            msg: self.msg,
            span,
        })
    }

    /// EDNS, parsed from the OPT record.
    #[must_use]
    pub fn edns(&self) -> Option<Edns<'a>> {
        let opt = self.opt()?;
        let (edns, _) = checked(Edns::from_opt(
            opt.class().0,
            opt.raw_ttl(),
            opt.rdata_reader(),
        ));
        Some(edns)
    }

    /// The whole message, decoded: what [`Message::decode`] returns for the same input.
    #[must_use]
    pub fn to_decoded(&self) -> Decoded<'a> {
        let message = Message {
            header: self.header,
            questions: self.questions().collect(),
            answer: self.answer().map(|r| r.to_record()).collect(),
            authority: self.authority().map(|r| r.to_record()).collect(),
            additional: self.additional().map(|r| r.to_record()).collect(),
            edns: self.edns(),
        };
        Decoded {
            message,
            violations: self.violations.to_vec(),
        }
    }

    fn part(&self, part: usize) -> &'a [Span] {
        let start = part.checked_sub(1).map_or(0, |before| self.ends[before]);
        &self.spans[start..self.ends[part]]
    }
}

/// The questions of a [`MessageView`].
#[derive(Debug, Clone)]
pub struct Questions<'a> {
    msg: &'a [u8],
    spans: slice::Iter<'a, Span>,
}

impl<'a> Questions<'a> {
    fn read(&self, span: Span) -> Question<'a> {
        let fixed = usize::from(span.fixed);
        Question {
            name: name_at(self.msg, span),
            qtype: RecordType(u16_at(self.msg, fixed)),
            qclass: Class(u16_at(self.msg, fixed + 2)),
        }
    }
}

impl<'a> Iterator for Questions<'a> {
    type Item = Question<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.spans.next().map(|&span| self.read(span))
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.spans.nth(n).map(|&span| self.read(span))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.spans.size_hint()
    }
}

impl DoubleEndedIterator for Questions<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.spans.next_back().map(|&span| self.read(span))
    }
}

impl ExactSizeIterator for Questions<'_> {}

/// The records of a section of a [`MessageView`]; `nth` jumps to a record without reading those before it.
#[derive(Debug, Clone)]
pub struct Records<'a> {
    msg: &'a [u8],
    spans: slice::Iter<'a, Span>,
}

impl<'a> Iterator for Records<'a> {
    type Item = RecordView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let msg = self.msg;
        self.spans.next().map(|&span| RecordView { msg, span })
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let msg = self.msg;
        self.spans.nth(n).map(|&span| RecordView { msg, span })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.spans.size_hint()
    }
}

impl DoubleEndedIterator for Records<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let msg = self.msg;
        self.spans.next_back().map(|&span| RecordView { msg, span })
    }
}

impl ExactSizeIterator for Records<'_> {}

/// A record of a [`MessageView`], read in place.
#[derive(Debug, Clone, Copy)]
pub struct RecordView<'a> {
    msg: &'a [u8],
    span: Span,
}

impl<'a> RecordView<'a> {
    /// The owner name.
    #[must_use]
    pub fn name(&self) -> Name<'a> {
        name_at(self.msg, self.span)
    }

    /// The record type.
    #[must_use]
    pub fn rtype(&self) -> RecordType {
        RecordType(u16_at(self.msg, self.fixed()))
    }

    /// The class.
    #[must_use]
    pub fn class(&self) -> Class {
        Class(u16_at(self.msg, self.fixed() + 2))
    }

    /// The TTL, as [`Record::ttl`].
    #[must_use]
    pub fn ttl(&self) -> Ttl {
        Ttl::of_record(self.rtype(), self.raw_ttl())
    }

    /// Where the 4-byte TTL sits in the message, so that a copy of the bytes can be served with a lower one.
    #[must_use]
    pub fn ttl_offset(&self) -> usize {
        self.fixed() + 4
    }

    /// The RDATA bytes; names in it may hold compression pointers into the message.
    #[must_use]
    pub fn rdata(&self) -> &'a [u8] {
        let start = self.fixed() + FIXED_LEN;
        &self.msg[start..start + self.rdlength()]
    }

    /// The RDATA parsed, as [`Record::data`]: opaque when invalid for its type (D9).
    #[must_use]
    pub fn data(&self) -> RData<'a> {
        checked(decode_rdata(self.rtype(), self.rdata_reader())).0
    }

    /// The whole record.
    #[must_use]
    pub fn to_record(&self) -> Record<'a> {
        Record::new(self.name(), self.class(), self.ttl(), self.data())
    }

    fn fixed(&self) -> usize {
        usize::from(self.span.fixed)
    }

    fn raw_ttl(&self) -> u32 {
        let at = self.ttl_offset();
        u32::from_be_bytes([
            self.msg[at],
            self.msg[at + 1],
            self.msg[at + 2],
            self.msg[at + 3],
        ])
    }

    fn rdlength(&self) -> usize {
        usize::from(u16_at(self.msg, self.fixed() + 8))
    }

    fn rdata_reader(&self) -> Reader<'a> {
        let start = self.fixed() + FIXED_LEN;
        Reader::range(self.msg, start, start + self.rdlength())
    }
}

/// The name of the entry at `span`.
fn name_at(msg: &[u8], span: Span) -> Name<'_> {
    let at = usize::from(span.name);
    checked(Name::decode(&mut Reader::range(
        msg,
        at,
        usize::from(span.fixed),
    )))
}

/// The big-endian 16-bit value at `at`, inside the message.
fn u16_at(msg: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([msg[at], msg[at + 1]])
}
