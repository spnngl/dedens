//! A query read in place, for a server (D21): the header, the question and the EDNS settings it answers by,
//! checked as [`Message::decode`](crate::Message::decode) checks them, without allocating.

use crate::edns::{EdnsView, read_options};
use crate::error::DecodeError;
use crate::header::Header;
use crate::message::{self, Entry, Violation};
use crate::question::Question;
use crate::record::decode_rdata;

/// A query read in place: what a server needs to answer it, from the input.
#[derive(Debug, Clone)]
pub struct Query<'a> {
    msg: &'a [u8],
    header: Header,
    question: Option<Question<'a>>,
    edns: Option<EdnsView<'a>>,
    violations: Vec<Violation>,
}

impl<'a> Query<'a> {
    /// Reads `msg`, checking all of it as [`Message::decode`](crate::Message::decode) does, records included,
    /// so that a query it rejects is rejected here too; allocates only to list violations.
    ///
    /// ```
    /// # use dedens_proto::{Query, RecordType};
    /// let wire = [0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    /// let query = Query::read(&wire)?;
    /// assert_eq!(query.header().id, 7);
    /// assert_eq!(query.question().map(|q| q.qtype), Some(RecordType::A));
    /// assert!(query.edns().is_none());
    /// # Ok::<(), dedens_proto::DecodeError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`Message::decode`](crate::Message::decode).
    pub fn read(msg: &'a [u8]) -> Result<Self, DecodeError> {
        let mut header = Header::default();
        let mut question = None;
        let mut edns = None;
        let mut violations = Vec::new();
        // Records met so far per section, to place a violation as `Message::decode` does.
        let mut records = [0; 3];
        message::walk(msg, &mut violations, |entry, violations| {
            match entry {
                Entry::Header(read, _) => header = read,
                Entry::Question(read, _) => {
                    // RFC 9619: more than one is a violation `walk` reports; the first is the one answered.
                    question.get_or_insert(read);
                }
                Entry::Opt(raw, _) => {
                    read_options(raw.rdata, |_, invalid| {
                        violations.extend(invalid.map(|o| Violation::InvalidOption {
                            code: o.code,
                            error: o.error,
                        }));
                    })?;
                    edns = Some(EdnsView::new(raw.class.0, raw.ttl, raw.rdata));
                }
                Entry::Record(section, raw, _) => {
                    let index = &mut records[section.position()];
                    if let (_, Some(error)) = decode_rdata(raw.rtype, raw.rdata)? {
                        violations.push(Violation::InvalidRdata {
                            section,
                            index: *index,
                            error,
                        });
                    }
                    *index += 1;
                }
            }
            Ok(())
        })?;
        Ok(Self {
            msg,
            header,
            question,
            edns,
            violations,
        })
    }

    /// The query as read.
    #[must_use]
    pub const fn wire(&self) -> &'a [u8] {
        self.msg
    }

    /// The header.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The first question; a query without one has nothing to answer.
    #[must_use]
    pub const fn question(&self) -> Option<&Question<'a>> {
        self.question.as_ref()
    }

    /// The client's EDNS settings, when it sent an OPT record.
    #[must_use]
    pub const fn edns(&self) -> Option<&EdnsView<'a>> {
        self.edns.as_ref()
    }

    /// The rules the query breaks, as [`Decoded::violations`](crate::Decoded::violations): a server answers
    /// FORMERR when there is any.
    #[must_use]
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }
}
