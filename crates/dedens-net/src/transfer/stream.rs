//! The response stream of a zone transfer, sans-IO: its messages in, one at a time, a [`Transfer`] out (D210).
//!
//! Each message is checked as RFC 5936 §2.2 and RFC 1995 §4 ask: its ID, its TSIG when the request was signed
//! (RFC 8945 §5.3.1), that it is a response to a query, its RCODE, and its question, which the first message
//! repeats and the next ones repeat or leave out (RFC 5936 §2.2.1). Its answer records go through a state machine:
//! the zone's SOA first, then the zone's records up to the same SOA (the AXFR form), or, for an IXFR, changesets,
//! each the old SOA, the removed records, the new SOA and the added ones, up to the first SOA again (RFC 1995 §4).
//! An IXFR answered with that SOA alone is up to date. A stream past one of the [`Limits`] is refused.

use dedens_proto::rdata::{RData, Soa};
use dedens_proto::{
    Class, DecodeError, Flags, Message, Name, Opcode, Question, Rcode, Record, RecordType, Section,
    Serial, Ttl, Violation,
};
use dedens_tsig::{ResponseError, ResponseVerifier};
use dedens_zone::{Changeset, ChangesetError, Report, Zone};

use super::{Limit, Limits, Transfer};

/// What the client asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// The whole zone (RFC 5936), with the serial the client holds, if any: a zone not ahead of it is refused.
    Axfr(Option<Serial>),
    /// The changes since the serial the client holds (RFC 1995 §3).
    Ixfr(Serial),
}

impl Asked {
    /// The serial the client holds.
    #[must_use]
    pub const fn from(self) -> Option<Serial> {
        match self {
            Self::Axfr(from) => from,
            Self::Ixfr(from) => Some(from),
        }
    }

    /// The type of the question.
    #[must_use]
    pub const fn qtype(self) -> RecordType {
        match self {
            Self::Axfr(_) => RecordType::AXFR,
            Self::Ixfr(_) => RecordType::IXFR,
        }
    }
}

/// Why a transfer's response stream is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// A message that does not decode.
    #[error("malformed message: {0}")]
    Malformed(DecodeError),
    /// A message of another ID than the query's (RFC 5936 §2.2).
    #[error("message ID {got}, not the query's {expected}")]
    WrongId {
        /// The query's.
        expected: u16,
        /// The message's.
        got: u16,
    },
    /// A message whose TSIG does not verify, with the RCODE it came with (RFC 8945 §5.3.1).
    #[error("{error} (RCODE {rcode})")]
    Tsig {
        /// What is wrong with it.
        error: ResponseError,
        /// The message's RCODE: NOTAUTH when the server refused the request's TSIG.
        rcode: Rcode,
    },
    /// A message that is not a response to a standard query.
    #[error("not a response to a query")]
    NotResponse,
    /// An SOA response without the AA bit: the primary does not serve the zone.
    #[error("the SOA response is not authoritative")]
    NotAuthoritative,
    /// A message with an RCODE other than NOERROR (RFC 5936 §2.2).
    #[error("the server answered {0}")]
    Rcode(Rcode),
    /// A message whose question is not the query's (RFC 5936 §2.2.1).
    #[error("the question is not the query's")]
    WrongQuestion,
    /// A first message with no answer records: no IXFR (RFC 1995 §4 leaves an IXFR the server cannot give to the
    /// AXFR form; Knot reads the empty answer as NOTIMP, `refresh.c:determine_xfr_type`).
    #[error("the first message has no answer")]
    NoAnswer,
    /// A record with RDATA invalid for its type.
    #[error("invalid RDATA in answer record {index}: {error}")]
    InvalidRdata {
        /// Its index in the message's answer.
        index: usize,
        /// What is wrong.
        error: DecodeError,
    },
    /// A stream that does not start with the zone's SOA (RFC 5936 §2.2, RFC 1995 §4).
    #[error("the first record is not the zone's SOA")]
    NoSoa,
    /// An SOA of another serial than the first inside an AXFR-form stream (RFC 5936 §2.2).
    #[error("an SOA of serial {0} inside the zone")]
    SoaInside(Serial),
    /// Records after the closing SOA (RFC 5936 §2.2).
    #[error("records after the closing SOA")]
    Trailing,
    /// An IXFR whose first changeset does not start at the serial asked for (RFC 1995 §4).
    #[error("the changes start at serial {got}, not {asked}")]
    WrongStart {
        /// The client's serial.
        asked: Serial,
        /// The first changeset's.
        got: Serial,
    },
    /// A changeset that cannot be: a serial going back, an SOA of another zone (RFC 1995 §4).
    #[error("bad changeset: {0}")]
    Changeset(ChangesetError),
    /// A zone or an IXFR answer of a serial not ahead of the client's (RFC 1982 §3.2).
    #[error("the primary's serial {theirs} is not ahead of ours, {ours}")]
    NotNewer {
        /// The client's.
        ours: Serial,
        /// The primary's.
        theirs: Serial,
    },
    /// A zone that does not load: its errors (D204).
    #[error("the zone does not load:\n{0}")]
    Zone(Box<Report>),
    /// A stream past one of the [`Limits`].
    #[error("past the limit of {0:?}")]
    Limit(Limit),
}

impl StreamError {
    /// Whether an IXFR refused so is asked again as an AXFR: an answer the server gave that the AXFR form may not
    /// repeat, as Knot (`refresh.c:try_refresh`, but on I/O errors) and BIND (`xfrin.c:xfrin_recv_done`, on error
    /// RCODEs and bad headers) do. Not a TSIG failure, a stream past the limits, a serial not ahead or a zone that
    /// does not load: an AXFR would meet them again.
    #[must_use]
    pub const fn retry_axfr(&self) -> bool {
        !matches!(
            self,
            Self::Tsig { .. } | Self::Limit(_) | Self::NotNewer { .. } | Self::Zone(_)
        )
    }
}

/// Where the records of the stream are.
#[derive(Debug)]
enum State {
    /// No record yet.
    Start,
    /// The opening SOA alone.
    Opened(Record<'static>),
    /// The AXFR form: the records so far, the opening SOA first.
    Full(Vec<Record<'static>>),
    /// The removed records of a changeset.
    Removing(Changes),
    /// Its added records, after the new SOA.
    Adding(Changes, Record<'static>),
}

/// An IXFR's changes so far.
#[derive(Debug)]
struct Changes {
    /// The changesets read.
    done: Vec<Changeset>,
    /// The old SOA of the one being read.
    from: Record<'static>,
    /// Its removed records.
    removed: Vec<Record<'static>>,
    /// Its added records.
    added: Vec<Record<'static>>,
}

/// The stream read so far, waiting for its next message.
#[derive(Debug)]
pub struct Reader<'k> {
    zone: Question<'static>,
    id: u16,
    asked: Asked,
    verifier: Option<ResponseVerifier<'k>>,
    limits: Limits,
    /// The serial of the opening SOA, once read.
    serial: Option<Serial>,
    messages: usize,
    bytes: usize,
    records: usize,
    state: State,
}

/// A reader after a message: the next one awaited, or the transfer.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "moved once per message of up to 64 KiB, which decoding costs far more than"
)]
pub enum Step<'k> {
    /// The stream goes on.
    More(Reader<'k>),
    /// It ended with that message.
    Done(Transfer),
}

impl<'k> Reader<'k> {
    /// A reader of the responses to the query of `id` for `zone`, verified by `verifier` when it was signed.
    #[must_use]
    pub fn new(
        zone: Name<'static>,
        id: u16,
        asked: Asked,
        verifier: Option<ResponseVerifier<'k>>,
        limits: &Limits,
    ) -> Self {
        Self {
            zone: Question::new(zone, asked.qtype()),
            id,
            asked,
            verifier,
            limits: *limits,
            serial: None,
            messages: 0,
            bytes: 0,
            records: 0,
            state: State::Start,
        }
    }

    /// Reads the next message, `wire`, at `now`, Unix seconds, for its TSIG.
    ///
    /// # Errors
    ///
    /// [`StreamError`] when the message or the stream so far is refused.
    pub fn message(mut self, wire: &[u8], now: u64) -> Result<Step<'k>, StreamError> {
        self.messages += 1;
        if self.messages > self.limits.messages {
            return Err(StreamError::Limit(Limit::Messages));
        }
        self.bytes = self.bytes.saturating_add(wire.len());
        if self.bytes > self.limits.bytes {
            return Err(StreamError::Limit(Limit::Bytes));
        }
        let message = check(
            wire,
            self.id,
            &self.zone,
            self.verifier.as_mut(),
            now,
            self.messages == 1,
        )?;
        if message.answer.is_empty() && matches!(self.state, State::Start) {
            return Err(StreamError::NoAnswer);
        }
        self.records = self.records.saturating_add(message.answer.len());
        if self.records > self.limits.records {
            return Err(StreamError::Limit(Limit::Records));
        }
        let mut records = message.answer.into_iter().map(Record::into_owned);
        for record in records.by_ref() {
            if let Some(end) = self.record(record)? {
                if records.next().is_some() {
                    return Err(StreamError::Trailing);
                }
                return self.end(end).map(Step::Done);
            }
        }
        // An IXFR answered with the opening SOA alone (RFC 1995 §4).
        if let (State::Opened(_), Asked::Ixfr(ours), Some(theirs)) =
            (&self.state, self.asked, self.serial)
        {
            if theirs == ours {
                return self.end(End::UpToDate).map(Step::Done);
            }
            if theirs.partial_cmp(&ours) != Some(core::cmp::Ordering::Greater) {
                return Err(StreamError::NotNewer { ours, theirs });
            }
        }
        Ok(Step::More(self))
    }

    /// Takes the next answer record: the end of the stream when it closes it.
    fn record(&mut self, record: Record<'static>) -> Result<Option<End>, StreamError> {
        let soa = soa_serial(&record, &self.zone);
        let ixfr = match self.asked {
            Asked::Ixfr(from) => Some(from),
            Asked::Axfr(_) => None,
        };
        let state = core::mem::replace(&mut self.state, State::Start);
        let (state, end) = match (state, soa, ixfr) {
            (State::Start, Some(serial), _) => {
                self.serial = Some(serial);
                (State::Opened(record), None)
            }
            (State::Start, None, _) => return Err(StreamError::NoSoa),
            // The second record decides the form: an SOA starts the changes of an IXFR (RFC 1995 §4).
            (State::Opened(_), Some(serial), Some(asked)) => {
                if serial != asked {
                    return Err(StreamError::WrongStart { asked, got: serial });
                }
                (
                    State::Removing(Changes {
                        done: Vec::new(),
                        from: record,
                        removed: Vec::new(),
                        added: Vec::new(),
                    }),
                    None,
                )
            }
            (State::Opened(opening), soa, _) => self.full(vec![opening], record, soa)?,
            (State::Full(records), soa, _) => self.full(records, record, soa)?,
            (State::Removing(changes), Some(_), _) => (State::Adding(changes, record), None),
            (State::Removing(mut changes), None, _) => {
                changes.removed.push(record);
                (State::Removing(changes), None)
            }
            (State::Adding(mut changes, to), Some(serial), _) => {
                let changeset = Changeset::new(
                    changes.from,
                    to,
                    core::mem::take(&mut changes.removed),
                    core::mem::take(&mut changes.added),
                )
                .map_err(StreamError::Changeset)?;
                if let Some(last) = changes.done.last()
                    && last.to_serial() != changeset.from_serial()
                {
                    return Err(StreamError::Changeset(ChangesetError::NotConsecutive));
                }
                let reached = Some(changeset.to_serial()) == self.serial;
                changes.done.push(changeset);
                if reached {
                    // The latest version reached: this SOA closes the stream, and must be the opening one.
                    if Some(serial) != self.serial {
                        return Err(StreamError::SoaInside(serial));
                    }
                    return Ok(Some(End::Incremental(changes.done)));
                }
                changes.from = record;
                (State::Removing(changes), None)
            }
            (State::Adding(mut changes, to), None, _) => {
                changes.added.push(record);
                (State::Adding(changes, to), None)
            }
        };
        self.state = state;
        Ok(end)
    }

    /// The AXFR form: `record` added to `records`, or the end when it is the closing SOA, the opening one again.
    fn full(
        &self,
        mut records: Vec<Record<'static>>,
        record: Record<'static>,
        soa: Option<Serial>,
    ) -> Result<(State, Option<End>), StreamError> {
        match soa {
            None => {
                records.push(record);
                Ok((State::Full(records), None))
            }
            Some(serial) if Some(serial) == self.serial => {
                Ok((State::Start, Some(End::Full(records))))
            }
            Some(serial) => Err(StreamError::SoaInside(serial)),
        }
    }

    /// The transfer the stream ended with, its last TSIG checked.
    fn end(self, end: End) -> Result<Transfer, StreamError> {
        if let Some(verifier) = self.verifier {
            verifier.finish().map_err(|error| StreamError::Tsig {
                error,
                rcode: Rcode::NOERROR,
            })?;
        }
        let newer = |theirs: Serial| match self.asked.from() {
            Some(ours) if theirs.partial_cmp(&ours) != Some(core::cmp::Ordering::Greater) => {
                Err(StreamError::NotNewer { ours, theirs })
            }
            _ => Ok(()),
        };
        match end {
            End::UpToDate => Ok(Transfer::UpToDate),
            End::Incremental(changesets) => Ok(Transfer::Incremental(changesets)),
            End::Full(records) => {
                if let Some(serial) = self.serial {
                    newer(serial)?;
                }
                Zone::from_records(self.zone.name, records, &self.limits.zone)
                    .map(Transfer::Full)
                    .map_err(|report| StreamError::Zone(Box::new(report)))
            }
        }
    }
}

/// How a stream ended.
#[derive(Debug)]
enum End {
    UpToDate,
    Full(Vec<Record<'static>>),
    Incremental(Vec<Changeset>),
}

/// The checks of every response, `wire` at `now`: decoded, of `id`, its TSIG verified by `verifier`, a response to a
/// query, NOERROR, of the `question` (left out of the `first` message only), and no answer record of invalid RDATA.
fn check<'w>(
    wire: &'w [u8],
    id: u16,
    question: &Question<'_>,
    verifier: Option<&mut ResponseVerifier<'_>>,
    now: u64,
    first: bool,
) -> Result<Message<'w>, StreamError> {
    let decoded = Message::decode(wire).map_err(StreamError::Malformed)?;
    let message = decoded.message;
    if message.header.id != id {
        return Err(StreamError::WrongId {
            expected: id,
            got: message.header.id,
        });
    }
    if let Some(verifier) = verifier {
        verifier
            .verify(wire, now)
            .map_err(|error| StreamError::Tsig {
                error,
                rcode: message.rcode(),
            })?;
    }
    if !message.header.flags.contains(Flags::QR) || message.header.opcode != Opcode::QUERY {
        return Err(StreamError::NotResponse);
    }
    if message.rcode() != Rcode::NOERROR {
        return Err(StreamError::Rcode(message.rcode()));
    }
    let question_ok = match message.questions.as_slice() {
        [] => !first,
        [asked] => asked == question,
        _ => false,
    };
    if !question_ok {
        return Err(StreamError::WrongQuestion);
    }
    if let Some(invalid) = decoded
        .violations
        .into_iter()
        .find_map(|violation| match violation {
            Violation::InvalidRdata {
                section: Section::Answer,
                index,
                error,
            } => Some(StreamError::InvalidRdata { index, error }),
            _ => None,
        })
    {
        return Err(invalid);
    }
    Ok(message)
}

/// The SOA of `zone` that `wire`, the response at `now` to the SOA query of `id`, answers, its TSIG verified by
/// `verifier` and its AA bit set: the primary serves the zone (RFC 1034 §4.3.2).
///
/// # Errors
///
/// [`StreamError`] when the response is refused, [`StreamError::NotAuthoritative`] when the AA bit is clear,
/// [`StreamError::NoSoa`] when it holds no SOA of the zone.
pub fn soa_response(
    wire: &[u8],
    id: u16,
    zone: &Name<'static>,
    mut verifier: Option<ResponseVerifier<'_>>,
    now: u64,
) -> Result<Soa<'static>, StreamError> {
    let question = Question::new(zone.clone(), RecordType::SOA);
    let message = check(wire, id, &question, verifier.as_mut(), now, true)?;
    if let Some(verifier) = verifier {
        verifier.finish().map_err(|error| StreamError::Tsig {
            error,
            rcode: Rcode::NOERROR,
        })?;
    }
    if !message.header.flags.contains(Flags::AA) {
        return Err(StreamError::NotAuthoritative);
    }
    message
        .answer
        .iter()
        .find_map(|record| match record.data() {
            RData::Soa(soa) if soa_serial(record, &question).is_some() => Some(soa.into_owned()),
            _ => None,
        })
        .ok_or(StreamError::NoSoa)
}

/// The serial of `record` when it is the SOA of `zone`'s name and class.
fn soa_serial(record: &Record<'_>, zone: &Question<'_>) -> Option<Serial> {
    if record.name != zone.name || record.class != zone.qclass {
        return None;
    }
    match record.data() {
        RData::Soa(Soa { serial, .. }) => Some(Serial::new(serial)),
        _ => None,
    }
}

/// The SOA record an IXFR query carries in its authority section (RFC 1995 §3): the zone's, of the client's
/// serial. Only the serial counts: Knot reads that alone (`ixfr.c:ixfr_query`), so the names are the root and the
/// timers zero.
#[must_use]
pub fn ixfr_soa(zone: &Name<'static>, serial: Serial) -> Record<'static> {
    let soa = Soa {
        mname: Name::root(),
        rname: Name::root(),
        serial: serial.get(),
        refresh: 0,
        retry: 0,
        expire: 0,
        minimum: 0,
    };
    Record::new(zone.clone(), Class::IN, Ttl::ZERO, &RData::Soa(soa))
}
