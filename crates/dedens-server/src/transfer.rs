//! Zone transfers out (D214): AXFR (RFC 5936) and IXFR (RFC 1995) answered as a stream of messages, each made when
//! the connection asks for it, from the version of the zone taken when the transfer began, and signed when the
//! request was (RFC 8945 §5.3.1).

use std::borrow::Cow;
use std::collections::VecDeque;
use std::iter;
use std::sync::Arc;

use dedens_proto::edns::{Edns, EdnsOption, ExtendedError, InfoCode};
use dedens_proto::{
    Flags, HEADER_LEN, Header, MAX_MESSAGE_LEN, Message, Question, Rcode, Record, Serial,
};
use dedens_tsig::ResponseSigner;
use dedens_zone::{At, Changeset, Zone};

use crate::pipeline::Pipeline;

/// The length a message of a transfer is filled to: 16383 bytes, the last offset a compression pointer reaches
/// (RFC 1035 §4.1.4), NSD's `AXFR_MAX_MESSAGE_LEN` (`axfr.c`), past which Knot starts a new message
/// (`KNOT_WIRE_PTR_MAX`, `axfr.c`, `ixfr.c`). A record longer alone gets a message of up to 65535 bytes.
pub const MESSAGE_LEN: usize = 16383;

/// The bytes a record takes in a message at least, besides its RDATA: its owner compressed to a pointer, then
/// type, class, TTL and RDATA length (RFC 1035 §4.1.3).
const RECORD_HEAD: usize = 2 + 10;

/// The changes that led to the version of a zone, oldest first, each from the version the one before ends at: what
/// an IXFR is answered from (RFC 1995 §4). A secondary whose serial none starts from gets the zone whole.
///
/// Bounded as Knot's journal by default: at most [`History::DEPTH`] changesets (`journal-max-depth`), and no more
/// records than the zone holds, past which the zone itself is the shorter answer (BIND's `max-ixfr-ratio`, 100%).
#[derive(Debug, Clone, Default)]
pub struct History {
    changesets: VecDeque<Arc<Changeset>>,
    /// The records of the changesets, their SOA records aside.
    records: usize,
}

impl History {
    /// How many changesets a history keeps: Knot's `journal-max-depth` default, as D207's journal.
    pub const DEPTH: usize = 20;

    /// The history after `changeset`, which leads to a version of `records` records, the oldest changesets dropped
    /// past the bounds. A changeset that does not start where the last ends starts the history again.
    #[must_use]
    pub fn with(mut self, changeset: Changeset, records: usize) -> Self {
        if self.tip().is_some_and(|tip| tip != changeset.from_serial()) {
            self = Self::default();
        }
        self.records += size(&changeset);
        self.changesets.push_back(Arc::new(changeset));
        while self.changesets.len() > Self::DEPTH || self.records > records {
            let Some(oldest) = self.changesets.pop_front() else {
                break;
            };
            self.records -= size(&oldest);
        }
        self
    }

    /// The serial the last changeset ends at; `None` for an empty history.
    #[must_use]
    pub fn tip(&self) -> Option<Serial> {
        self.changesets
            .back()
            .map(|changeset| changeset.to_serial())
    }

    /// How many changesets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changesets.len()
    }

    /// Whether there is none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changesets.is_empty()
    }

    /// The one changeset from the version of `serial` to that of `tip`, condensed (RFC 1995 §6); `None` when the
    /// history does not end at `tip` or has no changeset from `serial`.
    pub(crate) fn since(&self, serial: Serial, tip: Serial) -> Option<Changeset> {
        if self.tip() != Some(tip) {
            return None;
        }
        let at = self
            .changesets
            .iter()
            .position(|changeset| changeset.from_serial() == serial)?;
        let mut changes = self.changesets.iter().skip(at).map(|c| Changeset::clone(c));
        let first = changes.next()?;
        changes.try_fold(first, Changeset::condense).ok()
    }
}

/// The records of `changeset`, its SOA records aside.
fn size(changeset: &Changeset) -> usize {
    changeset.removed().len() + changeset.added().len()
}

/// What a transfer sends.
#[derive(Debug)]
enum Body {
    /// AXFR, or IXFR in its AXFR form: the SOA, every other record, the SOA (RFC 5936 §2.2, RFC 1995 §4).
    Zone,
    /// IXFR: the new SOA, the old SOA and the records removed, the new SOA and the records added, the new SOA (RFC
    /// 1995 §4).
    Changes(Changeset),
}

/// The record a transfer sends next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cursor {
    /// The opening SOA of [`Body::Zone`].
    Opening,
    /// A record of the zone's walk ([`Zone::transfer_records`]), or the closing SOA past the last.
    Walk(At),
    /// The record of [`Body::Changes`] at this index of its sequence.
    Change(usize),
    /// None: the transfer is whole.
    Done,
}

/// What [`Transfer::next`] made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Next {
    /// Send `out[..len]`, then ask for the next.
    Message(usize),
    /// Nothing: the transfer is whole, the connection reads the next request.
    Ended,
    /// Nothing, and close the connection: the transfer cannot go on. The key the request was signed with is
    /// revoked (D211), or a record is longer than a message.
    Cut,
}

/// A zone transfer out: the version of the zone it began with, what it sends of it, and where it is.
///
/// Made by [`Pipeline::query`] as [`Step::Transfer`](crate::Step::Transfer) for an AXFR or IXFR over TCP or TLS
/// that the zone's access list permits (D211). The connection asks for each message with [`Transfer::next`], when
/// it has room for it, so that a slow reader holds one message and the zone's version, never the transfer.
#[derive(Debug)]
pub struct Transfer {
    zone: Arc<Zone>,
    body: Body,
    cursor: Cursor,
    /// The header of each message: the request's ID and opcode, QR, AA and its RD (RFC 5936 §2.2.1).
    header: Header,
    question: Question<'static>,
    /// Ours, in every message when the request had one (RFC 9103 §6.3.4), with the request's cookie (D113).
    edns: Option<Edns<'static>>,
    signer: Option<ResponseSigner<'static>>,
    /// Whether no message was made yet: the first has the question (RFC 5936 §2.2.1).
    first: bool,
}

impl Transfer {
    /// The transfer of `zone` to the request of `header` and `question`, with `edns` in each message.
    pub(crate) fn new(
        zone: Arc<Zone>,
        changes: Option<Changeset>,
        (header, question): (Header, Question<'static>),
        edns: Option<Edns<'static>>,
    ) -> Self {
        let (body, cursor) = match changes {
            Some(changes) => (Body::Changes(changes), Cursor::Change(0)),
            None => (Body::Zone, Cursor::Opening),
        };
        Self {
            zone,
            body,
            cursor,
            header: Header {
                flags: header.flags & Flags::RD | Flags::QR | Flags::AA,
                rcode: Rcode::NOERROR,
                ..header
            },
            question,
            edns,
            signer: None,
            first: true,
        }
    }

    /// The same transfer, each message signed by `signer` (RFC 8945 §5.3.1).
    pub(crate) fn signed(mut self, signer: ResponseSigner<'static>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// The zone, at the version sent.
    #[must_use]
    pub fn zone(&self) -> &Arc<Zone> {
        &self.zone
    }

    /// Whether the transfer sends the changes since the client's version (IXFR, RFC 1995 §4), not the zone.
    #[must_use]
    pub const fn incremental(&self) -> bool {
        matches!(self.body, Body::Changes(_))
    }

    /// Writes the next message into `out`, at least [`MAX_MESSAGE_LEN`] bytes for a record of any length to fit.
    ///
    /// Each message is filled to [`MESSAGE_LEN`], its names compressed within it (RFC 5936 §3.4); a record that
    /// alone does not fit gets one of its own, up to 65535 bytes. A signed request's messages are each signed, at
    /// the time `pipeline`'s clock reads, with the key the request was verified with while `pipeline` holds it: a
    /// reload that revokes the key (D211) cuts the transfer at the next message.
    pub fn next(&mut self, pipeline: &Pipeline, out: &mut [u8]) -> Next {
        if self.cursor == Cursor::Done {
            return Next::Ended;
        }
        let now = match &self.signer {
            Some(signer) => match pipeline.signing_time(signer.key()) {
                Some(now) => Some(now),
                None => return Next::Cut,
            },
            None => None,
        };
        let tsig = self.signer.as_ref().map_or(0, |s| s.key().record_len());
        for limit in [MESSAGE_LEN, MAX_MESSAGE_LEN] {
            let limit = limit.min(out.len());
            let Some(room) = limit.checked_sub(tsig) else {
                return Next::Cut;
            };
            let Some((len, cursor)) = self.fill(&mut out[..room]) else {
                continue;
            };
            let len = match (&mut self.signer, now) {
                (Some(signer), Some(now)) => match signer.sign_in((&mut out[..limit], len), now) {
                    Ok(len) => len,
                    Err(_) => return Next::Cut,
                },
                _ => len,
            };
            self.cursor = cursor;
            self.first = false;
            return Next::Message(len);
        }
        Next::Cut
    }

    /// Writes into `out` the message of the records from the cursor that fit it, and returns its length and the
    /// cursor past them; `None` when not one fits.
    fn fill(&self, out: &mut [u8]) -> Option<(usize, Cursor)> {
        let mut message = self.message(Rcode::NOERROR, None);
        // The records that may fit: those whose least length adds up to the room, which is the length but for
        // names in RDATA compressed; the encoding keeps those that fit.
        let mut cursors = Vec::new();
        let mut least = HEADER_LEN + message.edns.as_ref().map_or(0, Edns::wire_len);
        for (record, cursor) in self.records() {
            least += RECORD_HEAD + record.rdata.wire().len();
            if least > out.len() && !cursors.is_empty() {
                break;
            }
            message.answer.push(record);
            cursors.push(cursor);
        }
        let encoded = message.encode_truncated(out).ok()?;
        let fitted = message.answer.len() - encoded.dropped;
        let cursor = *cursors.get(fitted.checked_sub(1)?)?;
        // A transfer's message is never truncated: the records left out are the next message's (RFC 5936
        // §2.2.1).
        let [tc, _] = Flags::TC.bits().to_be_bytes();
        out[2] &= !tc;
        Some((encoded.len, cursor))
    }

    /// The records from the cursor on, each with the cursor past it.
    fn records(&self) -> Box<dyn Iterator<Item = (Record<'_>, Cursor)> + '_> {
        match (&self.body, self.cursor) {
            (Body::Zone, Cursor::Opening | Cursor::Walk(_)) => {
                let soa = self.zone.soa_record();
                let (opening, at) = match self.cursor {
                    Cursor::Walk(at) => (None, at),
                    _ => (
                        Some((soa.clone(), Cursor::Walk(At::default()))),
                        At::default(),
                    ),
                };
                let walk = self.zone.transfer_records(at);
                Box::new(
                    opening
                        .into_iter()
                        .chain(walk.map(|(record, at)| (record, Cursor::Walk(at))))
                        .chain(iter::once((soa, Cursor::Done))),
                )
            }
            (Body::Changes(changes), Cursor::Change(at)) => {
                let new = iter::once(changes.to_soa());
                let sequence = new
                    .clone()
                    .chain(iter::once(changes.from_soa()))
                    .chain(changes.removed())
                    .chain(new.clone())
                    .chain(changes.added())
                    .chain(new);
                let last = 3 + size(changes);
                Box::new(sequence.enumerate().skip(at).map(move |(n, record)| {
                    let cursor = if n == last {
                        Cursor::Done
                    } else {
                        Cursor::Change(n + 1)
                    };
                    (borrowed(record), cursor)
                }))
            }
            _ => Box::new(iter::empty()),
        }
    }

    /// The message with no record yet, of `rcode` and the extended `error` if any: the question in the first only.
    fn message(&self, rcode: Rcode, error: Option<InfoCode>) -> Message<'_> {
        let mut edns = self.edns.clone();
        if let (Some(edns), Some(code)) = (&mut edns, error) {
            edns.options.push(EdnsOption::Ede(ExtendedError {
                code,
                text: Cow::Borrowed(""),
            }));
        }
        let mut message = Message {
            header: self.header,
            edns,
            ..Message::default()
        };
        if self.first || rcode != Rcode::NOERROR {
            message.questions.push(self.question.clone());
        }
        if message.set_rcode(rcode).is_err() {
            message.header.rcode = Rcode::SERVFAIL;
        }
        message
    }

    /// Writes into `out` the one message that answers the request instead of the transfer, `rcode` and the extended
    /// `error` if any, signed as [`Transfer::next`] signs, and returns its length: for the limits of the
    /// connection, such as the transfers a server runs at once (RFC 9103 §6.3.3). `None` when it cannot be
    /// written or signed.
    #[must_use]
    pub fn refuse(
        mut self,
        pipeline: &Pipeline,
        (rcode, error): (Rcode, Option<InfoCode>),
        out: &mut [u8],
    ) -> Option<usize> {
        self.header.flags = self.header.flags.without(Flags::AA);
        let limit = out.len().min(MAX_MESSAGE_LEN);
        let tsig = self.signer.as_ref().map_or(0, |s| s.key().record_len());
        let len = self
            .message(rcode, error)
            .encode(&mut out[..limit.checked_sub(tsig)?])
            .ok()?;
        match &mut self.signer {
            Some(signer) => {
                let now = pipeline.signing_time(signer.key())?;
                signer.sign_in((&mut out[..limit], len), now).ok()
            }
            None => Some(len),
        }
    }
}

/// `record`, borrowed.
fn borrowed<'r>(record: &'r Record<'_>) -> Record<'r> {
    Record {
        name: record.name.reborrow(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.reborrow(),
    }
}
