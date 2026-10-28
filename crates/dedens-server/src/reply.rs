//! What a reply takes from the query it answers: ID, opcode, flags, question, EDNS, and its size limit.

use std::borrow::Cow;

use dedens_proto::edns::{DEFAULT_UDP_PAYLOAD, EdnsOption, ExtendedError, InfoCode, OptionCode};
use dedens_proto::header::HEADER_LEN;
use dedens_proto::wire::MAX_MESSAGE_LEN;
use dedens_proto::{
    Edns, EdnsFlags, EdnsView, Flags, Header, Message, Query, Question, Rcode, Transport,
};

use crate::plugin::Answer;

/// The UDP payload of a query without EDNS (RFC 1035 §4.2.1), and the least one with EDNS means (RFC 6891
/// §6.2.3).
const MIN_UDP_PAYLOAD: u16 = 512;

/// The opcode's bits in the header's second 16-bit word (RFC 1035 §4.1.1).
const OPCODE_MASK: u16 = 0x7800;

/// An extended error option without text: code, length and INFO-CODE (RFC 8914 §2).
const EDE_LEN: usize = 6;

/// The client of a query, as its reply needs it.
#[derive(Debug, Clone)]
pub(crate) struct Client<'q> {
    pub(crate) header: Header,
    pub(crate) question: Option<Question<'q>>,
    pub(crate) edns: Option<EdnsView<'q>>,
    pub(crate) transport: Transport,
}

impl<'q> Client<'q> {
    /// The client of `query`.
    pub(crate) fn of(query: &Query<'q>, transport: Transport) -> Self {
        Self {
            header: query.header(),
            question: query.question().cloned(),
            edns: query.edns().cloned(),
            transport,
        }
    }

    /// The client of a query read no further than its header: the reply has no question and no OPT record
    /// (RFC 6891 §7).
    pub(crate) const fn unread(header: Header, transport: Transport) -> Self {
        Self {
            header,
            question: None,
            edns: None,
            transport,
        }
    }

    /// Writes `message` into `out` as the reply, with `rcode`, and returns its length; `None` when `out` cannot
    /// hold the header, the question and the OPT record.
    ///
    /// The reply has the client's ID, opcode and question, in its case (RFC 4343 §4); QR and RA set, RD and CD
    /// copied (RFC 1035 §4.1.1, RFC 4035 §3.2.2), AD kept only when the query had AD or DO (RFC 6840 §5.8), AA
    /// cleared: the server is not the authority. It has an OPT record, ours, when the query had one (RFC 6891 §7),
    /// with DO copied (RFC 3225 §3) and the extended `error` if any (RFC 8914); otherwise an extended `rcode`
    /// becomes SERVFAIL.
    pub(crate) fn reply(
        &self,
        mut message: Message<'q>,
        rcode: Rcode,
        error: Option<InfoCode>,
        out: &mut [u8],
    ) -> Option<usize> {
        message.header = Header {
            flags: self.flags(message.header.flags),
            ..self.header
        };
        message.questions.clear();
        message.questions.extend(self.question.clone());
        message.edns = self.edns.as_ref().map(|_| {
            let mut edns = self.our_edns();
            edns.options.extend(error.map(|code| {
                EdnsOption::Ede(ExtendedError {
                    code,
                    text: Cow::Borrowed(""),
                })
            }));
            edns
        });
        if message.set_rcode(rcode).is_err() {
            message.header.rcode = Rcode::SERVFAIL;
        }
        let limit = self.limit().min(out.len());
        message
            .encode_truncated(&mut out[..limit])
            .ok()
            .map(|encoded| encoded.len)
    }

    /// Writes a plugin's `answer` to the query `wire` into `out` as the reply, and returns its length; `None` when
    /// `out` cannot hold the header, the question and the OPT record. Allocates nothing.
    ///
    /// The header, flags and OPT record are as [`Client::reply`] writes them, with AA when the plugin is
    /// authoritative. The question is copied from the query: its name has no compression pointer, as no name
    /// precedes it. The records follow it as they are; when they do not fit, they are left out with TC set (RFC
    /// 2181 §9).
    pub(crate) fn answer(&self, wire: &[u8], answer: &Answer<'_>, out: &mut [u8]) -> Option<usize> {
        let question = self.question.as_ref()?;
        let mut edns = self.edns.as_ref().map(|_| self.our_edns());
        let mut rcode = u16::from(answer.rcode);
        match &mut edns {
            Some(edns) => edns.ext_rcode = u8::try_from(rcode >> 4).ok()?,
            None if rcode > 0x0F => rcode = u16::from(Rcode::SERVFAIL),
            None => {}
        }
        let error = answer.error.filter(|_| edns.is_some());
        let opt = edns.as_ref().map_or(0, Edns::wire_len) + error.map_or(0, |_| EDE_LEN);
        let at = HEADER_LEN + question.name.wire_len() + 4;
        let limit = self.limit().min(out.len());
        let records = answer
            .records
            .filter(|records| at + records.wire().len() + opt <= limit);
        let mut flags = self.flags(Flags::default());
        if answer.authoritative {
            flags = flags.with(Flags::AA);
        }
        if answer.records.is_some() && records.is_none() {
            flags = flags.with(Flags::TC);
        }
        let (records, count) = records.map_or((&[][..], 0), |r| (r.wire(), r.count()));
        let len = at + records.len();
        if len + opt > limit {
            return None;
        }
        out[..at].copy_from_slice(wire.get(..at)?);
        let word = u16::from_be_bytes([out[2], out[3]]) & OPCODE_MASK | flags.bits() | rcode & 0x0F;
        out[2..4].copy_from_slice(&word.to_be_bytes());
        let [an_hi, an_lo] = count.to_be_bytes();
        out[4..12].copy_from_slice(&[0, 1, an_hi, an_lo, 0, 0, 0, 0]);
        out[at..len].copy_from_slice(records);
        let Some(edns) = edns else {
            return Some(len);
        };
        let mut len = edns.append(out, len).ok()?;
        if let Some(code) = error {
            // Our OPT record ends with its RDLENGTH, 0: the option becomes its RDATA (RFC 8914 §2, no text).
            let [option_hi, option_lo] = u16::from(OptionCode::EDE).to_be_bytes();
            let [hi, lo] = u16::from(code).to_be_bytes();
            out[len - 2..len + EDE_LEN]
                .copy_from_slice(&[0, 6, option_hi, option_lo, 0, 2, hi, lo]);
            len += EDE_LEN;
        }
        Some(len)
    }

    /// The flags of a reply carrying a response with `flags`: QR and RA, the client's RD and CD, and AD when the
    /// response has it and the client asked with AD or DO.
    fn flags(&self, flags: Flags) -> Flags {
        let asked = self.header.flags;
        let reply = asked & (Flags::RD | Flags::CD) | Flags::QR | Flags::RA;
        if flags.contains(Flags::AD) && (self.dnssec() || asked.contains(Flags::AD)) {
            reply.with(Flags::AD)
        } else {
            reply
        }
    }

    /// Sets the header flags of `reply`, a response encoded for this client, as [`Client::reply`] sets them; TC
    /// stays as it is.
    pub(crate) fn patch_flags(&self, reply: &mut [u8]) {
        if let Some(word) = reply.get_mut(2..4) {
            let old = u16::from_be_bytes([word[0], word[1]]);
            let mut flags = self.flags(Flags::from_word(old));
            if Flags::from_word(old).contains(Flags::TC) {
                flags = flags.with(Flags::TC);
            }
            let new = old & !Flags::ALL.bits() | flags.bits();
            word.copy_from_slice(&new.to_be_bytes());
        }
    }

    /// Whether the client asked for DNSSEC records (RFC 3225 §3).
    fn dnssec(&self) -> bool {
        self.edns
            .as_ref()
            .is_some_and(|edns| edns.flags.contains(EdnsFlags::DO))
    }

    /// Our EDNS for this client: the default payload (D10), version 0, no option, and its DO bit (RFC 3225 §3).
    pub(crate) fn our_edns(&self) -> Edns<'static> {
        Edns {
            flags: if self.dnssec() {
                EdnsFlags::DO
            } else {
                EdnsFlags::default()
            },
            ..Edns::default()
        }
    }

    /// The longest reply.
    pub(crate) fn limit(&self) -> usize {
        match self.transport {
            Transport::Tcp => MAX_MESSAGE_LEN,
            Transport::Udp => usize::from(self.edns.as_ref().map_or(MIN_UDP_PAYLOAD, |edns| {
                edns.udp_payload.clamp(MIN_UDP_PAYLOAD, DEFAULT_UDP_PAYLOAD)
            })),
        }
    }
}
