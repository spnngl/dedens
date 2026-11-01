//! What a reply takes from the query it answers: ID, opcode, flags, question, EDNS, and its size limit.

use std::borrow::Cow;

use dedens_proto::edns::{
    DEFAULT_UDP_PAYLOAD, EDE_LEN, EdnsOption, ExtendedError, InfoCode, OptionCode,
};
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

/// The block a padded reply's length is a multiple of (RFC 8467 §4.1).
const PADDING_BLOCK: usize = 468;

/// The code and length of an EDNS option, before its data (RFC 6891 §6.1.2).
const OPTION_HEAD: usize = 4;

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
        let len = message.encode_truncated(&mut out[..limit]).ok()?.len;
        Some(if self.edns.is_some() {
            self.pad(out, len, error.map_or(0, |_| EDE_LEN))
        } else {
            len
        })
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
        match edns {
            Some(edns) => append_opt(&edns, error, out, len)
                .map(|len| self.pad(out, len, error.map_or(0, |_| EDE_LEN))),
            None => Some(len),
        }
    }

    /// Pads the reply of `len` bytes in `out`, which ends with our OPT record and its `rdata` bytes of options, to
    /// a multiple of [`PADDING_BLOCK`] bytes with a Padding option of zeros, for a client that padded its query
    /// over TLS, QUIC or HTTPS (RFC 7830 §4, RFC 8467 §4.1, RFC 9250 §5.4, RFC 8484 §9); up to the longest reply, past which the
    /// reply is padded less. Returns the new length, `len` for any other client: over Oblivious `DoH` the encryption
    /// pads (D79).
    pub(crate) fn pad(&self, out: &mut [u8], len: usize, rdata: usize) -> usize {
        let padded = matches!(
            self.transport,
            Transport::Tls | Transport::Quic | Transport::Https
        ) && self.edns.as_ref().is_some_and(|edns| {
            edns.options()
                .any(|option| option.code() == OptionCode::PADDING)
        });
        let end = (len + OPTION_HEAD)
            .next_multiple_of(PADDING_BLOCK)
            .min(self.limit())
            .min(out.len());
        // The OPT record's RDLENGTH is just before its options; every length is below 65536.
        let (true, Some(at), Ok(added), Ok(zeros)) = (
            padded,
            len.checked_sub(rdata + 2),
            u16::try_from(end.saturating_sub(len)),
            u16::try_from(end.wrapping_sub(len + OPTION_HEAD)),
        ) else {
            return len;
        };
        let rdlength = u16::from_be_bytes([out[at], out[at + 1]]) + added;
        out[at..at + 2].copy_from_slice(&rdlength.to_be_bytes());
        let [code_hi, code_lo] = u16::from(OptionCode::PADDING).to_be_bytes();
        let [len_hi, len_lo] = zeros.to_be_bytes();
        out[len..len + OPTION_HEAD].copy_from_slice(&[code_hi, code_lo, len_hi, len_lo]);
        // A buffer reused across replies holds older bytes: padding is zeros (RFC 7830 §3).
        out[len + OPTION_HEAD..end].fill(0);
        end
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
            Transport::Tcp
            | Transport::Tls
            | Transport::Quic
            | Transport::Https
            | Transport::Odoh
            | Transport::Coap => MAX_MESSAGE_LEN,
            Transport::Udp => usize::from(self.edns.as_ref().map_or(MIN_UDP_PAYLOAD, |edns| {
                edns.udp_payload.clamp(MIN_UDP_PAYLOAD, DEFAULT_UDP_PAYLOAD)
            })),
        }
    }
}

/// Appends `edns`, which has no option, to the message of `len` bytes in `out`, with the extended `error` if any
/// (RFC 8914 §2, no text), and returns the new length; `None` when `out` cannot hold them. Allocates nothing.
pub(crate) fn append_opt(
    edns: &Edns<'_>,
    error: Option<InfoCode>,
    out: &mut [u8],
    len: usize,
) -> Option<usize> {
    let len = edns.append(out, len).ok()?;
    let Some(code) = error else {
        return Some(len);
    };
    // The OPT record ends with its RDLENGTH, 0: the option becomes its RDATA.
    let [option_hi, option_lo] = u16::from(OptionCode::EDE).to_be_bytes();
    let [hi, lo] = u16::from(code).to_be_bytes();
    out.get_mut(len - 2..len + EDE_LEN)?
        .copy_from_slice(&[0, 6, option_hi, option_lo, 0, 2, hi, lo]);
    Some(len + EDE_LEN)
}
