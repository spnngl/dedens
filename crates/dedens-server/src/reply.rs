//! What a reply takes from the query it answers: ID, opcode, flags, question, EDNS, and its size limit.

use std::borrow::Cow;

use dedens_proto::edns::{
    Cookie, DEFAULT_UDP_PAYLOAD, EDE_LEN, Edns, EdnsFlags, EdnsOption, EdnsView, ExtendedError,
    InfoCode, OptionCode,
};
use dedens_proto::{
    Flags, HEADER_LEN, Header, MAX_MESSAGE_LEN, Message, Query, Question, Rcode, Transport,
    Violation,
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

/// The length of a Client Cookie (RFC 7873 §4).
const COOKIE_CLIENT_LEN: usize = 8;

/// The client of a query, as its reply needs it.
#[derive(Debug, Clone)]
pub(crate) struct Client<'q> {
    pub(crate) header: Header,
    pub(crate) question: Option<Question<'q>>,
    opt: Opt<'q>,
    pub(crate) transport: Transport,
    /// The cookie our reply carries: the client's, with the Server Cookie we made for it (D113).
    pub(crate) cookie: Option<Cookie>,
}

/// The OPT record of a query, as its reply needs it: the reply has ours when the query had one, and only then (RFC
/// 6891 §6.1.1, §7).
#[derive(Debug, Clone)]
enum Opt<'q> {
    /// None.
    Absent,
    /// Only OPT records the reader left opaque, outside the additional section, not owned by the root or with
    /// options overrunning it (RFC 6891 §6.1.1, §6.1.2): the query is answered FORMERR, with our OPT record all the
    /// same, since the error is in EDNS (§7). Nothing of the client's is read: no DO, the least UDP payload.
    Unread,
    /// The first OPT record of the additional section owned by the root.
    Read(EdnsView<'q>),
}

impl<'q> Client<'q> {
    /// The client of `query`.
    pub(crate) fn of(query: &Query<'q>, transport: Transport) -> Self {
        let opt = match query.edns() {
            Some(edns) => Opt::Read(edns.clone()),
            None if query.violations().iter().any(|violation| {
                matches!(
                    violation,
                    Violation::OptOutsideAdditional
                        | Violation::OptOwnerNotRoot
                        | Violation::OptOptionOverrun
                )
            }) =>
            {
                Opt::Unread
            }
            None => Opt::Absent,
        };
        Self {
            header: query.header(),
            question: query.question().cloned(),
            opt,
            transport,
            cookie: None,
        }
    }

    /// The same client, whose reply carries `cookie` (D113).
    pub(crate) const fn with_cookie(mut self, cookie: Option<Cookie>) -> Self {
        self.cookie = cookie;
        self
    }

    /// The client of a query read no further than its header: the reply has no question and no OPT record, as
    /// none was read.
    pub(crate) const fn unread(header: Header, transport: Transport) -> Self {
        Self {
            header,
            question: None,
            opt: Opt::Absent,
            transport,
            cookie: None,
        }
    }

    /// Writes `message` into `out` as the reply, with `rcode`, and returns its length; `None` when `out` cannot
    /// hold the header, the question and the OPT record.
    ///
    /// The reply has the client's ID, opcode and question, in its case (RFC 4343 §4); QR and RA set, RD and CD
    /// copied (RFC 1035 §4.1.1, RFC 4035 §3.2.2), AD kept only when the query had AD or DO (RFC 6840 §5.8), AA
    /// cleared: the server is not the authority. It has an OPT record, ours, when the query had one, read or not
    /// (RFC 6891 §6.1.1, §7), with DO copied (RFC 3225 §3), the extended `error` if any (RFC 8914) and the
    /// client's [`Client::padding`]; otherwise an extended `rcode` becomes SERVFAIL.
    ///
    /// The OPT record opens the additional section (D9), so its Padding option is sized from a first encoding
    /// and the message encoded again with it.
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
        message.edns = self.has_opt().then(|| {
            let mut edns = self.our_edns();
            edns.options.extend(self.cookie.map(EdnsOption::Cookie));
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
        match (&mut message.edns, self.padding(len, limit)) {
            (Some(edns), Some(zeros)) => {
                edns.options.push(EdnsOption::Padding(zeros));
                Some(message.encode_truncated(&mut out[..limit]).ok()?.len)
            }
            _ => Some(len),
        }
    }

    /// Writes the reply that only truncates, TC set, no record: the question and our OPT record, as
    /// [`Client::reply`] writes them with NOERROR (RFC 8482 §4.4, RFC 7766 §3). `None` when `out` cannot hold them.
    pub(crate) fn truncated(&self, out: &mut [u8]) -> Option<usize> {
        let len = self.reply(Message::default(), Rcode::NOERROR, None, out)?;
        let [high, _] = Flags::TC.bits().to_be_bytes();
        out[2] |= high;
        Some(len)
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
        let mut edns = self.has_opt().then(|| self.our_edns());
        let mut rcode = u16::from(answer.rcode);
        match &mut edns {
            Some(edns) => edns.ext_rcode = u8::try_from(rcode >> 4).ok()?,
            None if rcode > 0x0F => rcode = u16::from(Rcode::SERVFAIL),
            None => {}
        }
        let error = answer.error.filter(|_| edns.is_some());
        let opt = edns.as_ref().map_or(0, Edns::wire_len) + self.options_len(error);
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
            Some(edns) => self.append_opt(&edns, error, out, len),
            None => Some(len),
        }
    }

    /// The bytes of options our OPT record carries for this client, after its RDLENGTH: the COOKIE option (D113)
    /// and the extended `error`, if any.
    pub(crate) fn options_len(&self, error: Option<InfoCode>) -> usize {
        self.cookie.map_or(0, |cookie| {
            OPTION_HEAD + COOKIE_CLIENT_LEN + cookie.server().map_or(0, <[u8]>::len)
        }) + error.map_or(0, |_| EDE_LEN)
    }

    /// Appends `edns`, which has no option, to the message of `len` bytes in `out`, with the COOKIE option of the
    /// client (RFC 7873 §5.2.3), the extended `error` if any (RFC 8914 §2, no text) and the client's
    /// [`Client::padding`], and returns the new length; `None` when `out` cannot hold them. Allocates nothing.
    pub(crate) fn append_opt(
        &self,
        edns: &Edns<'_>,
        error: Option<InfoCode>,
        out: &mut [u8],
        len: usize,
    ) -> Option<usize> {
        let start = edns.append(out, len).ok()?;
        let mut end = start;
        if let Some(cookie) = &self.cookie {
            let server = cookie.server().unwrap_or_default();
            let size = u16::try_from(COOKIE_CLIENT_LEN + server.len()).ok()?;
            let [code_hi, code_lo] = u16::from(OptionCode::COOKIE).to_be_bytes();
            let [size_hi, size_lo] = size.to_be_bytes();
            end = put(out, end, &[code_hi, code_lo, size_hi, size_lo])?;
            end = put(out, end, &cookie.client())?;
            end = put(out, end, server)?;
        }
        if let Some(code) = error {
            let [option_hi, option_lo] = u16::from(OptionCode::EDE).to_be_bytes();
            let [hi, lo] = u16::from(code).to_be_bytes();
            end = put(out, end, &[option_hi, option_lo, 0, 2, hi, lo])?;
        }
        if let Some(zeros) = self.padding(end, self.limit().min(out.len())) {
            let [code_hi, code_lo] = u16::from(OptionCode::PADDING).to_be_bytes();
            let [len_hi, len_lo] = zeros.to_be_bytes();
            end = put(out, end, &[code_hi, code_lo, len_hi, len_lo])?;
            let padded = end.checked_add(usize::from(zeros))?;
            // A buffer reused across replies holds older bytes: padding is zeros (RFC 7830 §3).
            out.get_mut(end..padded)?.fill(0);
            end = padded;
        }
        // The OPT record ends with its RDLENGTH, 0: the options become its RDATA.
        let rdlength = u16::try_from(end - start).ok()?.to_be_bytes();
        put(out, start - 2, &rdlength)?;
        Some(end)
    }

    /// The zeros of the Padding option that brings a reply of `len` bytes without it to a multiple of
    /// [`PADDING_BLOCK`] bytes, for a client that padded its query over TLS, QUIC or HTTPS (RFC 7830 §4, RFC 8467
    /// §4.1, RFC 9250 §5.4, RFC 8484 §9); up to `limit` bytes, past which the reply is padded less. `None` when
    /// not even an empty option fits, and for any other client: over Oblivious `DoH` the encryption pads (D79).
    fn padding(&self, len: usize, limit: usize) -> Option<u16> {
        let padded = matches!(
            self.transport,
            Transport::Tls | Transport::Quic | Transport::Https
        ) && self.edns().is_some_and(|edns| {
            edns.options()
                .any(|option| option.code() == OptionCode::PADDING)
        });
        let head = len.checked_add(OPTION_HEAD).filter(|_| padded)?;
        let end = head.next_multiple_of(PADDING_BLOCK).min(limit);
        u16::try_from(end.checked_sub(head)?).ok()
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

    /// Whether the query had an OPT record, read or not: the reply has ours then, and only then (RFC 6891 §7).
    pub(crate) const fn has_opt(&self) -> bool {
        !matches!(self.opt, Opt::Absent)
    }

    /// The EDNS settings of the client, when its OPT record was read.
    const fn edns(&self) -> Option<&EdnsView<'q>> {
        match &self.opt {
            Opt::Read(edns) => Some(edns),
            Opt::Absent | Opt::Unread => None,
        }
    }

    /// Whether the client asked for DNSSEC records (RFC 3225 §3).
    pub(crate) fn dnssec(&self) -> bool {
        self.edns()
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
            Transport::Udp => usize::from(self.edns().map_or(MIN_UDP_PAYLOAD, |edns| {
                edns.udp_payload.clamp(MIN_UDP_PAYLOAD, DEFAULT_UDP_PAYLOAD)
            })),
        }
    }
}

/// Copies `bytes` into `out` at `at`, returning the end; `None` when they do not fit.
fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> Option<usize> {
    let end = at.checked_add(bytes.len())?;
    out.get_mut(at..end)?.copy_from_slice(bytes);
    Some(end)
}
