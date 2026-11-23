//! The client side of zone transfers (D210): a primary asked for its SOA ([`soa`]), then for the zone by IXFR or
//! AXFR over TCP ([`transfer`]), each message checked by [`stream::Reader`], sans-IO, and its TSIG verified when a
//! key signs the query (RFC 8945 §5.3.1).
//!
//! An IXFR the primary does not answer as one, with an error RCODE, no answer or a malformed sequence, is asked
//! again as an AXFR, once ([`StreamError::retry_axfr`]); an I/O error, a timeout, a TSIG failure or a stream past
//! the [`Limits`] ends the transfer. Queries carry no EDNS: a transfer goes over TCP, and the SOA fits in 512 bytes.
//! The SOA query goes over UDP, once, and over TCP when its response is truncated (RFC 7766 §5); timers and retries
//! are the caller's, after the zone's SOA (RFC 1035 §4.3.5).

#![deny(clippy::disallowed_methods)]

pub mod stream;

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::BufReader;
use compio::io::util::Splittable;
use dedens_proto::rdata::Soa;
use dedens_proto::{
    Flags, Header, Message, Name, Opcode, Question, Rcode, Record, RecordType, Serial,
};
use dedens_tsig::{Key, ResponseVerifier, SignError, sign_request};
use dedens_zone::{Changeset, Loaded};
use stream::{Asked, Reader, Step, StreamError, ixfr_soa, soa_response};

use crate::io::{Io, Udp};
use crate::tcp::{Outbound, frame, read_message};
use crate::udp::{MAX_DATAGRAM, unspecified};

/// How long an SOA query waits for its response, over UDP then TCP: NSD's `XFRD_UDP_TIMEOUT`, 10 s (`xfrd.c`);
/// Knot waits 5 s (`tcp-remote-io-timeout`, `conf/schema.c`).
pub const SOA_TIMEOUT: Duration = Duration::from_secs(10);

/// What a limit that overflows the clock becomes: 30 years, as tokio's far future.
const FAR: Duration = Duration::from_hours(262_800);

/// What a transfer brought.
#[derive(Debug)]
pub enum Transfer {
    /// The whole zone, loaded with the checks of `dedens-zone` (D204): its warnings are kept, an error refuses it.
    Full(Box<Loaded>),
    /// The changes from the client's serial to the primary's, in order (RFC 1995 §4).
    Incremental(Vec<Changeset>),
    /// The primary's serial is the client's.
    UpToDate,
}

/// The bound a transfer went past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// [`Limits::time`], or [`SOA_TIMEOUT`] for an SOA query.
    Time,
    /// [`Limits::idle`].
    Idle,
    /// [`Limits::messages`].
    Messages,
    /// [`Limits::bytes`].
    Bytes,
    /// [`Limits::records`].
    Records,
}

/// The bounds of a transfer: on time, so that a primary cannot hold a secondary's transfer forever, and on what it
/// sends, so that it cannot fill the secondary's memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The whole transfer, from the connection to the closing SOA, an AXFR after a failed IXFR included: 120 min,
    /// BIND's `max-transfer-time-in` (`bin/include/defaultconfig.h`). Knot and NSD have none.
    pub time: Duration,
    /// The longest wait for the connection or the next message: 120 s, NSD's `tcp-timeout` (`configure.ac`).
    /// Knot waits 5 s (`tcp-remote-io-timeout`, `conf/schema.c`), BIND 60 min (`max-transfer-idle-in`,
    /// `bin/include/defaultconfig.h`).
    pub idle: Duration,
    /// The messages of the response: 2^24, as many as [`Limits::records`], each message carrying a record at
    /// least, but for empty ones a primary has no reason to send. Knot, NSD and BIND count none.
    pub messages: usize,
    /// The bytes of the response: 1 GiB. Knot (`zone-max-size`, `conf/schema.c`) and NSD (`size-limit-xfr`,
    /// `xfrd.c`) have a bound, unlimited by default; BIND has none.
    pub bytes: usize,
    /// The answer records of the response, the removed ones of an IXFR included: 2^24, as many as a zone may
    /// hold ([`dedens_zone::Limits::records`]). BIND's `max-records` is unlimited by default.
    pub records: usize,
    /// The bounds of the zone a full transfer loads, records per `RRset` among them (D204).
    pub zone: dedens_zone::Limits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            time: Duration::from_hours(2),
            idle: Duration::from_secs(120),
            messages: 1 << 24,
            bytes: 1 << 30,
            records: 1 << 24,
            zone: dedens_zone::Limits::default(),
        }
    }
}

/// Why a transfer or an SOA query failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// No random ID for the query.
    #[error("no randomness")]
    Random(#[source] io::Error),
    /// The query cannot be signed.
    #[error("cannot sign the query")]
    Sign(#[source] SignError),
    /// The UDP socket of the SOA query cannot be opened.
    #[error("cannot open a UDP socket")]
    Socket(#[source] io::Error),
    /// The connection to the primary cannot be opened.
    #[error("cannot connect")]
    Connect(#[source] io::Error),
    /// Sending or receiving failed.
    #[error("I/O error")]
    Io(#[source] io::Error),
    /// The connection closed before the closing SOA, within a message or between two.
    #[error("connection closed before the end of the transfer")]
    Closed,
    /// The transfer took longer than one of its [`Limits`].
    #[error("past the limit of {0:?}")]
    Limit(Limit),
    /// The primary's response was refused.
    #[error(transparent)]
    Stream(#[from] StreamError),
    /// Past [`SOA_TIMEOUT`], no UDP response accepted: the last datagram waited past was refused so, as a response
    /// signed at a time too far from ours is.
    #[error("no response accepted before the deadline, the last refused: {0}")]
    Unanswered(#[source] StreamError),
}

/// The SOA of `zone` at `primary`, the query signed with `key` if any: over UDP, then over TCP when truncated,
/// within [`SOA_TIMEOUT`]. Over UDP, a datagram that does not come from an authenticated response is waited past:
/// anyone can send one, and the real response may follow (RFC 8945 §5.4, RFC 5452 §9.1). With a key, that is every
/// datagram before its TSIG verifies, one that does not decode included; without, one that does not decode or does
/// not repeat the question. Only a verified response, or a TSIG error that verifies, ends the query. Over TCP, a
/// response refused ends it.
///
/// # Errors
///
/// [`TransferError`]; [`TransferError::Limit`] with [`Limit::Time`] past [`SOA_TIMEOUT`] when nothing came,
/// [`TransferError::Unanswered`] when datagrams were waited past, with the last one's refusal.
pub async fn soa<N: Io>(
    io: &N,
    primary: SocketAddr,
    zone: &Name<'static>,
    key: Option<&Key>,
) -> Result<Soa<'static>, TransferError> {
    let deadline = after(io, SOA_TIMEOUT);
    let id = draw_id(io)?;
    let (wire, verifier) = signed(io, query(zone, RecordType::SOA, None, id), key)?;
    let udp = io
        .udp_bind(unspecified(primary))
        .await
        .map_err(TransferError::Socket)?;
    udp.connect(primary).await.map_err(TransferError::Socket)?;
    let BufResult(sent, _) = udp.send(wire.clone()).await;
    sent.map_err(TransferError::Io)?;
    // The last datagram waited past, the cause of a deadline that no response answers.
    let mut last = None;
    loop {
        let BufResult(received, response) = io
            .timeout_at(deadline, udp.recv(Vec::with_capacity(MAX_DATAGRAM)))
            .await
            .map_err(|_| {
                last.take()
                    .map_or(TransferError::Limit(Limit::Time), TransferError::Unanswered)
            })?;
        received.map_err(TransferError::Io)?;
        let Some(flags) = response_flags(&response, id) else {
            trace!(%primary, "not a response to the soa query, waiting on");
            continue;
        };
        if !flags.contains(Flags::TC) {
            // A failed verification leaves the verifier as it was, but `soa_response` takes it: a copy.
            match soa_response(&response, id, zone, verifier.clone(), io.unix_time()) {
                Err(error) if error.spoofable(key.is_some()) => {
                    debug!(%primary, %error, "soa response not accepted, waiting on");
                    last = Some(error);
                    continue;
                }
                done => return Ok(done?),
            }
        }
        debug!(%primary, "soa response truncated, asking over tcp");
        let mut tcp = Tcp::open(io, primary, &wire, deadline, SOA_TIMEOUT).await?;
        let response = tcp.next().await?;
        return Ok(soa_response(&response, id, zone, verifier, io.unix_time())?);
    }
}

/// Transfers `zone` from `primary` over TCP, the query signed with `key` if any: an IXFR from `from` when the
/// client holds the zone at that serial, else an AXFR (RFC 5936 §4.1.1, RFC 1995 §3). An IXFR refused as
/// [`StreamError::retry_axfr`] says is asked again as an AXFR, once, within the same [`Limits::time`].
///
/// # Errors
///
/// [`TransferError`].
pub async fn transfer<N: Io>(
    io: &N,
    primary: SocketAddr,
    zone: &Name<'static>,
    from: Option<Serial>,
    key: Option<&Key>,
    limits: &Limits,
) -> Result<Transfer, TransferError> {
    let deadline = after(io, limits.time);
    let Some(serial) = from else {
        return ask(io, primary, zone, Asked::Axfr(None), key, limits, deadline).await;
    };
    match ask(
        io,
        primary,
        zone,
        Asked::Ixfr(serial),
        key,
        limits,
        deadline,
    )
    .await
    {
        Err(TransferError::Stream(error)) if error.retry_axfr() => {
            debug!(%primary, zone = %zone, %error, "ixfr refused, asking for axfr");
            ask(io, primary, zone, Asked::Axfr(from), key, limits, deadline).await
        }
        done => done,
    }
}

/// One transfer, as `asked`, before `deadline`.
async fn ask<N: Io>(
    io: &N,
    primary: SocketAddr,
    zone: &Name<'static>,
    asked: Asked,
    key: Option<&Key>,
    limits: &Limits,
    deadline: Instant,
) -> Result<Transfer, TransferError> {
    let id = draw_id(io)?;
    let authority = match asked {
        Asked::Ixfr(serial) => Some(ixfr_soa(zone, serial)),
        Asked::Axfr(_) => None,
    };
    let (wire, verifier) = signed(io, query(zone, asked.qtype(), authority, id), key)?;
    let mut reader = Reader::new(zone.clone(), id, asked, verifier, limits);
    let mut tcp = Tcp::open(io, primary, &wire, deadline, limits.idle).await?;
    loop {
        let message = tcp.next().await?;
        match reader.message(&message, io.unix_time())? {
            Step::More(next) => reader = next,
            Step::Done(transfer) => {
                debug!(%primary, zone = %zone, "transfer done");
                return Ok(transfer);
            }
        }
    }
}

/// A connection to the primary, the query sent, its responses read before a deadline.
pub struct Tcp<'i, N: Io> {
    io: &'i N,
    read: BufReader<<N::Stream as Splittable>::ReadHalf>,
    /// Kept open until the end: dropping it would close the connection.
    _write: <N::Stream as Splittable>::WriteHalf,
    deadline: Instant,
    idle: Duration,
}

impl<'i, N: Io> Tcp<'i, N> {
    /// Connects to `primary` and sends `wire`, each step within `idle` and `deadline`.
    ///
    /// # Errors
    ///
    /// [`TransferError::Connect`], [`TransferError::Io`], or [`TransferError::Limit`] past a bound.
    ///
    /// # Panics
    ///
    /// When `wire` is longer than a TCP message (65535 bytes): the queries of [`query`] are not.
    pub async fn open(
        io: &'i N,
        primary: SocketAddr,
        wire: &[u8],
        deadline: Instant,
        idle: Duration,
    ) -> Result<Self, TransferError> {
        let stream = wait(io, deadline, idle, io.tcp_connect(primary))
            .await?
            .map_err(TransferError::Connect)?;
        let (read, mut write) = stream.split();
        let framed = frame(wire).expect("a query of one question and one SOA fits in 65535 bytes");
        let BufResult(sent, _) = wait(io, deadline, idle, write.write_all(framed)).await?;
        sent.map_err(TransferError::Io)?;
        Ok(Self {
            io,
            read: BufReader::new(read),
            _write: write,
            deadline,
            idle,
        })
    }

    /// The next message.
    ///
    /// # Errors
    ///
    /// [`TransferError::Closed`] when the primary closed the connection, [`TransferError::Io`], or
    /// [`TransferError::Limit`] past a bound.
    pub async fn next(&mut self) -> Result<Vec<u8>, TransferError> {
        wait(
            self.io,
            self.deadline,
            self.idle,
            read_message(&mut self.read),
        )
        .await?
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => TransferError::Closed,
            _ => TransferError::Io(error),
        })
    }
}

/// `future`, within `idle` from now and `deadline`.
async fn wait<N: Io, F: Future>(
    io: &N,
    deadline: Instant,
    idle: Duration,
    future: F,
) -> Result<F::Output, TransferError> {
    let idle_by = after(io, idle);
    io.timeout_at(deadline.min(idle_by), future)
        .await
        .map_err(|_| {
            TransferError::Limit(if idle_by < deadline {
                Limit::Idle
            } else {
                Limit::Time
            })
        })
}

/// `after` from now, or 30 years on when the clock cannot count so far: a limit set to `Duration::MAX` means none.
pub fn after(io: &impl Io, after: Duration) -> Instant {
    let now = io.now();
    now.checked_add(after).unwrap_or_else(|| now + FAR)
}

/// A random query ID (RFC 5452 §4.3).
///
/// # Errors
///
/// [`TransferError::Random`].
pub fn draw_id(io: &impl Io) -> Result<u16, TransferError> {
    let mut id = [0; 2];
    io.random(&mut id).map_err(TransferError::Random)?;
    Ok(u16::from_be_bytes(id))
}

/// The query of `id` for `qtype` of `zone`, with `authority`: no RD, no EDNS.
///
/// # Panics
///
/// Never for a name and an SOA each within the 255 bytes of a name: the query is under 512 bytes.
#[must_use]
pub fn query(
    zone: &Name<'static>,
    qtype: RecordType,
    authority: Option<Record<'static>>,
    id: u16,
) -> Vec<u8> {
    let message = Message {
        header: Header {
            id,
            flags: Flags::default(),
            opcode: Opcode::QUERY,
            rcode: Rcode::NOERROR,
        },
        questions: vec![Question::new(zone.clone(), qtype)],
        authority: authority.into_iter().collect(),
        ..Message::default()
    };
    let mut wire = vec![0; 512];
    let len = message
        .encode(&mut wire)
        .expect("a question and an SOA of names of 255 bytes at most fit in 512 bytes");
    wire.truncate(len);
    wire
}

/// `wire` signed with `key`, if any, and the verifier of its responses.
///
/// # Errors
///
/// [`TransferError::Sign`].
pub fn signed<'k>(
    io: &impl Io,
    mut wire: Vec<u8>,
    key: Option<&'k Key>,
) -> Result<(Vec<u8>, Option<ResponseVerifier<'k>>), TransferError> {
    let verifier = key
        .map(|key| sign_request(key, &mut wire, io.unix_time()))
        .transpose()
        .map_err(TransferError::Sign)?;
    Ok((wire, verifier))
}

/// The header flags of `response` when it is a response of `id`.
fn response_flags(response: &[u8], id: u16) -> Option<Flags> {
    let header = Header::peek(response)?;
    (header.id == id && header.flags.contains(Flags::QR)).then_some(header.flags)
}
