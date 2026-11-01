//! One CoAP request and its response, without I/O (RFC 7252 §4, §5, RFC 7959 §2; D80).
//!
//! An [`Exchange`] sends the request as a CON message and decides what happens next; its caller moves the
//! datagrams, keeps time and draws the randomness. It handles what CoAP puts between a request and its response:
//! retransmission with exponential back-off, the response in the ACK or separate from it, and block-wise
//! transfers: a request body over the block size goes out in Block1 blocks, a response body in Block2 blocks is
//! asked for and put together.
//!
//! ```
//! # use std::net::SocketAddr;
//! # use std::time::Instant;
//! # use dedens_net::coap::exchange::{Exchange, Next, Params, Request};
//! # use dedens_net::coap::{Code, Message, Options, Token, Type};
//! let server: SocketAddr = "[2001:db8::1]:5684".parse()?;
//! let mut options = Options::new();
//! options.push_uri_path([b"temperature".as_slice()]);
//! let request = Request { code: Code::GET, options, payload: vec![], token: Token::new(&[0x20])? };
//! let now = Instant::now();
//! let step = Exchange::start(request, server, Params::default(), 0x7d35, 1, now);
//! let Next::Wait(exchange) = step.next else { unreachable!() };
//! // Send step.send, wait until exchange.deadline(); the ACK comes:
//! let ack = Message {
//!     kind: Type::Acknowledgement,
//!     code: Code::CONTENT,
//!     id: 0x7d35,
//!     token: Token::new(&[0x20])?,
//!     options: Options::new(),
//!     payload: b"22.3 C".to_vec(),
//! };
//! let step = exchange.receive(server, &ack.to_vec()?, now);
//! let Next::Done(Ok(response)) = step.next else { unreachable!() };
//! assert_eq!(response.payload, b"22.3 C");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::block::{Block, BlockError, BlockSize, Reassembly, ReassemblyError};
use super::message::{Code, Message, OptionNumber, Options, Token, Type, WriteError};
use crate::exchange::after;

/// How an exchange behaves; the default is RFC 7252 §4.8's.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Params {
    /// `ACK_TIMEOUT`: the wait for an ACK before the first retransmission, at least (RFC 7252 §4.8).
    pub ack_timeout: Duration,
    /// `ACK_RANDOM_FACTOR`, at least 1: the first wait is a random time from `ack_timeout` to this many times it.
    pub ack_random_factor: f64,
    /// `MAX_RETRANSMIT`: the retransmissions of a message before giving up.
    pub max_retransmit: u8,
    /// How long to wait for the response after an empty ACK; RFC 7252 sets none, this is `MAX_TRANSMIT_WAIT`.
    pub separate_timeout: Duration,
    /// The size of the blocks of a request body over it (RFC 7959 §2.2).
    pub block1_size: BlockSize,
    /// The block size to propose for the response; none leaves it to the server (RFC 7959 §2.3).
    pub block2_size: Option<BlockSize>,
    /// The most a response body may hold, in bytes.
    pub max_body: usize,
    /// Whether a response in blocks must carry an `ETag`: without one, blocks of two versions of the body cannot
    /// be told apart (RFC 7959 §2.4 only asks the server to send one, and the client to compare when it is there).
    pub require_etag: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            ack_timeout: Duration::from_secs(2),
            ack_random_factor: 1.5,
            max_retransmit: 4,
            separate_timeout: Duration::from_secs(93),
            block1_size: BlockSize::MAX,
            block2_size: None,
            max_body: Reassembly::DEFAULT_LIMIT,
            require_etag: false,
        }
    }
}

/// The request of an exchange. The exchange sets the Block1 and Block2 options itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub code: Code,
    /// The options.
    pub options: Options,
    /// The request body.
    pub payload: Vec<u8>,
    /// The token, the same in every message of the exchange. Random, and at least 2 bytes over an unprotected
    /// transport (RFC 9953 §6): the caller draws it.
    pub token: Token,
}

/// The response that ended an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The response code.
    pub code: Code,
    /// The options; those of the first block of a block-wise response.
    pub options: Options,
    /// The response body: all blocks.
    pub payload: Vec<u8>,
}

/// Why an exchange ended without a response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// The code of the request is not a method.
    #[error("{0} is not a request method")]
    NotARequest(Code),
    /// No ACK to any of the transmissions, or no response after an empty ACK.
    #[error("no response")]
    TimedOut,
    /// The server answered with a RST (RFC 7252 §4.2).
    #[error("the server reset the request")]
    Reset,
    /// A response with a critical option that is not known (RFC 7252 §5.4.1).
    #[error("a response with the unknown critical option {0:?}")]
    UnknownCriticalOption(OptionNumber),
    /// A response with a Block1 or Block2 option that is not a block.
    #[error("a response with a bad block option")]
    Block(#[from] BlockError),
    /// A block that does not follow the others, or comes where none was due.
    #[error("a response with an unexpected block")]
    UnexpectedBlock,
    /// A response body that cannot be put together.
    #[error("cannot put the response body together")]
    Reassembly(#[from] ReassemblyError),
    /// The `ETag` changed between blocks: the body changed meanwhile (RFC 7959 §2.4).
    #[error("the ETag changed between the blocks of the response")]
    ETagChanged,
    /// A response in blocks without an `ETag`, which [`Params::require_etag`] asked for.
    #[error("the response in blocks has no ETag")]
    MissingETag,
    /// A message cannot be written.
    #[error("cannot write the request")]
    Encode(#[from] WriteError),
}

/// What an [`Exchange`] step asks of its caller: the datagrams to send, then wait or stop.
#[derive(Debug)]
pub struct Step {
    /// Datagrams to send to the server now, in order.
    pub send: Vec<Vec<u8>>,
    /// What comes next.
    pub next: Next,
}

/// What happens after a step of an [`Exchange`].
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "moved once a datagram, and boxing would cost an allocation to save a copy"
)]
pub enum Next {
    /// Wait until [`Exchange::deadline`] for a datagram; then call [`Exchange::time_out`].
    Wait(Exchange),
    /// The exchange is over.
    Done(Result<Response, Failure>),
}

impl Step {
    const fn wait(exchange: Exchange) -> Self {
        Self {
            send: Vec::new(),
            next: Next::Wait(exchange),
        }
    }

    const fn done(result: Result<Response, Failure>, send: Vec<Vec<u8>>) -> Self {
        Self {
            send,
            next: Next::Done(result),
        }
    }
}

/// What the exchange waits for.
#[derive(Debug)]
enum Awaiting {
    /// An ACK of the message sent, with the response or empty.
    Ack,
    /// The response, after the ACK was empty, until the deadline.
    Separate(Instant),
}

/// The CON message in flight.
#[derive(Debug)]
struct Sent {
    message: Message,
    wire: Vec<u8>,
    retransmits: u8,
    timeout: Duration,
    deadline: Instant,
}

/// A request body going out in Block1 blocks.
#[derive(Debug)]
struct Upload {
    size: BlockSize,
    /// The number of the block sent last, and where it ends in the body.
    num: u32,
    end: usize,
}

/// A response body coming in Block2 blocks.
#[derive(Debug)]
struct Download {
    reassembly: Reassembly,
    /// The first response: its code and options are those of the whole.
    first: Response,
    etag: Option<Vec<u8>>,
}

/// One request to one server: transmission, matching of the response and block-wise transfer (D80).
#[derive(Debug)]
pub struct Exchange {
    server: SocketAddr,
    request: Request,
    params: Params,
    /// The state of the generator of the retransmission jitter.
    random: u32,
    next_id: u16,
    sent: Sent,
    awaiting: Awaiting,
    /// Set when the request body goes out in blocks.
    upload: Option<Upload>,
    download: Option<Download>,
    /// The ID of the last separate CON response, to ACK it again if repeated (RFC 7252 §4.5).
    separate_id: Option<u16>,
}

impl Exchange {
    /// Starts the exchange of `request` with `server` at `now`.
    ///
    /// The messages take IDs from `first_id` up, one each; give exchanges with one server distinct ranges
    /// (RFC 7252 §4.4). `seed` makes the jitter of the retransmission times: any number, drawn at random.
    #[must_use]
    pub fn start(
        mut request: Request,
        server: SocketAddr,
        params: Params,
        first_id: u16,
        seed: u32,
        now: Instant,
    ) -> Step {
        if !request.code.is_request() {
            return Step::done(Err(Failure::NotARequest(request.code)), Vec::new());
        }
        request.options.remove(OptionNumber::BLOCK1);
        request.options.remove(OptionNumber::BLOCK2);
        let upload = (request.payload.len() > params.block1_size.bytes()).then_some(Upload {
            size: params.block1_size,
            num: 0,
            end: 0,
        });
        let placeholder = Sent {
            message: Message::empty(Type::Confirmable, first_id),
            wire: Vec::new(),
            retransmits: 0,
            timeout: params.ack_timeout,
            deadline: now,
        };
        let mut exchange = Self {
            server,
            request,
            params,
            // xorshift32 never leaves 0.
            random: seed | 1,
            next_id: first_id,
            sent: placeholder,
            awaiting: Awaiting::Ack,
            upload,
            download: None,
            separate_id: None,
        };
        let message = if exchange.upload.is_some() {
            exchange.block1_message(0, exchange.params.block1_size)
        } else {
            let block2 = exchange
                .params
                .block2_size
                .and_then(|size| Block::new(0, false, size));
            let payload = exchange.request.payload.clone();
            exchange.message(None, block2, payload)
        };
        exchange.transmit(message, now, Vec::new())
    }

    /// The server the datagrams go to and come from.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// When to call [`Exchange::time_out`] if nothing came.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        match self.awaiting {
            Awaiting::Ack => self.sent.deadline,
            Awaiting::Separate(deadline) => deadline,
        }
    }

    /// Takes a datagram received at `now` from `from`.
    ///
    /// What is not for this exchange is dropped and the wait goes on: from another address, unreadable, or
    /// matching neither the message ID of the request in flight (ACK, RST) nor the token (response). A CON
    /// message with an unknown token is answered with a RST (RFC 7252 §4.2, §5.2.2).
    #[must_use]
    pub fn receive(mut self, from: SocketAddr, bytes: &[u8], now: Instant) -> Step {
        if from != self.server {
            debug!(server = %self.server, %from, "dropped: from another address");
            return Step::wait(self);
        }
        let Ok(message) = Message::parse(bytes) else {
            debug!(server = %self.server, "dropped: unreadable");
            return Step::wait(self);
        };
        let ours = message.id == self.sent.message.id;
        match message.kind {
            Type::Acknowledgement if ours && message.code == Code::EMPTY => {
                // The response comes apart (RFC 7252 §5.2.2); a repeated empty ACK changes nothing.
                if matches!(self.awaiting, Awaiting::Ack) {
                    self.awaiting = Awaiting::Separate(after(now, self.params.separate_timeout));
                }
                Step::wait(self)
            }
            Type::Acknowledgement
                if ours && message.code.is_response() && message.token == self.request.token =>
            {
                self.accept(message, Vec::new(), now)
            }
            Type::Reset if ours => Step::done(Err(Failure::Reset), Vec::new()),
            Type::Confirmable | Type::NonConfirmable if message.code.is_response() => {
                let confirmable = message.kind == Type::Confirmable;
                if message.token != self.request.token {
                    let send = if confirmable {
                        reply(Type::Reset, message.id)
                    } else {
                        Vec::new()
                    };
                    return Step {
                        send,
                        next: Next::Wait(self),
                    };
                }
                if let Some(number) = message.unknown_critical().next() {
                    let send = if confirmable {
                        reply(Type::Reset, message.id)
                    } else {
                        Vec::new()
                    };
                    return Step::done(Err(Failure::UnknownCriticalOption(number)), send);
                }
                let mut send = Vec::new();
                if confirmable {
                    send = reply(Type::Acknowledgement, message.id);
                    if self.separate_id == Some(message.id) {
                        return Step {
                            send,
                            next: Next::Wait(self),
                        };
                    }
                    self.separate_id = Some(message.id);
                }
                self.accept(message, send, now)
            }
            _ => {
                debug!(server = %self.server, id = message.id, "dropped: not for this exchange");
                Step::wait(self)
            }
        }
    }

    /// Takes the passing of [`Exchange::deadline`]: sends the message again, or gives up (RFC 7252 §4.2).
    #[must_use]
    pub fn time_out(mut self, now: Instant) -> Step {
        match self.awaiting {
            Awaiting::Separate(_) => Step::done(Err(Failure::TimedOut), Vec::new()),
            Awaiting::Ack if self.sent.retransmits >= self.params.max_retransmit => {
                Step::done(Err(Failure::TimedOut), Vec::new())
            }
            Awaiting::Ack => {
                self.sent.retransmits += 1;
                self.sent.timeout = self.sent.timeout.saturating_mul(2);
                self.sent.deadline = after(now, self.sent.timeout);
                let send = vec![self.sent.wire.clone()];
                Step {
                    send,
                    next: Next::Wait(self),
                }
            }
        }
    }

    /// A response to the request in flight, matched by token (RFC 7252 §5.3.2), with the datagrams `send` to
    /// send with whatever it makes us send.
    fn accept(mut self, response: Message, send: Vec<Vec<u8>>, now: Instant) -> Step {
        if let Some(number) = response.unknown_critical().next() {
            return Step::done(Err(Failure::UnknownCriticalOption(number)), send);
        }
        // The next block of a request body: the server took this one (RFC 7959 §2.3).
        if response.code == Code::CONTINUE
            && let Some(upload) = &self.upload
        {
            let echo = match response.options.block1() {
                Ok(echo) => echo,
                Err(e) => return Step::done(Err(e.into()), send),
            };
            if upload.end >= self.request.payload.len()
                || echo.is_some_and(|echo| echo.num() != upload.num)
            {
                return Step::done(Err(Failure::UnexpectedBlock), send);
            }
            // The server may ask for smaller blocks; the next number counts in them.
            let size = echo.map_or(upload.size, |echo| echo.size().min(upload.size));
            let Ok(num) = u32::try_from(upload.end >> (size.szx() + 4)) else {
                return Step::done(Err(Failure::UnexpectedBlock), send);
            };
            let message = self.block1_message(num, size);
            return self.transmit(message, now, send);
        }
        if !response.code.is_response() || response.code.class() != 2 {
            return finish(response.code, response.options, response.payload, send);
        }
        let block = match response.options.block2() {
            Ok(block) => block,
            Err(e) => return Step::done(Err(e.into()), send),
        };
        let etag = response.options.etag().map(<[u8]>::to_vec);
        let (mut download, block) = match (self.download.take(), block) {
            (None, None) => {
                return finish(response.code, response.options, response.payload, send);
            }
            (None, Some(block)) if block.num() == 0 => {
                if self.params.require_etag && block.more() && etag.is_none() {
                    return Step::done(Err(Failure::MissingETag), send);
                }
                let mut options = response.options;
                options.remove(OptionNumber::BLOCK2);
                let first = Response {
                    code: response.code,
                    options,
                    payload: Vec::new(),
                };
                (
                    Download {
                        reassembly: Reassembly::new(self.params.max_body),
                        first,
                        etag,
                    },
                    block,
                )
            }
            (Some(download), Some(block)) if download.etag == etag => (download, block),
            (Some(_), Some(_)) => return Step::done(Err(Failure::ETagChanged), send),
            _ => return Step::done(Err(Failure::UnexpectedBlock), send),
        };
        match download.reassembly.push(block, &response.payload) {
            Err(e) => Step::done(Err(e.into()), send),
            Ok(None) => {
                debug!(server = %self.server, blocks = block.num() + 1, "block-wise response complete");
                let Download {
                    reassembly, first, ..
                } = download;
                Step::done(
                    Ok(Response {
                        payload: reassembly.into_body(),
                        ..first
                    }),
                    send,
                )
            }
            Ok(Some(next)) => {
                debug!(server = %self.server, block = next.num(), "asking for the next block");
                self.download = Some(download);
                // A body sent whole goes with each request, which a server without state needs to answer it
                // (RFC 8132 §2: the body is part of the cache key); one sent in blocks is the server's.
                let payload = if self.upload.is_some() {
                    Vec::new()
                } else {
                    self.request.payload.clone()
                };
                let message = self.message(None, Some(next), payload);
                self.transmit(message, now, send)
            }
        }
    }

    /// The Block1 request message for block `num` of `size` of the request body; remembered as the one sent.
    fn block1_message(&mut self, num: u32, size: BlockSize) -> Message {
        let start = Block::new(num, false, size).map_or(usize::MAX, Block::offset);
        let end = self
            .request
            .payload
            .len()
            .min(start.saturating_add(size.bytes()));
        let more = end < self.request.payload.len();
        if let Some(upload) = &mut self.upload {
            *upload = Upload { size, num, end };
        }
        let payload = self
            .request
            .payload
            .get(start..end)
            .unwrap_or_default()
            .to_vec();
        // The size asked for the response goes with the last block (RFC 7959 §3.3).
        let block2 = if more {
            None
        } else {
            self.params
                .block2_size
                .and_then(|size| Block::new(0, false, size))
        };
        self.message(Block::new(num, more, size), block2, payload)
    }

    /// A CON request message with the options of the request and the block options given.
    fn message(
        &mut self,
        block1: Option<Block>,
        block2: Option<Block>,
        payload: Vec<u8>,
    ) -> Message {
        let mut options = self.request.options.clone();
        if let Some(block) = block1 {
            options.set_block1(block);
            // The whole size goes with the first block, for the server to know what to expect (RFC 7959 §4).
            if block.num() == 0
                && let Ok(total) = u32::try_from(self.request.payload.len())
            {
                options.set_size1(total);
            }
        }
        if let Some(block) = block2 {
            options.set_block2(block);
        }
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        Message {
            kind: Type::Confirmable,
            code: self.request.code,
            id,
            token: self.request.token,
            options,
            payload,
        }
    }

    /// Sends `message` as the one in flight, after the `send` datagrams already due.
    fn transmit(mut self, message: Message, now: Instant, mut send: Vec<Vec<u8>>) -> Step {
        let wire = match message.to_vec() {
            Ok(wire) => wire,
            Err(e) => return Step::done(Err(e.into()), send),
        };
        let timeout = self.first_timeout();
        send.push(wire.clone());
        self.sent = Sent {
            message,
            wire,
            retransmits: 0,
            timeout,
            deadline: after(now, timeout),
        };
        self.awaiting = Awaiting::Ack;
        trace!(server = %self.server, id = self.sent.message.id, "sending");
        Step {
            send,
            next: Next::Wait(self),
        }
    }

    /// The first wait for an ACK: a random time from `ACK_TIMEOUT` to `ACK_RANDOM_FACTOR` times it (RFC 7252 §4.2).
    fn first_timeout(&mut self) -> Duration {
        // xorshift32: the jitter needs no more than being spread.
        let mut x = self.random;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.random = x;
        let spread = f64::from(x) / f64::from(u32::MAX);
        let factor = 1.0 + (self.params.ack_random_factor - 1.0).max(0.0) * spread;
        Duration::try_from_secs_f64(self.params.ack_timeout.as_secs_f64() * factor)
            .unwrap_or(self.params.ack_timeout)
    }
}

/// Ends the exchange with a response that needs no more blocks.
fn finish(code: Code, options: Options, payload: Vec<u8>, send: Vec<Vec<u8>>) -> Step {
    Step::done(
        Ok(Response {
            code,
            options,
            payload,
        }),
        send,
    )
}

/// An empty ACK or RST for message `id`, written.
fn reply(kind: Type, id: u16) -> Vec<Vec<u8>> {
    // An empty message always can be written.
    Message::empty(kind, id).to_vec().into_iter().collect()
}
