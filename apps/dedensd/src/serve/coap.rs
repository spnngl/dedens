//! DNS over CoAP (RFC 9953, D81): the requests of one UDP socket, each through the pipeline as any query and
//! answered as [`dedens_net::coap::dns`] says.
//!
//! A CON request is answered with an ACK carrying the response, at whatever time it is ready: the client goes on
//! retransmitting until then, and a retransmission is not asked again (RFC 7252 §4.5). A NON request gets a NON
//! response, and is not asked again either. There is no separate response, and no state for Block1: a request in
//! blocks is refused 4.13. A response in blocks is cut again from the response each request gets, and kept to cut the
//! next blocks from for the clients that ask for them without the query ([`Blocks`]). Limits (D105): a request is
//! read up to [`MAX_REQUEST`] bytes, [`TASKS`] are answered at once, a retransmission is answered again at most
//! `MAX_RETRANSMIT` times, and a kept response is served as many bytes as `Blocks` says.

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::time::Instant;

use compio::BufResult;
use compio::net::UdpSocket;
use dedens_net::coap::dns::{
    BLOCK_SIZE, Query, discovery, error, more_blocks, path_segments, query, response,
};
use dedens_net::coap::server::{Blocks, Dedup, EXCHANGE_LIFETIME, Found, NON_LIFETIME, Seen};
use dedens_net::coap::{Code, Message, Type};
use dedens_proto::Transport;

use super::isolate::{Listener, Origin};
use super::upstream::answer;
use super::{ERROR_PAUSE, Slot, Slots, Started, Thread, start};

/// The largest request read, in bytes (D105): a datagram over it is read to here and refused 4.13. A query fits the
/// largest block, 1024 bytes (RFC 7959 §2.2), and the header, token and options of a request take far less than the
/// other 1024. RFC 7252 §4.6 suggests 1152 bytes for a message, a bound for a path of unknown MTU.
const MAX_REQUEST: usize = 2048;

/// Requests answered at once per socket (D105): past them, a new request is dropped, and a CON request is sent again
/// by its client. As D47's TCP connections, per socket: a thread answers this many for each `coap://` listener.
const TASKS: usize = 256;

/// CON requests remembered per socket to tell a retransmission from a new request.
const DEDUP_CAPACITY: NonZeroUsize = NonZeroUsize::new(4096).expect("4096 is not zero");

/// Responses in blocks remembered per socket for the requests of the next blocks.
const BLOCKS_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).expect("64 is not zero");

/// What the tasks of one socket share, kept when its loop starts again (D121): a request seen stays seen.
pub(super) struct Coap {
    socket: Rc<UdpSocket>,
    /// The path `DoC` is served at.
    path: Vec<Box<[u8]>>,
    /// The CON requests seen, with the replies sent.
    dedup: RefCell<Dedup>,
    /// The NON requests seen: a duplicate gets no reply, a NON message is not retransmitted (RFC 7252 §4.5).
    non_dedup: RefCell<Dedup>,
    blocks: RefCell<Blocks>,
    /// The message ID of the next NON message: a counter from a random start (RFC 7252 §4.4), so that a reply cannot be
    /// told from its place in the run of the server's own.
    ids: Cell<u16>,
    /// The requests being answered.
    tasks: Slots,
}

impl Coap {
    /// The state of `socket`, serving the resource at `path`.
    pub(super) fn new(socket: Rc<UdpSocket>, path: &str) -> Self {
        Self {
            socket,
            path: path_segments(path),
            dedup: RefCell::new(Dedup::new(EXCHANGE_LIFETIME, DEDUP_CAPACITY)),
            non_dedup: RefCell::new(Dedup::new(NON_LIFETIME, DEDUP_CAPACITY)),
            blocks: RefCell::new(Blocks::new(EXCHANGE_LIFETIME, BLOCKS_CAPACITY)),
            ids: Cell::new(first_id()),
            tasks: Slots::new(TASKS),
        }
    }

    fn next_id(&self) -> u16 {
        let id = self.ids.get();
        self.ids.set(id.wrapping_add(1));
        id
    }

    /// Sends `datagram` to `peer`, and gives it back.
    async fn send(&self, peer: SocketAddr, datagram: Vec<u8>) -> Vec<u8> {
        let BufResult(sent, datagram) = self.socket.send_to(datagram, peer).await;
        if let Err(error) = sent {
            tracing::debug!(%error, %peer, "CoAP send");
        }
        datagram
    }

    /// Sends `reply` to `peer`, keeping it to send again for a retransmission of a CON `request`.
    async fn reply(&self, request: &Message, peer: SocketAddr, reply: Message) {
        let datagram = match reply.to_vec() {
            Ok(datagram) => datagram,
            Err(error) => return tracing::debug!(%error, %peer, "CoAP reply not written"),
        };
        let datagram = self.send(peer, datagram).await;
        if request.kind == Type::Confirmable {
            self.dedup.borrow_mut().reply(peer, request.id, datagram);
        }
    }

    /// Answers a request too large to read whole (RFC 7252 §4.6): 4.13 with the largest body the server takes, if what
    /// was read, `start`, is a request; anything else is dropped.
    async fn refuse_large(&self, start: &[u8], peer: SocketAddr) {
        let Ok(request) = Message::parse(start) else {
            return;
        };
        if !request.code.is_request() || request.kind == Type::Acknowledgement {
            return;
        }
        let mut reply = error(&request, self.next_id(), Code::REQUEST_ENTITY_TOO_LARGE);
        reply
            .options
            .set_size1(u32::try_from(BLOCK_SIZE.bytes()).expect("a block size fits 32 bits"));
        if let Ok(datagram) = reply.to_vec() {
            self.send(peer, datagram).await;
        }
    }

    /// Answers `request` with the DNS response `wire`; `keep` it, copied, for the next blocks when the block of the
    /// reply has more after it. A request for a later block does not (D105): the response is kept as it was.
    async fn respond(&self, request: &Message, peer: SocketAddr, wire: Vec<u8>, keep: bool) {
        let kept = (keep && more_blocks(request, &wire)).then(|| wire.clone());
        let reply = response(request, self.next_id(), wire)
            .unwrap_or_else(|code| error(request, self.next_id(), code));
        if let Some(kept) = kept {
            self.blocks.borrow_mut().keep(
                peer,
                request.options.request_tag(),
                Instant::now(),
                kept,
            );
        }
        self.reply(request, peer, reply).await;
    }
}

/// A random message ID to count from (RFC 7252 §4.4). Without randomness, 0: the IDs of the NON messages are no
/// secret worth stopping for.
fn first_id() -> u16 {
    let mut bytes = [0; 2];
    if let Err(error) = getrandom::fill(&mut bytes) {
        tracing::warn!(%error, "CoAP: no randomness for the first message ID");
    }
    u16::from_be_bytes(bytes)
}

/// Answers the requests of `coap`'s socket until the end of the process, as the listener `listener`.
pub(super) async fn serve(coap: Rc<Coap>, listener: Listener, thread: Rc<Thread>) {
    // One byte more than a request may hold, to tell a datagram that fills the buffer from one cut by it.
    let mut buf = Vec::with_capacity(MAX_REQUEST + 1);
    let mut failing = false;
    loop {
        buf.clear();
        let BufResult(received, back) = coap.socket.recv_from(buf).await;
        buf = back;
        let (len, peer) = match received {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(%error, "CoAP receive");
                if failing {
                    compio::time::sleep(ERROR_PAUSE).await;
                }
                failing = true;
                continue;
            }
        };
        failing = false;
        // `action: drop` (D91): no message sent, no task nor exchange state taken for the client.
        if thread.pipeline().drops(peer.ip()) {
            continue;
        }
        if len > MAX_REQUEST {
            tracing::debug!(len, %peer, "CoAP request too large");
            coap.refuse_large(&buf[..MAX_REQUEST], peer).await;
            continue;
        }
        // A CON message with a format error is rejected with a RST; the rest of what is not a message is dropped
        // (RFC 7252 §4.2).
        let Ok(message) = Message::parse(&buf[..len]) else {
            if let Some(reset) = Message::reject(&buf[..len])
                && let Ok(reset) = reset.to_vec()
            {
                coap.send(peer, reset).await;
            }
            continue;
        };
        let confirmable = message.kind == Type::Confirmable;
        // A ping, or a response nobody asked for, is rejected (RFC 7252 §4.3, §4.2).
        if confirmable && !message.code.is_request() {
            if let Ok(reset) = Message::empty(Type::Reset, message.id).to_vec() {
                coap.send(peer, reset).await;
            }
            continue;
        }
        if message.kind == Type::NonConfirmable && !message.code.is_request() {
            continue;
        }
        if matches!(message.kind, Type::Acknowledgement | Type::Reset) {
            continue;
        }
        // A duplicate needs no task: it is answered from what was kept, or not at all (D105).
        let dedup = if confirmable {
            &coap.dedup
        } else {
            &coap.non_dedup
        };
        let now = Instant::now();
        let seen = match dedup.borrow_mut().lookup(peer, message.id, now) {
            Seen::New => None,
            Seen::Duplicate(reply) => Some(reply.map(<[u8]>::to_vec)),
        };
        if let Some(reply) = seen {
            if let Some(reply) = reply {
                coap.send(peer, reply).await;
            }
            continue;
        }
        // A new request with no task to answer it is dropped, not noted as seen: its retransmission is asked. No 5.03:
        // as D47 drops past its limits, an answer under overload costs more than the request did.
        let Some(slot) = coap.tasks.take() else {
            tracing::debug!(%peer, "too many CoAP requests: dropped");
            continue;
        };
        dedup.borrow_mut().note(peer, message.id, now);
        Origin::new(&listener, peer).spawn(handle(
            Rc::clone(&coap),
            Rc::clone(&thread),
            message,
            peer,
            slot,
        ));
    }
}

/// Answers one request of a client the access lists do not drop ([`serve`] has seen to it, D91): the list of the
/// `DoC` resource if it asks for `/.well-known/core` ([`discovery`], D95), else the error [`query`] finds in it, else the pipeline's
/// reply, or 4.00 when the pipeline drops it, a body that is not a DNS message (RFC 9953 §4.3.1). A request for a
/// later block is answered from the response kept for it, unless the lists now deny the client (a reload), or 4.00.
/// A discovery or a DNS query from a network over its rate is answered with nothing (D113: the answer is bigger than
/// the request, as over UDP). The rest are not counted: an error is no bigger than its request, and a later block is
/// asked for after a DNS query that was, and is bounded by D105.
///
/// The `_slot` is the request's place among [`TASKS`], given back at the end.
async fn handle(
    coap: Rc<Coap>,
    thread: Rc<Thread>,
    request: Message,
    peer: SocketAddr,
    _slot: Slot,
) {
    let pipeline = thread.pipeline();
    let limited = || pipeline.limits(peer.ip(), super::now());
    if let Some(reply) = discovery(&request, coap.next_id(), &coap.path) {
        if limited() {
            return;
        }
        return coap.reply(&request, peer, reply).await;
    }
    let query = match query(&request, &coap.path) {
        Ok(Query::Dns(query)) => {
            if limited() {
                return;
            }
            query
        }
        Ok(Query::Block(requested)) => {
            let tag = request.options.request_tag();
            // Past what a response may be asked for, nothing is sent (D105).
            let kept = match coap
                .blocks
                .borrow_mut()
                .get(peer, tag, requested, Instant::now())
            {
                Found::Spent => return,
                Found::Unknown => None,
                Found::Response(wire) => Some(wire.to_vec()),
            };
            if let Some(wire) = kept.filter(|_| pipeline.denial(peer.ip()).is_none()) {
                return coap.respond(&request, peer, wire, false).await;
            }
            let reply = error(&request, coap.next_id(), Code::BAD_REQUEST);
            return coap.reply(&request, peer, reply).await;
        }
        Err(code) => {
            let reply = error(&request, coap.next_id(), code);
            return coap.reply(&request, peer, reply).await;
        }
    };
    let mut first = None;
    let started = start(
        &thread,
        &pipeline,
        query,
        Transport::Coap,
        peer.ip(),
        |wire| {
            first = Some(wire.to_vec());
            true
        },
    );
    let mut answered = false;
    if let Some(wire) = first {
        answered = true;
        coap.respond(&request, peer, wire, true).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |wire| {
            if !answered {
                answered = true;
                coap.respond(&request, peer, wire, true).await;
            }
        };
        answer(&thread, &pipeline, upstream, Transport::Coap, deliver).await;
        drop(slot);
    }
    if !answered {
        let reply = error(&request, coap.next_id(), Code::BAD_REQUEST);
        coap.reply(&request, peer, reply).await;
    }
}
