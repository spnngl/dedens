//! DNS over CoAP (RFC 9953, D81): the requests of one UDP socket, each through the pipeline as any query and
//! answered as [`dedens_net::coap::doc`] says.
//!
//! A CON request is answered with an ACK carrying the response, at whatever time it is ready: the client goes on
//! retransmitting until then, and a retransmission is not asked again (RFC 7252 §4.5). A NON request gets a NON
//! response. There is no separate response, and no state for Block1: a request in blocks is refused 4.13. A
//! response in blocks is cut again from the response each request gets, and kept to cut the next blocks from for the
//! clients that ask for them without the query ([`Blocks`]).

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use compio::BufResult;
use compio::net::UdpSocket;
use compio::runtime::spawn;
use dedens_net::coap::block::Block;
use dedens_net::coap::doc::{Query, discovery, error, path_segments, query, response};
use dedens_net::coap::server::{Blocks, Dedup, EXCHANGE_LIFETIME, Seen};
use dedens_net::coap::{Code, Message, Type};
use dedens_server::Transport;

use super::{ERROR_PAUSE, Started, Thread, answer, start};

/// The largest UDP payload, which a datagram may fill.
const MAX_DATAGRAM: usize = 65535;

/// CON requests remembered per socket to tell a retransmission from a new request.
const DEDUP_CAPACITY: NonZeroUsize = NonZeroUsize::new(4096).expect("4096 is not zero");

/// Responses in blocks remembered per socket for the requests of the next blocks.
const BLOCKS_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).expect("64 is not zero");

/// What the tasks of one socket share.
struct Coap {
    socket: UdpSocket,
    /// The path `DoC` is served at.
    path: Vec<Box<[u8]>>,
    dedup: RefCell<Dedup>,
    blocks: RefCell<Blocks>,
    /// The message ID of the next NON message: a counter from a random start (RFC 7252 §4.4), so that a reply cannot be
    /// told from its place in the run of the server's own.
    ids: Cell<u16>,
}

impl Coap {
    fn next_id(&self) -> u16 {
        let id = self.ids.get();
        self.ids.set(id.wrapping_add(1));
        id
    }

    async fn send(&self, peer: SocketAddr, datagram: Vec<u8>) {
        let BufResult(sent, _) = self.socket.send_to(datagram, peer).await;
        if let Err(error) = sent {
            tracing::debug!(%error, %peer, "CoAP send");
        }
    }

    /// Sends `reply` to `peer`, keeping it to send again for a retransmission of a CON `request`.
    async fn reply(&self, request: &Message, peer: SocketAddr, reply: Message) {
        let datagram = match reply.to_vec() {
            Ok(datagram) => datagram,
            Err(error) => return tracing::debug!(%error, %peer, "CoAP reply not written"),
        };
        if request.kind == Type::Confirmable {
            self.dedup
                .borrow_mut()
                .reply(peer, request.id, datagram.clone());
        }
        self.send(peer, datagram).await;
    }

    /// Answers `request` with the DNS response `wire`, keeping it if the reply is its first block of several.
    async fn respond(&self, request: &Message, peer: SocketAddr, wire: Vec<u8>) {
        let kept = wire.clone();
        let reply = response(request, self.next_id(), wire)
            .unwrap_or_else(|code| error(request, self.next_id(), code));
        if reply
            .options
            .block2()
            .ok()
            .flatten()
            .is_some_and(Block::more)
        {
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

/// Answers the requests of `socket` for the resource at `path`, until the end of the process.
pub(super) async fn serve(socket: UdpSocket, path: Arc<str>, thread: Rc<Thread>) {
    let coap = Rc::new(Coap {
        socket,
        path: path_segments(&path),
        dedup: RefCell::new(Dedup::new(EXCHANGE_LIFETIME, DEDUP_CAPACITY)),
        blocks: RefCell::new(Blocks::new(EXCHANGE_LIFETIME, BLOCKS_CAPACITY)),
        ids: Cell::new(first_id()),
    });
    let mut buf = Vec::with_capacity(MAX_DATAGRAM);
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
        if confirmable {
            let seen = match coap
                .dedup
                .borrow_mut()
                .check(peer, message.id, Instant::now())
            {
                Seen::New => None,
                Seen::Duplicate(reply) => Some(reply.map(<[u8]>::to_vec)),
            };
            if let Some(reply) = seen {
                if let Some(reply) = reply {
                    coap.send(peer, reply).await;
                }
                continue;
            }
        }
        spawn(handle(Rc::clone(&coap), Rc::clone(&thread), message, peer)).detach();
    }
}

/// Answers one request: the list of the `DoC` resource if it asks for `/.well-known/core` ([`discovery`], D95), else
/// the error [`query`] finds in it, else the pipeline's reply, or 4.00 when the pipeline
/// drops it, a body that is not a DNS message (RFC 9953 §4.3.1). A request for a later block is answered from the
/// response kept for it, or 4.00.
async fn handle(coap: Rc<Coap>, thread: Rc<Thread>, request: Message, peer: SocketAddr) {
    if let Some(reply) = discovery(&request, coap.next_id(), &coap.path) {
        return coap.reply(&request, peer, reply).await;
    }
    let query = match query(&request, &coap.path) {
        Ok(Query::Dns(query)) => query,
        Ok(Query::Block) => {
            let kept = coap
                .blocks
                .borrow_mut()
                .get(peer, request.options.request_tag(), Instant::now())
                .map(<[u8]>::to_vec);
            if let Some(wire) = kept {
                return coap.respond(&request, peer, wire).await;
            }
            let reply = error(&request, coap.next_id(), Code::BAD_REQUEST);
            return coap.reply(&request, peer, reply).await;
        }
        Err(code) => {
            let reply = error(&request, coap.next_id(), code);
            return coap.reply(&request, peer, reply).await;
        }
    };
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = start(&thread, &pipeline, query, Transport::Coap, |wire| {
        first = Some(wire.to_vec());
        true
    });
    let mut answered = false;
    if let Some(wire) = first {
        answered = true;
        coap.respond(&request, peer, wire).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |wire| {
            if !answered {
                answered = true;
                coap.respond(&request, peer, wire).await;
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
