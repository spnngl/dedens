//! The `coap_doc` target: a client `Exchange` against a model of the `dedensd` listener, driven by the input.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use dedens_net::coap::block::{Block, BlockSize};
use dedens_net::coap::doc::Query;
use dedens_net::coap::exchange::{Exchange, Failure, MAX_RETRANSMIT, Next, Params, Response, Step};
use dedens_net::coap::server::{Dedup, EXCHANGE_LIFETIME, Seen};
use dedens_net::coap::{Code, Message, OptionNumber, Token, Type, doc};

/// A captured response of more than one block of 1024 bytes (RFC 9953's server size).
const LARGE: &[u8] = include_bytes!("../../crates/dedens-proto/tests/testdata/txt_large.bin");
/// A captured response of one block.
const SMALL: &[u8] = include_bytes!("../../crates/dedens-proto/tests/testdata/aaaa.bin");

/// The most operations of one run.
const OPERATIONS: usize = 64;

const CLIENT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 40000);
const SERVER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 5683);

/// The bytes of the input, taken as they are needed; once they are over, zeros.
struct Script<'a>(&'a [u8]);

impl<'a> Script<'a> {
    fn byte(&mut self) -> u8 {
        let (first, rest) = self.0.split_first().map_or((0, self.0), |(b, r)| (*b, r));
        self.0 = rest;
        first
    }

    fn word(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }

    /// Up to `most` bytes, as many as the next byte says.
    fn bytes(&mut self, most: u8) -> &'a [u8] {
        let wanted = usize::from(self.byte()) % (usize::from(most) + 1);
        let (taken, rest) = self.0.split_at(wanted.min(self.0.len()));
        self.0 = rest;
        taken
    }
}

/// The three bodies the model server may hold: two versions of one large answer, which differ in the message ID
/// only, so their blocks fit together but for the `ETag`, and a small one.
fn versions() -> [Vec<u8>; 3] {
    let mut other = LARGE.to_vec();
    other[0] ^= 1;
    [LARGE.to_vec(), other, SMALL.to_vec()]
}

/// What a client must get for `body`: the DNS message with the least TTL taken off (RFC 9953 §4.3.2).
fn served(body: &[u8]) -> Vec<u8> {
    let mut dns = body.to_vec();
    doc::take_max_age(&mut dns).expect("a captured message");
    dns
}

/// The listener's answer to `datagram` with `body` as its DNS answer, as `apps/dedensd/src/serve/coap.rs` makes
/// it: a CON message seen again is not answered again but from the `Dedup`, and at most `MAX_RETRANSMIT` times
/// while it remembers it (`replays` counts them by message ID).
fn serve(
    dedup: &mut Dedup,
    replays: &mut HashMap<u16, u8>,
    datagram: &[u8],
    body: &[u8],
    id: &mut u16,
    now: Instant,
) -> Option<Vec<u8>> {
    let request = Message::parse(datagram).ok()?;
    let confirmable = request.kind == Type::Confirmable;
    if confirmable {
        match dedup.check(CLIENT, request.id, now) {
            Seen::Duplicate(reply) => {
                let again = reply.map(<[u8]>::to_vec);
                if again.is_some() {
                    let count = replays.entry(request.id).or_default();
                    *count += 1;
                    assert!(*count <= MAX_RETRANSMIT, "a reply sent again too often");
                }
                return again;
            }
            Seen::New => {
                replays.insert(request.id, 0);
            }
        }
    }
    *id = id.wrapping_add(1);
    let path = doc::path_segments("/dns");
    let reply = match doc::query(&request, &path) {
        Ok(_) => {
            let reply = doc::response(&request, *id, body.to_vec())
                .unwrap_or_else(|code| doc::error(&request, *id, code));
            let more = reply
                .options
                .block2()
                .ok()
                .flatten()
                .is_some_and(Block::more);
            assert_eq!(
                doc::more_blocks(&request, body),
                reply.code == Code::CONTENT && more,
                "the blocks kept are not the ones that go on"
            );
            reply
        }
        Err(code) => doc::error(&request, *id, code),
    };
    if reply.code == Code::CONTENT && reply.options.block2().ok().flatten().is_some() {
        let tag = reply.options.get(OptionNumber::ETAG);
        assert_eq!(
            tag,
            Some(&doc::etag(&served(body))[..]),
            "blocks without the ETag of the body"
        );
    }
    let wire = reply.to_vec().ok()?;
    if confirmable {
        dedup.reply(CLIENT, request.id, wire.clone());
    }
    Some(wire)
}

/// The Max-Age and query functions on bytes of any kind, and a request of any kind.
fn stateless(bytes: &[u8]) {
    let mut copy = bytes.to_vec();
    if let Ok(least) = doc::take_max_age(&mut copy) {
        let mut again = copy.clone();
        assert_eq!(
            doc::take_max_age(&mut again).ok(),
            Some(0),
            "a TTL left under the least"
        );
        assert!(
            doc::add_max_age(&mut copy, least).is_ok(),
            "a message read once is read again"
        );
    }
    let Ok(request) = Message::parse(bytes) else {
        return;
    };
    let path = doc::path_segments("/dns");
    match doc::query(&request, &path) {
        Ok(Query::Dns(query)) => assert!(!query.is_empty(), "a query with no body"),
        Ok(Query::Block(_)) => {}
        Err(code) => assert!(!code.is_request(), "{code:?} is no answer"),
    }
    if let Ok(reply) = doc::response(&request, 1, SMALL.to_vec()) {
        assert_eq!(reply.code, Code::CONTENT);
    }
}

/// The client side of a run: the exchange, what it sent and has not had answered, and how it ended.
struct Session {
    exchange: Option<Exchange>,
    sent: Vec<Vec<u8>>,
    result: Option<Result<Response, Failure>>,
}

impl Session {
    fn apply(&mut self, step: Step) {
        self.sent.extend(step.send);
        match step.next {
            Next::Wait(exchange) => self.exchange = Some(exchange),
            Next::Done(done) => self.result = Some(done),
        }
    }

    fn receive(&mut self, bytes: &[u8], now: Instant) {
        if let Some(exchange) = self.exchange.take() {
            let step = exchange.receive(SERVER, bytes, now);
            self.apply(step);
        }
    }

    fn time_out(&mut self, now: &mut Instant) {
        if let Some(exchange) = self.exchange.take() {
            *now = (*now).max(exchange.deadline());
            let step = exchange.time_out(*now);
            self.apply(step);
        }
    }
}

/// The model server: what it holds, and the clock.
struct Model {
    dedup: Dedup,
    /// The replies sent again for each CON message ID since it was last new.
    replays: HashMap<u16, u8>,
    bodies: [Vec<u8>; 3],
    current: usize,
    id: u16,
    now: Instant,
}

/// An [`Exchange`] with the model server for as long as the input has operations: delivering what it sent (twice,
/// the retransmission and the duplicate), letting its timer run out, changing the body between two blocks, time
/// passing, bytes of any kind in place of a reply. The DNS body, the block sizes, the capacity of the [`Dedup`], the
/// query and the message IDs are the input's as well.
///
/// What it must hold: no panic; a body the exchange returns is one of the versions the server had, whole, never
/// blocks of two (the `ETag`, RFC 7959 §2.4), unless bytes of the input were taken for a reply; the server sends
/// the `ETag` with every block.
///
/// # Panics
///
/// On a bug in the codec, the exchange or the model's server.
pub fn coap_doc(data: &[u8]) {
    let mut script = Script(data);
    let mut params = Params::default();
    let (size, proposed) = (script.byte(), script.byte() & 1 == 0);
    params.block2_size = BlockSize::new(size).filter(|_| proposed);
    params.block1_size = BlockSize::new(script.byte()).unwrap_or(BlockSize::MAX);
    params.require_etag = true;
    let capacity = NonZeroUsize::MIN.saturating_add(usize::from(script.byte() % 4));
    let mut query = script.bytes(64).to_vec();
    if query.is_empty() {
        query.push(0);
    }
    let Ok(token) = Token::new(&[script.byte(), script.byte()]) else {
        return;
    };
    let request = doc::request(&doc::path_segments("/dns"), query, token);
    let mut model = Model {
        dedup: Dedup::new(EXCHANGE_LIFETIME, capacity),
        replays: HashMap::new(),
        bodies: versions(),
        current: 0,
        id: script.word(),
        now: Instant::now(),
    };
    let expected = model.bodies.each_ref().map(|body| served(body));
    let first = Exchange::start(
        request,
        SERVER,
        params,
        script.word(),
        u32::from(script.word()),
        model.now,
    );
    let mut session = Session {
        exchange: None,
        sent: Vec::new(),
        result: None,
    };
    session.apply(first);
    let mut tainted = false;
    for _ in 0..OPERATIONS {
        if session.exchange.is_none() {
            break;
        }
        let operation = script.byte();
        match operation % 9 {
            0..=3 => {
                let times = if operation % 9 == 3 { 2 } else { 1 };
                for datagram in std::mem::take(&mut session.sent) {
                    for _ in 0..times {
                        let reply = serve(
                            &mut model.dedup,
                            &mut model.replays,
                            &datagram,
                            &model.bodies[model.current],
                            &mut model.id,
                            model.now,
                        );
                        if let Some(reply) = reply {
                            session.receive(&reply, model.now);
                        }
                    }
                }
            }
            4 => session.time_out(&mut model.now),
            5 => model.current = (model.current + 1) % model.bodies.len(),
            6 => {
                session.receive(script.bytes(255), model.now);
                tainted = true;
            }
            7 => model.now += Duration::from_secs(u64::from(script.byte()) * 2),
            _ => stateless(script.bytes(255)),
        }
    }
    check(session.result.as_ref(), &expected, tainted);
}

/// What the end of an exchange tells about the bodies.
fn check(done: Option<&Result<Response, Failure>>, expected: &[Vec<u8>; 3], tainted: bool) {
    let Some(Ok(response)) = done else {
        return;
    };
    if tainted || response.code != Code::CONTENT {
        return;
    }
    assert!(
        expected.contains(&response.payload),
        "a body of no version the server had"
    );
}
