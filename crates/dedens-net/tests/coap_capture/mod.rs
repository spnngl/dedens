//! The captures of `tests/testdata/coap/capture.py` and a way to play them against an [`Exchange`].
#![allow(dead_code, reason = "each test file uses its own subset")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use dedens_net::coap::exchange::{Exchange, Failure, Next, Params, Request, Response};
use dedens_net::coap::{Code, Message, OptionNumber, Type};

/// The address of the server of every capture.
pub(crate) const SERVER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 5683);

/// One datagram seen by the proxy of the capture.
#[derive(Debug, Clone)]
pub(crate) struct Datagram {
    /// Milliseconds since the first datagram.
    pub(crate) at_ms: u64,
    pub(crate) from_client: bool,
    /// The proxy dropped it.
    pub(crate) lost: bool,
    pub(crate) bytes: Vec<u8>,
}

impl Datagram {
    pub(crate) fn message(&self) -> Message {
        Message::parse(&self.bytes).expect("a captured datagram parses")
    }
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/coap")
}

/// The ids of all captures.
pub(crate) fn ids() -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(dir())
        .expect("the capture directory")
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".txt").map(str::to_owned)
        })
        .collect();
    ids.sort();
    ids
}

/// The datagrams of the capture `id`, in the order seen.
pub(crate) fn capture(id: &str) -> Vec<Datagram> {
    let text = std::fs::read_to_string(dir().join(format!("{id}.txt"))).expect("the capture file");
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split(' ');
            let at_ms = fields.next().and_then(|s| s.parse().ok()).expect("a time");
            let direction = fields.next().expect("a direction");
            let hex = fields.next().expect("the datagram");
            Datagram {
                at_ms,
                from_client: direction.starts_with("c2s"),
                lost: direction.ends_with("-lost"),
                bytes: (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                    .collect(),
            }
        })
        .collect()
}

/// The datagrams the client sent that the server saw, and those the server sent that the client got.
pub(crate) fn delivered(capture: &[Datagram], from_client: bool) -> Vec<&Datagram> {
    capture
        .iter()
        .filter(|d| d.from_client == from_client && !d.lost)
        .collect()
}

/// The request of the capture as the first message of the client says it, for `Exchange::start`, with the
/// token and the message ID to start with.
pub(crate) fn request_of(capture: &[Datagram]) -> (Request, u16) {
    let first = capture
        .iter()
        .find(|d| d.from_client)
        .expect("a request")
        .message();
    (
        Request {
            code: first.code,
            options: first.options,
            payload: first.payload,
            token: first.token,
        },
        first.id,
    )
}

/// `response`, the datagram of the server answering `to`, with the token and message ID of `to`.
///
/// aiocoap takes a new token and message ID for each block it asks for, and the exchange keeps its token; what
/// follows it is the same: code, options and payload.
pub(crate) fn retarget(response: &Datagram, to: &Message) -> Vec<u8> {
    let mut message = response.message();
    if message.code != Code::EMPTY {
        message.token = to.token;
    }
    if message.kind == Type::Acknowledgement {
        message.id = to.id;
    }
    message.to_vec().expect("a captured message writes")
}

/// What a message says without its token and message ID: kind, code, options and payload.
pub(crate) type Essence = (Type, Code, Vec<(OptionNumber, Vec<u8>)>, Vec<u8>);

pub(crate) fn essence(message: &Message) -> Essence {
    (
        message.kind,
        message.code,
        message
            .options
            .iter()
            .map(|(number, value)| (number, value.to_vec()))
            .collect(),
        message.payload.clone(),
    )
}

/// How a played capture went.
pub(crate) struct Played {
    pub(crate) result: Result<Response, Failure>,
    /// What the exchange sent, in order, read back.
    pub(crate) sent: Vec<Message>,
}

/// Plays the responses of the capture `id` against an exchange of its request, with `params`: each is given
/// when the exchange has sent the message it answers.
pub(crate) fn play(id: &str, params: Params) -> Played {
    let capture = capture(id);
    let (request, first_id) = request_of(&capture);
    let now = Instant::now();
    let mut sent = Vec::new();
    let mut step = Exchange::start(request, SERVER, params, first_id, 7, now);
    let mut inbox = delivered(&capture, false).into_iter();
    loop {
        for wire in &step.send {
            sent.push(Message::parse(wire).expect("the exchange sends messages"));
        }
        let exchange = match step.next {
            Next::Wait(exchange) => exchange,
            Next::Done(result) => return Played { result, sent },
        };
        let Some(datagram) = inbox.next() else {
            return Played {
                result: Err(Failure::TimedOut),
                sent,
            };
        };
        let last = sent
            .iter()
            .rev()
            .find(|m| m.kind == Type::Confirmable)
            .expect("a CON message went out");
        let wire = retarget(datagram, last);
        step = exchange.receive(SERVER, &wire, now + Duration::from_millis(datagram.at_ms));
    }
}
