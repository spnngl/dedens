//! Serving DNS over CoAP (RFC 9953), on addresses behind `coap://` (D81): the answers and their Max-Age, the codes of
//! requests that are no query, retransmissions, blocks of a large response, and the warning for CoAP being
//! unprotected (§6).
#![cfg(feature = "doc")]

mod common;

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{Responder, Server, captured, decode, query_for, write_config};
use dedens_net::coap::block::{Block, BlockSize};
use dedens_net::coap::{Code, Message, OptionNumber, Options, Token, Type};

/// The path `dedensd` serves `DoC` at in these tests.
const PATH: &[&[u8]] = &[b"dns", b"query"];

/// `dedensd` answering `DoC` on `listen` and `/dns/query`, forwarding to `upstream`.
fn serving(upstream: SocketAddr) -> Server {
    Server::configured(|listen| {
        format!(
            "listen: ['coap://{listen}/dns/query']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n"
        )
    })
}

/// A request that is no query: what it is, how it differs from [`fetch`], the code it gets.
type Case = (&'static str, Box<dyn Fn(&mut Message)>, Code);

/// A CON FETCH of `query` to `PATH`, as the RFC 9953 §4.1 says.
fn fetch(id: u16, query: &[u8]) -> Message {
    let mut options = Options::new();
    options.push_uri_path(PATH.iter().copied());
    options.set_content_format(Options::DNS_MESSAGE);
    options.set_accept(Options::DNS_MESSAGE);
    Message {
        kind: Type::Confirmable,
        code: Code::FETCH,
        id,
        token: Token::new(&[7, 7]).expect("a token"),
        options,
        payload: query.to_vec(),
    }
}

/// A UDP socket that waits a second for a datagram.
fn client() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("a timeout");
    socket
}

/// The datagram `server` sends back for `request`, `None` after a second of silence.
fn send(server: SocketAddr, request: &Message) -> Option<Message> {
    send_from(&client(), server, request)
}

/// As [`send`], from `socket`: the server tells the clients by address.
fn send_from(socket: &UdpSocket, server: SocketAddr, request: &Message) -> Option<Message> {
    socket
        .send_to(&request.to_vec().expect("it writes"), server)
        .expect("sent");
    let mut buf = vec![0; 65535];
    let len = socket.recv(&mut buf).ok()?;
    Some(Message::parse(&buf[..len]).expect("a CoAP message"))
}

fn ask(server: SocketAddr, request: &Message) -> Message {
    send(server, request).expect("a response")
}

fn ttls(wire: &[u8]) -> Vec<u32> {
    decode(wire).answer.iter().map(|r| r.ttl.get()).collect()
}

/// RFC 9953 §4.3, §4.3.2: a FETCH is answered 2.05, an ACK carrying the response with its ID as it came, in the content
/// format 553; the least TTL is its Max-Age, taken from each TTL.
#[test]
fn s4_3_a_fetch_is_answered_2_05_with_the_least_ttl_as_max_age() {
    let upstream = Responder::slow("a", 300, Duration::ZERO);
    let server = serving(upstream.addr);
    let request = fetch(0x1234, &query_for(&captured("a"), 0));
    let response = ask(server.addr, &request);
    assert_eq!(response.kind, Type::Acknowledgement);
    assert_eq!((response.id, response.token), (request.id, request.token));
    assert_eq!(response.code, Code::CONTENT);
    assert_eq!(response.options.content_format(), Some(553));
    assert_eq!(response.options.max_age(), 300);
    assert_ne!(ttls(&response.payload).len(), 0);
    assert!(ttls(&response.payload).iter().all(|&ttl| ttl == 0));
    assert_eq!(decode(&response.payload).header.id, 0);
}

/// D81: a POST is a query too, though RFC 9953 §4.2 defines FETCH only.
#[test]
fn s4_2_1_a_post_is_a_query_too() {
    let upstream = Responder::start(&["a"]);
    let server = serving(upstream.addr);
    let mut request = fetch(1, &query_for(&captured("a"), 0));
    request.code = Code::POST;
    assert_eq!(ask(server.addr, &request).code, Code::CONTENT);
}

/// RFC 9953 §4.3: a NON request gets a NON response, with a message ID of the server's own (RFC 7252 §5.2.3).
#[test]
fn s4_3_a_non_request_gets_a_non_response() {
    let upstream = Responder::start(&["a"]);
    let server = serving(upstream.addr);
    let mut request = fetch(0x0101, &query_for(&captured("a"), 0));
    request.kind = Type::NonConfirmable;
    let response = ask(server.addr, &request);
    assert_eq!(response.kind, Type::NonConfirmable);
    assert_eq!(response.token, request.token);
    assert_eq!(response.code, Code::CONTENT);
}

/// RFC 9953 §4.3.1: what is no query is answered with a CoAP error code, and the upstream is not asked.
#[test]
fn s4_3_1_a_request_that_is_no_query_gets_an_error_code() {
    let upstream = Responder::start(&["a"]);
    let server = serving(upstream.addr);
    let query = query_for(&captured("a"), 0);
    let cases: Vec<Case> = vec![
        (
            "another path",
            Box::new(|m| {
                let mut options = Options::new();
                options.push_uri_path([b"other".as_slice()]);
                options.set_content_format(Options::DNS_MESSAGE);
                m.options = options;
            }),
            Code::NOT_FOUND,
        ),
        (
            "GET",
            Box::new(|m| m.code = Code::GET),
            Code::METHOD_NOT_ALLOWED,
        ),
        (
            "PUT",
            Box::new(|m| m.code = Code::PUT),
            Code::METHOD_NOT_ALLOWED,
        ),
        (
            "another content format",
            Box::new(|m| m.options.set_content_format(0)),
            Code::UNSUPPORTED_CONTENT_FORMAT,
        ),
        (
            "no content format",
            Box::new(|m| {
                m.options.remove(OptionNumber::CONTENT_FORMAT);
            }),
            Code::UNSUPPORTED_CONTENT_FORMAT,
        ),
        (
            "another format accepted",
            Box::new(|m| m.options.set_accept(0)),
            Code::NOT_ACCEPTABLE,
        ),
        (
            "no body",
            Box::new(|m| m.payload.clear()),
            Code::BAD_REQUEST,
        ),
        (
            "an unknown critical option",
            Box::new(|m| m.options.insert(OptionNumber(2049), [1])),
            Code::BAD_OPTION,
        ),
        (
            "the query in Uri-Query",
            Box::new(|m| m.options.insert(OptionNumber::URI_QUERY, b"dns=AAAB")),
            Code::BAD_OPTION,
        ),
        (
            "Proxy-Uri",
            Box::new(|m| {
                m.options.remove(OptionNumber::URI_PATH);
                m.options
                    .insert(OptionNumber::PROXY_URI, b"coap://dns.example/dns/query");
            }),
            Code::PROXYING_NOT_SUPPORTED,
        ),
        (
            "Proxy-Scheme",
            Box::new(|m| m.options.insert(OptionNumber::PROXY_SCHEME, b"coap")),
            Code::PROXYING_NOT_SUPPORTED,
        ),
        (
            "an If-Match with a tag no representation has",
            Box::new(|m| m.options.insert(OptionNumber::IF_MATCH, [1, 2, 3, 4])),
            Code::PRECONDITION_FAILED,
        ),
        (
            "an If-None-Match, the resource existing",
            Box::new(|m| m.options.insert(OptionNumber::IF_NONE_MATCH, [])),
            Code::PRECONDITION_FAILED,
        ),
        (
            "a body in blocks",
            Box::new(|m| {
                let size = BlockSize::new(2).expect("64 bytes");
                m.options
                    .set_block1(Block::new(1, true, size).expect("a block"));
            }),
            Code::REQUEST_ENTITY_TOO_LARGE,
        ),
    ];
    for (name, change, code) in cases {
        let mut request = fetch(9, &query);
        change(&mut request);
        let response = ask(server.addr, &request);
        assert_eq!(response.code, code, "{name}");
        assert!(response.payload.is_empty(), "{name}");
        assert_eq!(response.token, request.token, "{name}");
    }
    assert_eq!(upstream.queries(), 0);
}

/// RFC 7252 §5.10.1, §5.10.8.1: a request naming the host and port, or asking for any representation, is a query as
/// another: the server has one resource, whatever the authority.
#[test]
fn s5_10_the_authority_and_an_empty_if_match_are_accepted() {
    let upstream = Responder::start(&["a"]);
    let server = serving(upstream.addr);
    let mut request = fetch(5, &query_for(&captured("a"), 0));
    request
        .options
        .insert(OptionNumber::URI_HOST, b"dns.example");
    request
        .options
        .insert(OptionNumber::URI_PORT, server.addr.port().to_be_bytes());
    request.options.insert(OptionNumber::IF_MATCH, []);
    assert_eq!(ask(server.addr, &request).code, Code::CONTENT);
}

/// RFC 7252 §4.5: a retransmitted CON request gets the reply again and is not asked of the upstream again.
#[test]
fn s4_5_a_retransmitted_request_is_not_asked_again() {
    let upstream = Responder::start(&["a"]);
    let server = serving(upstream.addr);
    let request = fetch(0x4242, &query_for(&captured("a"), 0));
    let datagram = request.to_vec().expect("it writes");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("a timeout");
    let mut buf = vec![0; 65535];
    let mut replies = Vec::new();
    for _ in 0..2 {
        socket.send_to(&datagram, server.addr).expect("sent");
        let len = socket.recv(&mut buf).expect("a reply");
        replies.push(buf[..len].to_vec());
    }
    assert_eq!(replies[0], replies[1]);
    assert_eq!(upstream.queries(), 1);
}

/// RFC 7252 §4.3: a ping, a CON message that is empty, is answered with a RST.
#[test]
fn s4_3_a_ping_is_answered_with_a_reset() {
    let upstream = Responder::start(&["a"]);
    let server = serving(upstream.addr);
    let ping = Message::empty(Type::Confirmable, 0x0505);
    let response = ask(server.addr, &ping);
    assert_eq!((response.kind, response.id), (Type::Reset, 0x0505));
}

/// RFC 9953 §4.3, RFC 7959 §2.4: a response over 1024 bytes goes in blocks of 1024, each asked for with the query
/// again; one asked in smaller blocks goes in those.
#[test]
fn s4_3_a_large_response_goes_in_blocks() {
    let upstream = Responder::start(&["txt_large"]);
    let server = serving(upstream.addr);
    let query = query_for(&captured("txt_large"), 0);
    let blocks = |size| {
        let mut body = Vec::new();
        let mut num = 0;
        loop {
            let mut request = fetch(u16::try_from(num).expect("a few blocks") + 1, &query);
            if let Some(size) = size {
                request
                    .options
                    .set_block2(Block::new(num, false, size).expect("a block"));
            } else if num > 0 {
                let size = BlockSize::MAX;
                request
                    .options
                    .set_block2(Block::new(num, false, size).expect("a block"));
            }
            let response = ask(server.addr, &request);
            assert_eq!(response.code, Code::CONTENT);
            let block = response.options.block2().expect("a Block2").expect("one");
            assert_eq!(block.num(), num);
            body.extend_from_slice(&response.payload);
            if !block.more() {
                return (body, num + 1);
            }
            num += 1;
        }
    };
    let (whole, count) = blocks(None);
    assert_eq!(count, 2);
    let small = BlockSize::new(2).expect("64 bytes");
    let (again, count) = blocks(Some(small));
    assert_eq!(again, whole);
    assert!(count > 2, "{count} blocks");
    // The body is the DNS response, a message of over 1024 bytes.
    assert!(whole.len() > 1024, "{} bytes", whole.len());
    assert_eq!(decode(&whole).questions.len(), 1);
}

/// RFC 8132 §2.5, RFC 7959 §2.4: a client that asks for the next blocks without the body of its FETCH (libcoap and
/// aiocoap do, `tests/testdata/coap/libcoap_fetch_doc_block2.txt`) gets them, found by its `Request-Tag`; any other
/// request of the kind has no body to answer.
#[test]
fn s4_3_the_next_blocks_are_asked_for_without_the_query() {
    let upstream = Responder::start(&["txt_large"]);
    let server = serving(upstream.addr);
    let query = query_for(&captured("txt_large"), 0);
    let socket = client();
    let ask = |request: &Message| send_from(&socket, server.addr, request).expect("a response");
    let tagged = |id, tag: &[u8], block: Option<Block>| {
        let mut request = fetch(id, if block.is_some() { &[] } else { &query });
        request.options.insert(OptionNumber::REQUEST_TAG, tag);
        if let Some(block) = block {
            request.options.set_block2(block);
        }
        request
    };
    let next = |num| Block::new(num, false, BlockSize::MAX);
    let first = ask(&tagged(1, &[1, 2], None));
    let second = ask(&tagged(2, &[1, 2], next(1)));
    assert_eq!(second.code, Code::CONTENT);
    let block = second.options.block2().expect("a Block2").expect("one");
    assert_eq!((block.num(), block.more()), (1, false));
    let mut body = first.payload;
    body.extend_from_slice(&second.payload);
    assert_eq!(decode(&body).questions.len(), 1);
    // Asked for again, and once more in smaller blocks.
    assert_eq!(ask(&tagged(3, &[1, 2], next(1))).payload, second.payload);
    let small = Block::new(3, false, BlockSize::new(2).expect("64 bytes"));
    assert_eq!(ask(&tagged(4, &[1, 2], small)).code, Code::CONTENT);
    // Another tag, or no tag, has no response kept; the first block is no follow-up.
    for (id, tag, block) in [
        (5, &[9][..], next(1)),
        (6, &[][..], next(1)),
        (7, &[1, 2][..], next(0)),
    ] {
        let response = ask(&tagged(id, tag, block));
        assert_eq!(response.code, Code::BAD_REQUEST, "{id}");
    }
    assert_eq!(upstream.queries(), 1);
}

/// RFC 9953 §4.3.2: the TTLs in the response, less their least, and that least as the Max-Age, reach the client
/// as they were.
#[test]
fn s4_3_2_a_ttl_is_the_max_age_less_what_was_taken() {
    let upstream = Responder::slow("a", 120, Duration::ZERO);
    let server = serving(upstream.addr);
    let response = ask(server.addr, &fetch(5, &query_for(&captured("a"), 0)));
    let mut wire = response.payload.clone();
    assert_eq!(ttls(&wire), vec![0; ttls(&wire).len()]);
    dedens_net::coap::doc::add_max_age(&mut wire, response.options.max_age()).expect("DNS");
    assert!(ttls(&wire).iter().all(|&ttl| ttl == 120));
}

/// RFC 9953 §6: CoAP is unprotected, which a warning at start says.
#[test]
fn s6_a_coap_listener_logs_a_warning() {
    let upstream = Responder::start(&["a"]);
    let port = UdpSocket::bind("127.0.0.1:0")
        .expect("a UDP port")
        .local_addr()
        .expect("its address");
    let config = write_config(&format!(
        "listen: ['coap://{port}']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{}']\n",
        upstream.addr
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(&config)
        .stderr(Stdio::piped())
        .spawn()
        .expect("dedensd starts");
    let stderr = child.stderr.take().expect("its piped stderr");
    let mut warned = false;
    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
        warned |= line.contains("NOT RECOMMENDED");
        if line.contains("\"serving\"") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(warned);
}
