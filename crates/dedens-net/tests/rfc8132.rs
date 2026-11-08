//! FETCH (RFC 8132 §2) as DNS over CoAP uses it (RFC 9953 §3.2, §4.2): the request a query makes, captured from
//! aiocoap (`tests/testdata/coap/capture.py`), and the `docpath` of an SVCB record as its path.

mod coap_capture;

use std::time::Instant;

use coap_capture::{SERVER, capture, delivered, play, request_of};
use dedens_net::coap::block::{Block, BlockSize};
use dedens_net::coap::exchange::{Exchange, Next, Params};
use dedens_net::coap::{Code, Message, OptionNumber, Token, dns};
use dedens_proto::rdata::{SvcParam, SvcParams};

const QUERY: &[u8] = include_bytes!("testdata/doh/quad9_mx.query");
const ANSWER: &[u8] = include_bytes!("testdata/doh/quad9_mx.body");

fn segments(segments: &[&str]) -> Vec<Box<[u8]>> {
    segments.iter().map(|s| s.as_bytes().into()).collect()
}

#[test]
fn fetch_is_code_0_05() {
    assert_eq!(Code::FETCH.0, 0x05);
    assert!(Code::FETCH.is_request());
}

#[test]
fn the_request_of_a_query_is_the_one_aiocoap_sends() {
    let capture = capture("fetch_doc");
    let first = delivered(&capture, true)[0];
    let token = first.message().token;
    let request = dns::request(&segments(&["dns"]), QUERY.to_vec(), token);
    let step = Exchange::start(
        request,
        SERVER,
        Params::default(),
        first.message().id,
        1,
        Instant::now(),
    );
    assert_eq!(step.send, std::slice::from_ref(&first.bytes));
}

#[test]
fn the_request_says_fetch_and_dns_message() {
    let request = dns::request(
        &segments(&["a", "b"]),
        QUERY.to_vec(),
        Token::new(&[1, 2]).expect("a value"),
    );
    assert_eq!(request.code, Code::FETCH);
    assert_eq!(request.options.uri_path().collect::<Vec<_>>(), [b"a", b"b"]);
    // RFC 9953 §4.1: Content-Format 553, application/dns-message, and the same asked for.
    assert_eq!(
        (request.options.content_format(), request.options.accept()),
        (Some(553), Some(553))
    );
    // The body is the query, FETCH having a body (RFC 8132 §2.3).
    assert_eq!(request.payload, QUERY);
    // The root path has no Uri-Path option.
    let root = dns::request(&[], QUERY.to_vec(), Token::new(&[1, 2]).expect("a value"));
    assert_eq!(root.options.get(OptionNumber::URI_PATH), None);
}

#[test]
fn captured_response() {
    let played = play("fetch_doc", Params::default());
    let response = played.result.expect("a value");
    assert_eq!(response.code, Code::CONTENT);
    assert_eq!(response.options.content_format(), Some(553));
    assert_eq!(response.payload, ANSWER);
}

#[test]
fn libcoap_answers_the_request_of_a_query() {
    // libcoap's server (coap-server, /example_data) answers a FETCH with the DNS message it holds: piggybacked, content
    // format 553, no Max-Age option, so 60 seconds (RFC 7252 §5.10.5).
    let capture = capture("libcoap_fetch_doc");
    let request = delivered(&capture, true)[0].message();
    assert_eq!(request.code, Code::FETCH);
    assert_eq!(request.payload, QUERY);
    let played = play("libcoap_fetch_doc", Params::default());
    assert_eq!(played.sent.len(), 1);
    assert_eq!(played.sent[0].payload, QUERY);
    let response = played.result.expect("a value");
    assert_eq!(response.code, Code::CONTENT);
    assert_eq!(response.options.content_format(), Some(553));
    assert_eq!(response.options.max_age(), 60);
    assert_eq!(response.payload, ANSWER);
}

#[test]
fn the_query_goes_with_each_request_for_a_block() {
    // RFC 8132 §2: the body is part of the cache key, so a server that keeps nothing needs it again.
    let capture = capture("fetch_doc_block2_64");
    let (request, first_id) = request_of(&capture);
    let mut params = Params::default();
    params.block2_size = BlockSize::new(2);
    let now = Instant::now();
    let step = Exchange::start(request, SERVER, params, first_id, 1, now);
    let Next::Wait(exchange) = step.next else {
        panic!("not waiting")
    };
    let reply = delivered(&capture, false)[0];
    let step = exchange.receive(
        SERVER,
        &coap_capture::retarget(reply, &Message::parse(&step.send[0]).expect("a value")),
        now,
    );
    let next = Message::parse(&step.send[0]).expect("a value");
    assert_eq!(next.code, Code::FETCH);
    assert_eq!(next.payload, QUERY);
    assert_eq!(
        next.options.block2().expect("a value"),
        Block::new(1, false, BlockSize::new(2).expect("a value"))
    );
}

#[test]
fn docpath_makes_the_uri_path() {
    // RFC 9953 §3.2.1: `docpath=n,s` is the path /n/s; a bare `docpath` is the root path.
    let params = SvcParams::new(vec![SvcParam::DocPath(segments(&["n", "s"]))]).expect("a value");
    let path = dns::docpath(&params).expect("a value");
    let request = dns::request(&path, QUERY.to_vec(), Token::EMPTY);
    assert_eq!(request.options.uri_path().collect::<Vec<_>>(), [b"n", b"s"]);
    let root = SvcParams::new(vec![SvcParam::DocPath(Vec::new())]).expect("a value");
    assert_eq!(dns::docpath(&root), Some(Vec::new()));
    // Without the parameter the record does not describe a DoC server.
    assert_eq!(
        dns::docpath(&SvcParams::new(Vec::new()).expect("a value")),
        None
    );
}

#[test]
fn rfc_9953_4_2_3_query_as_a_fetch_body() {
    // The query of the example: example.org AAAA, ID 0, RD.
    let query: Vec<u8> = [
        &[
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ][..],
        &[0x07],
        b"example",
        &[0x03],
        b"org",
        &[0x00, 0x00, 0x1c, 0x00, 0x01],
    ]
    .concat();
    let request = dns::request(
        &segments(&["dns"]),
        query.clone(),
        Token::new(&[0xaa, 0xbb]).expect("a value"),
    );
    let step = Exchange::start(request, SERVER, Params::default(), 1, 1, Instant::now());
    let sent = Message::parse(&step.send[0]).expect("a value");
    assert_eq!((sent.code, sent.payload), (Code::FETCH, query));
}
