//! DNS over CoAP (RFC 9953), against a scripted CoAP server on the loopback address: the request a query makes (§4.1,
//! §4.2), the response and its Max-Age (§4.3), what the client does with an error (§4.3.1), and the discovery of the
//! resource (§3.1, D95). The server's side of
//! the protocol, and the requests as aiocoap sends them, are tested with RFC 8132 and RFC 7959 (`rfc8132.rs`,
//! `rfc7959.rs`).
#![cfg(feature = "doc")]

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::net::UdpSocket;
use dedens_net::client::{Client, ClientError, Server};
use dedens_net::coap::block::{Block, BlockSize, slice};
use dedens_net::coap::dns::{
    Query, add_max_age, discovery, etag, more_blocks, path_segments, query as doc_query, response,
    take_max_age,
};
use dedens_net::coap::exchange::Failure;
use dedens_net::coap::link::LinkError;
use dedens_net::coap::{Code, Message, OptionNumber, Options, Token, Type};
use dedens_net::doc::DocError;
use dedens_net::exchange::{Failure as DnsFailure, Options as DnsOptions};
use dedens_proto::{Message as Dns, Transport};

/// A query for gmail.com MX with ID 0, and the response of Quad9 to it (`testdata/doh`), whose TTLs are 1822, 1822,
/// 1822, 1822 and 1822 for the answer and 0 for its OPT record.
const QUERY: &[u8] = include_bytes!("../../../testdata/doh/quad9_mx.query");
const ANSWER: &[u8] = include_bytes!("../../../testdata/doh/quad9_mx.body");
/// Another response of 99 bytes, over a block of 64 as `ANSWER` is, for a server whose answer changes.
const OTHER: &[u8] = include_bytes!("../../../testdata/doh/google_aaaa.body");

/// How the server answers.
#[derive(Clone)]
enum Serve {
    /// 2.05 with the whole response, and this Max-Age if any.
    Whole(Option<u32>),
    /// 2.05 with the block of 64 bytes the request asks for, each block piggybacked, with the `ETag` of the body.
    Blocks,
    /// As `Blocks`, without an `ETag`.
    BlocksWithoutETag,
    /// As `Blocks`, the first block of `ANSWER` and the others of `OTHER`, each with the `ETag` of its body.
    BlocksChanging,
    /// This code, with no body.
    Fail(Code),
    /// 2.05 with this content format.
    Format(u16),
    /// 2.05 with a body that is no DNS message.
    Garbage,
    /// No datagram back: a blackholed server.
    Silent,
    /// An empty ACK, the response to come separately (RFC 7252 §5.2.2), and never does.
    EmptyAck,
}

/// A CoAP server answering each request as `serve` says; the requests it got.
async fn coap_server(serve: Serve) -> (SocketAddr, Rc<RefCell<Vec<Message>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a socket");
    let addr = socket.local_addr().expect("an address");
    let seen = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&seen);
    compio::runtime::spawn(async move {
        loop {
            let BufResult(received, buf) = socket.recv_from(Vec::with_capacity(2048)).await;
            let (len, peer) = received.expect("a request");
            // A port is reused as soon as it closes: what comes may be meant for the socket before, such as the
            // packets a QUIC server of another test keeps sending to the port of a client that is gone.
            let Ok(request) = Message::parse(&buf[..len]) else {
                continue;
            };
            if request.code != Code::FETCH {
                continue;
            }
            log.borrow_mut().push(request.clone());
            let mut reply = Message::piggybacked(&request, Code::CONTENT);
            match &serve {
                Serve::Silent => continue,
                Serve::EmptyAck => reply = Message::empty(Type::Acknowledgement, request.id),
                Serve::Whole(max_age) => {
                    reply.options.set_content_format(Options::DNS_MESSAGE);
                    if let Some(max_age) = max_age {
                        reply.options.set_max_age(*max_age);
                    }
                    reply.payload = ANSWER.to_vec();
                }
                Serve::Blocks | Serve::BlocksWithoutETag | Serve::BlocksChanging => {
                    let asked = request.options.block2().expect("a Block2 or none");
                    let body = match (&serve, asked) {
                        (Serve::BlocksChanging, Some(block)) if block.num() > 0 => OTHER,
                        _ => ANSWER,
                    };
                    let size = BlockSize::new(2).expect("64 bytes");
                    let cut = slice(body, asked.or(Block::new(0, false, size)), size)
                        .expect("a block inside the body");
                    reply.options.set_content_format(Options::DNS_MESSAGE);
                    if !matches!(serve, Serve::BlocksWithoutETag) {
                        reply.options.insert(OptionNumber::ETAG, etag(body));
                    }
                    reply.options.set_block2(cut.block.expect("a block"));
                    reply.payload = cut.payload.to_vec();
                }
                Serve::Fail(code) => reply.code = *code,
                Serve::Format(format) => {
                    reply.options.set_content_format(*format);
                    reply.payload = ANSWER.to_vec();
                }
                Serve::Garbage => {
                    reply.options.set_content_format(Options::DNS_MESSAGE);
                    reply.payload = b"not a DNS message".to_vec();
                }
            }
            let BufResult(sent, _) = socket
                .send_to(reply.to_vec().expect("a reply that writes"), peer)
                .await;
            sent.expect("sent");
        }
    })
    .detach();
    (addr, seen)
}

fn server(addr: SocketAddr, path: &str) -> Server {
    Server {
        addr,
        name: None,
        doh: None,
        docpath: path_segments(path),
    }
}

fn coap() -> DnsOptions {
    let mut options = DnsOptions::default();
    options.transport = Transport::Coap;
    options
}

fn query() -> Dns<'static> {
    Dns::decode(QUERY).expect("a query").message.into_owned()
}

fn ttls(wire: &[u8]) -> Vec<u32> {
    let message = Dns::decode(wire).expect("a response").message;
    message
        .answer
        .iter()
        .map(|record| record.ttl.get())
        .collect()
}

/// RFC 9953 §4.1, §4.2: a query is a FETCH to the path, the DNS query as its body, in the content format
/// `application/dns-message` and asking for it, its DNS ID 0.
#[compio::test]
async fn s4_2_a_query_is_a_fetch_with_id_0_and_content_format_553() {
    let (addr, seen) = coap_server(Serve::Whole(None)).await;
    let response = Client::new()
        .exchange(query(), server(addr, "/dns/query"), &coap())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Coap);
    let seen = seen.borrow();
    let [request] = seen.as_slice() else {
        panic!("one request, not {}", seen.len());
    };
    assert_eq!(request.kind, Type::Confirmable);
    assert_eq!(request.code, Code::FETCH);
    assert_eq!(
        request.options.uri_path().collect::<Vec<_>>(),
        [b"dns".as_slice(), b"query"]
    );
    assert_eq!(request.options.content_format(), Some(553));
    assert_eq!(request.options.accept(), Some(553));
    let sent = Dns::decode(&request.payload).expect("a query").message;
    assert_eq!(sent.header.id, 0);
    assert_eq!(sent.questions, query().questions);
}

/// RFC 9953 §4.3.2: the Max-Age of the response, 60 seconds when it has none (RFC 7252 §5.10.5), is added to each TTL.
#[compio::test]
async fn s4_3_2_max_age_is_added_to_each_ttl() {
    let sent = ttls(ANSWER);
    for (max_age, added) in [(Some(30), 30), (None, 60), (Some(0), 0)] {
        let (addr, _) = coap_server(Serve::Whole(max_age)).await;
        let response = Client::new()
            .exchange(query(), server(addr, ""), &coap())
            .await
            .expect("a response");
        let expected: Vec<u32> = sent.iter().map(|ttl| ttl + added).collect();
        assert_eq!(ttls(&response.wire), expected, "Max-Age {max_age:?}");
    }
}

/// RFC 9953 §4.3.2: the TTLs stay below 2^31 whatever the Max-Age.
#[test]
fn s4_3_2_the_sum_stops_at_the_largest_ttl() {
    let mut wire = ANSWER.to_vec();
    add_max_age(&mut wire, u32::MAX).expect("a DNS message");
    assert_eq!(ttls(&wire), vec![0x7FFF_FFFF; 5]);
}

/// RFC 9953 §4.3.2: a server sends the least TTL as Max-Age and subtracts it from each TTL, so the client's sum is
/// the TTLs the server had.
#[test]
fn s4_3_2_the_least_ttl_is_the_max_age_and_adding_it_back_restores_the_response() {
    let mut wire = ANSWER.to_vec();
    let max_age = take_max_age(&mut wire).expect("a DNS message");
    assert_eq!(max_age, 1822);
    assert_eq!(ttls(&wire), vec![0; 5]);
    add_max_age(&mut wire, max_age).expect("a DNS message");
    assert_eq!(wire, ANSWER);
}

/// RFC 9953 §4.3: the least TTL of the records is the Max-Age, so the TTLs are not all taken down to 0.
#[test]
fn s4_3_2_the_ttls_differing_keep_their_difference() {
    let mut wire = ANSWER.to_vec();
    let at = wire.windows(4).position(|w| w == 1822_u32.to_be_bytes());
    let at = at.expect("a TTL of 1822");
    wire[at..at + 4].copy_from_slice(&1900_u32.to_be_bytes());
    let max_age = take_max_age(&mut wire).expect("a DNS message");
    assert_eq!(max_age, 1822);
    let mut taken = ttls(&wire);
    taken.sort_unstable();
    assert_eq!(taken, [0, 0, 0, 0, 78]);
}

/// RFC 9953 §4.3, RFC 7959 §2.4: a response in blocks is put together, each block asked for with the query again.
#[compio::test]
async fn s4_3_a_response_in_blocks_is_put_together() {
    let (addr, seen) = coap_server(Serve::Blocks).await;
    let response = Client::new()
        .exchange(query(), server(addr, "/"), &coap())
        .await
        .expect("a response");
    assert_eq!(ttls(&response.wire).len(), 5);
    let seen = seen.borrow();
    assert!(seen.len() > 1, "{} request", seen.len());
    assert!(
        seen.iter()
            .all(|request| request.payload == seen[0].payload)
    );
}

/// RFC 7959 §2.4: the blocks of a response are of one representation, which the `ETag` tells: a client refuses a response
/// whose `ETag` changes, or whose blocks have none to compare.
#[compio::test]
async fn s4_3_blocks_of_two_responses_are_refused() {
    let (addr, _) = coap_server(Serve::BlocksChanging).await;
    let error = Client::new()
        .exchange(query(), server(addr, "/"), &coap())
        .await;
    assert!(
        matches!(
            error,
            Err(ClientError::Doc(DocError::Exchange(Failure::ETagChanged)))
        ),
        "{error:?}"
    );
    let (addr, _) = coap_server(Serve::BlocksWithoutETag).await;
    let error = Client::new()
        .exchange(query(), server(addr, "/"), &coap())
        .await;
    assert!(
        matches!(
            error,
            Err(ClientError::Doc(DocError::Exchange(Failure::MissingETag)))
        ),
        "{error:?}"
    );
}

/// RFC 7959 §2.4, RFC 7252 §5.10.6: a server sends an `ETag` with each block, the same for the blocks of one body and
/// another for another body, of 1 to 8 bytes.
#[test]
fn s4_3_a_server_tags_the_blocks_of_a_response_with_its_etag() {
    let block = |dns: &[u8], num| {
        let size = BlockSize::new(2).expect("64 bytes");
        let mut request = Message::empty(Type::Confirmable, 1);
        request.code = Code::FETCH;
        request
            .options
            .set_block2(Block::new(num, false, size).expect("a block"));
        response(&request, 0, dns.to_vec()).expect("a response")
    };
    let tags: Vec<Vec<u8>> = [(ANSWER, 0), (ANSWER, 1), (OTHER, 0), (OTHER, 1)]
        .iter()
        .map(|&(dns, num)| {
            let reply = block(dns, num);
            reply.options.etag().expect("an ETag").to_vec()
        })
        .collect();
    assert_eq!(tags[0], tags[1]);
    assert_eq!(tags[2], tags[3]);
    assert_ne!(tags[0], tags[2]);
    assert!((1..=8).contains(&tags[0].len()));
}

/// D105: `more_blocks` tells what `response` sends: a block with more after it, and not the last block, an answer in
/// one message, a block past the end or a Block2 option that is not one, which `response` refuses.
#[test]
fn more_blocks_tells_whether_the_response_goes_on() {
    let request = |block: Option<Block>| {
        let mut request = Message::empty(Type::Confirmable, 1);
        request.code = Code::FETCH;
        if let Some(block) = block {
            request.options.set_block2(block);
        }
        request
    };
    let block = |num| Block::new(num, false, BlockSize::new(2).expect("64 bytes"));
    let last = u32::try_from((ANSWER.len() - 1) / 64).expect("a block number");
    assert!(last > 0, "an answer over 64 bytes");
    assert!(more_blocks(&request(block(0)), ANSWER));
    assert!(!more_blocks(&request(block(last)), ANSWER));
    assert!(!more_blocks(&request(None), ANSWER));
    assert!(!more_blocks(&request(block(last + 1)), ANSWER));
    assert_eq!(
        response(&request(block(last + 1)), 0, ANSWER.to_vec()).expect_err("past the end"),
        Code::BAD_OPTION
    );
    let mut malformed = request(None);
    malformed.options.insert(OptionNumber::BLOCK2, [0; 4]);
    assert!(!more_blocks(&malformed, ANSWER));
    assert_eq!(
        response(&malformed, 0, ANSWER.to_vec()).expect_err("a Block2 of 4 bytes"),
        Code::BAD_OPTION
    );
}

/// RFC 9953 §4.3.1: a CoAP error is no DNS response: the client reports the code.
#[compio::test]
async fn s4_3_1_an_error_code_is_an_error_not_a_response() {
    for code in [
        Code::NOT_FOUND,
        Code::BAD_REQUEST,
        Code::UNSUPPORTED_CONTENT_FORMAT,
        Code::INTERNAL_SERVER_ERROR,
    ] {
        let (addr, _) = coap_server(Serve::Fail(code)).await;
        let error = Client::new()
            .exchange(query(), server(addr, ""), &coap())
            .await;
        assert!(
            matches!(&error, Err(ClientError::Doc(DocError::Code(got))) if *got == code),
            "{code}: {error:?}"
        );
    }
}

/// RFC 9953 §4.3, RFC 7252 §4.8, §5.2.2: the whole exchange ends at the query's timeout, whether the server never
/// answers or only acknowledges and never sends the response, which CoAP alone waits 93 s for, and the caller gets the
/// timeout of the exchange, as over the other transports (D109).
#[compio::test]
async fn s4_3_the_exchange_ends_at_the_timeout_of_the_query() {
    let mut options = coap();
    options.timeout = Duration::from_millis(300);
    for serve in [Serve::Silent, Serve::EmptyAck] {
        let (addr, seen) = coap_server(serve.clone()).await;
        let started = Instant::now();
        // Far past the timeout, so that a query that is not bounded fails here, not by hanging the suite.
        let asked = compio::time::timeout(
            Duration::from_secs(5),
            Client::new().exchange(query(), server(addr, ""), &options),
        )
        .await;
        let error = asked.expect("an answer before 5 s");
        assert!(
            matches!(
                &error,
                Err(ClientError::Exchange(DnsFailure::TimedOut { sends: 1 }))
            ),
            "{error:?}"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= options.timeout && elapsed < options.timeout + Duration::from_millis(500),
            "{elapsed:?}"
        );
        assert!(!seen.borrow().is_empty());
    }
}

/// RFC 9953 §4.3: a content format other than `application/dns-message`, and a body that is no DNS message, are
/// refused.
#[compio::test]
async fn s4_3_another_content_format_or_a_body_that_is_no_dns_message_is_refused() {
    let (addr, _) = coap_server(Serve::Format(50)).await;
    let error = Client::new()
        .exchange(query(), server(addr, ""), &coap())
        .await;
    assert!(
        matches!(error, Err(ClientError::Doc(DocError::Format(50)))),
        "{error:?}"
    );
    let (addr, _) = coap_server(Serve::Garbage).await;
    let error = Client::new()
        .exchange(query(), server(addr, ""), &coap())
        .await;
    assert!(
        matches!(error, Err(ClientError::Doc(DocError::NotDns))),
        "{error:?}"
    );
}

/// A CoAP server answering each GET with this code, content format and payload; the requests it got.
async fn links_server(
    code: Code,
    format: Option<u16>,
    payload: &'static str,
) -> (SocketAddr, Rc<RefCell<Vec<Message>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a socket");
    let addr = socket.local_addr().expect("an address");
    let seen = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&seen);
    compio::runtime::spawn(async move {
        loop {
            let BufResult(received, buf) = socket.recv_from(Vec::with_capacity(2048)).await;
            let (len, peer) = received.expect("a request");
            let Ok(request) = Message::parse(&buf[..len]) else {
                continue;
            };
            if request.code != Code::GET {
                continue;
            }
            log.borrow_mut().push(request.clone());
            let mut reply = Message::piggybacked(&request, code);
            if let Some(format) = format {
                reply.options.set_content_format(format);
            }
            reply.payload = payload.as_bytes().to_vec();
            let BufResult(sent, _) = socket
                .send_to(reply.to_vec().expect("a reply that writes"), peer)
                .await;
            sent.expect("sent");
        }
    })
    .detach();
    (addr, seen)
}

const LINK_FORMAT: Option<u16> = Some(Options::LINK_FORMAT);

/// The paths of the resources `payload` lists, as text.
async fn discovered(
    code: Code,
    format: Option<u16>,
    payload: &'static str,
) -> Result<Vec<String>, ClientError> {
    let (addr, _) = links_server(code, format, payload).await;
    Client::new().discover_doc(addr).await.map(|paths| {
        paths
            .iter()
            .map(|path| {
                path.iter().fold(String::new(), |text, segment| {
                    text + "/" + &String::from_utf8_lossy(segment)
                })
            })
            .collect()
    })
}

/// RFC 9953 §3.1, RFC 6690 §4.1: discovery is a GET of `/.well-known/core` filtered on `rt=core.dns`, asking for the link
/// format; the path of the link it lists is the one to query (D95).
#[compio::test]
async fn s3_1_discovery_is_a_filtered_get_of_the_well_known_core() {
    let (addr, seen) = links_server(
        Code::CONTENT,
        LINK_FORMAT,
        "</dns/query>;rt=core.dns;ct=553",
    )
    .await;
    let paths = Client::new().discover_doc(addr).await.expect("a list");
    assert_eq!(
        paths,
        [path_segments("/dns/query")],
        "the path of the one link"
    );
    let seen = seen.borrow();
    let [request] = seen.as_slice() else {
        panic!("one request, not {}", seen.len());
    };
    assert_eq!(request.kind, Type::Confirmable);
    assert_eq!(
        request.options.uri_path().collect::<Vec<_>>(),
        [b".well-known".as_slice(), b"core"]
    );
    assert_eq!(
        request
            .options
            .get_all(OptionNumber::URI_QUERY)
            .collect::<Vec<_>>(),
        [b"rt=core.dns".as_slice()]
    );
    assert_eq!(request.options.accept(), Some(Options::LINK_FORMAT));
    assert_eq!(request.payload.len(), 0);
}

/// RFC 6690 §4.1: a server that does not filter lists every link; the client keeps the hosted ones with the resource
/// type `core.dns` (RFC 9953 §3.1), among several types, whose content formats allow 553, in the order listed.
#[compio::test]
async fn s3_1_the_client_picks_the_links_of_the_resource_type_from_an_unfiltered_list() {
    let text = "</sensors>;ct=40;title=\"Sensor Index\",\n\
                </sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\n\
                </dns>;rt=\"core.sen core.dns\";ct=\"553 50\",\n\
                </json>;rt=core.dns;ct=50,\n\
                </other>;rt=core.dns;anchor=\"/sensors/temp\",\n\
                </b>;rt=core.dns;rel=item,\n\
                <http://www.example.com/sensors/t123>;anchor=\"/sensors/temp\";rel=\"describedby\",\n\
                </a/b>;rt=core.dns";
    let paths = discovered(Code::CONTENT, LINK_FORMAT, text).await;
    assert_eq!(paths.expect("a list"), ["/dns", "/a/b"]);
}

/// RFC 6690 §4: no resource of the type, or no resource at all, is no error: no paths.
#[compio::test]
async fn s3_1_a_list_without_the_resource_type_has_no_paths() {
    for text in ["", "</sensors>;ct=40", "</temp>;rt=\"temperature-c\""] {
        let paths = discovered(Code::CONTENT, LINK_FORMAT, text).await;
        assert_eq!(paths.expect("a list"), Vec::<String>::new(), "{text:?}");
    }
}

/// RFC 9953 §3.1: a link at the root path is the root resource; no Content-Format is the link format asked for.
#[compio::test]
async fn s3_1_a_link_to_the_root_is_the_root_path() {
    let paths = discovered(Code::CONTENT, None, "</>;rt=core.dns;ct=553").await;
    assert_eq!(paths.expect("a list"), [""]);
}

/// RFC 9953 §3.1: a CoAP error is no list, another content format than the link format is refused, and so is a
/// payload outside the link format.
#[compio::test]
async fn s3_1_an_error_code_another_format_or_a_payload_outside_the_link_format_is_refused() {
    let error = discovered(Code::NOT_FOUND, None, "").await;
    assert!(
        matches!(
            &error,
            Err(ClientError::Doc(DocError::Code(Code::NOT_FOUND)))
        ),
        "{error:?}"
    );
    let error = discovered(
        Code::CONTENT,
        Some(Options::DNS_MESSAGE),
        "</a>;rt=core.dns",
    )
    .await;
    assert!(
        matches!(&error, Err(ClientError::Doc(DocError::NotLinks(553)))),
        "{error:?}"
    );
    let error = discovered(Code::CONTENT, LINK_FORMAT, "/a;rt=core.dns").await;
    assert!(
        matches!(
            &error,
            Err(ClientError::Doc(DocError::Links(LinkError::Syntax { .. })))
        ),
        "{error:?}"
    );
}

/// D95: a link to another host, port or scheme than the server's is refused, not followed; a refused link is no
/// error beside one that is fine.
#[compio::test]
async fn s3_1_a_link_to_another_server_is_refused() {
    for text in [
        "<coap://192.0.2.1/dns>;rt=core.dns",
        "<//dns.example/dns>;rt=core.dns",
        "</dns?a=b>;rt=core.dns",
    ] {
        let error = discovered(Code::CONTENT, LINK_FORMAT, text).await;
        assert!(
            matches!(
                &error,
                Err(ClientError::Doc(DocError::Links(LinkError::Target { .. })))
            ),
            "{text}: {error:?}"
        );
    }
    let paths = discovered(
        Code::CONTENT,
        LINK_FORMAT,
        "<coap://192.0.2.1/dns>;rt=core.dns,</dns/query>;rt=core.dns",
    )
    .await;
    assert_eq!(paths.expect("a list"), ["/dns/query"]);
}

/// RFC 7252 §6.4: the path of a URI is its segments, as written: none for the root, an empty one for each `//`.
#[test]
fn the_path_of_a_uri_is_its_segments() {
    let segments = |path| {
        path_segments(path)
            .iter()
            .map(|segment| String::from_utf8_lossy(segment).into_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(segments(""), Vec::<String>::new());
    assert_eq!(segments("/"), Vec::<String>::new());
    assert_eq!(segments("/dns"), ["dns"]);
    assert_eq!(segments("/a/b"), ["a", "b"]);
    assert_eq!(segments("/a//b"), ["a", "", "b"]);
    assert_eq!(segments("/a/"), ["a", ""]);
}

/// The server's request for `/dns/query`, as RFC 9953 §4.1 says: a CON FETCH of a query, in and asking for 553.
fn fetch() -> Message {
    let mut options = Options::new();
    options.push_uri_path(path_segments("/dns/query").iter().map(|segment| &**segment));
    options.set_content_format(Options::DNS_MESSAGE);
    options.set_accept(Options::DNS_MESSAGE);
    Message {
        kind: Type::Confirmable,
        code: Code::FETCH,
        id: 7,
        token: Token::new(&[7, 7]).expect("a token"),
        options,
        payload: QUERY.to_vec(),
    }
}

/// A CON GET of `/.well-known/core` asking for the link format, with these Uri-Query options.
fn well_known(queries: &[&str]) -> Message {
    let mut options = Options::new();
    options.push_uri_path([b".well-known".as_slice(), b"core"]);
    for query in queries {
        options.insert(OptionNumber::URI_QUERY, query.as_bytes());
    }
    options.set_accept(Options::LINK_FORMAT);
    Message {
        kind: Type::Confirmable,
        code: Code::GET,
        id: 9,
        token: Token::new(&[9, 9]).expect("a token"),
        options,
        payload: Vec::new(),
    }
}

/// The payload of the answer of a server at `path` to `request`, or the code of its error, `None` if the request is
/// not for `/.well-known/core`.
fn listing(request: &Message, path: &str) -> Option<Result<String, Code>> {
    let reply = discovery(request, 1, &path_segments(path))?;
    Some(if reply.code == Code::CONTENT {
        Ok(String::from_utf8(reply.payload).expect("a link"))
    } else {
        Err(reply.code)
    })
}

/// RFC 9953 §3.1, RFC 6690 §4, §4.1: a server answers a GET of `/.well-known/core` with its one link, in the link
/// format, and gives it to a request whose filter on `rt` it matches, a complete value or a prefix.
#[test]
fn s3_1_a_server_lists_its_resource_to_a_filter_it_matches() {
    let reply = discovery(
        &well_known(&["rt=core.dns"]),
        1,
        &path_segments("/dns/query"),
    )
    .expect("an answer");
    assert_eq!(reply.kind, Type::Acknowledgement);
    assert_eq!(reply.code, Code::CONTENT);
    assert_eq!(reply.options.content_format(), Some(Options::LINK_FORMAT));
    assert_eq!(reply.payload, b"</dns/query>;rt=core.dns;ct=553");
    for queries in [vec![], vec!["rt=core.*"], vec!["rt=*"], vec!["ct=553"]] {
        let payload = listing(&well_known(&queries), "/dns/query").expect("an answer");
        assert_eq!(payload.as_deref(), Ok("</dns/query>;rt=core.dns;ct=553"));
    }
    for queries in [
        vec!["rt=core.dns2"],
        vec!["rt=core.sen"],
        vec!["rt=core.dns", "rt=x"],
    ] {
        let payload = listing(&well_known(&queries), "/dns/query").expect("an answer");
        assert_eq!(payload.as_deref(), Ok(""), "{queries:?}");
    }
}

/// RFC 6690 §4: the request for another path is not one for the list, and neither is a request for a proxy to
/// make (RFC 7252 §5.7.2).
#[test]
fn s3_1_only_a_request_for_the_well_known_core_is_a_discovery() {
    assert!(discovery(&fetch(), 1, &path_segments("/dns/query")).is_none());
    let mut other = well_known(&[]);
    other.options.remove(OptionNumber::URI_PATH);
    other
        .options
        .push_uri_path([b".well-known".as_slice(), b"other"]);
    assert!(discovery(&other, 1, &path_segments("/dns/query")).is_none());
    for (number, value) in [
        (OptionNumber::PROXY_URI, b"coap://dns.example/".as_slice()),
        (OptionNumber::PROXY_SCHEME, b"coap".as_slice()),
    ] {
        let mut request = well_known(&[]);
        request.options.insert(number, value);
        assert!(discovery(&request, 1, &path_segments("/dns/query")).is_none());
    }
}

/// RFC 7252 §5.8, §5.10.4, §5.10.8, §5.9.2.5: a discovery that cannot be served gets the code of the reason: a method
/// other than GET is 4.05, an unknown critical option 4.02, another format accepted than the link format 4.06, a
/// condition the resource does not fulfil 4.12.
#[test]
fn s3_1_a_discovery_that_cannot_be_served_gets_an_error_code() {
    type Change = fn(&mut Message);
    let cases: [(&str, Change, Code); 6] = [
        ("a POST", |m| m.code = Code::POST, Code::METHOD_NOT_ALLOWED),
        (
            "an unknown critical option",
            |m| m.options.insert(OptionNumber(2049), [1]),
            Code::BAD_OPTION,
        ),
        (
            "accepting DNS",
            |m| m.options.set_accept(Options::DNS_MESSAGE),
            Code::NOT_ACCEPTABLE,
        ),
        (
            "an If-None-Match",
            |m| m.options.insert(OptionNumber::IF_NONE_MATCH, []),
            Code::PRECONDITION_FAILED,
        ),
        (
            "an If-Match with a tag",
            |m| m.options.insert(OptionNumber::IF_MATCH, [1, 2]),
            Code::PRECONDITION_FAILED,
        ),
        (
            "no format accepted",
            |m| m.options.remove(OptionNumber::ACCEPT),
            Code::CONTENT,
        ),
    ];
    for (what, change, code) in cases {
        let mut request = well_known(&[]);
        change(&mut request);
        let reply = discovery(&request, 1, &path_segments("/dns/query")).expect("an answer");
        assert_eq!(reply.code, code, "{what}");
        assert_eq!(reply.token, request.token, "{what}");
        assert_eq!(reply.payload.is_empty(), code != Code::CONTENT, "{what}");
    }
}

/// RFC 3986 §3.3, §4.2, RFC 9953 §3.1: the path in the link is written as a URI path: the bytes `pchar` allows as
/// they are, the others as `%` and two uppercase hexadecimal digits, one that opens with an empty segment after `/.`.
#[test]
fn s3_1_the_link_writes_the_path_as_a_uri_path() {
    let link = |segments: &[&[u8]]| {
        let path: Vec<Box<[u8]>> = segments.iter().map(|segment| (*segment).into()).collect();
        let reply = discovery(&well_known(&[]), 1, &path).expect("an answer");
        String::from_utf8(reply.payload).expect("a link")
    };
    let rest = ">;rt=core.dns;ct=553";
    assert_eq!(link(&[]), format!("</{rest}"));
    assert_eq!(link(&[b"dns", b"Query-0"]), format!("</dns/Query-0{rest}"));
    assert_eq!(
        link(&[b"-._~!$&'()*+,;=:@"]),
        format!("</-._~!$&'()*+,;=:@{rest}")
    );
    assert_eq!(
        link(&[b"a b", b"%", b"/?#"]),
        format!("</a%20b/%25/%2F%3F%23{rest}")
    );
    assert_eq!(
        link(&[&[0xA5, 0x0F, 0xF0, 0x00]]),
        format!("</%A5%0F%F0%00{rest}")
    );
    assert_eq!(link(&[b"", b"a"]), format!("</.//a{rest}"));
}

/// RFC 7252 §5.7.2, §5.10.1, §5.10.8: a request for a proxy is 5.05 and one for another path 4.04, whatever else is
/// wrong with it; a condition the resource does not fulfil is 4.12: an If-None-Match, or an If-Match with only
/// tags, which no representation of the resource has. An empty If-Match, which asks for any, is fulfilled.
#[test]
fn s4_3_1_a_request_for_a_proxy_or_with_a_failing_condition_is_refused() {
    let path = path_segments("/dns/query");
    assert!(matches!(doc_query(&fetch(), &path), Ok(Query::Dns(body)) if body == QUERY));
    let mut request = fetch();
    request
        .options
        .insert(OptionNumber::PROXY_URI, b"coap://dns.example/dns/query");
    assert_eq!(
        doc_query(&request, &path).err(),
        Some(Code::PROXYING_NOT_SUPPORTED)
    );
    let mut request = fetch();
    request.options.insert(OptionNumber::PROXY_SCHEME, b"coap");
    assert_eq!(
        doc_query(&request, &path).err(),
        Some(Code::PROXYING_NOT_SUPPORTED)
    );
    let mut request = fetch();
    request.options.insert(OptionNumber::IF_NONE_MATCH, []);
    assert_eq!(
        doc_query(&request, &path).err(),
        Some(Code::PRECONDITION_FAILED)
    );
    let mut request = fetch();
    request.options.insert(OptionNumber::IF_MATCH, [1, 2, 3, 4]);
    assert_eq!(
        doc_query(&request, &path).err(),
        Some(Code::PRECONDITION_FAILED)
    );
    request.options.insert(OptionNumber::IF_MATCH, []);
    assert!(
        doc_query(&request, &path).is_ok(),
        "one of the tags is empty"
    );
    let mut request = fetch();
    request.options.insert(OptionNumber::IF_MATCH, []);
    assert!(
        doc_query(&request, &path).is_ok(),
        "an empty tag asks for any"
    );
}

/// A request with no body asks for a later block of a response it got (RFC 7959 §2.4): a Block2 past the first.
/// One asking for the first block, or for none, has no query.
#[test]
fn an_empty_request_asks_for_a_later_block() {
    let path = path_segments("/dns/query");
    let size = BlockSize::new(2).expect("64 bytes");
    let asking = |block: Option<u32>| {
        let mut request = fetch();
        request.payload.clear();
        if let Some(num) = block {
            request
                .options
                .set_block2(Block::new(num, false, size).expect("a block"));
        }
        doc_query(&request, &path).map(|query| match query {
            Query::Block(block) => Some(block.num()),
            Query::Dns(_) => None,
        })
    };
    assert_eq!(asking(Some(1)), Ok(Some(1)));
    assert_eq!(asking(Some(0)), Err(Code::BAD_REQUEST));
    assert_eq!(asking(None), Err(Code::BAD_REQUEST));
}
