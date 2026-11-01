//! CoAP (RFC 7252): the message format of §3, the examples of Appendix A byte for byte, the reliability of §4
//! and the exchanges of §5, with datagrams captured from aiocoap (`tests/testdata/coap/capture.py`).

mod coap_capture;

use std::num::NonZero;
use std::time::{Duration, Instant};

use coap_capture::{SERVER, capture, delivered, essence, ids, play, request_of};
use dedens_net::coap::exchange::{Exchange, Failure, Next, Params, Request, Step};
use dedens_net::coap::server::{Dedup, EXCHANGE_LIFETIME, Seen};
use dedens_net::coap::{Code, Message, OptionNumber, Options, ParseError, Token, Type, WriteError};
use proptest::prelude::*;

fn token(bytes: &[u8]) -> Token {
    Token::new(bytes).expect("a value")
}

fn get_temperature(token: Token) -> Request {
    let mut options = Options::new();
    options.push_uri_path([b"temperature".as_slice()]);
    Request {
        code: Code::GET,
        options,
        payload: Vec::new(),
        token,
    }
}

/// `bytes` of the figure followed by `tail` as text.
fn with_text(bytes: &[u8], tail: &str) -> Vec<u8> {
    [bytes, tail.as_bytes()].concat()
}

/// The deadline of the exchange passes.
fn expire(exchange: Exchange) -> Step {
    let at = exchange.deadline();
    exchange.time_out(at)
}

fn wait(step: Step) -> (Vec<Vec<u8>>, Exchange) {
    match step.next {
        Next::Wait(exchange) => (step.send, exchange),
        Next::Done(result) => unreachable!("the exchange ended: {result:?}"),
    }
}

// §3 and Appendix A, Figures 16 to 22.

#[test]
fn figure_16_request_and_piggybacked_response() {
    let request = Message {
        kind: Type::Confirmable,
        code: Code::GET,
        id: 0x7d34,
        token: Token::EMPTY,
        options: get_temperature(Token::EMPTY).options,
        payload: Vec::new(),
    };
    let wire = with_text(&[0x40, 0x01, 0x7d, 0x34, 0xbb], "temperature");
    assert_eq!(request.to_vec().expect("a value"), wire);
    assert_eq!(Message::parse(&wire).expect("a value"), request);

    let response = Message {
        kind: Type::Acknowledgement,
        code: Code::CONTENT,
        id: 0x7d34,
        token: Token::EMPTY,
        options: Options::new(),
        payload: b"22.3 C".to_vec(),
    };
    let wire = with_text(&[0x60, 0x45, 0x7d, 0x34, 0xff], "22.3 C");
    assert_eq!(response.to_vec().expect("a value"), wire);
    assert_eq!(Message::parse(&wire).expect("a value"), response);
    let mut built = Message::piggybacked(&request, Code::CONTENT);
    built.payload = b"22.3 C".to_vec();
    assert_eq!(response, built);
}

#[test]
fn figure_17_with_a_token() {
    let now = Instant::now();
    let (sent, exchange) = wait(Exchange::start(
        get_temperature(token(&[0x20])),
        SERVER,
        Params::default(),
        0x7d35,
        1,
        now,
    ));
    assert_eq!(
        sent,
        [with_text(
            &[0x41, 0x01, 0x7d, 0x35, 0x20, 0xbb],
            "temperature"
        )]
    );
    let ack = with_text(&[0x61, 0x45, 0x7d, 0x35, 0x20, 0xff], "22.3 C");
    let Next::Done(Ok(response)) = exchange.receive(SERVER, &ack, now).next else {
        panic!("not done")
    };
    assert_eq!(
        (response.code, response.payload.as_slice()),
        (Code::CONTENT, b"22.3 C".as_slice())
    );
}

#[test]
fn figure_18_lost_request_is_sent_again_with_the_same_id() {
    let now = Instant::now();
    let (sent, exchange) = wait(Exchange::start(
        get_temperature(token(&[0x31])),
        SERVER,
        Params::default(),
        0x7d36,
        1,
        now,
    ));
    let first = Message::parse(&sent[0]).expect("a value");
    assert_eq!((first.id, first.kind), (0x7d36, Type::Confirmable));
    // §4.2: the first wait is from ACK_TIMEOUT to ACK_RANDOM_FACTOR times it.
    let wait_for = exchange.deadline() - now;
    assert!((Duration::from_secs(2)..=Duration::from_secs(3)).contains(&wait_for));
    let (again, exchange) = wait(expire(exchange));
    assert_eq!(again, sent);
    let ack = with_text(&[0x61, 0x45, 0x7d, 0x36, 0x31, 0xff], "22.3 C");
    assert!(matches!(
        exchange.receive(SERVER, &ack, now).next,
        Next::Done(Ok(_))
    ));
}

#[test]
fn figure_19_lost_ack_is_answered_by_the_same_ack_again() {
    // The client side: it sends again, and takes the ACK that comes.
    let now = Instant::now();
    let (sent, exchange) = wait(Exchange::start(
        get_temperature(token(&[0x42])),
        SERVER,
        Params::default(),
        0x7d37,
        1,
        now,
    ));
    let (again, exchange) = wait(expire(exchange));
    assert_eq!(again, sent);
    let ack = with_text(&[0x61, 0x45, 0x7d, 0x37, 0x42, 0xff], "22.3 C");
    assert!(matches!(
        exchange.receive(SERVER, &ack, now).next,
        Next::Done(Ok(_))
    ));

    // The server side: the second CON is a duplicate that gets the first reply again, not a second processing.
    let mut dedup = Dedup::new(EXCHANGE_LIFETIME, NonZero::new(8).expect("a value"));
    assert_eq!(dedup.check(SERVER, 0x7d37, now), Seen::New);
    dedup.reply(SERVER, 0x7d37, ack.clone());
    assert_eq!(
        dedup.check(SERVER, 0x7d37, now),
        Seen::Duplicate(Some(ack.as_slice()))
    );
}

#[test]
fn figure_20_separate_response() {
    let now = Instant::now();
    let (_, exchange) = wait(Exchange::start(
        get_temperature(token(&[0x53])),
        SERVER,
        Params::default(),
        0x7d38,
        1,
        now,
    ));
    let (none, exchange) = wait(exchange.receive(SERVER, &[0x60, 0x00, 0x7d, 0x38], now));
    assert_eq!(none, Vec::<Vec<u8>>::new());
    // The wait is longer than for an ACK now.
    assert!(exchange.deadline() > now + Duration::from_secs(60));
    let separate = with_text(&[0x41, 0x45, 0xad, 0x7b, 0x53, 0xff], "22.3 C");
    let step = exchange.receive(SERVER, &separate, now);
    // An empty ACK echoing the message ID of the response.
    assert_eq!(step.send, [vec![0x60, 0x00, 0xad, 0x7b]]);
    let Next::Done(Ok(response)) = step.next else {
        panic!("not done")
    };
    assert_eq!(response.payload, b"22.3 C");
}

#[test]
fn figure_21_unexpected_separate_response_is_reset() {
    let now = Instant::now();
    let (_, exchange) = wait(Exchange::start(
        get_temperature(token(&[0x64])),
        SERVER,
        Params::default(),
        0x7d39,
        1,
        now,
    ));
    let stray = with_text(&[0x41, 0x45, 0xad, 0x7c, 0x99, 0xff], "22.3 C");
    let (sent, _) = wait(exchange.receive(SERVER, &stray, now));
    assert_eq!(sent, [vec![0x70, 0x00, 0xad, 0x7c]]);
}

#[test]
fn figure_22_non_request_and_response() {
    let request = Message {
        kind: Type::NonConfirmable,
        code: Code::GET,
        id: 0x7d40,
        token: token(&[0x75]),
        options: get_temperature(Token::EMPTY).options,
        payload: Vec::new(),
    };
    let wire = with_text(&[0x51, 0x01, 0x7d, 0x40, 0x75, 0xbb], "temperature");
    assert_eq!(request.to_vec().expect("a value"), wire);
    let response = with_text(&[0x51, 0x45, 0xad, 0x7d, 0x75, 0xff], "22.3 C");
    assert_eq!(
        Message::parse(&response)
            .expect("a value")
            .to_vec()
            .expect("a value"),
        response
    );
}

// §3: the format.

#[test]
fn errors_of_the_format() {
    let cases: [(&[u8], ParseError); 9] = [
        (&[0x40, 0x01, 0x7d], ParseError::Truncated),
        (&[0x80, 0x01, 0x7d, 0x34], ParseError::Version(2)),
        (&[0x49, 0x01, 0x7d, 0x34], ParseError::TokenLength(9)),
        (&[0x41, 0x01, 0x7d, 0x34], ParseError::Truncated),
        // An empty message holds nothing more (§4.1).
        (
            &[0x40, 0x00, 0x7d, 0x34, 0xff],
            ParseError::EmptyWithContent,
        ),
        (
            &[0x41, 0x00, 0x7d, 0x34, 0x20],
            ParseError::EmptyWithContent,
        ),
        // The payload marker needs a payload (§3).
        (&[0x40, 0x01, 0x7d, 0x34, 0xff], ParseError::EmptyPayload),
        // 15 as the delta or the length of an option is reserved (§3.1).
        (
            &[0x40, 0x01, 0x7d, 0x34, 0xf1, 0x00],
            ParseError::ReservedNibble,
        ),
        (
            &[0x40, 0x01, 0x7d, 0x34, 0x1f, 0x00],
            ParseError::ReservedNibble,
        ),
    ];
    for (bytes, error) in cases {
        assert_eq!(Message::parse(bytes), Err(error), "{bytes:02x?}");
    }
}

#[test]
fn extended_option_deltas_and_lengths() {
    // Delta 13 + 1 byte (Size1, 60, after nothing), length 14 + 2 bytes (300 bytes of Uri-Path first).
    let mut options = Options::new();
    options.insert(OptionNumber::URI_PATH, vec![b'a'; 300]);
    options.insert(OptionNumber::URI_PATH, vec![b'b'; 13]);
    options.set_size1(1_000_000);
    // An elective option past 268: delta 14 + 2 bytes.
    options.insert(OptionNumber(2000), b"x".as_slice());
    let message = Message {
        kind: Type::NonConfirmable,
        code: Code::POST,
        id: 1,
        token: token(&[1, 2, 3, 4, 5, 6, 7, 8]),
        options,
        payload: b"body".to_vec(),
    };
    let wire = message.to_vec().expect("a value");
    // The first option: delta 11, length 14 → 0xbe, 300 - 269 = 31.
    assert_eq!(&wire[12..15], &[0xbe, 0x00, 0x1f]);
    assert_eq!(Message::parse(&wire).expect("a value"), message);
}

#[test]
fn unknown_options_are_kept_and_the_critical_ones_told() {
    let mut message = Message::empty(Type::Confirmable, 9);
    message.code = Code::GET;
    message
        .options
        .insert(OptionNumber(2001), b"critical".as_slice());
    message
        .options
        .insert(OptionNumber(2002), b"elective".as_slice());
    let parsed = Message::parse(&message.to_vec().expect("a value")).expect("a value");
    assert_eq!(parsed, message);
    assert_eq!(
        parsed.unknown_critical().collect::<Vec<_>>(),
        [OptionNumber(2001)]
    );
}

#[test]
fn an_empty_message_with_content_cannot_be_written() {
    let mut message = Message::empty(Type::Acknowledgement, 1);
    message.payload.push(1);
    assert_eq!(message.to_vec(), Err(WriteError::EmptyWithContent));
}

#[test]
fn code_names() {
    assert_eq!(Code::FETCH, Code::new(0, 5));
    assert_eq!(Code::CONTENT.to_string(), "2.05");
    assert_eq!(Code::UNSUPPORTED_CONTENT_FORMAT.to_string(), "4.15");
    assert_eq!(Code::SERVICE_UNAVAILABLE.0, 0xa3);
}

// §4.2: the limits of retransmission.

#[test]
fn gives_up_after_max_retransmit_with_doubling_waits() {
    let t0 = Instant::now();
    let (_, mut exchange) = wait(Exchange::start(
        get_temperature(token(&[1, 2])),
        SERVER,
        Params::default(),
        1,
        99,
        t0,
    ));
    let mut now = t0;
    let mut waits = Vec::new();
    for _ in 0..4 {
        waits.push(exchange.deadline() - now);
        now = exchange.deadline();
        let (sent, next) = wait(exchange.time_out(now));
        assert_eq!(sent.len(), 1);
        exchange = next;
    }
    waits.push(exchange.deadline() - now);
    for pair in waits.windows(2) {
        assert_eq!(pair[1], pair[0] * 2);
    }
    // 4 retransmissions, then the failure: at most MAX_TRANSMIT_WAIT in all (§4.8.2).
    let step = expire(exchange);
    assert_eq!(step.send, Vec::<Vec<u8>>::new());
    assert!(matches!(step.next, Next::Done(Err(Failure::TimedOut))));
    assert!(waits.iter().sum::<Duration>() <= Duration::from_secs(93));
}

#[test]
fn reset_ends_the_exchange() {
    let now = Instant::now();
    let (_, exchange) = wait(Exchange::start(
        get_temperature(token(&[1, 2])),
        SERVER,
        Params::default(),
        0x1234,
        1,
        now,
    ));
    let step = exchange.receive(SERVER, &[0x70, 0x00, 0x12, 0x34], now);
    assert!(matches!(step.next, Next::Done(Err(Failure::Reset))));
}

#[test]
fn datagrams_not_for_the_exchange_are_dropped() {
    let now = Instant::now();
    let (_, exchange) = wait(Exchange::start(
        get_temperature(token(&[1, 2])),
        SERVER,
        Params::default(),
        0x1234,
        1,
        now,
    ));
    // An ACK of another ID, garbage, and a good ACK from another address.
    let ack = with_text(&[0x62, 0x45, 0x12, 0x34, 0x01, 0x02, 0xff], "22.3 C");
    let other = "127.0.0.2:5683".parse().expect("a value");
    let (_, exchange) = wait(exchange.receive(SERVER, &[0x60, 0x45, 0x00, 0x01], now));
    let (_, exchange) = wait(exchange.receive(SERVER, &[0xff], now));
    let (_, exchange) = wait(exchange.receive(other, &ack, now));
    assert!(matches!(
        exchange.receive(SERVER, &ack, now).next,
        Next::Done(Ok(_))
    ));
}

#[test]
fn a_response_with_an_unknown_critical_option_is_rejected() {
    let now = Instant::now();
    let (_, exchange) = wait(Exchange::start(
        get_temperature(token(&[1, 2])),
        SERVER,
        Params::default(),
        0x1234,
        1,
        now,
    ));
    let mut response = Message::empty(Type::Acknowledgement, 0x1234);
    response.code = Code::CONTENT;
    response.token = token(&[1, 2]);
    response.options.insert(OptionNumber(2001), b"?".as_slice());
    let step = exchange.receive(SERVER, &response.to_vec().expect("a value"), now);
    assert!(matches!(
        step.next,
        Next::Done(Err(Failure::UnknownCriticalOption(OptionNumber(2001))))
    ));
}

// §4.5: duplicates, bounded.

#[test]
fn dedup_forgets_after_the_lifetime_and_at_capacity() {
    let t0 = Instant::now();
    let mut dedup = Dedup::new(Duration::from_secs(10), NonZero::new(2).expect("a value"));
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::New);
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::Duplicate(None));
    // Another endpoint, another message.
    let other = "127.0.0.2:5683".parse().expect("a value");
    assert_eq!(dedup.check(other, 1, t0), Seen::New);
    // Full: the oldest goes.
    assert_eq!(dedup.check(SERVER, 2, t0), Seen::New);
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::New);
    // The lifetime is over.
    assert_eq!(
        dedup.check(SERVER, 1, t0 + Duration::from_secs(11)),
        Seen::New
    );
}

// Captured from aiocoap.

#[test]
fn every_captured_datagram_is_read_and_written_back_byte_for_byte() {
    let mut seen = 0;
    for id in ids() {
        for datagram in capture(&id) {
            let message = Message::parse(&datagram.bytes).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(message.to_vec().expect("a value"), datagram.bytes, "{id}");
            seen += 1;
        }
    }
    assert!(seen > 100);
}

#[test]
fn captured_piggybacked_response() {
    let played = play("get_piggybacked", Params::default());
    let capture = capture("get_piggybacked");
    // The request goes out as aiocoap's, byte for byte.
    assert_eq!(played.sent.len(), 1);
    assert_eq!(played.sent[0].to_vec().expect("a value"), capture[0].bytes);
    let response = played.result.expect("a value");
    assert_eq!(
        (response.code, response.payload.as_slice()),
        (Code::CONTENT, b"22.3 C".as_slice())
    );
}

#[test]
fn captured_separate_response() {
    let played = play("get_separate", Params::default());
    let capture = capture("get_separate");
    let client: Vec<_> = delivered(&capture, true);
    // The request, then the empty ACK of the separate response, as aiocoap sent them.
    assert_eq!(played.sent.len(), 2);
    for (ours, theirs) in played.sent.iter().zip(&client) {
        assert_eq!(ours.to_vec().expect("a value"), theirs.bytes);
    }
    let response = played.result.expect("a value");
    assert_eq!(response.payload, b"22.3 C");
}

#[test]
fn captured_non_exchange() {
    let capture = capture("get_non");
    let request = capture[0].message();
    let response = capture[1].message();
    assert_eq!(
        (request.kind, response.kind),
        (Type::NonConfirmable, Type::NonConfirmable)
    );
    // The response to a NON request matches by token only (§5.3.2): its message ID is the server's own.
    assert_eq!(request.token, response.token);
    assert_ne!(request.id, response.id);
    assert_eq!(response.payload, b"22.3 C");
}

#[test]
fn captured_retransmissions_are_the_same_datagram() {
    for id in ["get_lost_request", "get_lost_ack"] {
        let capture = capture(id);
        let (request, first_id) = request_of(&capture);
        let now = Instant::now();
        let (sent, exchange) = wait(Exchange::start(
            request,
            SERVER,
            Params::default(),
            first_id,
            3,
            now,
        ));
        let (again, exchange) = wait(expire(exchange));
        assert_eq!(sent, again);
        let theirs: Vec<_> = delivered(&capture, true)
            .iter()
            .map(|d| d.bytes.clone())
            .collect();
        assert_eq!(sent[0], theirs[0], "{id}");
        // aiocoap waited between ACK_TIMEOUT and ACK_RANDOM_FACTOR times it as well.
        let second = capture
            .iter()
            .filter(|d| d.from_client)
            .nth(1)
            .expect("a value");
        assert!(
            (2000..=3000).contains(&second.at_ms),
            "{id}: {} ms",
            second.at_ms
        );
        assert_eq!(second.bytes, sent[0]);
        // And the reply, whether it was the first that got through or the second.
        let reply = delivered(&capture, false)[0];
        let step = exchange.receive(
            SERVER,
            &coap_capture::retarget(reply, &Message::parse(&sent[0]).expect("a value")),
            now,
        );
        assert!(matches!(step.next, Next::Done(Ok(_))), "{id}");
    }
}

#[test]
fn a_server_answers_a_captured_duplicate_with_its_first_reply() {
    // The proxy dropped the ACK, the client sent the request again: both datagrams are the same CON.
    let capture = capture("get_lost_ack");
    let requests = delivered(&capture, true);
    let reply = delivered(&capture, false)[0];
    let id = requests[0].message().id;
    let now = Instant::now();
    let mut dedup = Dedup::new(EXCHANGE_LIFETIME, NonZero::new(16).expect("a value"));
    assert_eq!(dedup.check(SERVER, id, now), Seen::New);
    dedup.reply(SERVER, id, reply.bytes.clone());
    let again = requests[1].message().id;
    // aiocoap's server did the same: the datagram it sent again is the first reply.
    assert_eq!(
        dedup.check(SERVER, again, now),
        Seen::Duplicate(Some(reply.bytes.as_slice()))
    );
    assert_eq!(
        essence(&requests[0].message()),
        essence(&requests[1].message())
    );
}

proptest! {
    #[test]
    fn a_message_is_read_as_it_is_written(
        kind in prop::sample::select(vec![Type::Confirmable, Type::NonConfirmable, Type::Acknowledgement, Type::Reset]),
        code in 1u8..=255,
        id in any::<u16>(),
        token_bytes in prop::collection::vec(any::<u8>(), 0..=8),
        options in prop::collection::vec((0u16..3000, prop::collection::vec(any::<u8>(), 0..300)), 0..8),
        payload in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut message = Message::empty(kind, id);
        message.code = Code(code);
        message.token = token(&token_bytes);
        for (number, value) in options {
            message.options.insert(OptionNumber(number), value);
        }
        message.payload = payload;
        let wire = message.to_vec().expect("a message writes");
        prop_assert_eq!(Message::parse(&wire), Ok(message));
    }

    #[test]
    fn what_is_read_is_written_back_as_read(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        if let Ok(message) = Message::parse(&bytes) {
            let wire = message.to_vec().expect("a message read writes");
            prop_assert_eq!(Message::parse(&wire), Ok(message));
        }
    }
}
