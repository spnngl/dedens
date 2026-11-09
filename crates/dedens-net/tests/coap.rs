//! CoAP (RFC 7252): the message format of §3, the examples of Appendix A byte for byte, the reliability of §4 and the
//! exchanges of §5, with datagrams captured from aiocoap (`testdata/coap/capture.py`).

use std::num::NonZero;
use std::time::{Duration, Instant};

use dedens_net::coap::block::{Block, BlockSize};
use dedens_net::coap::exchange::{Exchange, Failure, MAX_RETRANSMIT, Next, Params, Request, Step};
use dedens_net::coap::server::{Blocks, Dedup, EXCHANGE_LIFETIME, Found, NON_LIFETIME, Seen};
use dedens_net::coap::{
    Code, MAX_OPTIONS, Message, OptionNumber, Options, ParseError, Token, Type, WriteError,
};
use proptest::prelude::*;

use crate::util::coap_capture::{SERVER, capture, delivered, essence, ids, play, request_of};

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

/// A message of `count` options, each the 1 byte `delta 0, length 0`, as a datagram of 4 + `count` bytes holds.
fn with_empty_options(count: usize) -> Vec<u8> {
    let mut wire = vec![0x40, 0x01, 0x7d, 0x34];
    wire.resize(wire.len() + count, 0x00);
    wire
}

/// A message holds at most `MAX_OPTIONS` options: a datagram of 1000 of them is a format error (D105), not a list of
/// a thousand entries. The bytes are the audit's trigger (a datagram of zeros after the header), by hand: they hold no
/// DNS data.
#[test]
fn more_options_than_the_cap_is_a_format_error() {
    let at_cap = Message::parse(&with_empty_options(MAX_OPTIONS)).expect("a message");
    assert_eq!(at_cap.options.iter().count(), MAX_OPTIONS);
    for count in [MAX_OPTIONS + 1, 1000, 65_000] {
        assert_eq!(
            Message::parse(&with_empty_options(count)),
            Err(ParseError::TooManyOptions),
            "{count} options"
        );
    }
    // The RST of §4.2 is still sent to a CON message of that kind.
    assert_eq!(
        Message::reject(&with_empty_options(1000)),
        Some(Message::empty(Type::Reset, 0x7d34))
    );
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

#[test]
fn blocks_are_found_by_endpoint_and_tag_and_forgotten_like_dedup() {
    let t0 = Instant::now();
    let mut blocks = Blocks::new(Duration::from_secs(10), NonZero::new(2).expect("a value"));
    let other = "127.0.0.2:5683".parse().expect("a value");
    let asked = block(1, 6);
    blocks.keep(SERVER, &[1], t0, vec![1]);
    assert_eq!(blocks.get(SERVER, &[1], asked, t0), Found::Response(&[1]));
    // Another tag, another endpoint, no tag: nothing kept for them.
    assert_eq!(blocks.get(SERVER, &[2], asked, t0), Found::Unknown);
    assert_eq!(blocks.get(other, &[1], asked, t0), Found::Unknown);
    assert_eq!(blocks.get(SERVER, &[], asked, t0), Found::Unknown);
    // The same request again replaces the response, taking no room.
    blocks.keep(SERVER, &[1], t0, vec![2]);
    blocks.keep(other, &[1], t0, vec![3]);
    assert_eq!(blocks.get(SERVER, &[1], asked, t0), Found::Response(&[2]));
    // Full: the oldest goes.
    blocks.keep(SERVER, &[], t0, vec![4]);
    assert_eq!(blocks.get(SERVER, &[1], asked, t0), Found::Unknown);
    assert_eq!(blocks.get(other, &[1], asked, t0), Found::Response(&[3]));
    // The lifetime is over.
    let later = t0 + Duration::from_secs(11);
    assert_eq!(blocks.get(other, &[1], asked, later), Found::Unknown);
}

/// The block `num` of the size `szx` (64 bytes for 2, 1024 for 6), as a request for a later block asks.
fn block(num: u32, szx: u8) -> Block {
    Block::new(num, false, BlockSize::new(szx).expect("a size")).expect("a block")
}

/// A response kept is served as many bytes of blocks as `1 + MAX_RETRANSMIT` readings of it whole, whatever the size
/// of the blocks, and nothing after that, however long the client goes on asking (D105): the blocks asked for are not
/// a way to have the server send the same answer over and over for a datagram each. Asking does not keep it longer.
#[test]
fn a_kept_response_is_served_a_bounded_number_of_bytes_and_for_its_lifetime() {
    let t0 = Instant::now();
    let mut blocks = Blocks::new(EXCHANGE_LIFETIME, NonZero::new(2).expect("a value"));
    // 2649 bytes, as the answer libcoap read in 64-byte blocks (D81): 42 blocks.
    let response = vec![7; 2649];
    blocks.keep(SERVER, &[], t0, response.clone());
    let mut served = 0;
    // The block 1 of 1024 bytes, again and again: 1024 bytes each.
    while let Found::Response(sent) = blocks.get(SERVER, &[], block(1, 6), t0) {
        assert_eq!(sent, &response[..]);
        served += 1024;
    }
    assert_eq!(served, 5 * 2649 / 1024 * 1024);
    assert_eq!(blocks.get(SERVER, &[], block(1, 6), t0), Found::Spent);
    // A client with 64-byte blocks reads it whole, and again: every block counts the bytes it holds.
    blocks.keep(SERVER, &[], t0, response.clone());
    for _ in 0..=MAX_RETRANSMIT {
        for num in 1..=41 {
            assert!(matches!(
                blocks.get(SERVER, &[], block(num, 2), t0),
                Found::Response(_)
            ));
        }
    }
    // Asking does not keep it longer: gone after the lifetime from when it was kept, though asked all the while.
    blocks.keep(SERVER, &[1], t0, vec![1; 10]);
    let near_end = t0 + Duration::from_secs(246);
    assert_eq!(
        blocks.get(SERVER, &[1], block(1, 6), near_end),
        Found::Response(&[1; 10])
    );
    assert_eq!(
        blocks.get(SERVER, &[1], block(1, 6), t0 + EXCHANGE_LIFETIME),
        Found::Unknown
    );
}

/// §4.8: a client sends a CON message at most `MAX_RETRANSMIT` times again, so a reply is sent again at most that many
/// times, then not at all (D105): the same CON sent 100 times is answered 5 times at most, once by the processing.
#[test]
fn dedup_replays_a_reply_at_most_max_retransmit_times() {
    let t0 = Instant::now();
    let mut dedup = Dedup::new(EXCHANGE_LIFETIME, NonZero::new(2).expect("a value"));
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::New);
    // Sent again before the reply is ready: nothing to send, and nothing used of the replays.
    for _ in 0..10 {
        assert_eq!(dedup.check(SERVER, 1, t0), Seen::Duplicate(None));
    }
    dedup.reply(SERVER, 1, vec![9; 1024]);
    let replies = (0..100)
        .filter(|_| matches!(dedup.check(SERVER, 1, t0), Seen::Duplicate(Some(_))))
        .count();
    assert_eq!(replies, usize::from(MAX_RETRANSMIT));
    assert_eq!(MAX_RETRANSMIT, 4);
    // Still a duplicate, for the rest of the lifetime: not processed again.
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::Duplicate(None));
    // Another message has its own replays, and after the lifetime the same ID is new, with new ones.
    assert_eq!(dedup.check(SERVER, 2, t0), Seen::New);
    dedup.reply(SERVER, 2, vec![8]);
    assert!(matches!(
        dedup.check(SERVER, 2, t0),
        Seen::Duplicate(Some(_))
    ));
    let later = t0 + EXCHANGE_LIFETIME;
    assert_eq!(dedup.check(SERVER, 1, later), Seen::New);
    dedup.reply(SERVER, 1, vec![7]);
    assert_eq!(
        dedup.check(SERVER, 1, later),
        Seen::Duplicate(Some(&[7][..]))
    );
}

/// A full table still holds as many messages as its capacity says: only a message that is new makes room.
#[test]
fn dedup_at_capacity_still_knows_what_it_holds() {
    let t0 = Instant::now();
    let mut dedup = Dedup::new(EXCHANGE_LIFETIME, NonZero::new(2).expect("a value"));
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::New);
    assert_eq!(dedup.check(SERVER, 2, t0), Seen::New);
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::Duplicate(None));
    assert_eq!(dedup.check(SERVER, 2, t0), Seen::Duplicate(None));
    let mut dedup = Dedup::new(EXCHANGE_LIFETIME, NonZero::new(1).expect("a value"));
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::New);
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::Duplicate(None));
}

/// A message is noted when the caller says so, not by the lookup: a request dropped for want of a task is new when
/// its client sends it again (D105). Noting a message twice does not hold a place for it twice.
#[test]
fn dedup_notes_a_message_only_when_told_to() {
    let t0 = Instant::now();
    let mut dedup = Dedup::new(EXCHANGE_LIFETIME, NonZero::new(2).expect("a value"));
    assert_eq!(dedup.lookup(SERVER, 1, t0), Seen::New);
    assert_eq!(dedup.lookup(SERVER, 1, t0), Seen::New);
    dedup.note(SERVER, 1, t0);
    dedup.note(SERVER, 1, t0);
    assert_eq!(dedup.lookup(SERVER, 1, t0), Seen::Duplicate(None));
    dedup.note(SERVER, 2, t0);
    assert_eq!(dedup.lookup(SERVER, 1, t0), Seen::Duplicate(None));
    assert_eq!(dedup.lookup(SERVER, 2, t0), Seen::Duplicate(None));
}

/// §4.5, §4.8.2: a NON message is a duplicate for `NON_LIFETIME`, 145 seconds, which is shorter than the CON message's.
#[test]
fn non_messages_are_duplicates_for_the_non_lifetime() {
    assert_eq!(NON_LIFETIME, Duration::from_secs(145));
    let t0 = Instant::now();
    let mut dedup = Dedup::new(NON_LIFETIME, NonZero::new(4).expect("a value"));
    assert_eq!(dedup.check(SERVER, 1, t0), Seen::New);
    let before = t0 + Duration::from_secs(144);
    assert_eq!(dedup.check(SERVER, 1, before), Seen::Duplicate(None));
    assert_eq!(dedup.check(SERVER, 1, t0 + NON_LIFETIME), Seen::New);
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
fn libcoap_separate_response() {
    // libcoap's server answers a CON GET with an empty ACK, then, 4 s later, a CON of its own (RFC 7252 §5.2.2).
    let played = play("libcoap_get_async", Params::default());
    let capture = capture("libcoap_get_async");
    let client: Vec<_> = delivered(&capture, true);
    assert_eq!(played.sent.len(), 2);
    for (ours, theirs) in played.sent.iter().zip(&client) {
        assert_eq!(ours.to_vec().expect("a value"), theirs.bytes);
    }
    let response = played.result.expect("a value");
    assert_eq!((response.code, response.payload.len()), (Code::CONTENT, 4));
}

#[test]
fn libcoap_non_exchange() {
    // libcoap answers a NON request with a NON response, with the message ID of the request, an empty token on
    // both, and a Max-Age of 1: the exchange matches it by the token alone (§5.3.2).
    let capture = capture("libcoap_get_non");
    let (request, response) = (capture[0].message(), capture[1].message());
    assert_eq!(
        (request.kind, response.kind),
        (Type::NonConfirmable, Type::NonConfirmable)
    );
    assert_eq!(request.token, response.token);
    assert_eq!(response.options.max_age(), 1);
    let played = play("libcoap_get_non", Params::default());
    assert_eq!(played.sent.len(), 1);
    assert_eq!(played.result.expect("a value").payload, response.payload);
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
    for id in [
        "get_lost_request",
        "get_lost_ack",
        "libcoap_get_lost_request",
        "libcoap_get_lost_ack",
    ] {
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
        // aiocoap and libcoap waited between ACK_TIMEOUT and ACK_RANDOM_FACTOR times it as well.
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
            &crate::util::coap_capture::retarget(
                reply,
                &Message::parse(&sent[0]).expect("a value"),
            ),
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

mod blockwise {
    //! Block-wise transfers (RFC 7959): the Block option value of §2.2, the exchanges of §3 driven by hand, and
    //! multi-block exchanges captured from aiocoap (testdata/coap/capture.py).

    use std::time::Instant;

    use dedens_net::coap::block::{
        Block, BlockError, BlockSize, OutOfRange, Reassembly, ReassemblyError, slice,
    };
    use dedens_net::coap::exchange::{Exchange, Failure, Next, Params, Request};
    use dedens_net::coap::{Code, Message, OptionNumber, Options, Token, Type};

    use crate::util::coap_capture::{SERVER, capture, delivered, essence, play, request_of};

    /// The first len bytes of RFC 9953, the body of the transfers: real text, like the captures use.
    fn body(len: usize) -> Vec<u8> {
        let text = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/rfc/archive/rfc9953.txt"
        ))
        .expect("a value");
        text[..len].to_vec()
    }

    fn params(set: impl FnOnce(&mut Params)) -> Params {
        let mut params = Params::default();
        set(&mut params);
        params
    }

    fn size(bytes: usize) -> BlockSize {
        BlockSize::new(u8::try_from(bytes.ilog2() - 4).expect("a value")).expect("a value")
    }

    /// NUM/M/SZX as RFC 7959 writes it in its figures: block(2, false, 128) is 2/0/128.
    fn block(num: u32, more: bool, bytes: usize) -> Block {
        Block::new(num, more, size(bytes)).expect("a value")
    }

    fn request(code: Code, path: &str, payload: Vec<u8>) -> Request {
        let mut options = Options::new();
        options.push_uri_path([path.as_bytes()]);
        Request {
            code,
            options,
            payload,
            token: Token::new(&[0xab, 0xcd]).expect("a value"),
        }
    }

    /// What the client of Exchange is to send, read back.
    fn parse_all(send: &[Vec<u8>]) -> Vec<Message> {
        send.iter()
            .map(|wire| Message::parse(wire).expect("a value"))
            .collect()
    }

    /// A piggybacked response to request.
    fn answer(
        request: &Message,
        code: Code,
        set: impl FnOnce(&mut Options),
        payload: &[u8],
    ) -> Vec<u8> {
        let mut message = Message::piggybacked(request, code);
        set(&mut message.options);
        message.payload = payload.to_vec();
        message.to_vec().expect("a value")
    }

    /// The client side of a transfer: what the exchange sends, and the server's answer to each message.
    struct Driver {
        exchange: Option<Exchange>,
        last: Message,
        sent: Vec<Message>,
        result: Option<Result<dedens_net::coap::exchange::Response, Failure>>,
    }

    impl Driver {
        fn start(request: Request, params: Params) -> Self {
            let step = Exchange::start(request, SERVER, params, 1234, 5, Instant::now());
            let mut driver = Self {
                exchange: None,
                last: Message::empty(Type::Confirmable, 0),
                sent: Vec::new(),
                result: None,
            };
            driver.take(step);
            driver
        }

        fn take(&mut self, step: dedens_net::coap::exchange::Step) {
            let messages = parse_all(&step.send);
            if let Some(last) = messages.last() {
                self.last = last.clone();
            }
            self.sent.extend(messages);
            match step.next {
                Next::Wait(exchange) => self.exchange = Some(exchange),
                Next::Done(result) => self.result = Some(result),
            }
        }

        /// The server answers the last message with code, the options set and payload.
        fn reply(&mut self, code: Code, set: impl FnOnce(&mut Options), payload: &[u8]) {
            let wire = answer(&self.last, code, set, payload);
            let exchange = self.exchange.take().expect("the exchange waits");
            let step = exchange.receive(SERVER, &wire, Instant::now());
            self.take(step);
        }

        /// The block options of the messages sent so far.
        fn block1s(&self) -> Vec<Option<Block>> {
            self.sent
                .iter()
                .map(|m| m.options.block1().expect("a value"))
                .collect()
        }

        fn block2s(&self) -> Vec<Option<Block>> {
            self.sent
                .iter()
                .map(|m| m.options.block2().expect("a value"))
                .collect()
        }

        fn response(self) -> dedens_net::coap::exchange::Response {
            self.result
                .expect("the exchange is over")
                .expect("a response")
        }
    }

    // §2.2: the option value.

    #[test]
    fn block_option_values_of_the_figures() {
        // NUM << 4 | M << 3 | SZX.
        for (num, more, bytes, value) in [
            (0, true, 128, &[0x0b][..]),
            (1, false, 128, &[0x13]),
            (2, false, 128, &[0x23]),
            (5, false, 64, &[0x52]),
            (6, false, 32, &[0x61]),
            (0, false, 16, &[]),
            (15, true, 1024, &[0xfe]),
            (16, false, 1024, &[0x01, 0x06]),
            (0x0f_ffff, false, 16, &[0xff, 0xff, 0xf0]),
        ] {
            let block = block(num, more, bytes);
            assert_eq!(block.to_value(), value, "{num}/{more}/{bytes}");
            assert_eq!(Block::from_value(value), Ok(block));
            assert_eq!(
                (block.num(), block.more(), block.size().bytes()),
                (num, more, bytes)
            );
            assert_eq!(
                block.offset(),
                usize::try_from(num).expect("a value") * bytes
            );
        }
    }

    #[test]
    fn block_option_value_edge_cases() {
        // Empty is 0/0/16 (§2.2); leading zeros are accepted.
        assert_eq!(Block::from_value(&[]), Ok(block(0, false, 16)));
        assert_eq!(Block::from_value(&[0x00, 0x13]), Ok(block(1, false, 128)));
        // SZX 7 is reserved, and a value takes at most 3 bytes.
        assert_eq!(Block::from_value(&[0x07]), Err(BlockError::ReservedSize));
        assert_eq!(
            Block::from_value(&[0, 0, 0, 0]),
            Err(BlockError::TooLong(4))
        );
        // NUM has 20 bits.
        assert!(Block::new(0x10_0000, false, size(16)).is_none());
        assert!(BlockSize::new(7).is_none());
    }

    // §3.1: Block2, the figures driven by hand.

    #[test]
    fn figure_2_blockwise_get() {
        let text = body(384);
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), Params::default());
        // No Block2 in the first request: the server picks the size.
        assert_eq!(driver.block2s(), [None]);
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(0, true, 128)),
            &text[..128],
        );
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(1, true, 128)),
            &text[128..256],
        );
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(2, false, 128)),
            &text[256..],
        );
        assert_eq!(
            driver.block2s(),
            [None, Some(block(1, false, 128)), Some(block(2, false, 128))]
        );
        // Each block has its own message ID and the one token.
        assert_eq!(
            driver.sent.iter().map(|m| m.id).collect::<Vec<_>>(),
            [1234, 1235, 1236]
        );
        assert!(
            driver
                .sent
                .iter()
                .all(|m| m.token.as_bytes() == [0xab, 0xcd])
        );
        assert_eq!(driver.response().payload, text);
    }

    #[test]
    fn figure_3_client_proposes_a_size() {
        let text = body(340);
        let params = params(|p| {
            p.block2_size = Some(size(64));
        });
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), params);
        assert_eq!(driver.block2s(), [Some(block(0, false, 64))]);
        for num in 0..5 {
            let start = usize::try_from(num).expect("a value") * 64;
            driver.reply(
                Code::CONTENT,
                |o| o.set_block2(block(num, true, 64)),
                &text[start..start + 64],
            );
        }
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(5, false, 64)),
            &text[320..],
        );
        assert_eq!(driver.block2s().len(), 6);
        assert_eq!(driver.block2s()[5], Some(block(5, false, 64)));
        assert_eq!(driver.response().payload, text);
    }

    #[test]
    fn etag_is_checked_between_blocks() {
        let text = body(256);
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), Params::default());
        driver.reply(
            Code::CONTENT,
            |o| {
                o.set_block2(block(0, true, 128));
                o.insert(OptionNumber::ETAG, b"\x01".as_slice());
            },
            &text[..128],
        );
        driver.reply(
            Code::CONTENT,
            |o| {
                o.set_block2(block(1, false, 128));
                o.insert(OptionNumber::ETAG, b"\x02".as_slice());
            },
            &text[128..],
        );
        assert_eq!(driver.result, Some(Err(Failure::ETagChanged)));
    }

    #[test]
    fn blocks_out_of_order_or_too_many_are_refused() {
        let text = body(512);
        // A skipped block.
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), Params::default());
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(0, true, 128)),
            &text[..128],
        );
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(2, true, 128)),
            &text[256..384],
        );
        assert!(matches!(
            driver.result,
            Some(Err(Failure::Reassembly(ReassemblyError::OutOfOrder { .. })))
        ));
        // A transfer that starts past the first block.
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), Params::default());
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(1, true, 128)),
            &text[128..256],
        );
        assert_eq!(driver.result, Some(Err(Failure::UnexpectedBlock)));
        // A body over the limit.
        let params = params(|p| {
            p.max_body = 200;
        });
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), params);
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(0, true, 128)),
            &text[..128],
        );
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(1, false, 128)),
            &text[128..256],
        );
        assert!(matches!(
            driver.result,
            Some(Err(Failure::Reassembly(ReassemblyError::TooLarge(_))))
        ));
        // The reserved block size.
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), Params::default());
        driver.reply(
            Code::CONTENT,
            |o| o.set(OptionNumber::BLOCK2, [0x07]),
            &text[..128],
        );
        assert_eq!(
            driver.result,
            Some(Err(Failure::Block(BlockError::ReservedSize)))
        );
    }

    #[test]
    fn an_error_in_the_middle_of_a_transfer_is_the_response() {
        let text = body(256);
        let mut driver = Driver::start(request(Code::GET, "status", Vec::new()), Params::default());
        driver.reply(
            Code::CONTENT,
            |o| o.set_block2(block(0, true, 128)),
            &text[..128],
        );
        driver.reply(Code::SERVICE_UNAVAILABLE, |_| {}, b"");
        assert_eq!(driver.response().code, Code::SERVICE_UNAVAILABLE);
    }

    // §3.2: Block1, the figures driven by hand.

    #[test]
    fn figure_9_the_server_asks_for_smaller_blocks() {
        let text = body(200);
        let params = params(|p| {
            p.block1_size = size(128);
        });
        let mut driver = Driver::start(request(Code::PUT, "options", text.clone()), params);
        assert_eq!(driver.block1s(), [Some(block(0, true, 128))]);
        assert_eq!(driver.sent[0].payload, text[..128]);
        // 2.31 Continue with the size the server wants: the next block is the 5th of 32 bytes.
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(0, true, 32)), b"");
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(4, true, 32)), b"");
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(5, true, 32)), b"");
        driver.reply(Code::CHANGED, |o| o.set_block1(block(6, false, 32)), b"");
        assert_eq!(
            driver.block1s(),
            [
                Some(block(0, true, 128)),
                Some(block(4, true, 32)),
                Some(block(5, true, 32)),
                Some(block(6, false, 32))
            ]
        );
        assert_eq!(driver.sent[1].payload, text[128..160]);
        assert_eq!(driver.sent[3].payload, text[192..]);
        assert_eq!(
            driver.sent.iter().map(|m| m.id).collect::<Vec<_>>(),
            [1234, 1235, 1236, 1237]
        );
        assert_eq!(driver.response().code, Code::CHANGED);
    }

    #[test]
    fn figure_10_block1_then_block2() {
        let upload = body(300);
        let answer_text = body(400);
        let params = params(|p| {
            p.block1_size = size(128);
        });
        let mut driver = Driver::start(request(Code::POST, "soap", upload.clone()), params);
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(0, true, 128)), b"");
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(1, true, 128)), b"");
        // The last block's response starts the response body: Block1 and Block2 both.
        driver.reply(
            Code::CHANGED,
            |o| {
                o.set_block1(block(2, false, 128));
                o.set_block2(block(0, true, 128));
            },
            &answer_text[..128],
        );
        // The follow-ups ask for blocks of the response: no body and no Block1 now.
        let follow = &driver.sent[3];
        assert_eq!(
            (
                follow.options.block1().expect("a value"),
                follow.options.block2().expect("a value")
            ),
            (None, Some(block(1, false, 128)))
        );
        assert_eq!(follow.payload, b"");
        driver.reply(
            Code::CHANGED,
            |o| o.set_block2(block(1, true, 128)),
            &answer_text[128..256],
        );
        driver.reply(
            Code::CHANGED,
            |o| o.set_block2(block(2, true, 128)),
            &answer_text[256..384],
        );
        driver.reply(
            Code::CHANGED,
            |o| o.set_block2(block(3, false, 128)),
            &answer_text[384..],
        );
        assert_eq!(
            driver.block2s()[3..],
            [
                Some(block(1, false, 128)),
                Some(block(2, false, 128)),
                Some(block(3, false, 128))
            ]
        );
        assert_eq!(driver.response().payload, answer_text);
    }

    #[test]
    fn figure_11_early_negotiation_asks_for_a_size_with_the_last_block() {
        let upload = body(300);
        let params = params(|p| {
            p.block1_size = size(128);
            p.block2_size = Some(size(64));
        });
        let mut driver = Driver::start(request(Code::POST, "soap", upload), params);
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(0, true, 128)), b"");
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(1, true, 128)), b"");
        // Only the last Block1 request proposes the size of the response blocks (§3.3).
        assert_eq!(driver.block2s(), [None, None, Some(block(0, false, 64))]);
    }

    #[test]
    fn a_continue_for_another_block_is_refused() {
        let upload = body(300);
        let params = params(|p| {
            p.block1_size = size(128);
        });
        let mut driver = Driver::start(request(Code::POST, "soap", upload), params);
        driver.reply(Code::CONTINUE, |o| o.set_block1(block(5, true, 128)), b"");
        assert_eq!(driver.result, Some(Err(Failure::UnexpectedBlock)));
    }

    // The server side: slices of a body.

    #[test]
    fn server_slices_the_body() {
        let text = body(300);
        // A body that fits and no block asked for: sent whole, with no option.
        let whole = slice(&text[..100], None, size(128)).expect("a value");
        assert_eq!((whole.block, whole.payload.len()), (None, 100));
        // No block asked for, a body over the size: the first block.
        let first = slice(&text, None, size(128)).expect("a value");
        assert_eq!(first.block, Some(block(0, true, 128)));
        assert_eq!(first.payload, &text[..128]);
        // A block asked for, in the size asked or the largest we use.
        let second = slice(&text, Some(block(1, false, 128)), size(1024)).expect("a value");
        assert_eq!(
            (second.block, second.payload),
            (Some(block(1, true, 128)), &text[128..256])
        );
        let last = slice(&text, Some(block(2, false, 128)), size(1024)).expect("a value");
        assert_eq!(
            (last.block, last.payload),
            (Some(block(2, false, 128)), &text[256..])
        );
        // Our largest is smaller than the size asked: the number counts in ours (§2.4).
        let smaller = slice(&text, Some(block(1, false, 128)), size(64)).expect("a value");
        assert_eq!(
            (smaller.block, smaller.payload),
            (Some(block(2, true, 64)), &text[128..192])
        );
        // Past the end.
        assert_eq!(
            slice(&text, Some(block(3, false, 128)), size(1024)),
            Err(OutOfRange)
        );
    }

    #[test]
    fn reassembly_of_a_body() {
        let text = body(300);
        let mut reassembly = Reassembly::new(1000);
        assert_eq!(
            reassembly.push(block(0, true, 128), &text[..128]),
            Ok(Some(block(1, false, 128)))
        );
        assert_eq!(
            reassembly.push(block(1, true, 128), &text[128..256]),
            Ok(Some(block(2, false, 128)))
        );
        // A block with the more flag short of its size is wrong (§2.2).
        assert!(matches!(
            Reassembly::new(1000).push(block(0, true, 128), &text[..100]),
            Err(ReassemblyError::ShortBlock { .. })
        ));
        assert_eq!(
            reassembly.push(block(2, false, 128), &text[256..]),
            Ok(None)
        );
        assert_eq!(reassembly.into_body(), text);
    }

    // Captured from aiocoap.

    /// The blocks of the transfer as aiocoap asked for them: what we send is the same, option for option.
    fn same_requests(id: &str, played: &crate::util::coap_capture::Played, payload: bool) {
        let capture = capture(id);
        let theirs: Vec<Message> = delivered(&capture, true)
            .iter()
            .map(|d| d.message())
            .collect();
        assert_eq!(played.sent.len(), theirs.len(), "{id}");
        // The first request is the same bytes.
        assert_eq!(
            played.sent[0].to_vec().expect("a value"),
            delivered(&capture, true)[0].bytes,
            "{id}"
        );
        for (ours, theirs) in played.sent.iter().zip(&theirs) {
            let (ours, theirs) = (essence(ours), essence(theirs));
            assert_eq!(
                (&ours.0, &ours.1, &ours.2),
                (&theirs.0, &theirs.1, &theirs.2),
                "{id}"
            );
            if payload {
                assert_eq!(ours.3, theirs.3, "{id}");
            }
        }
    }

    #[test]
    fn captured_get_in_1024_byte_blocks() {
        let played = play("get_block2", Params::default());
        same_requests("get_block2", &played, true);
        assert_eq!(played.result.expect("a value").payload, body(2500));
    }

    #[test]
    fn captured_get_in_64_byte_blocks() {
        let params = params(|p| {
            p.block2_size = Some(size(64));
        });
        let played = play("get_block2_64", params);
        assert_eq!(played.sent.len(), 40);
        same_requests("get_block2_64", &played, true);
        assert_eq!(played.result.expect("a value").payload, body(2500));
    }

    /// The request of an upload capture: its first message holds the first block only.
    fn upload_exchange(
        id: &str,
        params: Params,
        payload: Vec<u8>,
    ) -> crate::util::coap_capture::Played {
        let capture = capture(id);
        let (mut request, first_id) = request_of(&capture);
        request.payload = payload;
        request.options.remove(OptionNumber::SIZE1);
        let now = Instant::now();
        let mut sent = Vec::new();
        let mut step = Exchange::start(request, SERVER, params, first_id, 7, now);
        let mut inbox = delivered(&capture, false).into_iter();
        loop {
            sent.extend(parse_all(&step.send));
            let exchange = match step.next {
                Next::Wait(exchange) => exchange,
                Next::Done(result) => return crate::util::coap_capture::Played { result, sent },
            };
            let datagram = inbox
                .next()
                .expect("the capture has a response for each request");
            let last = sent
                .iter()
                .rev()
                .find(|m| m.kind == Type::Confirmable)
                .expect("a value");
            step = exchange.receive(
                SERVER,
                &crate::util::coap_capture::retarget(datagram, last),
                now,
            );
        }
    }

    #[test]
    fn captured_post_in_1024_byte_blocks() {
        let played = upload_exchange("post_block1", Params::default(), body(2500));
        same_requests("post_block1", &played, true);
        assert_eq!(played.result.expect("a value").code, Code::CHANGED);
    }

    #[test]
    fn captured_post_in_64_byte_blocks() {
        let params = params(|p| {
            p.block1_size = size(64);
        });
        let played = upload_exchange("post_block1_64", params, body(2500));
        assert_eq!(played.sent.len(), 40);
        same_requests("post_block1_64", &played, true);
        assert_eq!(played.result.expect("a value").code, Code::CHANGED);
    }

    #[test]
    fn captured_post_in_blocks_with_a_response_in_blocks() {
        // Figure 10 of the RFC, from a real server: 40 blocks of the request, then 2 more of the response after the first.
        let params = params(|p| {
            p.block1_size = size(64);
        });
        let played = upload_exchange("post_block1_block2", params, body(2500));
        assert_eq!(played.sent.len(), 42);
        same_requests("post_block1_block2", &played, true);
        let response = played.result.expect("a value");
        assert_eq!(response.code, Code::CHANGED);
        assert_eq!(response.payload, body(2500));
    }

    #[test]
    fn captured_fetch_in_64_byte_blocks() {
        // aiocoap asks for the next blocks without the query; we send it again (RFC 8132 §2: it is part of the cache
        // key), so the requests are the same but for the payload.
        let params = params(|p| {
            p.block2_size = Some(size(64));
        });
        let played = play("fetch_doc_block2_64", params);
        same_requests("fetch_doc_block2_64", &played, false);
        assert_eq!(played.sent.len(), 3);
        assert!(played.sent.iter().all(|m| !m.payload.is_empty()));
        assert_eq!(played.result.expect("a value").payload.len(), 161);
    }

    // Captured from libcoap (testdata/coap/capture_libcoap.py).

    /// Real DNS responses over `DoH`, of 2808 and 1280 bytes: longer than a libcoap block.
    const TXT: &[u8] = include_bytes!("../../../testdata/coap/dns_txt.body");
    const DNSKEY: &[u8] = include_bytes!("../../../testdata/coap/dns_dnskey.body");

    /// What the client of libcoap adds to every request and ours does not: the port of the URI (RFC 7252 §5.10.1) and a
    /// Request-Tag (RFC 9175 §3.2).
    const LIBCOAP_EXTRAS: [OptionNumber; 2] = [OptionNumber::URI_PORT, OptionNumber(292)];

    /// The requests of `id`, libcoap's and ours, message by message: kind, code, options but those only libcoap adds,
    /// and the payload if `payload`.
    fn same_as_libcoap(id: &str, played: &crate::util::coap_capture::Played, payload: bool) {
        let capture = capture(id);
        let theirs: Vec<Message> = delivered(&capture, true)
            .iter()
            .map(|d| d.message())
            .collect();
        assert_eq!(played.sent.len(), theirs.len(), "{id}");
        for (n, (ours, theirs)) in played.sent.iter().zip(&theirs).enumerate() {
            let (mut ours, mut theirs) = (essence(ours), essence(theirs));
            for side in [&mut ours, &mut theirs] {
                side.2.retain(|(number, _)| {
                    !LIBCOAP_EXTRAS.contains(number) && *number != OptionNumber::SIZE1
                });
                if !payload {
                    side.3.clear();
                }
            }
            assert_eq!(ours, theirs, "{id}, request {n}");
        }
    }

    #[test]
    fn libcoap_get_in_1024_byte_blocks() {
        // libcoap blocks a body of 2808 bytes by itself, with an ETag and Size2 (RFC 7959 §2.4, §4).
        let played = play("libcoap_get_block2", Params::default());
        same_as_libcoap("libcoap_get_block2", &played, true);
        assert_eq!(played.sent.len(), 3);
        assert_eq!(played.result.expect("a value").payload, TXT);
    }

    #[test]
    fn libcoap_get_in_64_byte_blocks() {
        let params = params(|p| {
            p.block2_size = Some(size(64));
        });
        let played = play("libcoap_get_block2_64", params);
        same_as_libcoap("libcoap_get_block2_64", &played, true);
        assert_eq!(played.sent.len(), 44);
        assert_eq!(played.result.expect("a value").payload, TXT);
    }

    /// The exchange of `libcoap_get_block2`, waiting for its first block, and its three blocks as separate responses
    /// of `kind` (RFC 7252 §5.2.2, §5.2.3): libcoap's piggybacked ones, with the message IDs of the server from that of
    /// its separate CON in `libcoap_get_async` on.
    fn separate_blocks(kind: Type) -> (Next, Vec<Message>) {
        let transfer = capture("libcoap_get_block2");
        let (request, first_id) = request_of(&transfer);
        let token = request.token;
        let first = capture("libcoap_get_async")
            .iter()
            .map(crate::util::coap_capture::Datagram::message)
            .find(|m| m.kind == Type::Confirmable && m.code.is_response())
            .expect("the separate CON")
            .id;
        let blocks = delivered(&transfer, false)
            .iter()
            .zip(first..)
            .map(|(datagram, id)| Message {
                kind,
                id,
                token,
                ..datagram.message()
            })
            .collect();
        let step = Exchange::start(
            request,
            SERVER,
            Params::default(),
            first_id,
            5,
            Instant::now(),
        );
        (step.next, blocks)
    }

    /// Gives the exchange waiting in `next` the `blocks` in order, a step each, until it is over: what each step sent,
    /// and the next of the last.
    fn give(mut next: Next, blocks: &[&Message]) -> (Vec<Vec<Message>>, Next) {
        let mut sent = Vec::new();
        for block in blocks {
            let Next::Wait(exchange) = next else {
                break;
            };
            let wire = block.to_vec().expect("a value");
            let step = exchange.receive(SERVER, &wire, Instant::now());
            sent.push(parse_all(&step.send));
            next = step.next;
        }
        (sent, next)
    }

    #[test]
    fn a_repeated_separate_block_is_acked_and_ignored() {
        // Our ACK of block 0 was lost; block 1 came, then the server sent block 0 again (RFC 7252 §4.2): it is ACKed
        // again and not taken again (§4.5).
        let (start, blocks) = separate_blocks(Type::Confirmable);
        let (sent, next) = give(start, &[&blocks[0], &blocks[1], &blocks[0], &blocks[2]]);
        assert_eq!(sent.len(), 4, "over before the last block: {next:?}");
        assert_eq!(
            sent[2],
            [Message::empty(Type::Acknowledgement, blocks[0].id)]
        );
        let Next::Done(result) = next else {
            panic!("the exchange is over");
        };
        assert_eq!(result.expect("a response").payload, TXT);
    }

    #[test]
    fn a_duplicated_non_block_is_ignored() {
        // The network delivered the NON of block 0 twice, the second after block 1 (RFC 7252 §4.5).
        let (start, blocks) = separate_blocks(Type::NonConfirmable);
        let (sent, next) = give(start, &[&blocks[0], &blocks[1], &blocks[0], &blocks[2]]);
        assert_eq!(sent.len(), 4, "over before the last block: {next:?}");
        assert_eq!(sent[2], []);
        let Next::Done(result) = next else {
            panic!("the exchange is over");
        };
        assert_eq!(result.expect("a response").payload, TXT);
    }

    #[test]
    fn libcoap_fetch_in_1024_byte_blocks() {
        // libcoap's client asks for the next blocks without the query; we send it again (RFC 8132 §2), so the requests
        // are the same but for the payload.
        let played = play("libcoap_fetch_doc_block2", Params::default());
        same_as_libcoap("libcoap_fetch_doc_block2", &played, false);
        assert!(played.sent.iter().all(|m| !m.payload.is_empty()));
        let response = played.result.expect("a value");
        assert_eq!(response.payload, TXT);
        assert_eq!(response.options.content_format(), Some(553));
    }

    #[test]
    fn libcoap_put_in_64_byte_blocks_gets_continue_then_created() {
        // 2.31 Continue for each block but the last, 2.01 Created for it (RFC 7959 §2.9.1, RFC 7252 §5.9.1.1).
        let params = params(|p| {
            p.block1_size = size(64);
        });
        let played = upload_exchange("libcoap_put_block1_64", params, DNSKEY.to_vec());
        same_as_libcoap("libcoap_put_block1_64", &played, true);
        assert_eq!(played.sent.len(), 20);
        assert_eq!(played.result.expect("a value").code, Code::CREATED);
    }
}

mod fetch {
    //! FETCH (RFC 8132 §2) as DNS over CoAP uses it (RFC 9953 §3.2, §4.2): the request a query makes, captured from
    //! aiocoap (`testdata/coap/capture.py`), and the `docpath` of an SVCB record as its path.

    use std::time::Instant;

    use dedens_net::coap::block::{Block, BlockSize};
    use dedens_net::coap::exchange::{Exchange, Next, Params};
    use dedens_net::coap::{Code, Message, OptionNumber, Token, dns};
    use dedens_proto::rdata::{SvcParam, SvcParams};

    use crate::util::coap_capture::{SERVER, capture, delivered, play, request_of};

    const QUERY: &[u8] = include_bytes!("../../../testdata/doh/quad9_mx.query");
    const ANSWER: &[u8] = include_bytes!("../../../testdata/doh/quad9_mx.body");

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
            &crate::util::coap_capture::retarget(
                reply,
                &Message::parse(&step.send[0]).expect("a value"),
            ),
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
        let params =
            SvcParams::new(vec![SvcParam::DocPath(segments(&["n", "s"]))]).expect("a value");
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
}

mod link_format {
    //! The `CoRE` Link Format (RFC 6690): the examples of §5, the attributes of §2 and §3, and the path a link names on the
    //! server that sent it (D95).

    use std::net::SocketAddr;

    use dedens_net::coap::link::{Link, LinkError, parse};

    const SERVER: &str = "192.0.2.1:5683";

    fn server() -> SocketAddr {
        SERVER.parse().expect("a value")
    }

    fn links(payload: &str) -> Vec<Link> {
        parse(payload.as_bytes()).expect("a value")
    }

    fn targets(payload: &str) -> Vec<String> {
        links(payload).into_iter().map(|link| link.target).collect()
    }

    /// The path a link names, as text.
    fn path(target: &str) -> Result<String, LinkError> {
        let link = Link {
            target: target.to_owned(),
            anchored: false,
            rel: Vec::new(),
            rt: Vec::new(),
            ct: Vec::new(),
        };
        link.path(server()).map(|path| {
            path.iter().fold(String::new(), |text, segment| {
                text + "/" + &String::from_utf8_lossy(segment)
            })
        })
    }

    /// RFC 6690 §5.1: two links, one per line.
    #[test]
    fn the_links_of_a_listing_per_line_are_read() {
        let text = "</sensors/temp>;if=\"sensor\",\n</sensors/light>;if=\"sensor\"";
        assert_eq!(targets(text), ["/sensors/temp", "/sensors/light"]);
        assert_eq!(
            targets("</sensors/temp>;if=\"sensor\",</sensors/light>;if=\"sensor\""),
            ["/sensors/temp", "/sensors/light"]
        );
    }

    /// RFC 6690 §5.2: a link with a content format.
    #[test]
    fn the_content_format_of_a_link_is_read() {
        let [link] = links("</sensors>;ct=40").try_into().expect("a value");
        assert_eq!(link.ct, [40]);
        assert_eq!(link.rt.len(), 0);
    }

    /// RFC 6690 §5.3: the resource type of each link.
    #[test]
    fn the_resource_types_of_links_are_read() {
        let text = "</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\n</sensors/light>;rt=\"light-lux\";if=\"sensor\"";
        let found = links(text);
        assert_eq!(found[0].rt, ["temperature-c"]);
        assert_eq!(found[1].rt, ["light-lux"]);
    }

    /// RFC 6690 §5.4 and §3.1: an `rt` has several values, each a type.
    #[test]
    fn several_resource_types_in_one_value_are_read() {
        let [link] = links("</sensors/light>;rt=\"light-lux core.sen-light\";if=\"sensor\"")
            .try_into()
            .expect("a value");
        assert_eq!(link.rt, ["light-lux", "core.sen-light"]);
    }

    /// RFC 6690 §5.5: a whole listing, with a title, an anchor and a `rel`; the links with an anchor are not the server's.
    #[test]
    fn a_whole_listing_with_anchors_is_read() {
        let text = "</sensors>;ct=40;title=\"Sensor Index\",\n\
                    </sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\n\
                    </sensors/light>;rt=\"light-lux\";if=\"sensor\",\n\
                    <http://www.example.com/sensors/t123>;anchor=\"/sensors/temp\"\n\
                    ;rel=\"describedby\",\n\
                    </t>;anchor=\"/sensors/temp\";rel=\"alternate\"";
        let found = links(text);
        assert_eq!(found.len(), 5);
        assert_eq!(found[0].ct, [40]);
        assert_eq!(
            found.iter().map(Link::hosted).collect::<Vec<_>>(),
            [true, true, true, false, false]
        );
        assert_eq!(found[3].rel, ["describedby"]);
        assert_eq!(found[4].rel, ["alternate"]);
    }

    /// RFC 6690 §5.6: a size, which a client does not use and reads over.
    #[test]
    fn a_size_is_read_over() {
        let [link] = links("</firmware/v2.1>;rt=\"firmware\";sz=262144")
            .try_into()
            .expect("a value");
        assert_eq!(link.rt, ["firmware"]);
        assert_eq!(link.target, "/firmware/v2.1");
    }

    /// RFC 6690 §4: a server with no resource answers an empty payload.
    #[test]
    fn an_empty_payload_has_no_links() {
        assert_eq!(links("").len(), 0);
        assert_eq!(links(" \n").len(), 0);
    }

    /// RFC 6690 §2.2: a link with no `rel` has the relation `hosts`, one with another has not.
    #[test]
    fn a_link_hosts_unless_another_relation_or_an_anchor_says_not() {
        let found = links("</a>,</b>;rel=\"hosts\",</c>;rel=\"item\",</d>;anchor=\"/e\"");
        assert_eq!(
            found.iter().map(Link::hosted).collect::<Vec<_>>(),
            [true, true, false, false]
        );
    }

    /// RFC 6690 §3.1, §3.2, §3.3 and RFC 7252 §7.2.1: an attribute given once is not given twice.
    #[test]
    fn an_attribute_given_twice_is_refused() {
        for (text, name) in [
            ("</a>;rt=\"x\";rt=\"y\"", "rt"),
            ("</a>;if=\"x\";if=\"y\"", "if"),
            ("</a>;sz=1;sz=2", "sz"),
            ("</a>;ct=40;ct=41", "ct"),
        ] {
            assert_eq!(parse(text.as_bytes()), Err(LinkError::Repeated(name)));
        }
    }

    /// RFC 8288 §3.3: the first `rel` of a link is the one read.
    #[test]
    fn the_first_of_several_rel_is_read() {
        let [link] = links("</a>;rel=\"item\";rel=\"hosts\"")
            .try_into()
            .expect("a value");
        assert_eq!(link.rel, ["item"]);
    }

    /// RFC 6690 §2: what leaves the grammar is refused with its place.
    #[test]
    fn what_is_outside_the_grammar_is_refused() {
        for text in [
            "/a",
            "</a",
            "</a>;",
            "</a>;rt",
            "</a>;rt=",
            "</a>;rt=\"x",
            "</a>,",
            "</a> </b>",
            "</a>;ct=040",
            "</a>;sz=-1",
            "</a>;ct=65536",
            "</a>;rt=\"x  y\"",
        ] {
            assert!(parse(text.as_bytes()).is_err(), "{text:?} is accepted");
        }
        assert_eq!(parse(&[0xFF]), Err(LinkError::NotUtf8));
    }

    /// RFC 6690 §2.1: an attribute the reader does not know is checked and dropped; a quoted value has its escapes undone.
    #[test]
    fn an_unknown_attribute_is_dropped() {
        let [link] = links("</a>;title=\"a \\\"b\\\"\";obs;rt=\"core.dns\"")
            .try_into()
            .expect("a value");
        assert_eq!(link.rt, ["core.dns"]);
    }

    /// RFC 6690 §2.1: attribute names have no case.
    #[test]
    fn attribute_names_have_no_case() {
        let [link] = links("</a>;RT=\"core.dns\";CT=553")
            .try_into()
            .expect("a value");
        assert_eq!(link.rt, ["core.dns"]);
        assert_eq!(link.ct, [553]);
    }

    /// RFC 6690 §4 and RFC 3986 §5.2: a target resolves against `coap://server/.well-known/core`.
    #[test]
    fn a_target_resolves_against_the_well_known_uri() {
        assert_eq!(path("/dns/query").as_deref(), Ok("/dns/query"));
        assert_eq!(path("/").as_deref(), Ok(""));
        assert_eq!(path("dns").as_deref(), Ok("/.well-known/dns"));
        assert_eq!(path("../dns").as_deref(), Ok("/dns"));
        assert_eq!(path("/a/./b/../c").as_deref(), Ok("/a/c"));
        assert_eq!(
            path("coap://192.0.2.1/dns").as_deref(),
            Ok("/dns"),
            "the default port is the server's"
        );
        assert_eq!(path("coap://192.0.2.1:5683/dns").as_deref(), Ok("/dns"));
        assert_eq!(path("//192.0.2.1:5683/dns").as_deref(), Ok("/dns"));
    }

    /// RFC 7252 §6.4: the segments of a path are the bytes their percent-encodings stand for; the dot segments are removed
    /// before (RFC 3986 §6.2.2.2), and an encoded `/` is a byte of a segment, not a delimiter.
    #[test]
    fn a_target_is_percent_decoded_by_segment() {
        assert_eq!(path("/d%20ns/%C3%A9").as_deref(), Ok("/d ns/é"));
        assert_eq!(path("/a%2Fb/c").as_deref(), Ok("/a/b/c"), "shown as text");
        let link = Link {
            target: "/a%2Fb/c".to_owned(),
            anchored: false,
            rel: Vec::new(),
            rt: Vec::new(),
            ct: Vec::new(),
        };
        let segments = link.path(server()).expect("a value");
        assert_eq!(segments.len(), 2);
        assert_eq!(&*segments[0], b"a/b");
        assert_eq!(path("/%41").as_deref(), Ok("/A"));
    }

    /// A client acts on a link only for the server that sent it: another host, port or scheme is refused, as is a query, a
    /// fragment, a percent-encoding that is no byte and one that makes a dot segment (RFC 7252 §5.10.1).
    #[test]
    fn a_target_that_is_not_a_path_on_the_server_is_refused() {
        for target in [
            "coap://192.0.2.2/dns",
            "coap://192.0.2.1:5684/dns",
            "coap://dns.example/dns",
            "//192.0.2.2/dns",
            "coaps://192.0.2.1/dns",
            "http://192.0.2.1/dns",
            "/dns?dns=x",
            "/dns#x",
            "/%zz",
            "/a/%2",
            "/%2E%2e",
            "/a/%2e",
        ] {
            assert!(
                matches!(path(target), Err(LinkError::Target { .. })),
                "{target} is accepted"
            );
        }
    }

    /// RFC 6690 §2: an error tells the byte where the text leaves the grammar.
    #[test]
    fn a_syntax_error_tells_the_byte_it_is_at() {
        for (text, at) in [
            ("/a", 0),
            ("</a> </b>", 5),
            ("</a>;rt=\"x", 10),
            ("</a>,", 5),
        ] {
            assert!(
                matches!(parse(text.as_bytes()), Err(LinkError::Syntax { at: found, .. }) if found == at),
                "{text:?}: {:?}",
                parse(text.as_bytes())
            );
        }
    }

    /// RFC 3986 §3.1: a scheme is a letter, then letters, digits, `+`, `-` and `.`: a colon after anything else is in a
    /// path.
    #[test]
    fn a_colon_after_a_path_character_is_no_scheme() {
        assert_eq!(path("dns/a:b").as_deref(), Ok("/.well-known/dns/a:b"));
        assert_eq!(path("1a:b").as_deref(), Ok("/.well-known/1a:b"));
        assert_eq!(path("a b:c").as_deref(), Ok("/.well-known/a b:c"));
    }
}

#[cfg(feature = "doc")]
mod client {
    //! DNS over CoAP (RFC 9953), against a scripted CoAP server on the loopback address: the request a query makes (§4.1,
    //! §4.2), the response and its Max-Age (§4.3), what the client does with an error (§4.3.1), and the discovery of the
    //! resource (§3.1, D95). The server's side of
    //! the protocol, and the requests as aiocoap sends them, are tested with RFC 8132 and RFC 7959 (`fetch`,
    //! `blockwise`).

    use std::cell::RefCell;
    use std::net::SocketAddr;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use compio::BufResult;
    use compio::net::UdpSocket;
    use dedens_net::client::{Client, ClientError, Server};
    use dedens_net::coap::block::{Block, BlockSize, slice};
    use dedens_net::coap::dns::{
        Query, add_max_age, discovery, etag, more_blocks, path_segments, query as doc_query,
        response, take_max_age,
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
                elapsed >= options.timeout
                    && elapsed < options.timeout + Duration::from_millis(500),
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
}
