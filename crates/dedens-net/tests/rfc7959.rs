//! Block-wise transfers (RFC 7959): the Block option value of §2.2, the exchanges of §3 driven by hand, and
//! multi-block exchanges captured from aiocoap (tests/testdata/coap/capture.py).

mod coap_capture;

use std::time::Instant;

use coap_capture::{SERVER, capture, delivered, essence, play, request_of};
use dedens_net::coap::block::{
    Block, BlockError, BlockSize, OutOfRange, Reassembly, ReassemblyError, slice,
};
use dedens_net::coap::exchange::{Exchange, Failure, Next, Params, Request};
use dedens_net::coap::{Code, Message, OptionNumber, Options, Token, Type};

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
fn same_requests(id: &str, played: &coap_capture::Played, payload: bool) {
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
fn upload_exchange(id: &str, params: Params) -> coap_capture::Played {
    let capture = capture(id);
    let (mut request, first_id) = request_of(&capture);
    request.payload = body(2500);
    request.options.remove(OptionNumber::SIZE1);
    let now = Instant::now();
    let mut sent = Vec::new();
    let mut step = Exchange::start(request, SERVER, params, first_id, 7, now);
    let mut inbox = delivered(&capture, false).into_iter();
    loop {
        sent.extend(parse_all(&step.send));
        let exchange = match step.next {
            Next::Wait(exchange) => exchange,
            Next::Done(result) => return coap_capture::Played { result, sent },
        };
        let datagram = inbox
            .next()
            .expect("the capture has a response for each request");
        let last = sent
            .iter()
            .rev()
            .find(|m| m.kind == Type::Confirmable)
            .expect("a value");
        step = exchange.receive(SERVER, &coap_capture::retarget(datagram, last), now);
    }
}

#[test]
fn captured_post_in_1024_byte_blocks() {
    let played = upload_exchange("post_block1", Params::default());
    same_requests("post_block1", &played, true);
    assert_eq!(played.result.expect("a value").code, Code::CHANGED);
}

#[test]
fn captured_post_in_64_byte_blocks() {
    let params = params(|p| {
        p.block1_size = size(64);
    });
    let played = upload_exchange("post_block1_64", params);
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
    let played = upload_exchange("post_block1_block2", params);
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
