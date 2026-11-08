//! Targets of dedens-net's CoAP (RFC 7252) and `DoC` (D81): datagrams, a client exchange against the `dedensd`
//! listener, and the `CoRE` Link Format of discovery.

use std::net::SocketAddr;

use dedens_net::coap::block::{Block, BlockSize, slice};
use dedens_net::coap::exchange::{Exchange, Params, Request};
use dedens_net::coap::{Code, MAX_OPTIONS, Message as CoapMessage};

mod doc;
mod link_format;

pub use doc::coap_doc;
pub use link_format::parse_link_format;

/// A CoAP datagram (RFC 7252 §3) read, written back and read again, and given to a client exchange as the
/// response, with the Block option read from it and a body sliced by it: never a panic, and what is read is
/// written as a message that reads the same.
///
/// # Panics
///
/// On a bug in the codec.
pub fn parse_coap(data: &[u8]) {
    let Ok(message) = CoapMessage::parse(data) else {
        return;
    };
    assert!(
        message.options.iter().count() <= MAX_OPTIONS,
        "more options than the cap"
    );
    let wire = message.to_vec().expect("a message that was read writes");
    assert_eq!(
        CoapMessage::parse(&wire).as_ref(),
        Ok(&message),
        "read back differently"
    );
    let _ = message.unknown_critical().count();
    let _ = (message.options.block1(), message.options.block2());
    let _ = (
        message.options.content_format(),
        message.options.accept(),
        message.options.max_age(),
        message.options.size1(),
        message.options.size2(),
    );
    // As the response to a request of that token and message ID, so that the exchange takes it for its own.
    let server = SocketAddr::from(([127, 0, 0, 1], 5683));
    let request = Request {
        code: Code::FETCH,
        options: dedens_net::coap::Options::new(),
        payload: data.to_vec(),
        token: message.token,
    };
    let now = std::time::Instant::now();
    let step = Exchange::start(request, server, Params::default(), message.id, 1, now);
    if let dedens_net::coap::exchange::Next::Wait(exchange) = step.next {
        let _ = exchange.receive(server, data, now);
    }
    let body = [0_u8; 3000];
    let requested = message.options.block2().ok().flatten();
    if let Ok(sliced) = slice(&body, requested, BlockSize::MAX) {
        assert!(sliced.payload.len() <= BlockSize::MAX.bytes());
    }
    let value = message.payload.get(..3).unwrap_or(&message.payload);
    if let Ok(block) = Block::from_value(value) {
        assert_eq!(Block::from_value(&block.to_value()), Ok(block));
    }
}
