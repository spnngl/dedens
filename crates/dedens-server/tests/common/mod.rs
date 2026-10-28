//! Builders shared by the server tests: a forwarder, captured upstream responses, and a driver that plays the
//! transport.

#![allow(dead_code, reason = "each test file uses part of the helpers")]

use std::net::SocketAddr;

use dedens_cache::{Cache, Config};
use dedens_proto::{Flags, Message, Name, Rcode};
use dedens_server::{Forward, Pipeline, Stage, Step, Transport};

/// The upstream servers of [`forwarder`], in order.
pub(crate) fn servers() -> Vec<SocketAddr> {
    ["192.0.2.1:53", "192.0.2.2:53"]
        .iter()
        .map(|s| s.parse().expect("an address"))
        .collect()
}

/// A pipeline forwarding to [`servers`].
pub(crate) fn forwarder() -> Pipeline {
    Pipeline::new(vec![Stage::Forward(
        Forward::new(&servers()).expect("servers"),
    )])
}

/// A pipeline with a cache of the default settings, then forwarding to [`servers`].
pub(crate) fn caching() -> Pipeline {
    Pipeline::new(vec![
        Stage::Cache(Cache::new(Config::default()).expect("the default settings")),
        Stage::Forward(Forward::new(&servers()).expect("servers")),
    ])
}

pub(crate) fn dns(text: &str) -> Name<'static> {
    Name::from_labels(text.split('.').filter(|l| !l.is_empty()).map(str::as_bytes))
        .expect("a valid name")
}

/// A response captured from a real server, in `crates/dedens-proto/tests/testdata`.
pub(crate) fn captured(case: &str) -> Vec<u8> {
    let path = format!(
        "{}/../dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("a captured response")
}

/// `response` with its header flags also holding `flags`.
pub(crate) fn with_flags(mut response: Vec<u8>, flags: Flags) -> Vec<u8> {
    let [hi, lo] = flags.bits().to_be_bytes();
    response[2] |= hi;
    response[3] |= lo;
    response
}

/// `response` with the header rcode `rcode`, below 16.
pub(crate) fn with_rcode(mut response: Vec<u8>, rcode: Rcode) -> Vec<u8> {
    let low = u8::try_from(rcode.0).expect("a header rcode");
    response[3] = (response[3] & 0xF0) | low;
    response
}

/// The query `response` answers: its question, RD set, EDNS with the default payload, ID 7.
pub(crate) fn query_for(response: &[u8]) -> Message<'static> {
    let question = Message::decode(response)
        .expect("a captured response decodes")
        .message
        .questions
        .swap_remove(0)
        .into_owned();
    Message::query(7, question)
}

pub(crate) fn wire(message: &Message<'_>) -> Vec<u8> {
    message.to_vec().expect("the message fits")
}

pub(crate) fn decode(wire: &[u8]) -> Message<'_> {
    let decoded = Message::decode(wire).expect("the reply decodes");
    assert_eq!(decoded.violations, [], "the reply breaks no rule");
    decoded.message
}

/// What a query came to: the servers asked, in order, the requests sent them, and the reply, `None` when dropped.
#[derive(Debug)]
pub(crate) struct Run {
    pub(crate) asked: Vec<SocketAddr>,
    pub(crate) requests: Vec<Message<'static>>,
    pub(crate) reply: Option<Vec<u8>>,
}

/// Runs `query` through `pipeline` as if it came over `transport`, the upstream servers answering in turn with
/// `responses`, `None` for no response; once they are used up, no more responses come.
pub(crate) fn run(
    pipeline: &Pipeline,
    query: &[u8],
    transport: Transport,
    responses: &[Option<&[u8]>],
) -> Run {
    run_at(pipeline, query, transport, 0, responses)
}

/// [`run`] at `now`. A reply sent before a refresh is the reply; the refresh must end without one.
pub(crate) fn run_at(
    pipeline: &Pipeline,
    query: &[u8],
    transport: Transport,
    now: u32,
    responses: &[Option<&[u8]>],
) -> Run {
    let mut out = vec![0; 65535];
    let mut responses = responses.iter().copied();
    let mut asked = Vec::new();
    let mut requests = Vec::new();
    let mut sent = None;
    let mut step = pipeline.query(query, transport, now, &mut out);
    let reply = loop {
        match step {
            Step::Reply(len) => {
                assert_eq!(sent, None, "a refresh replies");
                break Some(out[..len].to_vec());
            }
            Step::Drop => break sent,
            Step::Refresh(len, upstream) => {
                sent = Some(out[..len].to_vec());
                step = Step::Upstream(upstream);
            }
            Step::Upstream(upstream) => {
                asked.push(upstream.server());
                requests.push(upstream.request().clone());
                step = pipeline.receive(upstream, responses.next().flatten(), now, &mut out);
            }
        }
    };
    Run {
        asked,
        requests,
        reply,
    }
}

/// The reply of a query that goes no further than the core, or the first server's answer.
pub(crate) fn reply(
    pipeline: &Pipeline,
    query: &[u8],
    transport: Transport,
    response: Option<&[u8]>,
) -> Vec<u8> {
    run(pipeline, query, transport, &[response])
        .reply
        .expect("a reply")
}
