//! Builders shared by the server tests: a forwarder, captured upstream responses, and a driver that plays the
//! transport.

#![allow(dead_code, reason = "each test file uses part of the helpers")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::validator::{Limits, Validator};
use dedens_proto::{Flags, Message, Name, Rcode, RecordType};
use dedens_server::{Forward, Pipeline, Stage, Step, Transport, Validating};

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
        Forward::new(servers()).expect("servers"),
    )])
}

/// A pipeline with a cache of the default settings, then forwarding to [`servers`].
pub(crate) fn caching() -> Pipeline {
    Pipeline::new(vec![
        Stage::Cache(Arc::new(
            Cache::new(Config::default()).expect("the default settings"),
        )),
        Stage::Forward(Forward::new(servers()).expect("servers")),
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
                asked.push(upstream.server().addr);
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

/// The captured responses of `dedens-dnssec` (its `testdata/README.md`), by the question each answers: the upstream
/// of the validation tests.
pub(crate) struct Captures(HashMap<(Name<'static>, RecordType), Vec<u8>>);

impl Captures {
    pub(crate) fn new() -> Self {
        let dir = format!(
            "{}/../dedens-dnssec/tests/testdata",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut all = HashMap::new();
        for entry in std::fs::read_dir(dir).expect("the captures") {
            let path = entry.expect("an entry").path();
            if path.extension().is_some_and(|extension| extension == "bin") {
                let wire = std::fs::read(&path).expect("a capture");
                let message = decode(&wire).into_owned();
                let question = message.questions.first().expect("a question");
                all.insert((question.name.clone(), question.qtype), wire);
            }
        }
        Self(all)
    }

    /// The capture `id`, as `testdata/README.md` names it.
    /// The same captures, `wire` answering its question instead of the one captured.
    pub(crate) fn with(mut self, wire: Vec<u8>) -> Self {
        let message = decode(&wire).into_owned();
        let question = message.questions.first().expect("a question");
        self.0.insert((question.name.clone(), question.qtype), wire);
        self
    }

    /// The same captures without the answer to `name` and `qtype`: upstream stays silent.
    pub(crate) fn without(mut self, name: &str, qtype: RecordType) -> Self {
        self.0.remove(&(dns(name), qtype));
        self
    }

    pub(crate) fn get(id: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../dedens-dnssec/tests/testdata/{id}.bin",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("a capture")
    }

    fn answer(&self, request: &Message<'_>) -> Option<&[u8]> {
        let question = request.questions.first()?;
        self.0
            .get(&(question.name.clone().into_owned(), question.qtype))
            .map(Vec::as_slice)
    }
}

/// The Unix time of the capture run: when the signatures are valid.
pub(crate) fn captured_at() -> u64 {
    std::fs::read_to_string(format!(
        "{}/../dedens-dnssec/tests/testdata/captured_at",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("captured_at")
    .trim()
    .parse()
    .expect("Unix time in seconds")
}

/// A pipeline with a cache, then forwarding to [`servers`] and validating against the root's trust anchor at
/// [`captured_at`].
pub(crate) fn validating() -> Pipeline {
    validating_with(TrustAnchors::root())
}

/// [`validating`] with `anchors`.
pub(crate) fn validating_with(anchors: TrustAnchors) -> Pipeline {
    let validator = Validator::new(anchors, Limits::default());
    let clock = std::sync::Arc::new(captured_at);
    Pipeline::new(vec![
        Stage::Cache(Arc::new(
            Cache::new(Config::default()).expect("the default settings"),
        )),
        Stage::Forward(
            Forward::new(servers())
                .expect("servers")
                .validating(Validating::new(validator, clock)),
        ),
    ])
}

/// [`run_at`] with upstream answering each request from `captures`, by its question: nothing for a question it
/// has no capture of.
pub(crate) fn run_captured(
    pipeline: &Pipeline,
    query: &[u8],
    now: u32,
    captures: &Captures,
) -> Run {
    run_captured_without(pipeline, query, now, captures, None)
}

/// [`run_captured`] with the server at `dead`, if any, answering nothing.
pub(crate) fn run_captured_without(
    pipeline: &Pipeline,
    query: &[u8],
    now: u32,
    captures: &Captures,
    dead: Option<SocketAddr>,
) -> Run {
    let mut out = vec![0; 65535];
    let mut asked = Vec::new();
    let mut requests = Vec::new();
    let mut sent = None;
    let mut step = pipeline.query(query, Transport::Udp, now, &mut out);
    let reply = loop {
        match step {
            Step::Reply(len) => break Some(out[..len].to_vec()),
            Step::Drop => break sent,
            Step::Refresh(len, upstream) => {
                sent = Some(out[..len].to_vec());
                step = Step::Upstream(upstream);
            }
            Step::Upstream(upstream) => {
                asked.push(upstream.server().addr);
                let request = upstream.request();
                let response = captures
                    .answer(&request)
                    .filter(|_| dead != Some(upstream.server().addr));
                requests.push(request);
                assert!(requests.len() < 200, "the query asks for ever");
                step = pipeline.receive(upstream, response, now, &mut out);
            }
        }
    };
    Run {
        asked,
        requests,
        reply,
    }
}

/// A query for `name` and `qtype` with RD, the client's `flags` and EDNS with DO set as `dnssec`.
pub(crate) fn client_query(name: &str, qtype: RecordType, flags: Flags, dnssec: bool) -> Vec<u8> {
    let mut query = Message::query(7, dedens_proto::Question::new(dns(name), qtype));
    query.header.flags = Flags::RD | flags;
    query.edns = Some(dedens_proto::Edns {
        flags: if dnssec {
            dedens_proto::EdnsFlags::DO
        } else {
            dedens_proto::EdnsFlags::default()
        },
        ..dedens_proto::Edns::default()
    });
    wire(&query)
}
