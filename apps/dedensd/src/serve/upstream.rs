//! A query asked upstream (D42): each server in turn over its transport (D65, D84, D99, D185), a question in flight
//! shared with the queries asking it (D86), expired data once the client response timer runs out (RFC 8767 §5).

#![deny(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::rustls::pki_types::ServerName;
use dedens_net::client::{ClientError, Server};
use dedens_net::exchange::{Options, Response};
use dedens_net::io::Io;
use dedens_net::tcp::frame;
use dedens_proto::{Message, Transport};
use dedens_server::{Parked, Pipeline, Resolving, Step, Upstream, Via};

use super::{Thread, pause, recurse};
use crate::flights::{Entered, Flights, Key, Lead};

/// What a query asks upstream: now, or once the validation allowance admits it (D186), or the authoritative servers
/// (D195).
pub(super) enum Ask {
    Now(Box<Upstream>),
    Parked(Parked),
    Resolve(Box<Resolving>),
}

impl From<Box<Upstream>> for Ask {
    fn from(upstream: Box<Upstream>) -> Self {
        Self::Now(upstream)
    }
}

impl Ask {
    /// `upstream`, from `pipeline`, to ask now, unless queries of `thread` wait for the allowance: it goes behind
    /// them then (D186).
    pub(super) fn after<N: Io>(
        thread: &Thread<N>,
        pipeline: &Pipeline,
        upstream: Box<Upstream>,
    ) -> Self {
        if !thread.parking.waiting() {
            return Self::Now(upstream);
        }
        match pipeline.defer(upstream) {
            Ok(parked) => Self::Parked(parked),
            Err(upstream) => Self::Now(upstream),
        }
    }

    /// The step of a query given up before it is asked, past the thread's upstream queries (D47): SERVFAIL, or the
    /// expired data a query that waited may have (D186), written into `out`.
    pub(super) fn abandon(self, pipeline: &Pipeline, now: u32, out: &mut [u8]) -> Step {
        match self {
            Self::Now(upstream) => pipeline.abandon(&upstream, out),
            Self::Parked(parked) => pipeline.shed(parked, now, out),
            Self::Resolve(resolving) => pipeline.resolved(&resolving, now, out),
        }
    }
}

/// Asks the upstream servers for `ask`, from `pipeline`, in turn, each over its transport ([`target`]), with
/// the forward stage's timeout and tries (D42), and hands `deliver` the replies to send, made in the thread's buffer and copied out
/// ([`copy_out`]): expired data when the client response timer runs out first, resolution going on to refresh the
/// cache (RFC 8767 §5), then the response's unless that went out; none after a prefetch. A query parked waits for
/// the allowance first ([`wait`]), and is given up if it waits too long. A query the recurse stage resolves goes to
/// [`recurse::resolve`].
pub(super) async fn answer<N: Io>(
    thread: &Thread<N>,
    pipeline: &Pipeline,
    ask: impl Into<Ask>,
    transport: Transport,
    mut deliver: impl AsyncFnMut(Vec<u8>),
) {
    // The client response timer runs from the query, the wait for the allowance included.
    let since = thread.io.now();
    let mut upstream = match ask.into() {
        Ask::Now(upstream) => upstream,
        Ask::Resolve(resolving) => {
            // Boxed: its steps would make every forwarded query's future larger.
            return Box::pin(recurse::resolve(
                thread, pipeline, resolving, transport, deliver,
            ))
            .await;
        }
        Ask::Parked(parked) => match wait(thread, pipeline, parked, since).await {
            Ok(upstream) => upstream,
            Err(parked) => {
                if let Some(reply) = given_up(thread, pipeline, parked, transport) {
                    deliver(reply).await;
                }
                return;
            }
        },
    };
    let mut options = Options::default();
    (options.timeout, options.tries) = upstream.patience();
    // A response without EDNS would be stored for clients asking for DNSSEC records (RFC 3225).
    options.edns_fallback = false;
    let mut stale_at = upstream.stale_after().map(|after| since + after);
    loop {
        // A copy: the stale reply below takes `upstream`.
        let server = upstream.server().clone();
        let target;
        (target, options.transport) = self::target(&server, transport);
        // The validator's questions are shared with the queries asking them at the same time (D86).
        let key = upstream.probe().map(|question| Key {
            server: server.clone(),
            udp: transport == Transport::Udp,
            question: question.clone(),
        });
        let fetched = 'ask: {
            let mut exchange = pin!(fetch(
                thread,
                key,
                upstream.request(),
                (&server.via, target),
                &options,
                upstream.random_case(options.transport),
            ));
            if let Some(at) = stale_at {
                // A reborrow: the exchange goes on after the timer.
                if let Ok(fetched) = thread.io.timeout_at(at, exchange.as_mut()).await {
                    break 'ask fetched;
                }
                stale_at = None;
                let stale = {
                    let mut out = thread.scratch.borrow_mut();
                    let len = pipeline.stale(&mut upstream, thread.now(), &mut out);
                    len.and_then(|len| copy_out(&out[..len], transport))
                };
                if let Some(reply) = stale {
                    deliver(reply).await;
                }
            }
            exchange.await
        };
        let (reply, next) = {
            let mut out = thread.scratch.borrow_mut();
            let step = match &fetched {
                Fetched::Own(Ok(response), _) => {
                    pipeline.receive(upstream, Some(&response.wire), thread.now(), &mut out)
                }
                Fetched::Own(Err(error), _) if error.is_local() => {
                    tracing::warn!(%error, %server, "upstream query not sent");
                    pipeline.abandon(&upstream, &mut out)
                }
                Fetched::Own(Err(error), _) => {
                    tracing::debug!(%error, %server, "upstream");
                    pipeline.receive(upstream, None, thread.now(), &mut out)
                }
                Fetched::Shared(wire) => {
                    pipeline.receive(upstream, wire.as_deref(), thread.now(), &mut out)
                }
            };
            match step {
                Step::Reply(len) | Step::Refresh(len, _) => {
                    (copy_out(&out[..len], transport), None)
                }
                // `receive` does not park: the query was admitted; nor does a forward stage resolve.
                Step::Drop | Step::Park(_) | Step::Resolve(_) => (None, None),
                Step::Upstream(next) => (None, Some(next)),
            }
        };
        // After `receive`, which put what the response proved in the key cache, and before the client is
        // written to, which may wait.
        if let Fetched::Own(result, Some(lead)) = fetched {
            match result {
                Ok(response) => lead.finish(Some(&response.wire)),
                Err(error) if !error.is_local() => lead.finish(None),
                // Not sent: the followers ask for themselves.
                Err(_) => drop(lead),
            }
        }
        if let Some(reply) = reply {
            deliver(reply).await;
        }
        let Some(next) = next else {
            return;
        };
        upstream = next;
    }
}

/// Waits in the line of `thread` for the allowance to admit `parked`, from `pipeline` (D186): the query to ask, or
/// `parked` back to give up when [`Parked::wait`] after `since` passes first, or the line has no place left. Only
/// the first of the line asks, once as it comes first and once a second after: the allowance refills at each second
/// of the thread's clock.
async fn wait<N: Io>(
    thread: &Thread<N>,
    pipeline: &Pipeline,
    mut parked: Parked,
    since: Instant,
) -> Result<Box<Upstream>, Parked> {
    let deadline = since + parked.wait();
    let Some(place) = thread.parking.enter() else {
        return Err(parked);
    };
    if thread.io.timeout_at(deadline, place.turn()).await.is_err() {
        return Err(parked);
    }
    loop {
        let now = thread.now();
        parked = match pipeline.unpark(parked, now) {
            Ok(upstream) => return Ok(upstream),
            Err(parked) => parked,
        };
        let next = thread.started + Duration::from_secs(u64::from(now) + 1);
        if next >= deadline {
            return Err(parked);
        }
        pause(&thread.io, next.saturating_duration_since(thread.io.now())).await;
    }
}

/// The reply to `parked`, from `pipeline`, given up (D186), copied out of the thread's buffer.
fn given_up<N: Io>(
    thread: &Thread<N>,
    pipeline: &Pipeline,
    parked: Parked,
    transport: Transport,
) -> Option<Vec<u8>> {
    let mut out = thread.scratch.borrow_mut();
    match pipeline.shed(parked, thread.now(), &mut out) {
        Step::Reply(len) => copy_out(&out[..len], transport),
        _ => None,
    }
}

/// What an upstream question got.
#[expect(
    clippy::large_enum_variant,
    reason = "made once per upstream query and used at once: a box would be an allocation on the forwarding path"
)]
enum Fetched<'a> {
    /// The response, or why there was none, to a query sent by this one; `Some` when others wait for it.
    Own(Result<Response, ClientError>, Option<Lead<'a>>),
    /// The response, bytes only, of the query another sent, or none if that one failed on the server's side.
    Shared(Option<Arc<[u8]>>),
}

/// Sends `request` to `target`, with `0x20` bits from the thread's randomness when `random_case` (D184), unless a
/// query of the same `key` is in flight: then waits for its response, which came back in the case of the question.
async fn fetch<'a, N: Io>(
    thread: &'a Thread<N>,
    key: Option<Key>,
    request: Message<'static>,
    (via, target): (&Via, Server),
    options: &Options,
    random_case: bool,
) -> Fetched<'a> {
    let flights: &Flights = thread.current.flights();
    let mut lead = None;
    if let Some(key) = key {
        match flights.enter(&key).await {
            Entered::Lead(flight) => lead = Some(flight),
            Entered::Shared(response) => return Fetched::Shared(response),
        }
    }
    let mut options = *options;
    if random_case {
        match thread.client.random_case() {
            Ok(bits) => options.random_case = Some(bits),
            Err(error) => return Fetched::Own(Err(error), lead),
        }
    }
    let options = &options;
    let result = match via {
        Via::Dnscrypt { stamp, relays } => {
            exchange_dnscrypt(thread, request, (stamp, relays), options).await
        }
        Via::Odoh { proxy, .. } => {
            exchange_oblivious(thread, request, target, proxy, options).await
        }
        _ => thread.client.exchange(request, target, options).await,
    };
    Fetched::Own(result, lead)
}

/// Asks the `DNSCrypt` server of `stamp`, through the `relays` if there are any, the texts of stamps checked when the
/// configuration was read (D99, D100).
#[cfg(feature = "dnscrypt")]
async fn exchange_dnscrypt<N: Io>(
    thread: &Thread<N>,
    request: Message<'static>,
    (stamp, relays): (&str, &[Arc<str>]),
    options: &Options,
) -> Result<Response, ClientError> {
    use dedens_net::stamp::{Relay, Stamp};

    let Ok(Stamp::DnsCrypt(stamp)) = stamp.parse() else {
        // The configuration holds resolvers' stamps in the text `Stamp` writes.
        return Err(ClientError::NotBuilt("DNSCrypt stamp"));
    };
    let relays: Option<Vec<Relay>> = relays.iter().map(|relay| relay.parse().ok()).collect();
    let Some(relays) = relays else {
        // Nor a relay: a relay is not dropped, which would show the client's address to the resolver.
        return Err(ClientError::NotBuilt("DNSCrypt relay stamp"));
    };
    thread
        .client
        .exchange_dnscrypt_via(request, &stamp, &relays, options)
        .await
}

/// Without the `dnscrypt` feature no configuration holds such a server (D99).
#[cfg(not(feature = "dnscrypt"))]
#[expect(
    clippy::unused_async,
    reason = "the same call as the one built with the feature"
)]
async fn exchange_dnscrypt<N: Io>(
    _thread: &Thread<N>,
    _request: Message<'static>,
    _stamp: (&str, &[Arc<str>]),
    _options: &Options,
) -> Result<Response, ClientError> {
    Err(ClientError::NotBuilt("DNSCrypt"))
}

/// Asks the Oblivious `DoH` `target` through `proxy` (D185): the target's configurations are the thread client's,
/// fetched from the target and kept as D79 says.
#[cfg(feature = "odoh")]
async fn exchange_oblivious<N: Io>(
    thread: &Thread<N>,
    request: Message<'static>,
    target: Server,
    proxy: &dedens_server::OdohProxy,
    options: &Options,
) -> Result<Response, ClientError> {
    let proxy = peer(proxy.addr, proxy.name.as_deref(), Some(&proxy.path));
    thread
        .client
        .exchange_oblivious(request, target, Some(proxy), options)
        .await
}

/// Without the `odoh` feature no configuration holds such a server (D185).
#[cfg(not(feature = "odoh"))]
#[expect(
    clippy::unused_async,
    reason = "the same call as the one built with the feature"
)]
async fn exchange_oblivious<N: Io>(
    _thread: &Thread<N>,
    _request: Message<'static>,
    _target: Server,
    _proxy: &dedens_server::OdohProxy,
    _options: &Options,
) -> Result<Response, ClientError> {
    Err(ClientError::NotBuilt("Oblivious DoH"))
}

/// The server to ask for `server`, and the transport: its own, else UDP for a client over UDP and TCP for a client
/// over a connection (D65); the URI template of an HTTPS one, or an Oblivious `DoH` target, is at its path (D84,
/// D185); a `DNSCrypt` one is asked over the client's, as a plain one (D99). A name and a path were checked when the
/// configuration was read.
fn target(server: &dedens_server::Server, client: Transport) -> (Server, Transport) {
    let (transport, name, path) = match &server.via {
        Via::Plain | Via::Dnscrypt { .. } if client == Transport::Udp => {
            (Transport::Udp, None, None)
        }
        Via::Plain | Via::Dnscrypt { .. } => (Transport::Tcp, None, None),
        Via::Tls(name) => (Transport::Tls, name.as_deref(), None),
        Via::Quic(name) => (Transport::Quic, name.as_deref(), None),
        Via::Https { name, path } => (Transport::Https, name.as_deref(), Some(&**path)),
        Via::Odoh { name, path, .. } => (Transport::Odoh, name.as_deref(), Some(&**path)),
    };
    (peer(server.addr, name, path), transport)
}

/// The server at `addr`, its certificate holding `name`, its URI template at `path` if it is an HTTPS one.
fn peer(addr: SocketAddr, name: Option<&str>, path: Option<&str>) -> Server {
    let name = name
        .and_then(|name| ServerName::try_from(name).ok())
        .map(|name| name.to_owned());
    let mut peer = Server {
        addr,
        name,
        doh: None,
        docpath: Vec::new(),
    };
    if let Some(path) = path {
        peer.doh = peer.template_at(path).ok();
    }
    peer
}

/// The reply `wire`, made in the thread's buffer, copied out to be sent over `transport`: behind its length but
/// over UDP, HTTPS and CoAP. Only its bytes leave the buffer, never those of an earlier reply.
pub(super) fn copy_out(wire: &[u8], transport: Transport) -> Option<Vec<u8>> {
    if matches!(
        transport,
        Transport::Udp | Transport::Https | Transport::Odoh | Transport::Coap
    ) {
        Some(wire.to_vec())
    } else {
        frame(wire)
    }
}

// The tests run sockets and a runtime, which loom's threads and locks cannot drive (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
#[expect(
    clippy::disallowed_methods,
    reason = "the tests run on compio's runtime and sockets"
)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::future::poll_fn;
    use std::net::IpAddr;
    use std::pin::{Pin, pin};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::{Duration, Instant};

    use compio::BufResult;
    use compio::net::UdpSocket;
    use compio::runtime::{Runtime, spawn};
    use dedens_dnssec::{Limits, TrustAnchors, Validator};
    use dedens_net::io::Compio;
    use dedens_net::tls::Trust;
    use dedens_proto::edns::{EdnsOption, InfoCode};
    use dedens_proto::{Message, Rcode, RecordType, Transport};
    use dedens_server::{
        Allowance, Forward, Parked, Pipeline, Server, Stage, Step, Validating, Via,
    };
    use dedens_testkit::dnssec::capture;
    use dedens_testkit::responder::Responder;
    use futures_util::future::{join, join_all};

    use super::{Ask, answer, target};
    use crate::flights::Key;
    use crate::lists::Store;
    use crate::reload::Current;
    use crate::serve::tests::example_com_a;
    use crate::serve::{PARKED, Thread};

    /// D42: a server that fails on our side, here a QUIC one at an unspecified address, which QUIC will not dial,
    /// gives the query up with SERVFAIL, the next server not asked; a server that does not answer passes the query
    /// to the next.
    #[test]
    fn a_local_failure_gives_up_where_a_silent_server_passes_on() {
        let (query, response) = example_com_a();
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let (next, asked) = respond(response, true).await;
            for (first, rcode, asked_next) in [
                ("quic://0.0.0.0", Rcode::SERVFAIL, 0),
                ("192.0.2.1", Rcode::NOERROR, 1),
            ] {
                asked.set(0);
                let stage = format!("servers: ['{first}', '{next}']");
                let reply = forward(&stage, &query).await;
                assert_eq!((reply.rcode(), asked.get()), (rcode, asked_next), "{first}");
            }
        });
    }

    /// D184: a server that sends the question back in a case of its own, here the captured one, is taken for a
    /// forger and its responses dropped, the query failing once the server's time is up, unless the stage turns
    /// `0x20` off; the client gets its question back in its own case either way.
    #[test]
    fn a_server_that_changes_the_case_is_dropped_unless_random_case_is_off() {
        let (mut query, response) = example_com_a();
        // The client's own case, upper, which the captured response does not have.
        let name = Message::decode(&query).expect("decodes").message.questions[0]
            .name
            .wire_len();
        query[12..12 + name].make_ascii_uppercase();
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let (server, asked) = respond(response, false).await;
            for (random_case, rcode) in [(true, Rcode::SERVFAIL), (false, Rcode::NOERROR)] {
                asked.set(0);
                let stage = format!("servers: ['{server}']\n    random_case: {random_case}");
                let reply = forward(&stage, &query).await;
                assert_eq!((reply.rcode(), asked.get()), (rcode, 1), "{random_case}");
                let client = Message::decode(&query).expect("decodes").message;
                let [got] = &reply.questions[..] else {
                    panic!("one question")
                };
                let [asked] = &client.questions[..] else {
                    panic!("one question")
                };
                assert!(got.name.labels().eq(asked.name.labels()), "{random_case}");
            }
        });
    }

    /// A UDP server answering each query with `response`, its ID that of the query and, when `echo`, its question's
    /// name in the query's case: its address and the count of queries it got.
    async fn respond(response: Vec<u8>, echo: bool) -> (std::net::SocketAddr, Rc<Cell<usize>>) {
        let responder = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
        let addr = responder.local_addr().expect("its address");
        let name = Message::decode(&response)
            .expect("decodes")
            .message
            .questions[0]
            .name
            .wire_len();
        let asked = Rc::new(Cell::new(0));
        let counted = Rc::clone(&asked);
        spawn(async move {
            loop {
                let BufResult(received, request) =
                    responder.recv_from(Vec::with_capacity(512)).await;
                let Ok((_, peer)) = received else { return };
                counted.set(counted.get() + 1);
                let mut reply = response.clone();
                reply[..2].copy_from_slice(&request[..2]);
                if echo {
                    reply[12..12 + name].copy_from_slice(&request[12..12 + name]);
                }
                if responder.send_to(reply, peer).await.0.is_err() {
                    return;
                }
            }
        })
        .detach();
        (addr, asked)
    }

    /// The reply of a forward stage configured by `stage`, its lines after `type`, to the UDP client's `query`.
    async fn forward(stage: &str, query: &[u8]) -> Message<'static> {
        let text = format!(
            "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    {stage}\n    timeout_ms: 200\n    tries: 1\n"
        );
        let config =
            crate::config::read(&text, |_| None, &Pipeline::default(), &mut Store::default())
                .expect("read");
        let thread = Thread::new(Arc::new(Current::new(config.pipeline)), 1, Trust::default());
        let pipeline = thread.pipeline();
        let mut out = vec![0; 65535];
        let from = IpAddr::from([127, 0, 0, 1]);
        let Step::Upstream(upstream) =
            pipeline.query(query, Transport::Udp, from, thread.now(), &mut out)
        else {
            panic!("asked upstream")
        };
        let mut replies = Vec::new();
        answer(
            &thread,
            &pipeline,
            upstream,
            Transport::Udp,
            async |reply| {
                replies.push(reply);
            },
        )
        .await;
        let [reply] = &replies[..] else {
            panic!("one reply: {replies:?}")
        };
        Message::decode(reply)
            .expect("decodes")
            .message
            .into_owned()
    }

    /// D86: a flight whose lead fails on our side, here a QUIC server at an unspecified address, lets its follower
    /// ask for itself, which fails the same way, the next server not asked; a lead that failed on the server's side
    /// would hand the follower no response, which passes the question on to the next server. One thread: the QUIC
    /// exchange awaits before it fails, so the second query finds the first's flight.
    #[test]
    fn a_flight_failing_on_our_side_lets_its_follower_ask() {
        let responder = Responder::start(&["root_dnskey"]);
        let response = capture("alg8_a");
        let question = dedens_testkit::message(&response).questions.swap_remove(0);
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let text = format!(
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['quic://0.0.0.0', '{}']\n    timeout_ms: 200\n    tries: 1\n    dnssec: validate\n",
                responder.addr
            );
            let config = crate::config::read(
                &text,
                |_| None,
                &Pipeline::default(),
                &mut Store::default(),
            )
            .expect("read");
            let thread = Thread::new(Arc::new(Current::new(config.pipeline)), 1, Trust::default());
            let pipeline = thread.pipeline();
            let mut out = vec![0; 65535];
            let from = IpAddr::from([127, 0, 0, 1]);
            // Two clients' queries, each at the validator's first question, the root's keys, of the QUIC server.
            let [lead, follower] = [1, 2].map(|id| {
                let query = Message::query(id, question.clone()).to_vec().expect("a query fits");
                let Step::Upstream(upstream) =
                    pipeline.query(&query, Transport::Udp, from, thread.now(), &mut out)
                else {
                    panic!("asked upstream")
                };
                let Step::Upstream(probe) =
                    pipeline.receive(upstream, Some(&response), thread.now(), &mut out)
                else {
                    panic!("the validator asks")
                };
                probe
            });
            let key = Key {
                server: lead.server().clone(),
                udp: true,
                question: lead.probe().expect("the validator's question").clone(),
            };
            let replies = RefCell::new(Vec::new());
            let deliver = async |reply| replies.borrow_mut().push(reply);
            let mut lead = pin!(answer(&thread, &pipeline, lead, Transport::Udp, deliver));
            let mut follower = pin!(answer(&thread, &pipeline, follower, Transport::Udp, deliver));
            // The lead polled once is in its exchange, its flight open: the follower, polled next before anything
            // else runs, follows it.
            assert!(poll_once(lead.as_mut()).await.is_pending());
            assert!(
                poll_once(pin!(thread.current.flights().enter(&key)))
                    .await
                    .is_pending(),
                "the lead's flight is open"
            );
            assert!(poll_once(follower.as_mut()).await.is_pending());
            join(lead, follower).await;
            let replies = replies.take();
            assert_eq!(replies.len(), 2);
            for reply in replies {
                let reply = Message::decode(&reply).expect("decodes").message;
                assert_eq!(reply.rcode(), Rcode::SERVFAIL);
            }
        });
        assert_eq!(responder.asked(".", RecordType::DNSKEY), 0);
    }

    /// A thread whose pipeline forwards to `responder`, validating under `allowance`, its clock the capture's
    /// epoch (every signature is then out of its dates: a query ends bogus at its first check, which is not what
    /// these tests look at).
    fn validating_thread(responder: &Responder, allowance: Allowance) -> Thread<Compio> {
        let validating = Validating::new(
            Validator::new(TrustAnchors::root(), Limits::default()),
            Arc::new(|| 0),
        )
        .allowing(allowance);
        let forward = Forward::new([responder.addr])
            .expect("a server")
            .validating(validating);
        let pipeline = Pipeline::new(vec![Stage::Forward(forward)]);
        Thread::new(Arc::new(Current::new(pipeline)), 1, Trust::default())
    }

    /// The first step of the client's query `id` for the capture `alg8_a` on `thread`.
    fn step(thread: &Thread<Compio>, pipeline: &Pipeline, id: u16) -> Step {
        let question = dedens_testkit::message(&capture("alg8_a"))
            .questions
            .swap_remove(0);
        let query = Message::query(id, question).to_vec().expect("a query fits");
        let mut out = vec![0; 65535];
        let from = IpAddr::from([127, 0, 0, 1]);
        pipeline.query(&query, Transport::Udp, from, thread.now(), &mut out)
    }

    /// The ask of `step`, the step of a query the allowance refused.
    fn parked(step: Step) -> Ask {
        let Step::Park(parked) = step else {
            panic!("parked: {step:?}")
        };
        Ask::Parked(parked)
    }

    /// The ID, extended error and time of each reply `asks` get on `thread`, in the order they are sent.
    async fn replies(
        thread: &Thread<Compio>,
        pipeline: &Pipeline,
        asks: Vec<Ask>,
    ) -> Vec<(u16, Option<InfoCode>, Duration)> {
        let since = Instant::now();
        let replies = RefCell::new(Vec::new());
        let deliver = async |reply: Vec<u8>| {
            let message = Message::decode(&reply).expect("decodes").message;
            let ede =
                message.edns.iter().flat_map(|edns| &edns.options).find_map(
                    |option| match option {
                        EdnsOption::Ede(ede) => Some(ede.code),
                        _ => None,
                    },
                );
            replies
                .borrow_mut()
                .push((message.header.id, ede, since.elapsed()));
        };
        join_all(
            asks.into_iter()
                .map(|ask| answer(thread, pipeline, ask, Transport::Udp, deliver)),
        )
        .await;
        replies.take()
    }

    /// D186: a query the allowance refuses waits on its thread, and is asked once the allowance refills at the
    /// next second of the thread's clock: its reply is the validation's, not Not Ready.
    #[test]
    fn a_query_past_the_allowance_waits_and_is_asked_once_it_refills() {
        // Room for a validation's questions (D106).
        const BURST: u16 = 10;
        let responder = Responder::start(&["alg8_a", "root_dnskey"]);
        let allowance = Allowance {
            per_second: 100,
            burst: BURST.into(),
            ..Allowance::default()
        };
        let thread = validating_thread(&responder, allowance);
        let pipeline = thread.pipeline();
        // The burst, held in flight.
        let held: Vec<Step> = (1..=BURST).map(|id| step(&thread, &pipeline, id)).collect();
        assert!(held.iter().all(|step| matches!(step, Step::Upstream(_))));
        let waiting = parked(step(&thread, &pipeline, BURST + 1));
        let runtime = Runtime::new().expect("a runtime");
        let replies = runtime.block_on(replies(&thread, &pipeline, vec![waiting]));
        let [(id, ede, waited)] = replies[..] else {
            panic!("one reply: {replies:?}")
        };
        assert_eq!(id, BURST + 1);
        assert_ne!(ede, Some(InfoCode::NOT_READY), "validated, not shed");
        assert!(waited < Parked::WAIT, "{waited:?}");
        assert_eq!(responder.asked("nlnetlabs.nl.", RecordType::A), 1);
    }

    /// D186: a query the allowance admits while others of its thread wait goes behind them, its unit given back.
    #[test]
    fn a_query_admitted_while_others_wait_goes_behind_them() {
        let responder = Responder::start(&["alg8_a", "root_dnskey"]);
        let thread = validating_thread(&responder, Allowance::default());
        let pipeline = thread.pipeline();
        let Step::Upstream(upstream) = step(&thread, &pipeline, 1) else {
            panic!("admitted")
        };
        assert!(matches!(
            Ask::after(&thread, &pipeline, upstream),
            Ask::Now(_)
        ));
        let waiting = thread.parking.enter().expect("a place");
        let Step::Upstream(upstream) = step(&thread, &pipeline, 2) else {
            panic!("admitted")
        };
        assert!(matches!(
            Ask::after(&thread, &pipeline, upstream),
            Ask::Parked(_)
        ));
        drop(waiting);
    }

    /// D186: the line of a thread holds [`PARKED`] queries, the newest past them shed at once; what still waits
    /// once [`Parked::WAIT`] would pass is shed then. Shed is SERVFAIL with Not Ready, and nothing asked.
    #[test]
    fn a_query_past_the_line_is_shed_at_once_and_one_waiting_too_long_once_its_time_is_up() {
        let responder = Responder::start(&["alg8_a", "root_dnskey"]);
        // One unit, never refilled.
        let allowance = Allowance {
            per_second: 0,
            burst: 1,
            ..Allowance::default()
        };
        let thread = validating_thread(&responder, allowance);
        let pipeline = thread.pipeline();
        assert!(matches!(step(&thread, &pipeline, 0), Step::Upstream(_)));
        let last = u16::try_from(PARKED).expect("fits") + 1;
        let asks = (1..=last)
            .map(|id| parked(step(&thread, &pipeline, id)))
            .collect();
        let runtime = Runtime::new().expect("a runtime");
        let replies = runtime.block_on(replies(&thread, &pipeline, asks));
        assert_eq!(replies.len(), PARKED + 1);
        let (id, ede, at) = replies[0];
        assert_eq!(
            (id, ede),
            (last, Some(InfoCode::NOT_READY)),
            "the newest first"
        );
        assert!(at < Parked::WAIT / 2, "at once: {at:?}");
        for &(id, ede, at) in &replies[1..] {
            assert_eq!(ede, Some(InfoCode::NOT_READY), "{id}");
            // Given up at the last second of the thread's clock within its wait, or, when the line has not reached
            // it by then, at its deadline: its wait runs from its own start, after `replies`' clock started, and the
            // timer fires a little late on a loaded machine (1.80000025 s seen).
            assert!(
                at > Parked::WAIT.saturating_sub(Duration::from_secs(1))
                    && at <= Parked::WAIT + Duration::from_millis(100),
                "{id} after {at:?}"
            );
        }
        assert_eq!(responder.asked("nlnetlabs.nl.", RecordType::A), 0);
    }

    /// What `future` gives when polled once, with the task's waker.
    async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
        poll_fn(|context| Poll::Ready(future.as_mut().poll(context))).await
    }

    /// D65: a plain server is asked over UDP for a client over UDP and over TCP for one over a connection; another
    /// is asked over its own transport whatever the client's.
    #[test]
    fn a_plain_server_is_asked_over_the_clients_transport() {
        let plain = Server {
            addr: ([192, 0, 2, 1], 53).into(),
            via: Via::Plain,
        };
        let tls = Server {
            addr: ([192, 0, 2, 1], 853).into(),
            via: Via::Tls(None),
        };
        for (client, plain_over) in [
            (Transport::Udp, Transport::Udp),
            (Transport::Tcp, Transport::Tcp),
            (Transport::Tls, Transport::Tcp),
            (Transport::Https, Transport::Tcp),
        ] {
            assert_eq!(target(&plain, client).1, plain_over, "{client:?}");
            assert_eq!(target(&tls, client).1, Transport::Tls, "{client:?}");
        }
    }
}
