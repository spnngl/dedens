//! A query asked upstream (D42): each server in turn over its transport (D65, D84), a question in flight shared
//! with the queries asking it (D86), expired data once the client response timer runs out (RFC 8767 §5).

use std::pin::pin;
use std::sync::Arc;
use std::time::Instant;

use compio::rustls::pki_types::ServerName;
use dedens_net::client::{ClientError, Server};
use dedens_net::exchange::{Options, Response};
use dedens_net::tcp::frame;
use dedens_proto::{Message, Transport};
use dedens_server::{Pipeline, Step, Upstream, Via};

use super::{Thread, now};
use crate::flights::{Entered, Flights, Key, Lead};

/// Asks the upstream servers for `upstream`, from `pipeline`, in turn, each over its transport ([`target`]), with
/// the forward stage's timeout and tries (D42), and hands `deliver` the replies to send, made in the thread's buffer and copied out
/// ([`copy_out`]): expired data when the client response timer runs out first, resolution going on to refresh the
/// cache (RFC 8767 §5), then the response's unless that went out; none after a prefetch.
pub(super) async fn answer(
    thread: &Thread,
    pipeline: &Pipeline,
    mut upstream: Box<Upstream>,
    transport: Transport,
    mut deliver: impl AsyncFnMut(Vec<u8>),
) {
    let mut options = Options::default();
    (options.timeout, options.tries) = upstream.patience();
    // A response without EDNS would be stored for clients asking for DNSSEC records (RFC 3225).
    options.edns_fallback = false;
    let mut stale_at = upstream.stale_after().map(|after| Instant::now() + after);
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
            let mut exchange = pin!(fetch(thread, key, upstream.request(), target, &options));
            if let Some(at) = stale_at {
                // A reborrow: the exchange goes on after the timer.
                if let Ok(fetched) = compio::time::timeout_at(at, exchange.as_mut()).await {
                    break 'ask fetched;
                }
                stale_at = None;
                let stale = {
                    let mut out = thread.scratch.borrow_mut();
                    let len = pipeline.stale(&mut upstream, now(), &mut out);
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
                    pipeline.receive(upstream, Some(&response.wire), now(), &mut out)
                }
                Fetched::Own(Err(error), _) if error.is_local() => {
                    tracing::warn!(%error, %server, "upstream query not sent");
                    pipeline.abandon(&upstream, &mut out)
                }
                Fetched::Own(Err(error), _) => {
                    tracing::debug!(%error, %server, "upstream");
                    pipeline.receive(upstream, None, now(), &mut out)
                }
                Fetched::Shared(wire) => {
                    pipeline.receive(upstream, wire.as_deref(), now(), &mut out)
                }
            };
            match step {
                Step::Reply(len) | Step::Refresh(len, _) => {
                    (copy_out(&out[..len], transport), None)
                }
                Step::Drop => (None, None),
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

/// Sends `request` to `target`, unless a query of the same `key` is in flight: then waits for its response.
async fn fetch<'a>(
    thread: &'a Thread,
    key: Option<Key>,
    request: Message<'static>,
    target: Server,
    options: &Options,
) -> Fetched<'a> {
    let flights: &Flights = thread.current.flights();
    let mut lead = None;
    if let Some(key) = key {
        match flights.enter(&key).await {
            Entered::Lead(flight) => lead = Some(flight),
            Entered::Shared(response) => return Fetched::Shared(response),
        }
    }
    Fetched::Own(thread.client.exchange(request, target, options).await, lead)
}

/// The server to ask for `server`, and the transport: its own, else UDP for a client over UDP and TCP for a client
/// over a connection (D65); the URI template of an HTTPS one is at its path (D84). A name and a path were checked when
/// the configuration was read.
fn target(server: &dedens_server::Server, client: Transport) -> (Server, Transport) {
    let (transport, name) = match &server.via {
        Via::Plain if client == Transport::Udp => (Transport::Udp, None),
        Via::Plain => (Transport::Tcp, None),
        Via::Tls(name) => (Transport::Tls, name.as_deref()),
        Via::Quic(name) => (Transport::Quic, name.as_deref()),
        Via::Https { name, .. } => (Transport::Https, name.as_deref()),
    };
    let name = name
        .and_then(|name| ServerName::try_from(name).ok())
        .map(|name| name.to_owned());
    let mut target = Server {
        addr: server.addr,
        name,
        doh: None,
        docpath: Vec::new(),
    };
    if let Via::Https { path, .. } = &server.via {
        target.doh = target.template_at(path).ok();
    }
    (target, transport)
}

/// The reply `wire`, made in the thread's buffer, copied out to be sent over `transport`: behind its length but
/// over UDP, HTTPS and CoAP. Only its bytes leave the buffer, never those of an earlier reply.
fn copy_out(wire: &[u8], transport: Transport) -> Option<Vec<u8>> {
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
mod tests {
    use std::cell::{Cell, RefCell};
    use std::future::poll_fn;
    use std::net::IpAddr;
    use std::pin::{Pin, pin};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::task::Poll;

    use compio::BufResult;
    use compio::net::UdpSocket;
    use compio::runtime::{Runtime, spawn};
    use dedens_net::tls::Trust;
    use dedens_proto::{Message, Rcode, RecordType, Transport};
    use dedens_server::{Pipeline, Server, Step, Via};
    use dedens_testkit::dnssec::capture;
    use dedens_testkit::responder::Responder;
    use futures_util::future::join;

    use super::{answer, target};
    use crate::flights::Key;
    use crate::lists::Store;
    use crate::reload::Current;
    use crate::serve::tests::example_com_a;
    use crate::serve::{Thread, now};

    /// D42: a server that fails on our side, here a QUIC one at an unspecified address, which QUIC will not dial,
    /// gives the query up with SERVFAIL, the next server not asked; a server that does not answer passes the query
    /// to the next.
    #[test]
    fn a_local_failure_gives_up_where_a_silent_server_passes_on() {
        let (query, response) = example_com_a();
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let responder = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
            let next = responder.local_addr().expect("its address");
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
                    if responder.send_to(reply, peer).await.0.is_err() {
                        return;
                    }
                }
            })
            .detach();
            for (first, rcode, asked_next) in [
                ("quic://0.0.0.0", Rcode::SERVFAIL, 0),
                ("192.0.2.1", Rcode::NOERROR, 1),
            ] {
                asked.set(0);
                let text = format!(
                    "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{first}', '{next}']\n    timeout_ms: 200\n    tries: 1\n"
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
                let Step::Upstream(upstream) =
                    pipeline.query(&query, Transport::Udp, from, now(), &mut out)
                else {
                    panic!("asked upstream")
                };
                let mut replies = Vec::new();
                answer(&thread, &pipeline, upstream, Transport::Udp, async |reply| {
                    replies.push(reply);
                })
                .await;
                let [reply] = &replies[..] else {
                    panic!("one reply after {first}: {replies:?}")
                };
                let reply = Message::decode(reply).expect("decodes").message;
                assert_eq!((reply.rcode(), asked.get()), (rcode, asked_next), "{first}");
            }
        });
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
                    pipeline.query(&query, Transport::Udp, from, now(), &mut out)
                else {
                    panic!("asked upstream")
                };
                let Step::Upstream(probe) =
                    pipeline.receive(upstream, Some(&response), now(), &mut out)
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
