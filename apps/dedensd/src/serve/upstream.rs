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
