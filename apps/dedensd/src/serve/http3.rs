//! DNS over HTTPS over HTTP/3 (RFC 8484, RFC 9114, D84): the requests of a connection under its byte budget (D119),
//! and Oblivious `DoH`, the target and the proxy (RFC 9230, D79, D94).

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::quic::Connection;
use dedens_net::doh::Method;
use dedens_net::http3::{Http3Error, Incoming, Pending, Requests};
#[cfg(feature = "odoh")]
use dedens_net::odoh::proxy::{Destination, ProxyError, Route, failure, rejection, route};
#[cfg(feature = "odoh")]
use dedens_net::odoh::{Kind, MAX_BODY};
#[cfg(feature = "odoh")]
use dedens_odoh::ResponseContext;
use dedens_proto::Transport;
use http::StatusCode;

use super::h3_budget::Budget;
use super::isolate::Origin;
#[cfg(feature = "odoh")]
use super::now;
use super::tcp::TCP_WRITE;
use super::upstream::answer;
use super::{Slot, Started, TCP_IDLE, Thread, start};
#[cfg(feature = "odoh")]
use crate::odoh;
#[cfg(feature = "odoh")]
use crate::odoh::proxy::Proxy;

/// Uni streams an HTTP/3 client may open: its control stream and QPACK's two (RFC 9114 §6.2), with room for
/// the reserved ones it may add (§6.2.3).
pub(super) const H3_UNI_STREAMS: u32 = 16;

/// Answers the requests of one HTTP/3 connection (RFC 9114 §4), each alone on a stream the client opened, as
/// soon as it can be: the HTTP/3 setup and each request's reading must end within [`TCP_IDLE`], and a new request
/// must come within it too, as `quic::streams` says, unless one is still being answered: closing would lose its
/// response (RFC 9114 §5.1). Requests go through the pipeline as any query; the client is `peer`.
/// Once the connection passed its byte budget (D119) it is sent `GOAWAY` at the next request, and ends when it is
/// quiet: nothing in flight, and no request taken for [`DRAIN_QUIET`]. Each request's task holds the connection's
/// `slot`.
pub(super) async fn requests(
    connection: Connection,
    path: &Arc<str>,
    origin: &Origin,
    thread: &Rc<Thread>,
    budget: &Rc<Budget>,
    slot: &Rc<Slot>,
) {
    let peer = origin.peer;
    let mut requests = match compio::time::timeout(TCP_IDLE, Requests::new(connection)).await {
        Ok(Ok(requests)) => requests,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 setup failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 setup timed out"),
    };
    // Set at `GOAWAY`: the last time a request was taken, then.
    let mut going_away = None::<Instant>;
    loop {
        if budget.passed() && going_away.is_none() {
            if let Err(error) = requests.shutdown().await {
                return tracing::debug!(%peer, %error, "HTTP/3 GOAWAY failed");
            }
            going_away = Some(Instant::now());
        }
        let wait = if going_away.is_some() {
            DRAIN_TICK
        } else {
            TCP_IDLE
        };
        match compio::time::timeout(wait, requests.accept()).await {
            Ok(Ok(Some(pending))) => {
                let (path, thread, flight) = (Arc::clone(path), Rc::clone(thread), budget.fly());
                let slot = Rc::clone(slot);
                origin.clone().spawn(async move {
                    request(pending, &path, peer, &thread).await;
                    drop(flight);
                    drop(slot);
                });
                if let Some(last) = &mut going_away {
                    *last = Instant::now();
                }
            }
            Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 connection ended"),
            Ok(Ok(None)) if going_away.is_none() => return,
            Err(_) if going_away.is_none() => {
                if budget.quiet() {
                    return tracing::debug!(%peer, "HTTP/3 connection idle");
                }
            }
            // After `GOAWAY`, h3 ends `accept` once the client did too: a request it sent before it heard of
            // `GOAWAY` may still come, to be refused, and dropping `requests` closes the connection.
            Ok(Ok(None)) | Err(_) => {
                if budget.quiet() && going_away.is_some_and(|last| last.elapsed() >= DRAIN_QUIET) {
                    return tracing::debug!(%peer, "HTTP/3 connection drained");
                }
                compio::time::sleep(DRAIN_TICK).await;
            }
        }
    }
}

/// How long a connection sent `GOAWAY` waits for a request that was in flight, once its own are answered.
const DRAIN_QUIET: Duration = Duration::from_millis(100);

/// How often a connection sent `GOAWAY` looks for a request still to come, and for the end of its own.
const DRAIN_TICK: Duration = Duration::from_millis(10);

/// Answers one request: what [`Pending::read`] makes of it if it is no query, else the pipeline's reply, or 400 when
/// the pipeline drops it, a query too short to be a DNS message (RFC 8484 §4.2.1).
async fn request(pending: Pending, path: &str, peer: SocketAddr, thread: &Thread) {
    #[cfg(feature = "odoh")]
    if let Some(target) = &thread.odoh {
        return oblivious(pending, path, peer, thread, target).await;
    }
    let incoming = match compio::time::timeout(TCP_IDLE, pending.read(path)).await {
        Ok(Ok(incoming)) => incoming,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 request failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 request timed out"),
    };
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = match incoming.query() {
        Ok(query) => start(
            thread,
            &pipeline,
            query,
            Transport::Https,
            peer.ip(),
            |wire| {
                first = Some(wire.to_vec());
                true
            },
        ),
        Err(status) => return reject(incoming, status, peer).await,
    };
    let mut incoming = Some(incoming);
    if let Some(wire) = first {
        respond_http(&mut incoming, wire, peer).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |wire| respond_http(&mut incoming, wire, peer).await;
        answer(thread, &pipeline, upstream, Transport::Https, deliver).await;
        drop(slot);
    }
    if let Some(incoming) = incoming {
        reject(incoming, StatusCode::BAD_REQUEST, peer).await;
    }
}

/// Answers one request at a listener that is an Oblivious `DoH` target too (D79): a POST of an encrypted query is
/// opened, asked of the pipeline as a query over [`Transport::Odoh`] and answered sealed; a GET of the configurations
/// is answered with them; any other request is `DoH`'s, as [`request`] answers it. When the target is a proxy too, a
/// request that names a target of its own is forwarded there (D94).
#[cfg(feature = "odoh")]
async fn oblivious(
    pending: Pending,
    path: &str,
    peer: SocketAddr,
    thread: &Thread,
    target: &odoh::Service,
) {
    let read = pending.read_with(MAX_BODY, |request, body| {
        route(request, body, path, target.proxy.as_ref())
    });
    let incoming = match compio::time::timeout(TCP_IDLE, read).await {
        Ok(Ok(incoming)) => incoming,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 request failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 request timed out"),
    };
    let (transport, mut context, query) = match (incoming.kind(), incoming.query()) {
        // Not `DoH` requests: not counted (D84).
        (Route::Target(Kind::Configs), Err(status)) => {
            sent(incoming.reject(status), peer).await;
            return;
        }
        (Route::Malformed(status), _) => {
            let response = rejection(*status);
            return proxied(incoming, response, peer).await;
        }
        (_, Err(status)) => return reject(incoming, status, peer).await,
        (Route::Target(Kind::Configs), Ok(_)) => {
            sent(incoming.respond_with(target.configs()), peer).await;
            return;
        }
        (Route::Proxy(proxy, destination), Ok(body)) => {
            // A client the access lists deny is served no forward, whatever the action (D91, D94).
            let response = if thread.pipeline().denies(peer.ip()) {
                failure(StatusCode::FORBIDDEN, ProxyError::ClientDenied)
            } else {
                forward(proxy, destination, body, thread).await
            };
            return proxied(incoming, response, peer).await;
        }
        (Route::Target(Kind::Oblivious), Ok(body)) => {
            // The target opens it only for a client with budget left, the opening being work an unauthenticated
            // client makes it do; a source on the rate limit's exempt list pays no network unit (D117, D113).
            let exempt = thread
                .pipeline()
                .rate_limit()
                .is_some_and(|limit| limit.exempts(peer.ip()));
            match target.open(peer.ip(), now(), exempt, body) {
                Ok((query, context)) => (Transport::Odoh, Some(context), query),
                Err(status) => return reject(incoming, status, peer).await,
            }
        }
        (Route::Target(Kind::Dns), Ok(query)) => (Transport::Https, None, query.to_vec()),
    };
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = start(thread, &pipeline, &query, transport, peer.ip(), |wire| {
        first = Some(wire.to_vec());
        true
    });
    let mut incoming = Some(incoming);
    if let Some(wire) = first {
        respond_sealed(&mut incoming, &mut context, wire, peer).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |wire| respond_sealed(&mut incoming, &mut context, wire, peer).await;
        answer(thread, &pipeline, upstream, transport, deliver).await;
        drop(slot);
    }
    if let Some(incoming) = incoming {
        reject(incoming, StatusCode::BAD_REQUEST, peer).await;
    }
}

/// The response to the request to forward the encrypted query `body` to `destination` (D94): the target's, or the
/// proxy's error. Boxed: the futures of the HTTP/3 request tasks are large already.
#[cfg(feature = "odoh")]
async fn forward(
    proxy: &Proxy,
    destination: &Destination,
    body: &[u8],
    thread: &Thread,
) -> http::Response<Vec<u8>> {
    Box::pin(proxy.forward(&thread.forwarder, destination, body)).await
}

/// The label `status` of the proxied count (D94): a status the proxy answers with, else "other".
#[cfg(feature = "odoh")]
const fn proxied_status(status: StatusCode) -> &'static str {
    match status {
        StatusCode::OK => "200",
        StatusCode::BAD_REQUEST => "400",
        StatusCode::UNAUTHORIZED => "401",
        StatusCode::FORBIDDEN => "403",
        StatusCode::METHOD_NOT_ALLOWED => "405",
        StatusCode::PAYLOAD_TOO_LARGE => "413",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "415",
        StatusCode::INTERNAL_SERVER_ERROR => "500",
        StatusCode::BAD_GATEWAY => "502",
        StatusCode::SERVICE_UNAVAILABLE => "503",
        StatusCode::GATEWAY_TIMEOUT => "504",
        _ => "other",
    }
}

/// Answers `incoming` with `response` of the proxy role, and counts it (D94).
#[cfg(feature = "odoh")]
async fn proxied(
    incoming: Incoming<Route<&Proxy>>,
    response: http::Response<Vec<u8>>,
    peer: SocketAddr,
) {
    let status = proxied_status(response.status());
    metrics::counter!(ODOH_PROXIED, "status" => status).increment(1);
    sent(incoming.respond_with(response), peer).await;
}

#[cfg(feature = "odoh")]
const ODOH_PROXIED: &str = "dedensd_odoh_proxied_total";

/// Answers 200 with `wire` on `incoming`, sealed for the client when `context` holds what that takes, unless it was
/// answered already.
#[cfg(feature = "odoh")]
async fn respond_sealed(
    incoming: &mut Option<Incoming<Route<&Proxy>>>,
    context: &mut Option<ResponseContext>,
    wire: Vec<u8>,
    peer: SocketAddr,
) {
    let Some(context) = context.take() else {
        return respond_http(incoming, wire, peer).await;
    };
    let Some(incoming) = incoming.take() else {
        return;
    };
    match odoh::seal(context, &wire) {
        Ok(response) => {
            count_doh(incoming.method(), StatusCode::OK);
            sent(incoming.respond_with(response), peer).await;
        }
        Err(status) => reject(incoming, status, peer).await,
    }
}

/// Answers 200 with `wire` on `incoming`, unless it was answered already.
async fn respond_http<K>(incoming: &mut Option<Incoming<K>>, wire: Vec<u8>, peer: SocketAddr) {
    if let Some(incoming) = incoming.take() {
        count_doh(incoming.method(), StatusCode::OK);
        sent(incoming.respond(wire), peer).await;
    }
}

/// Answers `status` without a message.
async fn reject<K>(incoming: Incoming<K>, status: StatusCode, peer: SocketAddr) {
    count_doh(incoming.method(), status);
    sent(incoming.reject(status), peer).await;
}

/// Waits for the response `write` to `peer` to go out, at most [`TCP_WRITE`]: a client that grants no credit to
/// receive it loses the request, as a TCP one reading too slowly loses its connection (D47). The write is boxed: the
/// futures of the HTTP/3 request tasks are large already.
async fn sent(write: impl Future<Output = Result<(), Http3Error>>, peer: SocketAddr) {
    match compio::time::timeout(TCP_WRITE, Box::pin(write)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(%peer, %error, "HTTP/3 response failed"),
        Err(_) => tracing::debug!(%peer, "HTTP/3 response timed out"),
    }
}

/// Counts a `DoH` request answered with `status` (D84): the statuses [`Pending::read`] and this module answer with
/// and the methods `DoH` uses are labelled, the others "other", so the labels stay few.
fn count_doh(method: Option<Method>, status: StatusCode) {
    let method = match method {
        Some(Method::Get) => "get",
        Some(Method::Post) => "post",
        None => "other",
    };
    let status = match status {
        StatusCode::OK => "200",
        StatusCode::UNAUTHORIZED => "401",
        StatusCode::BAD_REQUEST => "400",
        StatusCode::NOT_FOUND => "404",
        StatusCode::METHOD_NOT_ALLOWED => "405",
        StatusCode::PAYLOAD_TOO_LARGE => "413",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "415",
        _ => "other",
    };
    metrics::counter!(DOH_QUERIES, "method" => method, "status" => status).increment(1);
}

const DOH_QUERIES: &str = "dedensd_doh_queries_total";

// The tests run sockets and a runtime, which loom's threads and locks cannot drive (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
mod tests {

    /// D84: a `DoH` request is counted by method and status, a status `DoH` does not answer with as "other", and a
    /// request without a method `DoH` uses as "other".
    #[test]
    fn doh_requests_are_counted_by_method_and_status() {
        use dedens_net::doh::Method;
        use http::StatusCode;
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        use super::{DOH_QUERIES, count_doh};

        let answered = [
            (Some(Method::Get), 200, "get", "200"),
            (Some(Method::Post), 400, "post", "400"),
            (None, 401, "other", "401"),
            (Some(Method::Get), 404, "get", "404"),
            (Some(Method::Post), 405, "post", "405"),
            (None, 413, "other", "413"),
            (Some(Method::Get), 415, "get", "415"),
            (Some(Method::Post), 500, "post", "other"),
        ];
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            for (method, code, ..) in answered {
                count_doh(method, StatusCode::from_u16(code).expect("a status"));
            }
        });
        let mut counted: Vec<_> = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, ..)| key.key().name() == DOH_QUERIES)
            .map(|(key, _, _, value)| {
                let labels: Vec<_> = key
                    .key()
                    .labels()
                    .map(|label| label.value().to_owned())
                    .collect();
                (labels, value)
            })
            .collect();
        counted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut expected: Vec<_> = answered
            .iter()
            .map(|&(_, _, method, status)| {
                (
                    vec![method.to_owned(), status.to_owned()],
                    DebugValue::Counter(1),
                )
            })
            .collect();
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(counted, expected);
    }

    /// D94: each status the proxy answers with has its label in the count, and another is "other".
    #[cfg(feature = "odoh")]
    #[test]
    fn the_proxied_count_is_labelled_by_status() {
        use http::StatusCode;

        use super::proxied_status;

        for code in [200, 400, 401, 403, 405, 413, 415, 500, 502, 503, 504] {
            let status = StatusCode::from_u16(code).expect("a status");
            assert_eq!(proxied_status(status), code.to_string());
        }
        for code in [204, 404, 429, 501] {
            let status = StatusCode::from_u16(code).expect("a status");
            assert_eq!(proxied_status(status), "other");
        }
    }
}
