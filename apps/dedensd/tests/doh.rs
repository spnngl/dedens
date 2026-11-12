//! Serving DNS over HTTPS over HTTP/3, and what HTTP/3 peers cost.

mod queries {
    //! Serving DNS over HTTPS (RFC 8484) over HTTP/3 (RFC 9114), on addresses behind `https://` with the certificate of
    //! `tls` (D84): the answers, their `cache-control`, the statuses of requests that are no query, the path. The
    //! statuses are RFC 9110's: 404 (§15.5.5), 405 (§15.5.6), 413 (§15.5.14), 415 (§15.5.16).

    use std::net::SocketAddr;
    use std::num::NonZero;

    use compio::bytes::{Buf, Bytes};
    use compio::quic::{ClientBuilder, h3};
    use compio::runtime::{Runtime, spawn};
    use compio::rustls::RootCertStore;
    use dedens_net::client::Client;
    use dedens_net::doh::{MEDIA_TYPE, Method, Template, request};
    use dedens_net::exchange::Options;
    use dedens_net::tls::Trust;
    use dedens_proto::{Message, Rcode, Transport};
    use dedens_testkit::captured;
    use dedens_testkit::certificates::{Certificates, NAME, certificates, named};
    use dedens_testkit::responder::Responder;
    use http::header::{CACHE_CONTROL, CONTENT_TYPE};
    use http::{HeaderMap, StatusCode};

    use crate::util::{Server, decode, query_for, write_config};

    /// `dedensd` answering `DoH` over HTTP/3 on `listen` (`ADDR`, then the path) with the certificate of `certificates`,
    /// forwarding to `upstream`.
    fn serving(certificates: &Certificates, listen_path: &str, upstream: SocketAddr) -> Server {
        let config = write_config("");
        let (certificate, key) = (
            config.with_extension("crt.pem"),
            config.with_extension("key.pem"),
        );
        std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
        crate::util::write_key(&key, &certificates.key_pem);
        Server::configured(|listen| {
            format!(
                "listen: ['https://{listen}{listen_path}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
                certificate.display(),
                key.display()
            )
        })
    }

    /// The answer of an HTTP/3 server to a request.
    struct Got {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    /// Sends `request` with `body` to the HTTP/3 server at `addr`, trusting `certificates`, and reads the response.
    fn send(
        addr: SocketAddr,
        certificates: &Certificates,
        request: http::Request<()>,
        body: &[u8],
    ) -> Got {
        let mut roots = RootCertStore::empty();
        roots.add(certificates.ca.clone()).expect("a root");
        Runtime::new().expect("a runtime").block_on(async {
            let endpoint = ClientBuilder::new_with_root_certificates(roots)
                .with_alpn_protocols(&["h3"])
                .bind("127.0.0.1:0")
                .await
                .expect("a QUIC endpoint");
            let connection = endpoint
                .connect(addr, NAME, None)
                .expect("connecting")
                .await
                .expect("connected");
            let (mut driver, mut requests) = h3::client::new(connection).await.expect("HTTP/3");
            spawn(async move { driver.wait_idle().await }).detach();
            let mut stream = requests.send_request(request).await.expect("a stream");
            if !body.is_empty() {
                stream
                    .send_data(Bytes::copy_from_slice(body))
                    .await
                    .expect("the body sent");
            }
            stream.finish().await.expect("the request finished");
            let head = stream.recv_response().await.expect("a response");
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.expect("the body") {
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            Got {
                status: head.status(),
                headers: head.headers().clone(),
                body,
            }
        })
    }

    /// The request of `method` for the query `wire` at `path` of the server at `addr`, as the client makes it.
    fn query_request(addr: SocketAddr, path: &str, method: Method) -> http::Request<Vec<u8>> {
        let template =
            Template::parse(&format!("https://{NAME}:{}{path}", addr.port())).expect("a template");
        request(&template, &query_for("a", 0), method).expect("a request")
    }

    /// A request that is no query: `method` at `path` with an optional content type.
    fn other(
        addr: SocketAddr,
        method: http::Method,
        path: &str,
        content_type: Option<&str>,
    ) -> http::Request<()> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("https://{NAME}:{}{path}", addr.port()));
        if let Some(value) = content_type {
            builder = builder.header(CONTENT_TYPE, value);
        }
        builder.body(()).expect("a request")
    }

    /// The least TTL of the answer in the DNS message `wire`.
    fn least_ttl(wire: &[u8]) -> u32 {
        decode(wire)
            .answer
            .iter()
            .map(|record| record.ttl.get())
            .min()
            .expect("an answer")
    }

    /// §4.1: both methods are answered, through the pipeline as any query; the replies are padded, as the clients' queries
    /// are (RFC 8467).
    #[test]
    fn s4_1_clients_get_and_post_answers() {
        let response = captured("a");
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, "", upstream.addr);
        for method in [Method::Get, Method::Post] {
            // A client of its own: its connection lives on the runtime that opened it.
            let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
            let mut options = Options::default();
            options.transport = Transport::Https;
            options.method = method;
            options.tries = NonZero::<u8>::MIN;
            let query = dedens_testkit::query("a", 0);
            let reply = Runtime::new().expect("a runtime").block_on(async {
                let response = client
                    .exchange(query, named(server.addr, NAME), &options)
                    .await
                    .expect("an answer");
                assert_eq!(response.transport, Transport::Https);
                decode(&response.wire)
            });
            assert_eq!(
                (reply.rcode(), &reply.answer),
                (Rcode::NOERROR, &decode(&response).answer),
                "{method:?}"
            );
            assert_eq!(
                reply.to_vec().expect("encodes").len() % 468,
                0,
                "{method:?}"
            );
        }
        assert_eq!(upstream.queries().len(), 2);
    }

    /// §5.1: a GET's `cache-control` has the least TTL of the answer; a POST's has none.
    #[test]
    fn s5_1_cache_control_is_the_least_ttl() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, "", upstream.addr);
        let get = query_request(server.addr, "/dns-query", Method::Get);
        let got = send(server.addr, &ca, get.map(|_| ()), &[]);
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.headers[CONTENT_TYPE], MEDIA_TYPE);
        assert_eq!(
            got.headers[CACHE_CONTROL],
            format!("max-age={}", least_ttl(&got.body))
        );
        let post = query_request(server.addr, "/dns-query", Method::Post);
        let (head, body) = post.into_parts();
        let got = send(server.addr, &ca, http::Request::from_parts(head, ()), &body);
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.headers[CONTENT_TYPE], MEDIA_TYPE);
        assert!(!got.headers.contains_key(CACHE_CONTROL));
        assert_eq!(
            Message::decode(&got.body)
                .expect("a message")
                .message
                .rcode(),
            Rcode::NOERROR
        );
    }

    /// §4.1, §6: what is no query gets a status and no message: 415 for a POST of another media type, 405 for another
    /// method, 400 for a GET without a query or a query that is no message, 413 for a body past a message's size.
    #[test]
    fn s4_2_1_requests_that_are_no_query_get_statuses() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, "", upstream.addr);
        let addr = server.addr;
        let post = |content_type| other(addr, http::Method::POST, "/dns-query", content_type);
        for (request, body, status) in [
            (
                post(Some("text/plain")),
                vec![0; 12],
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (post(None), vec![0; 12], StatusCode::UNSUPPORTED_MEDIA_TYPE),
            (
                other(addr, http::Method::PUT, "/dns-query", Some(MEDIA_TYPE)),
                vec![0; 12],
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                other(addr, http::Method::DELETE, "/dns-query", None),
                vec![],
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                other(addr, http::Method::GET, "/dns-query", None),
                vec![],
                StatusCode::BAD_REQUEST,
            ),
            (
                other(addr, http::Method::GET, "/dns-query?dns=AA", None),
                vec![],
                // Too short to be a DNS message: the pipeline drops it.
                StatusCode::BAD_REQUEST,
            ),
            (
                post(Some(MEDIA_TYPE)),
                vec![0; 65536],
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let uri = request.uri().to_string();
            let got = send(addr, &ca, request, &body);
            assert_eq!(got.status, status, "{uri}");
            assert!(got.body.is_empty(), "{uri}");
        }
        assert_eq!(upstream.queries().len(), 0);
    }

    /// §3: the service is at the path of the listener, `/dns-query` unless set; another path is 404.
    #[test]
    fn s3_the_path_is_the_listeners() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        for (listen_path, served, not_served) in
            [("", "/dns-query", "/doh"), ("/doh", "/doh", "/dns-query")]
        {
            let server = serving(&ca, listen_path, upstream.addr);
            let get = |path| query_request(server.addr, path, Method::Get).map(|_| ());
            let got = send(server.addr, &ca, get(served), &[]);
            assert_eq!(got.status, StatusCode::OK, "{served}");
            let got = send(server.addr, &ca, get(not_served), &[]);
            assert_eq!(got.status, StatusCode::NOT_FOUND, "{not_served}");
            assert!(got.body.is_empty(), "{not_served}");
        }
    }

    /// §4.2.1: an upstream failure is still an answer with status 200, a DNS error.
    #[test]
    fn s4_2_1_an_upstream_failure_is_a_dns_error() {
        let (silent, upstream) = crate::util::silent();
        let ca = certificates();
        let server = serving(&ca, "", upstream);
        let get = query_request(server.addr, "/dns-query", Method::Get);
        let got = send(server.addr, &ca, get.map(|_| ()), &[]);
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(decode(&got.body).rcode(), Rcode::SERVFAIL);
        assert_eq!(got.headers[CACHE_CONTROL], "max-age=0");
        drop(silent);
    }
}

mod h3_frames {
    //! HTTP/3 (RFC 9114) as `dedensd` serves it: what a peer that declares a frame it never completes costs the server,
    //! and that a busy honest connection is rotated, not closed (D119). h3 0.0.8 buffers a frame until it is whole, and
    //! reads the stream meanwhile, so the QUIC windows reopen and nothing but the bytes the connection received bounds
    //! the buffer.

    use std::cell::Cell;
    use std::num::NonZero;
    use std::sync::Arc;
    use std::time::Duration;

    use compio::bytes::{Buf, Bytes};
    use compio::io::AsyncWriteExt;
    use compio::quic::h3::client::SendRequest;
    use compio::quic::h3::error::{Code, StreamError};
    use compio::quic::h3::{self, OpenStreams};
    use compio::quic::{
        ClientBuilder, Connection, ConnectionError, Endpoint, SendStream, TransportConfig,
    };
    use compio::runtime::Runtime;
    use dedens_net::client::Client;
    use dedens_net::exchange::Options;
    use dedens_net::http3::H3_EXCESSIVE_LOAD;
    use dedens_net::tls::Trust;
    use dedens_proto::{Rcode, Transport};
    use dedens_testkit::certificates::{Certificates, NAME, certificates, named};
    use dedens_testkit::responder::Responder;
    use futures_util::future::join_all;

    use crate::util::{Server, decode, query_for, write_config};

    /// What a client may send before the server must have closed the connection: the budget of D119 is 4 MiB, and the
    /// server checks it every 20 ms, in which this paced client sends far less than the other 4 MiB. The server sends
    /// `GOAWAY` at the budget and closes at the budget and a connection window (256 KiB) after it.
    const CLOSED_BEFORE: usize = 8 << 20;

    /// The bytes the client stops at if the server never closes, and the time it gives the server.
    const CAP: usize = 64 << 20;
    const PATIENCE: Duration = Duration::from_secs(30);

    /// `dedensd` answering `DoH` over HTTP/3, forwarding to `upstream`.
    fn serving(certificates: &Certificates, upstream: &Responder) -> Server {
        serving_with(certificates, upstream, "", 2000)
    }

    /// As [`serving`], with the lines `extra` in the configuration, `upstream` given `timeout_ms` to answer.
    fn serving_with(
        certificates: &Certificates,
        upstream: &Responder,
        extra: &str,
        timeout_ms: u32,
    ) -> Server {
        let config = write_config("");
        let (certificate, key) = (
            config.with_extension("crt.pem"),
            config.with_extension("key.pem"),
        );
        std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
        crate::util::write_key(&key, &certificates.key_pem);
        let upstream = upstream.addr;
        Server::configured(|listen| {
            format!(
                "{extra}listen: ['https://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: {timeout_ms}\n    tries: 1\n",
                certificate.display(),
                key.display()
            )
        })
    }

    /// A variable-length integer on eight bytes (RFC 9000 §16), as a peer that wants the longest length writes it.
    fn varint8(value: u64) -> [u8; 8] {
        assert!(value < 1 << 62, "{value} fits a variable-length integer");
        (value | 0b11 << 62).to_be_bytes()
    }

    /// An HTTP/3 connection to `addr` whose client control stream has sent its empty SETTINGS, the stream is returned
    /// with it to keep it open.
    async fn connected(addr: std::net::SocketAddr, ca: &Certificates) -> (Connection, SendStream) {
        let endpoint = ClientBuilder::new_with_empty_roots()
            .with_custom_certificate(ca.ca.clone())
            .expect("a root")
            .with_no_crls()
            .with_alpn_protocols(&["h3"])
            .bind("127.0.0.1:0")
            .await
            .expect("an endpoint");
        let connection = endpoint
            .connect(addr, NAME, None)
            .expect("connecting")
            .await
            .expect("connected");
        let mut control = connection.open_uni_wait().await.expect("a control stream");
        // The stream type (control), then a SETTINGS frame (type 4, no setting).
        control
            .write_all(vec![0x00, 0x04, 0x00])
            .await
            .0
            .expect("the SETTINGS sent");
        (connection, control)
    }

    /// Writes `chunk`s to `streams` in turns, slowly, until the server closes the connection or `CAP` bytes are
    /// out. Returns what was sent, and why the connection ended.
    async fn flood(
        connection: &Connection,
        streams: &mut [SendStream],
    ) -> (usize, Option<ConnectionError>) {
        let sent = Cell::new(0);
        let chunk = vec![0_u8; 16 << 10];
        let flooding = async {
            while sent.get() < CAP {
                for stream in streams.iter_mut() {
                    if stream.write_all(chunk.clone()).await.0.is_err() {
                        return;
                    }
                    sent.set(sent.get() + chunk.len());
                }
                compio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        // A server that stops reading leaves the writes waiting for credit: the timeout ends them.
        let _ = compio::time::timeout(PATIENCE, flooding).await;
        let reason = compio::time::timeout(Duration::from_secs(5), connection.closed())
            .await
            .ok();
        (sent.get(), reason)
    }

    /// The connection must end with `H3_EXCESSIVE_LOAD` after at most `CLOSED_BEFORE` bytes.
    fn assert_refused(sent: usize, reason: Option<&ConnectionError>) {
        assert!(sent < CLOSED_BEFORE, "{sent} bytes sent before the end");
        let code = match reason {
            Some(ConnectionError::ApplicationClosed(close)) => Some(u64::from(close.error_code)),
            _ => None,
        };
        assert_eq!(code, Some(H3_EXCESSIVE_LOAD), "{reason:?}");
    }

    /// What the server's closing of `connection` said, within `patience`: its code, or how the connection ended if not
    /// closed by the server; `None` if it is still open.
    async fn closed(
        connection: &Connection,
        patience: Duration,
    ) -> Option<Result<u64, ConnectionError>> {
        let reason = compio::time::timeout(patience, connection.closed())
            .await
            .ok()?;
        Some(match reason {
            ConnectionError::ApplicationClosed(close) => Ok(u64::from(close.error_code)),
            reason => Err(reason),
        })
    }

    /// An HTTP/3 connection to `addr`, trusting `ca`, that pings it every `keep_alive` if set, with what h3 makes of it:
    /// the driver, to hold and not to poll, so the client does not hear of `GOAWAY` and its requests may cross it, and
    /// what sends the requests.
    async fn h3_connected(
        addr: std::net::SocketAddr,
        ca: &Certificates,
        keep_alive: Option<Duration>,
    ) -> (
        Connection,
        h3::client::Connection<Connection, Bytes>,
        SendRequest<OpenStreams, Bytes>,
    ) {
        let mut config = ClientBuilder::new_with_empty_roots()
            .with_custom_certificate(ca.ca.clone())
            .expect("a root")
            .with_no_crls()
            .with_alpn_protocols(&["h3"])
            .build();
        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(keep_alive);
        config.transport_config(Arc::new(transport));
        let endpoint = Endpoint::client("127.0.0.1:0").await.expect("an endpoint");
        let connection = endpoint
            .connect(addr, NAME, Some(config))
            .expect("connecting")
            .await
            .expect("connected");
        let (driver, requests) = h3::client::new(connection.clone()).await.expect("HTTP/3");
        (connection, driver, requests)
    }

    /// POSTs `body` to the `DoH` path of `addr` and reads the response: its status and body.
    async fn post(
        requests: &mut SendRequest<OpenStreams, Bytes>,
        addr: std::net::SocketAddr,
        body: &[u8],
    ) -> Result<(http::StatusCode, Vec<u8>), StreamError> {
        let request = http::Request::post(format!("https://{NAME}:{}/dns-query", addr.port()))
            .header("content-type", "application/dns-message")
            .body(())
            .expect("a request");
        let mut stream = requests.send_request(request).await?;
        stream.send_data(Bytes::copy_from_slice(body)).await?;
        stream.finish().await?;
        let status = stream.recv_response().await?.status();
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        Ok((status, body))
    }

    /// Sends the server bodies of no DNS message, each answered before the next, until the connection passed its budget
    /// (4 MiB of UDP payload, which the server counts as the client does on loopback) and not a connection window more
    /// (256 KiB, where it is closed), then waits for the server to see it (it checks every 20 ms). It stops at the body
    /// that passes: one more could be the request the server sends `GOAWAY` after.
    async fn past_budget(
        connection: &Connection,
        requests: &mut SendRequest<OpenStreams, Bytes>,
        addr: std::net::SocketAddr,
    ) {
        let junk = vec![0; 60_000];
        while connection.stats().udp_tx.bytes < 4 << 20 {
            post(requests, addr, &junk).await.expect("a response");
        }
        compio::time::sleep(Duration::from_millis(200)).await;
    }

    /// §5.2: the request that comes once the connection passed its budget is answered even when slow, and the server
    /// closes the connection when it is, with `H3_NO_ERROR`: not before, and not after the 10 s it gives a connection to
    /// end.
    #[test]
    fn s5_2_a_connection_past_its_budget_is_closed_once_its_last_request_is_answered() {
        let upstream = Responder::delayed(&["a"], Duration::from_millis(500));
        let ca = certificates();
        let server = serving(&ca, &upstream);
        Runtime::new().expect("a runtime").block_on(async {
            let (connection, _driver, mut requests) = h3_connected(server.addr, &ca, None).await;
            past_budget(&connection, &mut requests, server.addr).await;
            let (status, body) = post(&mut requests, server.addr, &query_for("a", 0))
                .await
                .expect("the last request answered");
            assert_eq!(status, http::StatusCode::OK);
            assert_eq!(decode(&body).rcode(), Rcode::NOERROR);
            let code = closed(&connection, Duration::from_secs(5)).await;
            assert_eq!(code, Some(Ok(Code::H3_NO_ERROR.value())));
        });
        assert_eq!(upstream.queries().len(), 1);
    }

    /// §5.2: a request the client sent before it heard the server's `GOAWAY` is refused with `H3_REQUEST_REJECTED`, which
    /// it may retry, not cut by the end of the connection: the server waits for those a moment after its last request.
    #[test]
    fn s5_2_a_request_that_crosses_goaway_is_refused() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, &upstream);
        let query = query_for("a", 0);
        Runtime::new().expect("a runtime").block_on(async {
            let (connection, _driver, mut requests) = h3_connected(server.addr, &ca, None).await;
            past_budget(&connection, &mut requests, server.addr).await;
            post(&mut requests, server.addr, &query)
                .await
                .expect("the last request answered");
            for _ in 0..2 {
                let refused = post(&mut requests, server.addr, &query).await;
                assert!(
                    matches!(&refused, Err(StreamError::RemoteTerminate { code, .. }) if *code == Code::H3_REQUEST_REJECTED),
                    "{refused:?}"
                );
            }
            let code = closed(&connection, Duration::from_secs(5)).await;
            assert_eq!(code, Some(Ok(Code::H3_NO_ERROR.value())));
        });
    }

    /// §5.2: a client that sends `GOAWAY` has the server close the connection once its requests are answered.
    #[test]
    fn s5_2_a_client_going_away_has_the_connection_closed() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, &upstream);
        Runtime::new().expect("a runtime").block_on(async {
            let (connection, mut driver, mut requests) = h3_connected(server.addr, &ca, None).await;
            post(&mut requests, server.addr, &query_for("a", 0))
                .await
                .expect("an answer");
            driver.shutdown(0).await.expect("GOAWAY sent");
            let code = closed(&connection, Duration::from_secs(5)).await;
            assert_eq!(code, Some(Ok(Code::H3_NO_ERROR.value())));
        });
    }

    /// §5.1: a connection waiting for a response is not idle: an upstream that answers past the idle time still has
    /// its answer sent.
    #[test]
    fn s5_1_a_connection_waiting_for_a_response_is_not_idle() {
        let upstream = Responder::slow("a", 300, Duration::from_secs(11));
        let ca = certificates();
        let server = serving_with(&ca, &upstream, "", 15_000);
        Runtime::new().expect("a runtime").block_on(async {
            let keep_alive = Some(Duration::from_secs(1));
            let (_connection, _driver, mut requests) =
                h3_connected(server.addr, &ca, keep_alive).await;
            // The upstream answers its first query at once, the next 11 s late.
            for _ in 0..2 {
                let (status, body) = post(&mut requests, server.addr, &query_for("a", 0))
                    .await
                    .expect("an answer");
                assert_eq!(status, http::StatusCode::OK);
                assert_eq!(decode(&body).rcode(), Rcode::NOERROR);
            }
        });
    }

    /// §5.1: the server closes a connection without a request for 10 s, though its client keeps it alive with pings.
    #[test]
    fn s5_1_an_idle_connection_is_closed() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, &upstream);
        Runtime::new().expect("a runtime").block_on(async {
            let keep_alive = Some(Duration::from_secs(1));
            let (connection, _driver, _requests) = h3_connected(server.addr, &ca, keep_alive).await;
            let code = closed(&connection, Duration::from_secs(20)).await;
            assert_eq!(code, Some(Ok(Code::H3_NO_ERROR.value())));
        });
    }

    /// §7.2.1, §10.5: a reserved frame on the control stream that declares 2^61 bytes, then trickles, is not buffered
    /// for good: the server closes the connection once the peer has sent its budget.
    #[test]
    fn s10_5_a_control_frame_that_never_ends_closes_the_connection() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, &upstream);
        Runtime::new().expect("a runtime").block_on(async {
            let (connection, mut control) = connected(server.addr, &ca).await;
            // A reserved frame type (0x1f * N + 0x21) and its length.
            let mut frame = vec![0x21];
            frame.extend_from_slice(&varint8(1 << 61));
            control.write_all(frame).await.0.expect("the header sent");
            let (sent, reason) = flood(&connection, &mut [control]).await;
            assert_refused(sent, reason.as_ref());
        });
    }

    /// §4.1, §10.5: sixteen request streams whose HEADERS frame declares 2^30 bytes and trickles are not buffered for
    /// good either.
    #[test]
    fn s10_5_request_headers_that_never_end_close_the_connection() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, &upstream);
        Runtime::new().expect("a runtime").block_on(async {
            let (connection, _control) = connected(server.addr, &ca).await;
            let mut streams = Vec::new();
            for _ in 0..16 {
                let (mut send, _recv) = connection.open_bi_wait().await.expect("a request stream");
                // HEADERS (type 1) and its length.
                let mut frame = vec![0x01];
                frame.extend_from_slice(&varint8(1 << 30));
                send.write_all(frame).await.0.expect("the header sent");
                streams.push(send);
            }
            let (sent, reason) = flood(&connection, &mut streams).await;
            assert_refused(sent, reason.as_ref());
        });
    }

    /// §10.5: a thread checks its connections while it has any, and again for the next once it had none: the second
    /// connection of a thread with one is closed for its budget as the first would be.
    #[test]
    fn s10_5_the_next_connection_is_checked_too() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving_with(&ca, &upstream, "threads: 1\n", 2000);
        Runtime::new().expect("a runtime").block_on(async {
            let (first, _control) = connected(server.addr, &ca).await;
            first.close(0_u32.into(), b"");
            // Some checks, the last of which finds no connection.
            compio::time::sleep(Duration::from_millis(200)).await;
            let (connection, mut control) = connected(server.addr, &ca).await;
            let mut frame = vec![0x21];
            frame.extend_from_slice(&varint8(1 << 61));
            control.write_all(frame).await.0.expect("the header sent");
            let (sent, reason) = flood(&connection, &mut [control]).await;
            assert_refused(sent, reason.as_ref());
        });
    }

    /// §5.2, §10.5: a connection that does not end within 10 s of its `GOAWAY`, for a request that does not, is closed
    /// with `H3_EXCESSIVE_LOAD`.
    #[test]
    fn s10_5_a_connection_that_does_not_end_after_goaway_is_closed() {
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, &upstream);
        Runtime::new().expect("a runtime").block_on(async {
            // Pinged, so as not to end for being idle meanwhile.
            let keep_alive = Some(Duration::from_secs(1));
            let (connection, _driver, mut requests) =
                h3_connected(server.addr, &ca, keep_alive).await;
            past_budget(&connection, &mut requests, server.addr).await;
            // Well after the server saw the budget passed: its request read gives up 10 s after the request came, the
            // connection is closed 10 s after the budget.
            compio::time::sleep(Duration::from_secs(1)).await;
            let request =
                http::Request::post(format!("https://{NAME}:{}/dns-query", server.addr.port()))
                    .header("content-type", "application/dns-message")
                    .body(())
                    .expect("a request");
            let _stream = requests.send_request(request).await.expect("a stream");
            let code = closed(&connection, Duration::from_secs(15)).await;
            assert_eq!(code, Some(Ok(H3_EXCESSIVE_LOAD)));
        });
    }

    /// §5.2: a connection that passed its budget is sent `GOAWAY`, not closed: 60 000 requests of a client, which pass the
    /// budget (some 25 000 requests) twice, are all answered, each on a connection that opens as the one before ends. The
    /// client is `dedens`' own, which opens another connection after `GOAWAY` and after a request the server refused
    /// (D83), with one try: a request cut by a close would fail.
    #[test]
    fn s5_2_a_busy_connection_is_rotated_not_closed() {
        const QUERIES: usize = 60_000;
        const BATCH: usize = 100;
        let upstream = Responder::start(&["a"]);
        let ca = certificates();
        let server = serving(&ca, &upstream);
        let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
        let mut options = Options::default();
        options.transport = Transport::Https;
        options.tries = NonZero::<u8>::MIN;
        let query = dedens_testkit::query("a", 0);
        Runtime::new().expect("a runtime").block_on(async {
            for _ in 0..QUERIES / BATCH {
                let answers =
                    join_all((0..BATCH).map(|_| {
                        client.exchange(query.clone(), named(server.addr, NAME), &options)
                    }))
                    .await;
                for answer in answers {
                    let answer = answer.expect("an answer");
                    assert_eq!(decode(&answer.wire).rcode(), Rcode::NOERROR);
                }
            }
        });
        assert_eq!(upstream.queries().len(), QUERIES);
        let rotations = server
            .stderr()
            .iter()
            .filter(|line| line.contains("GOAWAY"))
            .count();
        assert!(rotations >= 2, "{rotations} connections sent GOAWAY");
    }
}
