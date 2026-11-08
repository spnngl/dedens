# dedens-net

DNS transports (UDP, TCP, TLS, QUIC, DoH over HTTP/3, DoC) on compio (D4, D60, D61, D83, D81): the only library
crate that touches sockets and timers.

- `src/exchange.rs`: the sans-IO exchange of one query (D26, D27, D31), fed bytes and time; no socket, no clock,
  no randomness.
- `src/io.rs`: the seam (D134): `Io`, the clock, tasks, timers, randomness and sockets the UDP and TCP pools and
  `Client` use; `Compio` is production, `dedens-sim` supplies another. `clippy.toml` bans the direct calls in
  `udp.rs`, `tcp.rs` and `client.rs`; it repeats the root `clippy.toml` first, which it replaces for this crate.
- `src/udp.rs`, `src/tcp.rs`: the transports, thin over `Io`; `udp.rs` muxes queries on a pool of sockets
  per server (D50), a few datagrams kept per query (D108); `tcp.rs` keeps one connection per server, TCP or TLS,
  writing the queries queued meanwhile together, a bounded queue (D108).
- `src/tls.rs`: the certificates trusted and the TLS configurations (D60).
- `src/dial.rs`: the QUIC endpoints and connections of DoQ and DoH, and the per-server slots holding them; the
  client's receive windows (D119), no QUIC datagrams (D107).
- `src/quic.rs`: one QUIC connection per server, a stream per query, closed on a response not framed (D61, D109); the
  receive windows of both sides (`RECEIVE_WINDOW`, `STREAM_RECEIVE_WINDOW`, `CLIENT_RECEIVE_WINDOW`, D119).
- `src/http3.rs`: HTTP/3, client and server: one connection per server, a request stream per query, opened again
  after GOAWAY or a close (D83), the `h3` crate's connection driver run as a task; the server's `Requests` and
  `Incoming` (D84).
- `src/doh.rs`: the sans-IO core of DoH (D82), for client, server and ODoH, on `http` types, no HTTP version: URI
  templates, requests and responses, the server's reading of a request and its response; fuzzed by
  `parse_doh_template`, `server_request` and `read_doh_response`.
- `src/coap/`: the sans-IO CoAP codec and exchanges of DoC (D80): `message.rs` (RFC 7252 messages, options, codes),
  `block.rs` (RFC 7959 Block options, reassembly, slicing), `exchange.rs` (client: retransmission, matching,
  separate responses, block-wise transfers), `server.rs` (deduplication of CON and NON requests, responses kept for the next blocks, D105), `dns.rs` (the
  FETCH request of a query, the path of a `docpath`, the `/.well-known/core` request and the server's list of its
  resource, D95), `link.rs` (RFC 6690 link lists, and the path a link names on a server); no socket, no clock, no
  randomness; fuzzed by `parse_coap` and `parse_link_format`.
- `src/odoh/mod.rs`, feature `odoh`: Oblivious DoH over `http3.rs` (D79): the requests, responses and target
  classifier on `http` types, which send nothing themselves, and `Entropy`, the system's randomness; fuzzed by
  `read_odoh_http`. `src/odoh/client.rs`: the configurations cache and the exchange, run by
  `Client::exchange_oblivious`. `src/odoh/proxy.rs` is the proxy's side (D94): routing a request, the listed
  `Target`s, the forwarded request and response, the `Proxy-Status` errors; fuzzed by `read_odoh_http`.
- `src/doc.rs` (feature `doc`, D81): DoC over a UDP socket per query, CoAP's retransmission, the Max-Age added to the TTLs, all
  ended at the query's deadline (D109);
  the discovery of the resource by `/.well-known/core` (D95).
- `src/client.rs`: the exchange run over the transports, with random IDs, the spare IDs of its fallbacks (D114) and
  cookies per server.
- `src/resolv_conf.rs`: `/etc/resolv.conf` read (servers, search list, ndots); fuzzed by `parse_resolv_conf`.
- `tests/rfcNNNN.rs`: the exchange driven by hand; `rfc7858.rs`, `rfc9250.rs`, `rfc9221.rs`, `rfc8484.rs` and `rfc9230.rs`
  against loopback TLS, QUIC and HTTP/3 servers too, with certificates of `dedens_testkit::certificates`.
  `tests/udp.rs`, `tests/tcp.rs`, `tests/client.rs`: the transports and the client against scripted servers on the loopback address
  (`tests/common/loopback.rs`); `tests/common/` builds messages and steps. `rfc8484.rs` and `rfc9461.rs` run
  `doh` on the RFC examples and on the responses of public servers in `testdata/doh/` (`capture.nu` has
  the commands). `rfc7252.rs`, `rfc7959.rs` and `rfc8132.rs` drive `coap` on the RFC figures and on the
  datagrams of aiocoap in `testdata/coap/` (`capture.nu` has the commands; `tests/coap_capture/` reads them).
  `rfc6690.rs` reads the link lists of the RFC. `rfc9953.rs` (feature `doc`) runs the DoC client against a scripted CoAP
  server on loopback. The one ignored test of `rfc9230.rs` asks public ODoH targets (`just odoh-live`).

`benches/transports.rs` runs DoQ and DoH3 against loopback servers (`cargo bench -p dedens-net --bench transports`);
`benches/pools.rs` the UDP and TCP pools of the `Client` (`--bench pools`).
Measure a transport change with `just bench-dnsperf <base> forward` or `forward-tcp`.
