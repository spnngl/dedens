# dedens-net

DNS transports (UDP, TCP, TLS, QUIC, DoH over HTTP/3, DoC) on compio (D4, D60, D61, D83, D81): the only library
crate that touches sockets and timers.

- `src/exchange.rs`: the sans-IO exchange of one query (D26, D27, D31), fed bytes and time; no socket, no clock,
  no randomness.
- `src/udp.rs`, `src/tcp.rs`: the transports, thin over compio; `udp.rs` muxes queries on a pool of sockets
  per server (D50), `tcp.rs` keeps one connection per server, TCP or TLS, writing the queries queued meanwhile
  together.
- `src/tls.rs`: the certificates trusted and the TLS configurations (D60).
- `src/dial.rs`: the QUIC endpoints and connections of DoQ and DoH, and the per-server slots holding them.
- `src/quic.rs`: one QUIC connection per server, a stream per query (D61).
- `src/https.rs`: one HTTP/3 connection per server, a request stream per query, opened again after GOAWAY or a
  close (D83); the `h3` crate's connection driver runs as a task.
- `src/doh.rs`: the sans-IO core of DoH (D82), for client, server and ODoH, on `http` types, no HTTP version: URI
  templates, requests and responses, the server's reading of a request and its response; fuzzed by
  `parse_doh_template`, `server_request` and `read_doh_response`.
- `src/coap/`: the sans-IO CoAP codec and exchanges of DoC (D80): `message.rs` (RFC 7252 messages, options, codes),
  `block.rs` (RFC 7959 Block options, reassembly, slicing), `exchange.rs` (client: retransmission, matching,
  separate responses, block-wise transfers), `server.rs` (deduplication of confirmable requests), `doc.rs` (the
  FETCH request of a query, the path of a `docpath`); no socket, no clock, no randomness; fuzzed by `parse_coap`.
- `src/doc.rs` (feature `doc`, D81): DoC over a UDP socket per query, CoAP''s retransmission, the Max-Age added to the TTLs.
- `src/client.rs`: the exchange run over the transports, with random IDs and cookies per server.
- `src/resolv_conf.rs`: `/etc/resolv.conf` read (servers, search list, ndots); fuzzed by `parse_resolv_conf`.
- `tests/rfcNNNN.rs`: the exchange driven by hand; `rfc7858.rs`, `rfc9250.rs` and `rfc8484.rs` against loopback
  TLS, QUIC and HTTP/3 servers too, with certificates of `tests/common/certificates.rs`. `tests/udp.rs`, `tests/tcp.rs`,
  `tests/client.rs`: the transports and the client against scripted servers on the loopback address
  (`tests/common/loopback.rs`); `tests/common/` builds messages and steps. `rfc8484.rs` and `rfc9461.rs` run
  `doh` on the RFC examples and on the responses of public servers in `tests/testdata/doh/` (`capture.nu` has
  the commands). `rfc7252.rs`, `rfc7959.rs` and `rfc8132.rs` drive `coap` on the RFC figures and on the
  datagrams of aiocoap in `tests/testdata/coap/` (`capture.nu` has the commands; `tests/coap_capture/` reads them).
  `rfc9953.rs` (feature `doc`) runs the DoC client against a scripted CoAP server on loopback.

`benches/transports.rs` runs DoQ and DoH3 against loopback servers (`cargo bench -p dedens-net --bench transports`).
Measure a transport change with `just bench-dnsperf <base> forward` or `forward-tcp`.
