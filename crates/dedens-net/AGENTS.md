# dedens-net

DNS transports (UDP, TCP, TLS, QUIC; DoH over HTTP/3 to come, D82) on compio (D4, D60, D61): the only library
crate that touches sockets and timers.

- `src/exchange.rs`: the sans-IO exchange of one query (D26, D27, D31), fed bytes and time; no socket, no clock,
  no randomness.
- `src/udp.rs`, `src/tcp.rs`: the transports, thin over compio; `udp.rs` muxes queries on a pool of sockets
  per server (D50), `tcp.rs` keeps one connection per server, TCP or TLS, writing the queries queued meanwhile
  together.
- `src/tls.rs`: the certificates trusted and the TLS configurations (D60).
- `src/quic.rs`: one QUIC connection per server, a stream per query (D61).
- `src/doh.rs`: the sans-IO core of DoH (D82), for client, server and ODoH, on `http` types, no HTTP version: URI
  templates, requests and responses, the server's reading of a request and its response; fuzzed by
  `parse_doh_template`, `server_request` and `read_doh_response`.
- `src/client.rs`: the exchange run over the transports, with random IDs and cookies per server.
- `src/resolv_conf.rs`: `/etc/resolv.conf` read (servers, search list, ndots); fuzzed by `parse_resolv_conf`.
- `tests/rfcNNNN.rs`: the exchange driven by hand; `rfc7858.rs` and `rfc9250.rs` against loopback TLS and QUIC
  servers too, with certificates of `tests/common/certificates.rs`. `tests/udp.rs`, `tests/tcp.rs`,
  `tests/client.rs`: the transports and the client against scripted servers on the loopback address
  (`tests/common/loopback.rs`); `tests/common/` builds messages and steps. `rfc8484.rs` and `rfc9461.rs` run
  `doh` on the RFC examples and on the responses of public servers in `tests/testdata/doh/` (`capture.nu` has
  the commands).

Measure a transport change with `just bench-dnsperf <base> forward` or `forward-tcp`.
