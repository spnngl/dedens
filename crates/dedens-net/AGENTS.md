# dedens-net

DNS transports (UDP, TCP, later DoT, DoH, DoQ) on compio (D4): the only library crate that touches sockets and
timers.

- `src/exchange.rs`: the sans-IO exchange of one query (D26, D27, D31), fed bytes and time; no socket, no clock,
  no randomness.
- `src/udp.rs`, `src/tcp.rs`: the transports, thin over compio; `udp.rs` muxes queries on a pool of sockets
  per server (D50), `tcp.rs` keeps one connection per server, writing the queries queued meanwhile together.
- `src/client.rs`: the exchange run over the transports, with random IDs and cookies per server.
- `src/resolv_conf.rs`: `/etc/resolv.conf` read (servers, search list, ndots); fuzzed by `parse_resolv_conf`.
- `tests/rfcNNNN.rs`: the exchange driven by hand; `tests/udp.rs`, `tests/tcp.rs`, `tests/client.rs`: the
  transports and the client against scripted servers on the loopback address (`tests/common/loopback.rs`);
  `tests/common/` builds messages and steps.

Measure a transport change with `just bench-dnsperf <base> forward` or `forward-tcp`.
