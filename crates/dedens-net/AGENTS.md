# dedens-net

DNS transports (UDP, TCP, later DoT, DoH, DoQ) on compio (D4): the only crate that touches sockets and timers.

- `src/exchange.rs`: the sans-IO exchange of one query (D26, D27, D31), fed bytes and time; no socket, no clock,
  no randomness.
- `src/udp.rs`, `src/tcp.rs`: the transports, thin over compio; `tcp.rs` keeps one connection per server.
- `src/client.rs`: the exchange run over the transports, with random IDs and cookies per server.
- `tests/rfcNNNN.rs`: the exchange driven by hand, one file per RFC; `tests/udp.rs`, `tests/tcp.rs`, `tests/client.rs`:
  the transports and the client against scripted servers on the loopback address (`tests/common/loopback.rs`); `tests/common/` builds messages and
  steps.

Open questions are in `docs/TODECIDE.md`.
