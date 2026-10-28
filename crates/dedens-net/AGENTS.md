# dedens-net

DNS transports (UDP, TCP, later DoT, DoH, DoQ) on compio (D4): the only crate that touches sockets and timers.

- `src/exchange.rs`: the sans-IO exchange of one query (D26, D27, D31), fed bytes and time; no socket, no clock,
  no randomness.
- `tests/rfcNNNN.rs`: the exchange driven by hand, one file per RFC; `tests/common/` builds messages and steps.

Open questions are in `docs/TODECIDE.md`.
