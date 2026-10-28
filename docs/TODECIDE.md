# To decide

Open questions, each with its proposed default. Once answered, record the outcome in
[`decisions.md`](decisions.md) under a new number and delete it here.

## Phase 4: transports (`dedens-net`)

- Client API: one `Client` with `exchange(&Message, server, &Options)`, which handles retries, the TC fallback
  to TCP and EDNS? Default: yes, with UDP and TCP exchanges public beneath it.
- compio version: 0.19.2 (2026-08) or 0.20.0-beta.1? Default: 0.19.2, then 0.20 once released.
- UDP source port (RFC 5452 §9.2): a new connected socket on port 0 per query, so the OS picks a random port?
  Default: yes; the ID comes from a CSPRNG (`getrandom`).
- Response matching: source address, ID and question (case-insensitive, RFC 5452 §9.1); a mismatch is dropped and
  the wait goes on. Default: yes.
- Timeouts and retries: dig's `+time=5 +tries=3`? Default: yes, as `Options` fields.
- EDNS fallback: retry once without EDNS on FORMERR or NOTIMP to an EDNS query (RFC 6891 §7)? Default: yes; off
  with `+noednsneg` as in dig.
- Cookies (RFC 7873 §5.1, RFC 9018 for the server side later): client cookie = SipHash of a random per-process
  secret, client IP and server IP; server cookies kept per server in memory for the process. Default: yes.
- TCP (RFC 7766): one connection per server, pipelined queries matched by ID, out-of-order responses, idle
  close, edns-tcp-keepalive (RFC 7828) honoured. Default: yes; a connection pool waits for the server.
- Test server: an in-process compio server in `dedens-net`'s tests answering from scripts (delays, drops, TC,
  wrong ID, FORMERR, closed connections). Default: yes.

## Later

- Order after the server forwarder: kubernetes stage, recursive resolver (with an RRset cache), authoritative
  (zones, AXFR/IXFR, NOTIFY, UPDATE, TSIG), DNSSEC, DoT/DoH/DoQ.
- Server reload: what needs a restart (listeners, thread count); decided when the server starts.
- Dynamic stage loading (D23): WASM or gRPC, as one stage type after a cache miss, or never. Against: Vector
  dropped its WASM transform; a Rust dylib needs an ABI workaround; gRPC costs milliseconds.
- A small typed rule language for matchers (D23), beyond declarative matchers.
- crates.io publishing, a container image, dnsperf benchmarks against Unbound and CoreDNS.
