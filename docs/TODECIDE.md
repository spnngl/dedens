# To decide

Open questions, each with its proposed default. Once answered, record the outcome in
[`decisions.md`](decisions.md) under a new number and delete it here.

## Server forwarder (phase 7)

- Upstream UDP: a pool of N sockets on random ports, renewed often, queries muxed by ID and question, with
  cookies and `0x20` to win back the entropy a fixed port loses (D27)? Default: decide with dnsperf numbers
  against one socket per query.
- Upstream TCP: a connection pool per upstream (size, idle timeout, reuse across workers) instead of D27's one
  connection per server? Default: decide with the forwarder's load tests.

- Limits: TCP connections per listener, queries in flight per connection and per thread (RFC 7766 §6.2.2),
  so a client cannot hold every socket or task. Default: per-thread caps in the configuration step, refusing
  new connections past them.

## Later

- Cache lock contention: one mutex per shard, and DNS traffic concentrates on few names (8 threads on one
  name: 364 ns a hit, against about 100 ns on one thread). Measure under the server's thread-per-core load
  first, then pick: read-mostly hot entries, per-core copies, or a lock-free read path.
- An encoder that also returns the TTL offsets it wrote, so `Cache::insert` skips its own pass over the
  response bytes. Default: add it when that pass shows in a profile of the server.
- `RecordType` constants for TKEY, TSIG, MAILA and MAILB: the cache tests and its meta-type check use the raw
  numbers. Default: add them with TSIG, in the authoritative phase.
- Order after the server forwarder: kubernetes stage, recursive resolver (with an RRset cache, priming per
  RFC 8109, BCP 123 behaviour per RFC 4697), authoritative (zones, AXFR/IXFR, NOTIFY, UPDATE, TSIG, RFC 2182),
  DNSSEC, DoT/DoH/DoQ, then ODoH (RFC 9230) and DoC (RFC 9953) as experimental; the error reporting option
  (RFC 9567) with the server.
- Server reload: what needs a restart (listeners, thread count); decided when the server starts.
- Dynamic stage loading (D23): WASM or gRPC, as one stage type after a cache miss, or never. Against: Vector
  dropped its WASM transform; a Rust dylib needs an ABI workaround; gRPC costs milliseconds.
- A small typed rule language for matchers (D23), beyond declarative matchers.
- crates.io publishing, a container image, dnsperf benchmarks against Unbound and CoreDNS.
