# To decide

Open questions, each with its proposed default. Once answered, record the outcome in
[`decisions.md`](decisions.md) under a new number and delete it here.

## Server forwarder

- Upstream TCP: a connection pool per upstream (size, idle timeout, reuse across workers) instead of D27's one
  connection per server? Default: decide with the forwarder's load tests.

## Later

- Renewing the pooled upstream UDP sockets (D50) now and then, for the port entropy of RFC 5452 §9.2 against
  an attacker who learned a kept port. Default: keep the sockets, relying on `0x20` and cookies.
- Client allow and block lists (RFC 5358: no open resolver): networks allowed to query, others REFUSED.
  Default: a stage or core setting, loopback and private ranges allowed when unset; networks in a
  longest-prefix tree (as HAProxy's `ip` match), never a list scanned, also for blocking by answer address.
- Steering each datagram to the socket of the CPU that received it: `SO_INCOMING_CPU` on each thread's socket
  (the kernel's `SO_REUSEPORT` choice prefers it: `reuseport_select_sock_by_hash`) and threads pinned to their CPUs, or a
  `SO_REUSEPORT_CBPF` program. Default: wait for a benchmark between two machines; on loopback the sender's
  CPU handles the packet, so `just bench-dnsperf` cannot show it.
- Counters shared by all threads (`metrics` atomics) once an exporter is installed: every thread writes the same
  cache lines. Default: per-thread counters summed by the exporter, measured with it.
- Changing a blocklist or hosts list while running, without a reload (HAProxy's `add map`, `del map`), through
  a control socket. Default: with the metrics exporter's HTTP endpoint, or a socket of its own.
- Coalescing identical upstream queries in flight (RFC 5452 §5): later ones wait on the first exchange.
  Default: a per-thread map by cache key, with dnsperf numbers.
- Replies from a wildcard UDP listener leave from the address the query came to (`IP_PKTINFO`). Default: add
  when a multihomed deployment needs it.
- Scrubbing upstream answers of records outside the question's CNAME chain and bailiwick. Default: with the
  recursive resolver.
- An AF_XDP UDP listener (eBPF steering datagrams into our memory, past the kernel's network stack, as Knot DNS
  does): we would build IP and UDP headers ourselves; it needs root and per-NIC setup, does no TCP, and cannot
  be measured on loopback. Default: a later optional listener mode, benchmarked between two machines.
- Cache lock contention: one mutex per shard, and DNS traffic concentrates on few names (8 threads on one
  name: 364 ns a hit, against about 100 ns on one thread). Default: measure under the server's thread-per-core
  load first, then pick: read-mostly hot entries, per-core copies, or a lock-free read path.
- An encoder that also returns the TTL offsets it wrote, so `Cache::insert` skips its own pass over the
  response bytes. Default: add it when that pass shows in a profile of the server.
- SIMD base64 and hex for DNSSEC keys and signatures in zone text (`text/encoding.rs` decodes a byte at a time
  through a table): `core::arch` per CPU, since `std::simd` is nightly-only. Default: when DNSSEC lands, bench
  the `base64-simd` crate and our table against a signed zone; `unsafe` only if it wins.
- `RecordType` constants for TKEY, TSIG, MAILA and MAILB: the cache tests and its meta-type check use the raw
  numbers. Default: add them with TSIG, in the authoritative phase.
- Order after the server forwarder: kubernetes stage, recursive resolver (with an RRset cache, priming per
  RFC 8109, BCP 123 behaviour per RFC 4697), authoritative (zones, AXFR/IXFR, NOTIFY, UPDATE, TSIG, RFC 2182),
  DNSSEC, then ODoH (RFC 9230) and DoC (RFC 9953) as experimental; the error reporting option
  (RFC 9567) with the server.
- A `rewrite` plugin (renaming query names, exact or by suffix, as `CoreDNS`'s `rewrite name`, names in the
  response mapped back). Default: after the plugins that need no upstream step, as D54 plugins cannot yet
  touch an upstream exchange.
- Blocklists downloaded from URLs and refreshed, with allow-exceptions. A refresh replaces only the list, as
  HAProxy's `prepare map` and `commit` do, keeping the pipeline and its cache. Then a compact list (names in one
  buffer with a table of offsets, or 64-bit hashes only, against a `HashSet` of boxed names), with a bench and
  its memory on a real downloaded list.
- A systemd-resolved replacement plugin for desktop Linux: the stub on 127.0.0.53, per-link servers and
  routing domains pushed over D-Bus `org.freedesktop.resolve1` by NetworkManager and systemd-networkd,
  `stub-resolv.conf`, `/etc/hosts`, the synthesized names (localhost, the hostname, `_gateway`). Default:
  study the interfaces it must keep (`src/resolve/` of systemd) after reload lands; dynamic upstreams need it.
- Dynamic stage loading (D23): WASM or gRPC, as one stage type after a cache miss, or never. Against: Vector
  dropped its WASM transform; a Rust dylib needs an ABI workaround; gRPC costs milliseconds.
- A small typed rule language for matchers (D23), beyond declarative matchers.
- crates.io publishing, a container image, dnsperf benchmarks against Unbound and CoreDNS.
- A fuzz target for `dedensd`'s configuration reader (`apps/dedensd/src/config.rs`), which needs the reader in a
  library crate. Default: move it to `dedens-server` when reload comes.
