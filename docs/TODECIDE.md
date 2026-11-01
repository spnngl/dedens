# To decide

Open questions, each with its proposed default. Once answered, record the outcome in
[`decisions.md`](decisions.md) under a new number and delete it here.

## Server forwarder

- Upstream TCP: a connection pool per upstream (size, idle timeout, reuse across workers) instead of D27's one
  connection per server? Default: decide with the forwarder's load tests.

## DNSSEC and experimental transports

- ODoQ (Oblivious DNS over QUIC): no RFC exists. Default: dropped; revisit when the IETF publishes one.
- Ed448 (algorithm 16, RFC 8080): `ring` has no Ed448. Default: unsupported, so a zone signed with it is
  insecure (RFC 6840 §5.2); a pure-Rust crate only if a signed zone in use needs it.
- SHA-1 switch: RFC 9905 §2 tells operators of validating resolvers to treat RSASHA1, RSASHA1-NSEC3-SHA1 and their
  DS records as unsupported (insecure), and implementations to keep validating them (D71 validates by default).
  Default: validated; a setting of the validator marking algorithms 5 and 7 unsupported, added with 06.
- Trust anchor rollover (RFC 5011): follow a root key roll while running. Default: bundled anchors and anchor
  files only, replaced by hand; automate in the recursive phase, when a daemon holds state.
- NTA end time (RFC 7646 §2.1 SHOULD): a negative trust anchor lasts as long as the `TrustAnchors` holding it
  (D72). Default: none, the caller drops it (`--insecure NAME`, `insecure:` in the configuration); an `until` with the
  clock passed in when `dedensd` keeps state across reloads.
- Aggressive use of the cache for denial (RFC 8198). Default: not before the recursive resolver's cache.
- Key tag signalling (RFC 8145) and the trust anchor sentinel (RFC 8509). Default: not sent.
- Clock skew when checking signature windows (RFC 4035 §5.3.1). Default: none, the clock as given, with the
  window's edges inclusive; an option when a deployment shows it.

## Later

- DoH servers where HTTP/3 does not answer (21 of the 44 URLs of `providers.yaml`, November 2026): 19 do not
  advertise `h3`; the two of UncensoredDNS do, but the QUIC handshake stalls after their first flight. They sit
  under `https_h2`, parsed but not asked, until HTTP/2 (step 23). Default: find whether our client or their
  server is at fault for UncensoredDNS.
- `dedens -f` aborts the whole run when one server's host name does not resolve (`failed to lookup address
  information`, macOS for `doh.dns.sb`, a CNAME chain), where one query should fail alone. Default: resolve per
  query, as the exchange errors are.

- QUIC connections sharing the client's one UDP socket per address family (`crates/dedens-net/src/quic.rs`):
  over IPv6, two at once to NextDNS (`2a07:a8c0::`, `2a07:a8c1::`) or to Control D (`2606:1a40::11` under two
  names) often time out, one per process never does; IPv4 does not show it. Default: find whether the servers'
  load balancers or quinn cause it before giving each connection its own socket.
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
- Order after the server forwarder: DoH over HTTP/3 and DNSSEC validation (`plan/4-dnssec-experimental`),
  DoH over HTTP/2 once compio releases tokio's I/O traits (D62), kubernetes stage, recursive resolver (with an RRset cache, priming per
  RFC 8109, BCP 123 behaviour per RFC 4697), authoritative (zones, AXFR/IXFR, NOTIFY, UPDATE, TSIG, RFC 2182),
  then ODoH (RFC 9230) and DoC (RFC 9953) as experimental; the error reporting option (RFC 9567) with the
  server.
- A `rewrite` plugin (renaming query names, exact or by suffix, as `CoreDNS`'s `rewrite name`, names in the
  response mapped back). Default: after the plugins that need no upstream step, as D54 plugins cannot yet
  touch an upstream exchange.
- A systemd-resolved replacement plugin for desktop Linux: the stub on 127.0.0.53, per-link servers and
  routing domains pushed over D-Bus `org.freedesktop.resolve1` by NetworkManager and systemd-networkd,
  `stub-resolv.conf`, `/etc/hosts`, the synthesized names (localhost, the hostname, `_gateway`). Default:
  study the interfaces it must keep (`src/resolve/` of systemd); its upstreams change at run time, as reload
  (D55) does not.
- Dynamic stage loading (D23): WASM or gRPC, as one stage type after a cache miss, or never. Against: Vector
  dropped its WASM transform; a Rust dylib needs an ABI workaround; gRPC costs milliseconds.
- A small typed rule language for matchers (D23), beyond declarative matchers.
- crates.io publishing, a container image, dnsperf benchmarks against Unbound and CoreDNS.
- A fuzz target for `dedensd`'s configuration reader (`apps/dedensd/src/config.rs`), which needs the reader in a
  library crate. Default: move the reader to `dedens-server` with the next change to the configuration.
