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
  Default: validated; a setting of the validator marking algorithms 5 and 7 unsupported, which
  needs a filter on the DS records and RRSIGs that `rrsig` does not have (D75 leaves it out).
- Trust anchor rollover (RFC 5011): follow a root key roll while running. Default: bundled anchors and anchor
  files only, replaced by hand; automate in the recursive phase, when a daemon holds state.
- NTA end time (RFC 7646 §2.1 SHOULD): a negative trust anchor lasts as long as the `TrustAnchors` holding it
  (D72). Default: none, the caller drops it (`--insecure NAME`, `insecure:` in the configuration); an `until` with the
  clock passed in when `dedensd` keeps state across reloads.
- `+trace +validate` (D76 refuses it): validate each hop, a referral by `start_referral` and the answer by `start`,
  asking DS and DNSKEY of the servers the trace reached. Default: refused; `+validate @server` is the way to a verdict.
- Key cache, lock (D86, D92): one `Mutex` over two tables, which a hit takes too (it moves the entry in the LRU
  order). Default: as is; shards by name, or an `RwLock` with a lazier LRU, when `dedensd`'s load tests show the
  lock contended.
- Singleflight (D86): the validator's questions in flight are shared, but each query still verifies what it
  learns, and the client's own question is each query's. A query walking a zone another walks verifies the zone
  again. Default: as is; a `Next::Wait` (the validator asks the caller to park on a zone another validation
  settles), or coalescing the client's question of a forwarder that has no cache stage, when a load test shows the
  duplicate checks or upstream traffic costing.
- ODoH suites other than RFC 9230 §9's (X25519, HKDF-SHA256, AES-128-GCM) (D78): P-256, P-384, HKDF-SHA384,
  AES-256-GCM, ChaCha20-Poly1305. Default: skipped in the configs a target publishes; add one when a target in use
  asks for it.
- ODoH target keys (D78, D79): `dedensd` serves one key, from `odoh.key` or made at start. Default: replaced by hand
  with a restart; several keys served at once (the configurations list them, a client picks the first) and rotation
  with an overlap, when a daemon holds state.
- ODoH proxy role (D79): `dedensd` as the proxy of RFC 9230 §4 (forwards the POST to `targethost` and `targetpath`;
  §4.1's checks: no non-standard port, 502 when the target is unreachable, no caching, no redirects). Default: out of
  this phase, `dedensd` is a target only.
- ODoH configurations discovery (D79): fetched from `/.well-known/odohconfigs` of the target, straight to it, so the
  target sees the client's address, and the query that follows may be linked to it by timing; `dedens` keeps them an
  hour at least (a longer-lived `dedensd` client fetches rarely) and warns when the target forbids keeping them, but
  a one-shot `dedens` fetches each run: `+odoh-config=FILE` is its way out. Alternatives: through the proxy (needs a
  proxy that relays GET), from the target's SVCB record (RFC 9460; the ODoH SVCB parameters are not in an RFC), a
  fetch at a random time apart from the query. Default: well-known, direct.
- ODoH target throttle (D79): `dedensd` opens every POST of the media type, an X25519 decapsulation and an AEAD open,
  before it knows the sender; the proxy of RFC 9230 §4 is no authentication, and the limit per address
  (D90) is the deployment's, in front of `dedensd`. Default: none.
- ODoH proxy URI templates (D79): RFC 9230 §4.1 gives the proxy as a URI Template (RFC 6570) with `targethost` and
  `targetpath` variables; `+odoh-proxy` takes a plain URI and appends the two as a query. Default: plain URIs only,
  one that already holds the variables is refused; the two simple expansions when a proxy in use needs one.
- ODoH over HTTP/2 (D79): `odoh-relay.edgecompute.app` speaks HTTP/3, but it refuses one target (403 for
  `doh.tiarap.org`) and other public proxies may speak HTTP/2 only. Default: HTTP/3 only (D83); step 23 when a proxy
  in use needs HTTP/2.
- A mix of NSEC and NSEC3 records in one response (D74 uses the NSEC3 and ignores the NSEC; RFC 5155 §8.2 does not say).
  Default: as D74; bogus if a zone shows it.
- CoAP (D80): non-confirmable requests by the client (RFC 7252 §4.3) and server-side Block1 reassembly (a DoC query
  fits one datagram, so a server needs neither). Default: not built until DoC meets a server that needs them.
- DoC (D81): the proxy parts of RFC 9953, §9.2 redirects (a 3.xx or 5.03 with Location-*) and §9.3 hop limit
  (RFC 8768), are ignored by the client and the server. Default: not built until DoC meets a CoAP proxy to forward to.
- DoC (D81): DTLS (`coaps://`, RFC 9953 §6) and OSCORE (§5.2), needing a CoAP-level security stack. Default: not
  before phase 4 asks for an encrypted DoC; the unprotected listener warns at start.
- DoC (D81): a `coap://` upstream of the `forward` stage, the discovery of a server by SVCB `docpath` or
  `rt=core.dns` (§3), GET with `?dns=` (RFC 9953 does not define it), server-side Block1 reassembly. Default: not
  built.
- Aggressive use of the cache for denial (RFC 8198). Default: not before the recursive resolver's cache.
- Key tag signalling (RFC 8145) and the trust anchor sentinel (RFC 8509). Default: not sent.
- Clock skew when checking signature windows (RFC 4035 §5.3.1). Default: none, the clock as given, with the
  window's edges inclusive; an option when a deployment shows it.
- Validating forwarder (D77): the BAD-cache threshold of RFC 4035 §4.7 (answer from the bad cache only after N
  failures). Default: none, a bogus verdict is cached at once for 60 s, as Unbound does.
- Validating forwarder (D77): an EDE on an answer cached as insecure (the stored bytes carry no OPT), and the text of
  an EDE (the reply's OPT holds the code only). Default: neither; the code is on a bogus or indeterminate SERVFAIL.
- Validating forwarder (D77): an answer proved insecure is cached for the response cache's `max_ttl`, 7 days, against
  a day for keys (D86), so a zone that turns secure serves its old insecure answers that long (AD is never set on
  them). Default: as is; a lower insecure TTL if a deployment shows the need.
- Validating forwarder (D77): Bogus and indeterminate counts are per query, not per zone; no `trust_anchors` reload
  without a configuration reload. Default: none.
- Validating forwarder (D77): the cost of a query upstream. A bogus answer Response::build refuses to cache (a NODATA
  without SOA, TTL 0) is validated again on each query; up to 64 questions hold one upstream slot until a verdict;
  no deadline per query; the dead server is skipped for one query only. Default: as is; a per-query deadline if a
  deployment shows the need.
- Validating forwarder (D77): the allowance is one bucket for all clients and has no knob in the configuration
  (`Allowance` defaults), and a unit weighs the same for every algorithm (a P-384 check takes 12 times a P-256
  one). Default: global, fixed (a limit per source is the deployment's, D90); `dnssec_allowance:` keys when a
  deployment hits the default, units weighted by algorithm
  when one signs with P-384 to burn the bucket's CPU.
- Validating forwarder (D77): an upstream SERVFAIL or REFUSED for the client's question, and a held failure, reply a
  bare SERVFAIL, with no EDE 22 (No Reachable Authority) or 23 (Network Error). Default: bare.

## Later

- DoH servers where HTTP/3 does not answer (21 of the 44 URLs of `providers.yaml`, November 2026): 19 do not
  advertise `h3`; the two of UncensoredDNS do, but the QUIC handshake stalls after their first flight. They sit
  under `https_h2`, parsed but not asked, until HTTP/2 (step 23). Default: find whether our client or their
  server is at fault for UncensoredDNS.
- Upstream DoH servers by host name (`servers: ["https://dns.quad9.net/dns-query"]`): D65 takes an address only, so
  `https://IP[:PORT][/PATH][#NAME]` is what `dedensd` reads (D84). Default: a host name resolved at start and on
  reload by the system resolver, the first address kept, once `dedensd` has a way to refresh it.
- `dedensd`'s `https://` listener serves any `Host` or `:authority` on its path, and the pipeline has no client
  address (the QUIC peer's) to give stages. Default: serve any, add the address when a stage needs it.
- `dedens -f` aborts the whole run when one server's host name does not resolve (`failed to lookup address
  information`, macOS for `doh.dns.sb`, a CNAME chain), where one query should fail alone. Default: resolve per
  query, as the exchange errors are.

- QUIC connections sharing the client's one UDP socket per address family (`crates/dedens-net/src/quic.rs`):
  over IPv6, two at once to NextDNS (`2a07:a8c0::`, `2a07:a8c1::`) or to Control D (`2606:1a40::11` under two
  names) often time out, one per process never does; IPv4 does not show it. Default: find whether the servers'
  load balancers or quinn cause it before giving each connection its own socket.
- Renewing the pooled upstream UDP sockets (D50) now and then, for the port entropy of RFC 5452 §9.2 against
  an attacker who learned a kept port. Default: keep the sockets, relying on `0x20` and cookies.
- QUIC datagram without control data (D89): `compio-io`'s `CMsgIter::new` panics on an empty control buffer, which
  macOS gives for a datagram queued before the socket options were set. Default: as is (`serving` waits for the
  endpoints); an upstream fix (accept an empty buffer), then drop the note.
- Client allow and block lists (RFC 5358: no open resolver): networks allowed to query, others REFUSED. Rate limits
  and a cap of connections per address are the deployment's, not `dedensd`'s (D90). Default: a stage or core setting, loopback and private ranges
  allowed when unset; networks in a longest-prefix tree (as HAProxy's `ip` match), never a list scanned, also for
  blocking by answer address.
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
- Order after phase 4 (DoH over HTTP/3, DNSSEC validation, ODoH and DoC, all merged): prewarm (names from the
  configuration kept in the cache), DNSCrypt (client, server, Anonymized DNSCrypt client, PQDNSCrypt; the
  relay role later), kubernetes stage, recursive resolver (with an RRset cache, priming per RFC 8109, BCP 123 behaviour per RFC 4697), authoritative (zones,
  AXFR/IXFR, NOTIFY, UPDATE, TSIG, RFC 2182); the error reporting option (RFC 9567) with the server; DoH over
  HTTP/2 once compio releases tokio's I/O traits (D62).
- An Anonymized DNSCrypt relay in `dedensd` (the draft's "Forwarding and Validation"): an open relay forwards
  for anyone, so it needs an address and port policy and abuse limits. Default: after the client side.
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
