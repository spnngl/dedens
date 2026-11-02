# To decide

Open questions, each with its proposed default. Once answered, record the outcome in
[`decisions.md`](decisions.md) under a new number and delete it here.

## Server forwarder

- A QUIC endpoint whose worker panicked (D89, D121): the panic stays in a compio task, the endpoint goes deaf and
  `wait_incoming` never ends, so `dedensd` serves no DoQ or DoH over HTTP/3 on that socket and sees nothing. Detecting
  it needs a probe of the endpoint (a watchdog sending itself an Initial) or a compio change. Default: a compio
  change to surface worker panics, once one is proposed upstream.
- Bare `spawn`s in `dedens-net` whose panics nothing logs or counts (D121): the upstream UDP pool `crates/dedens-net/src/udp.rs:95`,
  the read and write halves of a TCP exchange `crates/dedens-net/src/tcp.rs:332` and `:450`, `crates/dedens-net/src/https.rs:223`.
  compio hides each; the client of a query then times out. Default: a `dedens-net` helper like `Origin::spawn` (a
  counter by name), once a second user of it exists.
- Export of `dedensd_task_panics_total` and `dedensd_listener_restarts_total` (D121): no exporter is installed
  (D30), so the counts go nowhere but the log. Default: with the Prometheus exporter.
- Upstream TCP: a connection pool per upstream (size, idle timeout, reuse across workers) instead of D27's one
  connection per server? Default: decide with the forwarder's load tests.
- Blocklist lookup of a 127-label name (D110): audit P4 asked it to cost under 3 times one of 3 labels; it costs
  5 times (`benches/blocklist.rs` `lookup`, `docs/benchmarks.md`), 15 times less than before. The rest is the walk
  that finds where each label starts: a name is read from its front, label by label, ~1.3 ns each. Default: as
  is, the name is the client's choice but 0.2 µs; store the label offsets in `Name` (a `dedens-proto` change) only if
  a profile of `dedensd` shows the walk.

- `trust_upstream_ad` (D114 clears upstream's AD without `dnssec: validate`): an opt-in per forward stage to pass
  it on (RFC 4035 §4.9.3), allowed only when every server of the stage is authenticated and encrypted (tls://,
  quic://, https:// with a trusted certificate); the cache would then store such answers with a verdict of their
  own, not `Unchecked`. Default: not offered; add when a deployment that cannot validate needs AD.

- HTTP/3 byte budget (D119): `dedensd` sends `GOAWAY` to an HTTP/3 connection after `BUDGET` bytes received, as h3
  0.0.8 buffers a frame of any declared length. A fix is written for hyperium/h3 (a declared length above a bound is
  refused before the frame is buffered, unknown frames discarded). Default: replace the budget (`src/h3_budget.rs` and
  its sweeper) by the fix once an h3 release with it is in compio's `h3` feature and `tests/rfc9114.rs` passes
  without it; keep the windows. Until then the rotation of honest connections stays.
- The client's side of the same (D119): the server a client dials is trusted by its operator, but h3 reads its control
  stream for the connection's life with no bound on a frame. Default: none; add the budget to `Dialer`'s HTTP/3
  connections if a deployment dials servers it does not run.

- Service manager and Kubernetes (D122): `dedensd` drops root itself with `user:`, but a unit should not start it as root at
  all. A systemd unit: `DynamicUser=yes` or `User=`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` and
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (no `user:` in the file: nothing to drop), `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `StateDirectory=dedensd` for the downloads `dir` (D104), `ExecReload=kill -HUP $MAINPID`
  (D55), and a `SystemCallFilter` that allows `io_uring_setup`, `io_uring_enter` and `io_uring_register`, or the threads
  serve on `poll`. Kubernetes (a later phase) sets `securityContext` instead (`runAsUser`, `runAsNonRoot`, `capabilities`
  with `NET_BIND_SERVICE`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, `fsGroup` for the key files):
  `user:` is left out there too. Default: write the unit with the packaging phase, and the manifest with the Kubernetes
  one. Socket activation (`LISTEN_FDS`) would let the unit bind :53 and start `dedensd` unprivileged, with no `user:`
  and no `AmbientCapabilities`; default: with the unit.

## Cache

- Minimum TTL of secure answers (D124): `min_ttl` does not raise a `Checked::Secure` answer, as the cache cannot tell a
  TTL the validator lowered for the signatures' expiration (RFC 4035 §5.3.3) from a short one. Raising them needs the
  verdict to carry the expiration (`dedens-dnssec` `Verdict`, `denial`) so the cache may floor up to it. Default: as
  is, until a deployment's secure short-TTL names show in the upstream load.
- `MAX_ROTATIONS` (D116) was chosen on Zipf draws of equal-size entries, where every K from 1 gives the ratio of an
  unbounded eviction. Replay a real capture (a DITL or OARC trace, or a `dedensd` query log) through
  `crates/dedens-bench/examples/hit_ratio.rs --trace FILE --entries N` and change K only if the ratio moves.
  Default: 32, as is.
- A positive answer that loses an authority record to a 512-byte buffer gets TC set (`Response::serve`, as
  `Message::encode_truncated`, D10), while RFC 2181 §9 says TC is not for "merely because some extra information
  could have been included". Authority records of a positive answer (the NS set) are such information in most
  resolvers' reading. Default: as is (a client that sees TC retries over TCP, and gets all of it); change both
  `encode_truncated` and the cache's cut together if a resolver is shown to prefer a cut without TC.

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
  duplicate checks or upstream traffic costing. Coalescing identical client questions of any forwarder (RFC 5452 §5):
  a per-thread map by cache key, with dnsperf numbers.
- ODoH suites other than RFC 9230 §9's (X25519, HKDF-SHA256, AES-128-GCM) (D78): P-256, P-384, HKDF-SHA384,
  AES-256-GCM, ChaCha20-Poly1305. Default: skipped in the configs a target publishes; add one when a target in use
  asks for it.
- ODoH target keys (D78, D79): `dedensd` serves one key, from `odoh.key` or made at start. Default: replaced by hand
  with a restart; several keys served at once (the configurations list them, a client picks the first) and rotation
  with an overlap, when a daemon holds state.
- ODoH proxy connections (D94): a target name's first global address is tried alone, and a pool slot is kept for each
  address a listed name ever resolved to. Default: one address, no fallback to the next or to IPv6 or IPv4 (a host
  without the one family fails with `connection_timeout`); several addresses tried in turn (RFC 8305), and slots
  dropped with their idle connection, when a target in use needs it or a rotating name grows the pool.
- Trust per hop in the CLI (D79, D94): `--tls-ca` and `--tls-insecure` apply to the proxy and the target alike, so
  `dedens +odoh-proxy=https://PROXY @https://TARGET` against a proxy with a private certificate needs the target's
  configurations pinned (`+odoh-config`) or a CA that signs both. Default: one trust for all; a `--tls-ca` for the
  proxy only (or one `+odoh-proxy` option carrying it) when a deployment with a private proxy needs the target's
  configurations fetched.
- ODoH configurations discovery (D79): fetched from `/.well-known/odohconfigs` of the target, straight to it, so the
  target sees the client's address, and the query that follows may be linked to it by timing; `dedens` keeps them an
  hour at least (a longer-lived `dedensd` client fetches rarely) and warns when the target forbids keeping them, but
  a one-shot `dedens` fetches each run: `+odoh-config=FILE` is its way out. Alternatives: through the proxy (needs a
  proxy that relays GET), from the target's SVCB record (RFC 9460; the ODoH SVCB parameters are not in an RFC), a
  fetch at a random time apart from the query. Default: well-known, direct.
- ODoH target limits (D117): a target sees the proxy's address, not the client's (D91), so every client of a proxy
  spends one network budget. Default: raised by the operator who fronts the target with a busy proxy, or the proxy in
  `rrl.exempt`; a per-client budget carried in the request, if proxies ever authenticate their clients. Open too: a
  per-connection limit, a connection opened for each request being as cheap for the client as a request on one; and
  the QUIC and TLS handshakes of each connection, which no budget bounds before the request.
- ODoH proxy URI templates (D79): RFC 9230 §4.1 gives the proxy as a URI Template (RFC 6570) with `targethost` and
  `targetpath` variables; `+odoh-proxy` takes a plain URI and appends the two as a query. Default: plain URIs only,
  one that already holds the variables is refused; the two simple expansions when a proxy in use needs one.
- ODoH over HTTP/2 (D79): `odoh-relay.edgecompute.app` speaks HTTP/3, but it refuses one target (403 for
  `doh.tiarap.org`) and other public proxies may speak HTTP/2 only. Default: HTTP/3 only (D83); HTTP/2 (D62)
  when a proxy in use needs it.
- A mix of NSEC and NSEC3 records in one response (D74 uses the NSEC3 and ignores the NSEC; RFC 5155 §8.2 does not say).
  Default: as D74; bogus if a zone shows it.
- CoAP (D80): non-confirmable requests by the client (RFC 7252 §4.3) and server-side Block1 reassembly (a DoC query
  fits one datagram, so a server needs neither). Default: not built until DoC meets a server that needs them.
- DoC (D81): the proxy parts of RFC 9953, §9.2 redirects (a 3.xx or 5.03 with Location-*) and §9.3 hop limit
  (RFC 8768), are ignored by the client and the server. Default: not built until DoC meets a CoAP proxy to forward to.
- DoC (D81): DTLS (`coaps://`, RFC 9953 §6) and OSCORE (§5.2), needing a CoAP-level security stack. Default: not
  built until a deployment asks for an encrypted DoC; the unprotected listener warns at start.
- DoC (D81): a `coap://` upstream of the `forward` stage, GET with `?dns=` (RFC 9953 does not define it).
  Default: not built.
- DoC (D95): the discovery of a server by SVCB `docpath` (RFC 9953 §3.2), which needs CoAP over TLS or DTLS
  (the SVCB ALPN says which), and a client that follows `+doc-discover` on its own (a list from an untrusted source
  may not be used, §6). Default: not built; `+doc-discover` is asked for, one server at a time.
- Aggressive use of the cache for denial (RFC 8198). Default: not before the recursive resolver's cache.
- Key tag signalling (RFC 8145) and the trust anchor sentinel (RFC 8509). Default: not sent.
- Clock skew when checking signature windows (RFC 4035 §5.3.1). Default: none, the clock as given, with the
  window's edges inclusive; an option when a deployment shows it.
- Validating forwarder (D77): the BAD-cache threshold of RFC 4035 §4.7 (answer from the bad cache only after N
  failures). Default: none, a bogus verdict is cached at once for 60 s, as Unbound does.
- Validating forwarder (D77): an EDE on an answer cached as insecure (the stored bytes carry no OPT), and the text of
  an EDE (the reply's OPT holds the code only). Default: neither; the code is on a bogus or indeterminate SERVFAIL.
- Validating forwarder (D77): Bogus and indeterminate counts are per query, not per zone; no `trust_anchors` reload
  without a configuration reload. Default: none.
- Validating forwarder (D77): the cost of a query upstream. A bogus answer Response::build refuses to cache (a NODATA
  without SOA, TTL 0) is validated again on each query; up to 64 questions hold one upstream slot until a verdict;
  no deadline per query; the dead server is skipped for one query only. Default: as is; a per-query deadline if a
  deployment shows the need.
- Validating forwarder (D77, D117): the global allowance has no knob in the configuration (`Allowance` defaults;
  `client_share` is the network's), and a unit weighs the same for every algorithm (a P-384 check takes 12 times a
  P-256 one). Default: fixed; `dnssec_allowance:` keys when a deployment hits the default, units weighted by algorithm
  when one signs with P-384 to burn the bucket's CPU.
- Validating forwarder (D117): a network's share does not reserve units for warm validations (2 units), so an
  attacker's cold validations from the same network shed that network's other unproven queries; and spoofed UDP
  sources can drain the share of a network they do not hold (proven clients have their own), or spread over networks
  to drain the global allowance. Default: none; a reserve for warm validations, if a deployment shows the need.
- Validating forwarder (D77): an upstream SERVFAIL or REFUSED for the client's question, and a held failure, reply a
  bare SERVFAIL, with no EDE 22 (No Reachable Authority) or 23 (Network Error). Default: bare.

## Later

- DoH servers where HTTP/3 does not answer (21 of the 44 URLs of `providers.yaml`, November 2026): 19 do not
  advertise `h3`; the two of UncensoredDNS do, but the QUIC handshake stalls after their first flight. They sit
  under `https_h2`, parsed but not asked, until HTTP/2 (D62). Default: find whether our client or their
  server is at fault for UncensoredDNS.
- Upstream DoH servers by host name (`servers: ["https://dns.quad9.net/dns-query"]`): D65 takes an address only, so
  `https://IP[:PORT][/PATH][#NAME]` is what `dedensd` reads (D84). Default: a host name resolved at start and on
  reload by the system resolver, the first address kept, once `dedensd` has a way to refresh it.
- `dedensd`'s `https://` listener serves any `Host` or `:authority` on its path. Default: serve any.
- `dedens -f` aborts the whole run when one server's host name does not resolve (`failed to lookup address
  information`, macOS for `doh.dns.sb`, a CNAME chain), where one query should fail alone. Default: resolve per
  query, as the exchange errors are.

- QUIC connections sharing the client's one UDP socket per address family (`crates/dedens-net/src/quic.rs`):
  over IPv6, two at once to NextDNS (`2a07:a8c0::`, `2a07:a8c1::`) or to Control D (`2606:1a40::11` under two
  names) often time out, one per process never does; IPv4 does not show it. Default: find whether the servers'
  load balancers or quinn cause it before giving each connection its own socket.
- Renewing the pooled upstream UDP sockets (D50) now and then, for the port entropy of RFC 5452 §9.2 against
  an attacker who learned a kept port. Default: keep the sockets, relying on cookies (RFC 7873); `dedensd` sends no
  `0x20` (D77), which would be the next step.
- QUIC datagram without control data (D89): `compio-io`'s `CMsgIter::new` panics on an empty control buffer, which
  macOS gives for a datagram queued before the socket options were set. Default: as is (`serving` waits for the
  endpoints); an upstream fix (accept an empty buffer), then drop the note.
- Blocking by answer address: an answer holding an address in a listed network (a blocklist of IPs, as HAProxy's
  `ip` match) becomes REFUSED or NXDOMAIN. Client lists are D91, with the longest-prefix tree to reuse. Default:
  none; the blocklist stage judges names only.
- Steering each datagram to the socket of the CPU that received it: `SO_INCOMING_CPU` on each thread's socket
  (the kernel's `SO_REUSEPORT` choice prefers it: `reuseport_select_sock_by_hash`) and threads pinned to their CPUs, or a
  `SO_REUSEPORT_CBPF` program. Default: wait for a benchmark between two machines; on loopback the sender's
  CPU handles the packet, so `just bench-dnsperf` cannot show it.
- Counters shared by all threads (`metrics` atomics) once an exporter is installed: every thread writes the same
  cache lines. Default: per-thread counters summed by the exporter, measured with it.
- Changing a blocklist or hosts list while running, without a reload (HAProxy's `add map`, `del map`), through
  a control socket. Default: with the metrics exporter's HTTP endpoint, or a socket of its own.
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
- An encoder that also returns the TTL offsets it wrote, so `Response::build` skips its `message::ttl_offsets` pass
  over the response bytes. Default: add it when that pass shows in a profile of the server.
- SIMD base64 and hex for DNSSEC keys and signatures in zone text (`text/encoding.rs` decodes a byte at a time
  through a table): `core::arch` per CPU, since `std::simd` is nightly-only. Default: when a
  profile shows zone-text decoding, bench the `base64-simd` crate and our table against a signed zone; `unsafe` only if
  it wins.
- `RecordType` constants for TKEY, TSIG, MAILA and MAILB: the cache tests and its meta-type check use the raw
  numbers. Default: add them with TSIG, in the authoritative phase.
- What to build after DoH over HTTP/3 (D83), DNSSEC validation (D77), ODoH (D79) and DoC (D81): prewarm (names from
  the configuration kept in the cache), DNSCrypt (client, server, Anonymized DNSCrypt client, PQDNSCrypt; the relay
  role later), kubernetes stage, recursive resolver (with an RRset cache, priming per RFC 8109, BCP 123 behaviour per
  RFC 4697), authoritative (zones, AXFR/IXFR, NOTIFY, UPDATE, TSIG, RFC 2182). Default: in that order; the error
  reporting option (RFC 9567) with the server, and DoH over HTTP/2 once compio releases tokio's I/O traits (D62).
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
