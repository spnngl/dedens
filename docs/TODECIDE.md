# To decide

Open questions, each with its proposed default. Once answered, record the outcome in
[`decisions/`](decisions/README.md) under a new number and delete it here.

## Server forwarder

- Plugins that see the client (aardvark-dns's per-network views, `src/backend/mod.rs:62-116`; CoreDNS's `pods
  verified` and autopath): `Plugin::answer` takes the query alone (`crates/dedens-server/src/plugin.rs:14`), the
  client address reaches the access check only (D91). Default: pass the address to plugins with the Kubernetes
  stage, its first user.
- A domain `dedensd` answers for (aardvark-dns gives NXDOMAIN to unknown names of its domain, never forwards them;
  CoreDNS for `cluster.local`): the hosts stage passes an unknown name to the next stage
  (`crates/dedens-plugins/src/hosts.rs:150-158`), so a private domain's misses go upstream. Default: a `zone:`
  option on hosts (NXDOMAIN with AA and the zone's SOA, NODATA as today) with the Kubernetes stage. TelltaleDNS also
  answers any type from local records and zone files (`crates/telltale-policy/src/local.rs`): a `zone` plugin
  reading a file with `ZoneReader` would give both; default: with the authoritative phase's zone loading.
- Private names past the `tlds` stage: RFC 6761 §6.2 asks caching servers for an option to resolve `test` names
  upstream, and a network may delegate an `internal` zone to its own servers; the stage answers them NXDOMAIN
  (`internal` with DO excepted), so only a stage before it (hosts) or no `tlds` stage reaches them
  (D128). Default: a `pass:` list of names on the `tlds` stage, sent on as the absent TLDs with DO are.
- A QUIC endpoint whose worker panicked (D89, D121): the panic stays in a compio task, the endpoint goes deaf and
  `wait_incoming` never ends, so `dedensd` serves no DoQ or DoH over HTTP/3 on that socket and sees nothing. Detecting
  it needs a probe of the endpoint (a watchdog sending itself an Initial) or a compio change. Default: a compio
  change to surface worker panics, once one is proposed upstream.
- compio's cancel of a dropped operation (`compio-driver` `sys/driver/iour/mod.rs`, `cancel`) only warns when the
  submission queue is full and drops the `AsyncCancel`: a multishot receive dropped by a listener's restart
  (`supervise`, `apps/dedensd/src/serve/isolate.rs`) then stays armed beside its replacement and takes datagrams
  nobody reads. Default: a compio change that retries the cancel after the next submit, proposed upstream.
- compio's buffer ring (D49) publishes its tail without a release store (`compio-driver`
  `sys/buffer_pool/iour.rs`: an `unsync` `AtomicU16`, which ignores orderings). The kernel reads the tail with acquire,
  so on arm64 it may see a new tail before the entry's address, length and id, and fill a buffer a task still reads:
  a reply to the wrong question, or compio's panic "Buffer should not be in use". Never seen. A fix is written
  (compio `e0e0ae5e`, branch `fix/buffer-ring-release`). Default: propose it upstream, take it with the release.
- A TCP reply's write deadline (D47) runs from the moment the queue was last empty (`write`,
  `apps/dedensd/src/serve/tcp.rs`): a fast reader under sustained pipelined load never empties it, and is closed
  `TCP_WRITE` (10 s) after its burst began. Default: start the deadline again after each completed write, so it
  bounds a stalled write, not a busy connection.
- Bare `spawn`s in `dedens-net` whose panics nothing logs or counts (D121): the pools' tasks through `Io::spawn`
  (D134; compio's in `crates/dedens-net/src/io.rs`), `receive` of `crates/dedens-net/src/udp.rs`, `run` and `read`
  of `crates/dedens-net/src/tcp.rs`, and the HTTP/3 driver of `connection` in `crates/dedens-net/src/http3.rs`.
  compio hides each; the client of a query then times out. Default: a `dedens-net` helper like `Origin::spawn` (a
  counter by name), once a second user of it exists.
- Export of `dedensd_task_panics_total` and `dedensd_listener_restarts_total` (D121): no exporter is installed
  (D30), so the counts go nowhere but the log. Default: with the Prometheus exporter.
- Upstream TCP: a connection pool per upstream (size, idle timeout, reuse across workers) instead of D27's one
  connection per server? Default: decide with the forwarder's load tests.
- The TCP pool gives up connecting at its idle timeout, `TCP_IDLE` = 10 s (`crates/dedens-net/src/client.rs:42`,
  `run` in `crates/dedens-net/src/tcp.rs`), whatever the exchange's tries and timeout (3 × 5 s by default). A
  server that drops SYNs ends the exchange in `TcpError::Connect(TimedOut)` 10 s in, during the third try, not in
  `Failure::TimedOut { sends: 3 }` at 15 s; other options give either. D134's simulation found it:
  `a_tcp_query_to_a_crashed_resolver_gives_up_connecting_at_the_idle_timeout`, `crates/dedens-sim/tests/baseline.rs`.
  Default: connect within the try's deadline, and count a connection that does not open as a timed-out try.
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
  refused before the frame is buffered, unknown frames discarded). Default: replace the budget (`src/serve/h3_budget.rs` and
  its sweeper) by the fix once an h3 release with it is in compio's `h3` feature and `apps/dedensd/tests/doh.rs` passes
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
- The Prometheus exporter (D30) and health endpoints: the counters go nowhere. TelltaleDNS serves `/metrics`,
  `/livez`, `/healthz` and `/readyz` on one HTTP listener (`crates/telltale/src/http.rs`, axum). Options:
  `metrics-exporter-prometheus`'s own listener (hyper on tokio), or its recorder rendered by a small HTTP/1.1
  listener of `dedensd` on a thread of its own, as D57's downloads. Default: the second, with `/metrics`, `/livez`, and
  `/readyz` once every listener is bound; the entries waiting on the exporter follow it. Decided by `cargo tree` and a
  bench of the recording on the hot path.
- Conditional forwarding: a domain or reverse zone sent to its own servers (a home's `lan` to its router, a company's
  domain over its VPN); TelltaleDNS picks the upstream group by longest suffix
  (`crates/telltale-upstream/src/router.rs`). D23's router stage would branch by zone, not built. Options: the
  router, or a `zones:` list on `forward` that passes other names on, so the pipeline stays a chain (one forward
  stage per zone, the catch-all last). Default: `zones:` on `forward`; the router when a branch needs stages of its
  own. Under `dnssec: validate` a private zone below a signed one needs a negative trust anchor.
- Upstream choice and health (D41: servers asked in order, the next on a failure): a dead first server costs each
  query its timeout. TelltaleDNS has failover, round robin, weighted, fastest, parallel and hedged groups
  (`crates/telltale-upstream/src/group.rs`) and a breaker per server: 3 failures in a row, or over half of the last
  50, skip it 10 s doubling to 5 min, then one probe (`health.rs`). Default: the breaker, the order kept; fastest
  (smoothed RTT, as Unbound) or hedged when a bench with a slow upstream shows the need.
- A query log: `dedensd` logs no query. TelltaleDNS, as Unbound, Knot and CoreDNS, writes dnstap: client and
  forwarder messages over Frame Streams to a Unix socket or TCP, one query in `sample_every`, copied into a bounded
  queue that drops the copy when full (`crates/telltale/src/dnstap.rs`). Options: dnstap, or JSON lines through
  `tracing`. Default: dnstap, a queue per thread and a writer thread; views per device stay product.
- Policy per client (a blocklist or upstream per network or device): D23's router by client CIDR would give it per
  address. A client id beyond the address, from the DoH path (`/dns-query/{id}`) or the TLS SNI's first label, as
  TelltaleDNS and NextDNS read it, has no place in the pipeline. Default: the router by CIDR first; ids when clients
  behind NAT or roaming need them. Groups and schedules stay product.
- PROXY protocol v2: the proxy D90 puts in front for rate limits over TCP, TLS, QUIC and HTTPS hides the client's
  address, so the access lists (D91), RRL (D113) and the client shares (D117) see the proxy's. TelltaleDNS requires
  v2 on each TCP stream of a listener marked for it (`crates/telltale-net/src/proxy.rs`). Default: the same, on TCP
  and TLS listeners; datagrams later.
- CPU and latency of `forward` at a low rate (`docs/benchmarks.md`, "Where the time goes at the common rate"): the
  profile found no system call or wake-up a query of our own; `tcp`'s gap is the kernel's and `dnssec`'s was the
  memo (D86). Left: 3-core `forward` spends 1.3 times Unbound's CPU (28.5 µs against 22.9, the 5% of names sent
  upstream by a cold server, page faults of fresh memory among them), and 1-core `forward` answers in 0.22 ms
  against 0.13 (p99 1.2 against 0.7), though `miss`, every name upstream, costs less than Unbound's. The second
  pass split the cold start from the hits, and the hits' gap was two turns of the runtime a wake-up, closed by D123's
  reply sent at once. Default: profile the first pass the same way (fresh memory, the cache growing) before any
  change.
- Memory: idle, `dedensd` holds 11 MiB against Unbound's 4. Loaded, 3-core `miss` went from 168 MiB to 89 (Unbound
  26) by a receive buffer shared by each upstream pool (D50) and transparent huge pages off (D154); the cache's 64 MiB
  capacity (D116, kept: the hit ratio of real traffic is worth more than the bench's row) holds 58 of them, and the
  rest is about Unbound's total (`docs/benchmarks.md`, the 8 MiB cache row). Left: the idle 11 MiB. Default: account
  for it (buffer rings, threads' stacks, the allocator's arenas) before changing a default.

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
- Persistence across restarts: a restart empties the cache. TelltaleDNS dumps it on shutdown and loads it on start,
  each entry aged by the downtime, a dump of other routes ignored (`crates/telltale-cache/src/persist.rs`). D43
  prefetches what is asked, D96 prewarms listed names. Default: none, a restart's misses costing one upstream
  question each; revisit if a restart is measured to hurt.

## DNSSEC and experimental transports

- ODoQ (Oblivious DNS over QUIC): no RFC exists. Default: dropped; revisit when the IETF publishes one.
- Ed448 (algorithm 16, RFC 8080): `ring` has no Ed448. Default: unsupported, so a zone signed with it is
  insecure (RFC 6840 §5.2); a pure-Rust crate only if a signed zone in use needs it.
- SHA-1 switch: RFC 9905 §2 tells operators of validating resolvers to treat RSASHA1, RSASHA1-NSEC3-SHA1 and their
  DS records as unsupported (insecure), and implementations to keep validating them (D71 validates by default).
  Default: validated; a setting of the validator marking algorithms 5 and 7 unsupported, which
  needs a filter on the DS records and RRSIGs that `rrsig` does not have (D75 leaves it out).
- Trust anchor rollover (RFC 5011): follow a root key roll while running from the root's DNSKEY RRset. The
  signed download of `root-anchors.xml` is settled (D127); tracking a roll in the zone itself is left to the
  recursive resolver, which holds the state. Default: bundled anchors, the signed download, anchor files.
- NTA end time (RFC 7646 §2.1 SHOULD): a negative trust anchor lasts as long as the `TrustAnchors` holding it
  (D72). Default: none, the caller drops it (`--insecure NAME`, `insecure:` in the configuration); an `until` with the
  clock passed in when `dedensd` keeps state across reloads.
- `+trace +validate` (D76 refuses it): validate each hop, a referral by `start_referral` and the answer by `start`,
  asking DS and DNSKEY of the servers the trace reached. Default: refused; `+validate @server` is the way to a verdict.
- Key cache, lock (D86, D92): one `Mutex` over two tables, which a hit takes too (it moves the entry in the LRU
  order). Default: as is; shards by name, or an `RwLock` with a lazier LRU, when `dedensd`'s load tests show the
  lock contended. The answer cache's read lock failed to scale (D137): a reader still writes the lock word, so an
  `RwLock` here would gain little beside shards.
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
  configurations pinned (`+odoh-config`) or a CA that signs both. `dedensd`'s `upstream_ca` does the same for a
  stage's `odoh_proxy` and its targets (D185), with no pinning. Default: one trust for all; a `--tls-ca` for the
  proxy only (or one `+odoh-proxy` option carrying it) when a deployment with a private proxy needs the target's
  configurations fetched.
- ODoH configurations discovery (D79): fetched from `/.well-known/odohconfigs` of the target, straight to it, so the
  target sees the client's address, and the query that follows may be linked to it by timing; `dedens` keeps them an
  hour at least and warns when the target forbids keeping them, but a one-shot `dedens` fetches each run:
  `+odoh-config=FILE` is its way out. `dedensd` as a client (D185) fetches on the first query of each thread and
  then at most once an hour a thread, with no pinned file. Alternatives: through the proxy (needs a proxy that
  relays GET), from the target's SVCB record (RFC 9460; the ODoH SVCB parameters are not in an RFC), a fetch at a
  random time apart from the query (a timer task for each thread of `dedensd`). Default: well-known, direct.
- ODoH target limits (D117): a target sees the proxy's address, not the client's (D91), so every client of a proxy
  spends one network budget. Default: raised by the operator who fronts the target with a busy proxy, or the proxy in
  `rrl.exempt`; a per-client budget carried in the request, if proxies ever authenticate their clients. Open too: a
  per-connection limit, a connection opened for each request being as cheap for the client as a request on one; and
  the QUIC and TLS handshakes of each connection, which no budget bounds before the request.
- ODoH proxy URI templates (D79): RFC 9230 §4.1 gives the proxy as a URI Template (RFC 6570) with `targethost` and
  `targetpath` variables; `+odoh-proxy` and a forward stage's `odoh_proxy` (D185) take a plain URI and append the two
  as a query. Default: plain URIs only,
  one that already holds the variables is refused; the two simple expansions when a proxy in use needs one.
- ODoH over HTTP/2 (D79): `odoh-relay.edgecompute.app` speaks HTTP/3, but it refuses one target (403 for
  `doh.tiarap.org`) and other public proxies may speak HTTP/2 only. Default: HTTP/3 only (D83), for `dedens` and
  `dedensd`'s `odoh_proxy` (D185); HTTP/2 (D62) when a proxy in use needs it.
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
- Validating forwarder (D77, D117): the global allowance, scaled by the serving threads, has no knob in the
  configuration (`Allowance::serving`; `client_share` is the network's), and a unit weighs the same for every
  algorithm (a P-384 check takes 12 times a P-256 one). Default: by the threads; `dnssec_allowance:` keys when a
  deployment hits the default, units weighted by algorithm when one signs with P-384 to burn the bucket's CPU.
- Validating forwarder (D117): a network's share does not reserve units for warm validations (2 units), so an
  attacker's cold validations from the same network shed that network's other unproven queries; and spoofed UDP
  sources can drain the share of a network they do not hold (proven clients have their own), or spread over networks
  to drain the global allowance. Default: none; a reserve for warm validations, if a deployment shows the need.
- Validating forwarder (D77): an upstream SERVFAIL or REFUSED for the client's question, and a held failure, reply a
  bare SERVFAIL, with no EDE 22 (No Reachable Authority) or 23 (Network Error). Default: bare.

## Later

- RAPx on dedens-proto (D187): 0.7.75 stops with an internal compiler error (`item_name: no name for DefPath`,
  a closure of `Iterator::map`, from `rapx::def_ids::other_api::is_align_offset`): `tcx.item_name` is called on
  items without a name since RAPx 0.7.72 (also `is_box_new`, `is_nonnull_dangling`), so `just rapx` and `rapx.yml`
  fail. `tcx.opt_item_name` there passes it (tried on a local build), and the analysis of dedens-proto then runs
  past 25 minutes, as 0.7.71's did past `rapx.yml`'s 90 (runs of 2026-11-16 and 2026-11-17 cancelled). Default:
  the fix sent upstream and `rapx_version` raised to its release; then find the function the analysis loops on.
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
  none; the blocklist stage judges names only. Rebinding protection first if any: TelltaleDNS refuses private,
  loopback and link-local addresses in answers for public names (`AnswerFilter`,
  `crates/telltale-policy/src/clients.rs`).
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
  name: 364 ns a hit, against about 100 ns on one thread). A read lock with a hit writing two atomics did not
  help (D137: inside the spread on two machines; the reader still writes the lock word). Default: as is; per-core
  copies of hot entries, or a read path that writes no shared line (an epoch or a seqlock), when `dedensd`'s load
  shows the shard lock waited on.
- Cache shards from `threads` (D137): `Config::shards` is 64 whatever the core count; `quick_cache` takes 4 a
  CPU. Default: 64 until `hit_spread` on 16 or more cores shows locks waited on; then a default from `threads`,
  rounded to a power of two.
- An encoder that also returns the TTL offsets it wrote, so `Response::build` skips its `ttl_offsets` pass
  over the response bytes. Default: add it when that pass shows in a profile of the server.
- SIMD base64 and hex for DNSSEC keys and signatures in zone text (`text/encoding.rs` decodes a byte at a time
  through a table): `core::arch` per CPU, since `std::simd` is nightly-only. Default: when a
  profile shows zone-text decoding, bench the `base64-simd` crate and our table against a signed zone; `unsafe` only if
  it wins.
- `RecordType` constants for TKEY, TSIG, MAILA and MAILB: the cache tests and its meta-type check use the raw
  numbers. Default: add them with TSIG, in the authoritative phase.
- What to build after DoH over HTTP/3 (D83), DNSSEC validation (D77), ODoH (D79) and DoC (D81): prewarm (names from
  the configuration kept in the cache), DNSCrypt (client, server, Anonymized DNSCrypt client, PQDNSCrypt; the relay
  role later), kubernetes stage, roots (root and TLD hints bundled, the TLD list and root anchors refreshed, the
  anchors checked by their signature, special-use and nonexistent TLDs answered locally, TLD and domain lookups over
  RDAP), recursive resolver (with an RRset cache, priming per RFC 8109, BCP 123 behaviour per RFC 4697, TLD hints),
  authoritative (zones, AXFR/IXFR, NOTIFY, UPDATE, TSIG, RFC 2182). Default: in that order; the error reporting option
  (RFC 9567) with the server, and DoH over HTTP/2 once compio releases tokio's I/O traits (D62).
- Zone files held by the resolver: the root's (`root.zone`, RFC 8806, Unbound's `auth-zone`) or TLDs' (generic ones
  through ICANN's CZDS: an account, each registry's approval, daily copies, no redistribution; `.com` alone about
  160 million domains). Default: none; the root and TLD hints of `named.root` and `tlds.json` save the root query,
  and the cache saves the TLD ones.
- Special-use names below the TLDs (IANA's Special-Use Domain Names registry: `home.arpa` per RFC 8375,
  `resolver.arpa` per RFC 9462, the locally served zones of RFC 6303): `tlds.json` lists TLDs only. Default: with
  the recursive resolver, which must not send them upstream.
- One socket for `dnscrypt://` and another listener (D99): a `dnscrypt://` address on the port of an `https://` (UDP) or
  plain one is refused at the config, as the draft's "Client Queries Over UDP" lets a resolver share a port with
  QUIC or plain DNS only by telling the packets apart (the client magic, the QUIC header, a DNS message), which the
  listeners cannot do with a socket each. Default: refused; a shared socket when a deployment needs `:443` for both.
- The DNSCrypt signing key beside query processing (D99, the draft's "Key Management" advises a signing key kept
  apart): `dedensd` holds the provider seed in the process that serves queries, read once at start. Default: the
  key file, 0600; a separate signer that certifies the short-term keys, with the rotation, when a deployment asks.
- PQDNSCrypt ticket keys across a `dedensd` restart (D101): the ticket key is random and kept in memory, so a restart
  ends every ticket and each client falls back to a full query after one lost query. Default: as is; a key file
  or a derivation from the provider seed when a deployment's restarts or its decapsulation cost ask for it.
- The PQDNSCrypt decapsulation budgets as settings (D101): a client network 250 a second (500 at once) and all clients 2500
  (5000) are constants of `dedensd`, one unit a decapsulation. Default: as is; `dnscrypt.client_budget` and
  `dnscrypt.budget` as `odoh`'s (D117) when a deployment's clients or its cores ask for other numbers.
- Caching the expanded `X-Wing` key (D101): `x-wing` 0.1.1 keeps only the seed, so each decapsulation derives the ML-KEM key
  again, about half of the 101 µs. Default: as is, D101 rejecting a combiner of our own; raise it with the crate's
  maintainers, or take a cached form when a decapsulation's cost is what limits a deployment.
- Dropping a ticket on a network change in a long-lived `dedensd` forwarder (D101; the draft's "Resumption Tickets" says
  clients SHOULD, `dnscrypt-proxy` keeps a network epoch): `dedens` is one process with a fresh socket per query and a
  ticket that lives 600 seconds at most, so a ticket never outlives a network; the forwarder of `dedensd` (D100, D99) keeps
  its upstream's ticket across changes of its own route, which links its queries to one client for that time (they are
  one forwarder's anyway). Default: as is; an epoch that drops the tickets when the route or the source address changes.
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
  dropped its WASM transform; a Rust dylib needs an ABI workaround; gRPC costs milliseconds. Or a process speaking
  DNS over a Unix socket as an upstream, which TelltaleDNS starts and restarts itself
  (`crates/telltale-upstream/src/plugin.rs`): a `forward` server like any other.
- A small typed rule language for matchers (D23), beyond declarative matchers.
- crates.io publishing.
- Blocklist formats beyond names and hosts lines (D56: AdBlock syntax "later, with need"); TelltaleDNS reads AdBlock
  and regex lines too. A regex costs a match per query (TelltaleDNS compiles them into one `regex-automata` set);
  hagezi and OISD publish a names form beside the AdBlock one. Default: AdBlock's domain rules only (`||name^`
  blocked, `@@||name^` allowed, the rest skipped as unread downloaded lines) when a list a user needs has no names
  form; no regex.
- DNS64 (RFC 6147): AAAA made from the A answer for IPv6-only clients behind NAT64 (TelltaleDNS `dns64_for`,
  `crates/telltale/src/pipeline.rs`). It needs the upstream's answer, as the `rewrite` plugin does. Default: with
  that plugin.
- Upstreams through a SOCKS5 proxy (Tor), as TelltaleDNS (`crates/telltale-upstream/src/proxy.rs`). Default: none;
  ODoH (D79) and Anonymized DNSCrypt (D100) hide the client from the resolver without one.
- Deployment beyond the image (D151, D153: x86_64 and aarch64): TelltaleDNS also ships `linux/arm/v7`, a Helm chart
  and a compose file. Default: the Helm chart with the Kubernetes phase, a compose example when asked; no 32-bit
  image, as no 32-bit target is tested.
- A fuzz target for `dedensd`'s configuration reader (`apps/dedensd/src/config/`), which needs the reader in a
  library crate. Default: move the reader to `dedens-server` with the next change to the configuration.
- Cross builds with the lld wrapper (D150): `lld-cc` calls the host `cc`, so a `--target` other than the host's
  needs `CARGO_TARGET_<TRIPLE>_LINKER` set to a cross `cc`. The musl targets build natively in Alpine instead (D151).
  Default: as is.
- The trust store of the image (D153): it carries Alpine's `ca-certificates` bundle, as of its build, so a CA the
  bundle drops stays trusted until the next release. Default: as is. Alternative: bundled roots (`webpki-roots`),
  which the host's own CAs (a corporate proxy) would not extend either.
- A user name defined outside `/etc/passwd` (D151): musl has no NSS, so `user: nobody` fails where it is defined in
  `nss-altfiles`, LDAP or systemd's userdb. Default: a numeric id there, as documented in `config/mod.rs`.
- The image's registry access (D153): the GHCR package starts private, and nothing protects `v*` tags, so any pushed
  tag publishes. Default: by hand, once (`.github/AGENTS.md`, "First release"): make the package public, add a tag ruleset.
- `CAP_NET_BIND_SERVICE` under systemd (D156): the unit grants it for the bind, and `dedensd` keeps it for its life
  (`CapEff` 0x400), though `listen` cannot change on reload. Default: as is. Alternative: `dedensd` clearing its
  effective and ambient capabilities once bound, as D122's drop ends with none.
- IPv6 in the packaged `dedensd.yaml` (D156): `127.0.0.1:53` only, since a host without IPv6 has no `[::1]` and the
  start fails. Default: as is. Alternative: `dedensd` skipping a loopback address the host lacks, with a warning.
- Crashes of test binaries in the coverage job (glibc x86_64, instrumented), each gone on rerun: a SIGSEGV of
  `rfc8484` (D107; run 42254972560, 2026-11-06; 300 runs on the VPS, with and without coverage and on `io_uring`, did
  not crash), and `free(): corrupted unsorted chunks` (SIGABRT) of `dedensd`'s `tests`, twice (run 43624984047,
  2026-11-14, and PR #64's first run), each time after `access::networks::a_network_that_is_no_network_stops_the_start`.
  `cargo llvm-cov` runs a binary's tests as threads of one process, so the culprit is any test in flight. `dedensd`
  has no `unsafe`: suspects are native code and io_uring, and the tests' client runtimes, dropped with QUIC operations
  in flight, which `dedensd` never does (D107). Default: hunt it, the coverage job on `cargo llvm-cov nextest` (one
  process per test names it), then that test under AddressSanitizer.
- DNS stamps of the other kinds (D102): `dedens_net::stamp` reads the DNSCrypt (0x01) and relay (0x81) kinds and
  refuses plain DNS (0x00), DoH (0x02), DoT (0x03), DoQ (0x04) and Oblivious DoH (0x05, 0x85) by name. The encrypted
  kinds name servers of transports we have (certificate hashes, host names with ports, bootstrap addresses, a DoH
  path), so `@sdns://...` could be an upstream of `dedens` and of the `forward` stage. Default: not read.
  Alternative: read them, as the published lists hold 497 of them, and map each to the transport's upstream.
