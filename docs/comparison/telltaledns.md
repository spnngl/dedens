# dedens against TelltaleDNS: features

Versions, method and cell format: [`README.md`](README.md). A dedens cell names a file of this repository and the
decision; a TelltaleDNS cell names a file of theirs (paths from their repository root) and the requirement id of
their `spec/01-requirements.md` with its priority. "no": neither code nor spec; "spec only": their spec asks for
it, their code does not do it; "partial": what is missing follows.

## Listeners

| Feature | dedens | TelltaleDNS |
|---|---|---|
| UDP | `apps/dedensd/src/serve/udp.rs`, compio thread per core, `SO_REUSEPORT` (D42) | `crates/telltale-net/src/udp.rs`, `crates/telltale-net/src/sys.rs`: a thread per `SO_REUSEPORT` socket, `recvmmsg`/`sendmmsg` batches of 32 (DNS-001 P0) |
| TCP, pipelined, out of order (RFC 7766) | `apps/dedensd/src/serve/tcp.rs`: 64 in flight, 128 KiB queued replies, 10 s write deadline (D47, D64) | `crates/telltale-net/src/tcp.rs`: 64 in flight, 10 s idle (DNS-001 P0); partial: idle timeout not configurable |
| DoT server | `apps/dedensd/src/serve/tcp.rs` (D66) | `crates/telltale-net/src/tls.rs`, client id from SNI (DNS-002 P0) |
| DoH server, HTTP/2 and HTTP/1.1 | no (HTTP/3 only) | `crates/telltale-net/src/doh.rs`: GET and POST, `/dns-query/{client-id}`, over TLS only (DNS-003 P0) |
| DoH server, HTTP/3 | `apps/dedensd/src/serve/http3.rs`, `apps/dedensd/src/serve/h3_budget.rs` (D84, D119) | `crates/telltale-net/src/doh3.rs`, advertised by `Alt-Svc` (DNS-004 P1) |
| DoQ server (RFC 9250) | `apps/dedensd/src/serve/quic.rs`, Retry to unvalidated addresses (D66, D119) | `crates/telltale-net/src/doq.rs`, 100 streams (DNS-004 P1) |
| DNSCrypt server, PQ X-Wing | `apps/dedensd/src/serve/dnscrypt.rs`, keys rotated every 12 h, `pq` system (D99, D101) | no |
| ODoH target and proxy (RFC 9230) | `apps/dedensd/src/odoh/mod.rs`, `apps/dedensd/src/odoh/proxy.rs` (D79, D94) | no |
| DNS over CoAP (RFC 9953) | `apps/dedensd/src/serve/coap.rs`, `doc` feature (D81) | no |
| PROXY protocol v2 | no | `crates/telltale-net/src/proxy.rs`, TCP, DoT and DoH only (DNS-020 P1) |
| Connection caps | per thread: 256 TCP connections, 1024 upstream queries (D47); QUIC peer bounds (D119) | `crates/telltale-net/src/peer_limit.rs`: 32 per address or IPv6 /64; 1024 per listener (`crates/telltale-config/src/schema.rs`) |
| Certificate reload, ACME | on SIGHUP (D55); no ACME | files polled every 10 s (`crates/telltale-net/src/tls.rs`); no ACME, which DNS-002 P0 asks for |

## Upstreams

| Feature | dedens | TelltaleDNS |
|---|---|---|
| UDP, TCP | `crates/dedens-net/src/udp.rs`, `crates/dedens-net/src/tcp.rs` (D27, D65) | `crates/telltale-upstream/src/upstream.rs`, `crates/telltale-upstream/src/conn.rs` (UPS-001 P0) |
| DoT | `crates/dedens-net/src/tls.rs` (D65) | `crates/telltale-upstream/src/conn.rs`, SPKI pins (UPS-001 P0) |
| DoH, HTTP/2 | no (HTTP/3 only) | `crates/telltale-upstream/src/doh.rs` (UPS-001 P0) |
| DoH, HTTP/3 | `crates/dedens-net/src/http3.rs` (D83, D84) | `crates/telltale-upstream/src/doh3.rs` (UPS-002 P1); partial: `http_version = "auto"` never upgrades |
| DoQ | `crates/dedens-net/src/quic.rs` (D65) | `crates/telltale-upstream/src/doq.rs` (UPS-002 P1) |
| DNSCrypt client, stamps | `apps/dedensd/src/config/upstream.rs`, `sdns://` servers, X-Wing (D98, D99, D101, D102) | `crates/telltale-upstream/src/dnscrypt.rs`: XSalsa20 and XChaCha20, stamps 0x01-0x04 (UPS-003 P1); no PQ |
| Anonymized DNSCrypt relays | forward stage `relays` (D100) | `crates/telltale-upstream/src/dnscrypt.rs`, `relay` (UPS-003 P1) |
| ODoH client | `dedens` CLI only (D79); no forward stage | no (stamp 0x05 refused) |
| Server choice | in order, each `tries` times (`crates/dedens-server/src/forward.rs`, D41, D45) | `crates/telltale-upstream/src/group.rs`: failover, round robin, weighted, fastest, parallel, hedged (UPS-005 P0) |
| Health, circuit breaker | no | `crates/telltale-upstream/src/health.rs`, active root NS probe (UPS-006 P0) |
| Routing by domain, group, type; conditional forwarding | no (one pipeline per listener, D23) | `crates/telltale-upstream/src/router.rs`, longest suffix, reverse zones (UPS-007 P0, DNS-017 P0) |
| Connection reuse | one TCP connection per server (D27); QUIC and HTTP/3 multiplexed (D83) | `crates/telltale-upstream/src/conn.rs` pool, pipelined (UPS-008 P0) |
| Bootstrap of upstream names | no: servers are addresses, a TLS name after `#` | `crates/telltale-upstream/src/bootstrap.rs` (UPS-009 P0) |
| SOCKS5, HTTP CONNECT | no | `crates/telltale-upstream/src/proxy.rs` (UPS-010 P1) |
| exec or Unix-socket plugin | no | `crates/telltale-upstream/src/plugin.rs` (UPS-011 P1); WASM spec only (P2) |
| Presets catalog | `docs/providers/providers.yaml`, for the CLI (D67) | `crates/telltale-upstream/src/presets.rs` (UPS-004 P0) |
| Response matching against forgery | address, ID, question, response checked against the question (`crates/dedens-net/src/exchange.rs`, D27, D111); `0x20` in the library, on in `dedensd` for plain servers over UDP (D184) | ID and question (`crates/telltale-upstream/src/upstream.rs`); `0x20` only in the recursor, which spec `04-upstreams.md` gives UDP upstreams |
| TC to TCP; EDNS kept on timeout (RFC 8906) | `crates/dedens-net/src/exchange.rs` | TC to TCP (`crates/telltale-upstream/src/upstream.rs`); no EDNS fallback |

## Cache

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Structure | sharded S3-FIFO (`crates/dedens-cache/src/cache.rs`, D22) | sharded S3-FIFO (`crates/telltale-cache/src/s3fifo.rs`, DNS-006 P0) |
| Memory bound | bytes (`crates/dedens-cache/src/config.rs`, D116) | bytes, 32 MiB default (`crates/telltale-cache/src/lib.rs`) |
| Min and max TTL | `min_ttl`, `max_ttl`, `max_insecure_ttl` (D124) | `crates/telltale-cache/src/entry.rs` |
| Negative caching (RFC 2308) | `crates/dedens-cache/src/response.rs` (D22) | `crates/telltale-cache/src/entry.rs`, capped by `negative_ttl_max` |
| Serve-stale (RFC 8767) | `crates/dedens-cache/src/cache.rs`, client response timer (D45), EDE 3 and 19 | `crates/telltale/src/pipeline.rs` (DNS-007 P0); partial: no EDE 19 |
| Resolution failures (RFC 9520) | holds with exponential backoff (`crates/dedens-cache/src/cache.rs`, D22, D96) | partial: SERVFAIL held a fixed 5 s (`crates/telltale-cache/src/entry.rs`) |
| Query coalescing | `apps/dedensd/src/flights.rs` (D86) | `crates/telltale-cache/src/singleflight.rs` |
| Prefetch | partial: listed names only, `prewarm` (`apps/dedensd/src/serve/prewarm.rs`, D96) | popular entries near expiry (`crates/telltale/src/pipeline.rs`, DNS-008 P1) |
| Persistence across restarts | no | `crates/telltale-cache/src/persist.rs` (DNS-009 P1); partial: no zstd, which the spec says |
| DO, CD in the key | `crates/dedens-cache/src/key.rs` (D43) | `crates/telltale-cache/src/lib.rs` |
| ECS-scoped answers | not cached (`crates/dedens-cache/src/response.rs`) | keyed by source subnet, scope ignored (`crates/telltale-cache/src/lib.rs`) |
| Flush | no (a reload with new settings empties it, D55) | by name, subtree, all: `crates/telltale-api/src/cache_api.rs` |
| No allocation on a hit | measured (`docs/benchmarks.md` "Server hit path", D23) | tested (`crates/telltale-cache/tests/alloc.rs`, NFR-002 P0) |

## DNSSEC

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Validator | own, sans-IO (`crates/dedens-dnssec/src/validator/mod.rs`, D69, D75), `dnssec: validate` per forward stage (D77) | hickory-net 0.26 `DnssecDnsHandle` wrapped (`crates/telltale-upstream/src/dnssec.rs`, DNS-011 P0) |
| Default | off (D77) | off (`crates/telltale-config/src/schema.rs` `DnssecMode`); `spec/03-resolution-pipeline.md` says validate |
| Algorithms | RSA SHA-1/256/512, ECDSA P-256/P-384, Ed25519 on `ring` (`crates/dedens-dnssec/src/crypto/verify.rs`, D71); no Ed448 | the same, from hickory with `ring`; no Ed448 |
| DS digests | SHA-1, SHA-256, SHA-384 (`crates/dedens-dnssec/src/crypto/digest.rs`) | the same (hickory) |
| NSEC, NSEC3 denial | `crates/dedens-dnssec/src/denial/nsec.rs`, `crates/dedens-dnssec/src/denial/nsec3.rs` (D74) | hickory |
| NSEC3 iteration limits (RFC 9276) | cost charged in SHA-1 blocks (`crates/dedens-dnssec/src/crypto/budget.rs`, D106) | hickory: 100 soft, 500 hard |
| Cost limits (KeyTrap) | validator limits (D75), bounded debt (D106), per-client share (D117) | hickory caps; 2 query budgets, 8 proofs (`crates/telltale-upstream/src/dnssec.rs`) |
| Trust anchors | root DS bundled (`crates/dedens-dnssec/src/root.ds`, RFC 9718), DS or DNSKEY files, per zone (D72) | root KSKs from hickory; DNSKEY file |
| Negative trust anchors (RFC 7646) | `insecure:` (`crates/dedens-dnssec/src/anchor.rs`, D72) | `negative_trust_anchors` (`crates/telltale/src/pipeline.rs`) |
| Key cache | `crates/dedens-dnssec/src/validator/cache.rs`, no bogus zone kept (D86, D92) | hickory's LRU; insecure proofs 15 min |
| Bogus answer | SERVFAIL with its EDE (D77); AD ours alone (D114) | SERVFAIL, EDE 6, 7, 8 or 10; never served stale |
| Signatures removed for clients without DO | `crates/dedens-server/src/reply.rs` (D77) | partial: DNSKEY and DS kept (`strip_dnssec`) |
| Aggressive NSEC (RFC 8198) | no | partial: NSEC only, validation on (`crates/telltale-upstream/src/nsec.rs`) |
| Compact denial (RFC 9824) | partial: name error proofs, EDE 30 (`crates/dedens-dnssec/src/denial/mod.rs`) | no |

## Recursion

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Recursive resolver | no: planned crate `dedens-resolver` (D69); `dedens +trace` follows referrals (`apps/dedens/src/trace.rs`) | `crates/telltale-recursor/src/lib.rs`, `recursive://` upstream (DNS-012 P1, UPS-012 P1); one test file, a mock tree |
| QNAME minimisation (RFC 9156) | no | relaxed mode (`crates/telltale-recursor/src/lib.rs`) |
| Root priming (RFC 8109) | no | daily (`crates/telltale-recursor/src/lib.rs`) |
| Bailiwick, glue, work limits | no | `crates/telltale-recursor/src/msg.rs`; 96 queries, 32 referrals |

## Filtering

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Blocklist formats | hosts, plain names, `*.name` (`crates/dedens-plugins/src/blocklist/lists.rs`, D56) | the same plus AdBlock with `$important`, `$badfilter`, `$client`, `$dnstype`, `$denyallow`, `$dnsrewrite`, and Pi-hole regex (`crates/telltale-filter/src/parse/mod.rs`, FLT-001 P0) |
| Exact match | no: a name and its subdomains (D54) | per list or rule (FLT-002 P0) |
| Index | keyed SipHash set, suffix walk (D58, D110) | `fst` built, hash index queried; regex by `regex_automata::meta` (`crates/telltale-filter/src/matcher.rs`, FLT-003 P0) |
| Allowlists | `allow` (D56) | `kind = "allow"`, `@@`, four precedence tiers |
| Downloads | `ETag`, last copy kept, size cap (`apps/dedensd/src/download.rs`, D57, D104) | `ETag`, `If-Modified-Since`, last good kept, shrink refused (`crates/telltale-filter/src/fetch/mod.rs`, FLT-004 P0) |
| Lists parsed once | D120 | `crates/telltale/src/lists.rs` |
| CNAME targets inspected | D118 | `crates/telltale/src/pipeline.rs` (FLT-007 P0) |
| Block answer | NXDOMAIN, NODATA, REFUSED, null address, EDE 15 (`crates/dedens-plugins/src/blocklist/mod.rs`) | the same plus custom address, EDE 15 or 17 (FLT-008 P0) |
| Which rule blocked | no | partial: list and rule kind kept, line found by reparsing (`crates/telltale-filter/src/explain.rs`, FLT-013 P0) |
| Answer address filter, rebinding | no | `crates/telltale-policy/src/clients.rs` `AnswerFilter` (FLT-015 P1) |
| AAAA filter | no | `crates/telltale/src/pipeline.rs` (FLT-016 P2) |
| Per-client policy | no: plugins see the query only (`crates/dedens-server/src/plugin.rs`, D54) | groups by IP, CIDR, MAC, client id (`crates/telltale-policy/src/clients.rs`, FLT-005 P0, FLT-006 P0); hostname matching spec only |

## Local data: hosts, zones, rewrites

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Hosts file, PTR from addresses | `crates/dedens-plugins/src/hosts.rs` (D54) | `crates/telltale-policy/src/local.rs` `add_hosts`, generated PTR (DNS-010 P0) |
| Local records (A, AAAA, CNAME, TXT, SRV, MX, wildcard) | partial: A, AAAA, PTR (D54) | `crates/telltale-policy/src/local.rs` (DNS-010 P0) |
| Zone file parser | full RFC 1035 text, every type (`crates/dedens-proto/src/text/zone.rs`, D25) | subset: 7 types and apex SOA, NS (`crates/telltale/src/import.rs`) |
| Authoritative local zones | no: parser only | `crates/telltale/src/server.rs` `load_zones`, per group (DNS-018 P1) |
| Rewrites | no | `crates/telltale-filter/src/rewrite.rs`, group rewrites (FLT-014 P1) |
| Special-use names (RFC 6761, 6303) | no | `crates/telltale-policy/src/special.rs`: localhost, `.invalid`, private reverse zones, Firefox canary |
| DNS64 (RFC 6147) | no | `crates/telltale/src/pipeline.rs` `dns64_for` (DNS-016 P1) |

## Privacy: ECS, padding, ODoH, DNSCrypt

| Feature | dedens | TelltaleDNS |
|---|---|---|
| ECS (RFC 7871) | client's option never forwarded (`crates/dedens-server/src/forward.rs`, D41); none sent | stripped, or a fixed subnet, or the client's /24 or /56 (`crates/telltale-upstream/src/upstream.rs`, DNS-015 P1); pass-through spec only |
| Padding (RFC 7830, 8467) | queries and replies over TLS, QUIC, HTTPS (`crates/dedens-net/src/exchange.rs`, `crates/dedens-server/src/reply.rs`) | no (`PADDING` constant unused) |
| ODoH | target, proxy, client (D79, D94) | no |
| DNSCrypt | server and client, PQ (D97, D99, D101) | client (UPS-003 P1) |
| Query-name minimisation upstream | n/a (forwarder) | recursor only |
| Query log privacy | n/a: no query log | levels 0-3 (`crates/telltale/src/privacy.rs`) |

## Abuse limits: rate limits, cookies, budgets

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Access lists (RFC 5358) | allow and deny, refuse or drop (`crates/dedens-server/src/access.rs`, D91) | allow only (`crates/telltale-policy/src/lib.rs`, `[access]`) |
| Response rate limiting, UDP and DoC | per /24 or /56, slip TC=1 (`crates/dedens-server/src/rrl.rs`, D113) | no |
| Per-client query rate | no (RRL is UDP and DoC only) | per /32 or /64, any transport, REFUSED or drop (`crates/telltale-policy/src/ratelimit.rs`, DNS-014 P0) |
| Server cookies (RFC 7873, 9018) | `crates/dedens-server/src/cookie.rs`, constant-time (D113, D136) | no; spec `03-resolution-pipeline.md` reads the option |
| Per-client work budget | validation and decapsulation per /24 or /48 (`crates/dedens-server/src/budget.rs`, D117) | no: 4096 upstream permits, global |
| ANY (RFC 8482), AXFR and IXFR | `crates/dedens-server/src/pipeline/mod.rs` (D114) | `crates/telltale/src/pipeline.rs` (DNS-019 P0) |
| Malformed input | FORMERR, QDCOUNT over one too (`crates/dedens-server/src/pipeline/mod.rs`, D41) | `crates/telltale-proto/src/query.rs` (DNS-019 P0) |
| Configuration bounds | D115 | schema checks (`crates/telltale-config/src/validate.rs`) |

## Operations: config, reload, privileges, sandbox, metrics, logs

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Configuration | one YAML file, `${VAR}`, bounded (`apps/dedensd/src/config/mod.rs`, D44, D115) | layered TOML, env overrides, JSON Schema (`crates/telltale-config/src/schema.rs`, OPS-005 P0) |
| Reload | SIGHUP, queries in flight finish on the old pipeline (`apps/dedensd/src/reload.rs`, D55); loom-checked (D135) | SIGHUP, API (`crates/telltale/src/server.rs`, OPS-009 P0); no test of zero loss |
| Shutdown | closes its QUIC connections on SIGTERM, then exits (D157) | drains (`crates/telltale/tests/shutdown_drain.rs`, OPS-007 P0) |
| Privileges | drops root once bound (`apps/dedensd/src/privileges/unix.rs`, D122) | no drop in code; the image and unit run unprivileged, compose as root |
| Sandbox | systemd hardening (`deploy/packages/dedensd.service`, D156) | systemd and Helm (`deploy/systemd/telltale.service`) |
| Panic | one task ends, the listener restarts (`apps/dedensd/src/serve/isolate.rs`, D121) | `panic = "abort"`: the process ends |
| Metrics | partial: counters through the `metrics` facade (`crates/dedens-server/src/metrics.rs`, D30), no exporter | Prometheus (`crates/telltale-telemetry/src/prom.rs`, OBS-005 P0), OTLP (`crates/telltale/src/otlp.rs`, OBS-006 P1) |
| Health endpoints | no | `/healthz`, `/readyz`, `/livez` (`crates/telltale/src/http.rs`, OPS-006 P0) |
| Process logs | `tracing`, JSON or text (`apps/dedensd/src/log.rs`, D30) | `tracing`, text only |
| Query logs | no | store (`crates/telltale-store/src/qlog/`, OBS-003 P0), dnstap (`crates/telltale/src/dnstap.rs`, OBS-007 P1), syslog, JSON lines, webhook (`crates/telltale/src/sinks.rs`, OBS-010 P1) |
| Allocator | mimalloc, secure (D154) | mimalloc |

## Packaging

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Static binary | musl static PIE (D151) | musl static (`Dockerfile`) |
| OCI image | `Containerfile`, `FROM scratch`, x86_64 and aarch64 (D153) | `Dockerfile`, `FROM scratch`, amd64, arm64, arm/v7, size checked (OPS-001 P0) |
| deb, rpm | nfpm (`deploy/packages/`, D156) | no |
| systemd unit | `deploy/packages/dedensd.service` | `deploy/systemd/telltale.service`, `deploy/systemd/install.sh` |
| Helm, compose | no | `deploy/helm/telltale/` (OPS-002 P0; PDB, HPA spec only), `deploy/compose/compose.yaml` (OPS-004 P0) |
| Man pages | `deploy/packages/man` (D158) | no |
| Licences of dependencies | cargo-about (`deploy/about.toml`, D158) | no |
| Signed releases | build provenance attested, archives and image (`.github/workflows/release.yml`, D153) | cosign images, minisign checksums (`deploy/release/verify.sh`, NFR-005 P0) |
| Dependency list | in the binary, `cargo auditable` (D153) | `cargo auditable`; CycloneDX SBOM (NFR-005 P0) |
| Reproducible builds | binaries built twice and compared on each release (`just release`, D153) | partial: amd64, nightly only (`.github/workflows/nightly.yml`) |
| Self-update | no | minisign-checked (`crates/telltale/src/selfupdate.rs`) |

## Tests and verification: fuzz, Kani, Verus, simulation, mutants

| Feature | dedens | TelltaleDNS |
|---|---|---|
| Tests | ~2200 `#[test]` and async | ~870 |
| Fuzz | 37 targets in `fuzz/fuzz_targets/`, nightly per target (D141, D181) | 6 in `fuzz/fuzz_targets/`, nightly 30 min (NFR-004 P0); partial: compiler, API, config, cache dump not fuzzed |
| Differential parsing | `fuzz/fuzz_targets/differential_hickory.rs` | `fuzz/fuzz_targets/differential.rs`, proptest (`crates/telltale-proto/tests/proto.rs`) |
| Kani | wire decoders, four packages (`.github/workflows/kani.yml`, D145, D179) | no |
| Verus | name reading, decompression, NSEC cover (`crates/dedens-proto/src/name.rs`, D180) | no |
| Network simulation | turmoil, the cores and `dedensd`'s serving loop (`crates/dedens-sim/`, D133, D182) | no; election only (`crates/telltale-cluster/tests/sim.rs`) |
| Loom | reload wake-up, flights (D135) | no |
| Mutation testing | cargo-mutants on pull requests (`.github/workflows/mutants.yml`, D103) | no |
| Sanitizers | cargo-careful and ASan (D144) | ASan through fuzzing |
| CodeQL | weekly (`.github/workflows/codeql.yml`, D146) | no |
| `unsafe` | none (D15) | 43 blocks in `crates/telltale-net/src/sys.rs`, tested to stay there (NFR-003 P0) |
| Test data | real captures and RFC zones (`testdata/`, D161) | synthetic |
| Interoperability | ODoH against `odoh-rs`, by hand (`tests/interop`, D79) | no; end-to-end scripts against itself (`deploy/dnssec-e2e.sh` and others) |
| Benchmarks | divan and dnsperf (`docs/benchmarks.md`) | dnsperf and h2load (`bench/`), `docs/v1-gate.md` |

## RFCs

dedens's status and code per RFC are in [`../rfc/coverage.md`](../rfc/coverage.md); the dedens column gives the
status there and one file. TelltaleDNS's "via hickory" means the code is hickory-net's, wrapped.

| RFC | dedens | TelltaleDNS |
|---|---|---|
| 1034 | partial: no resolver (`apps/dedens/src/trace.rs`) | `crates/telltale-recursor/src/lib.rs` |
| 1035 | partial (`crates/dedens-proto/src/record.rs`) | partial: compresses the question name only (`crates/telltale-proto/src/writer.rs`) |
| 1123 | partial (`crates/dedens-net/src/exchange.rs`) | partial (`crates/telltale-net/src/tcp.rs`) |
| 1982 | partial (`crates/dedens-dnssec/src/rrsig/verify.rs`) | partial: via hickory |
| 1995 | partial: refused (`crates/dedens-server/src/pipeline/mod.rs`) | refused (`crates/telltale/src/pipeline.rs`) |
| 2181 | partial (`crates/dedens-proto/src/record.rs`) | partial (`crates/telltale-recursor/src/msg.rs`) |
| 2308 | partial (`crates/dedens-cache/src/response.rs`) | `crates/telltale-cache/src/entry.rs` |
| 2782 | done (`crates/dedens-proto/src/rdata/srv.rs`) | partial: local data only (`crates/telltale-policy/src/local.rs`) |
| 3110 | partial (`crates/dedens-dnssec/src/crypto/verify.rs`) | via hickory |
| 3152 | done (`crates/dedens-proto/src/name.rs`) | partial (`crates/telltale-policy/src/special.rs`) |
| 3225 | done (`crates/dedens-cache/src/key.rs`) | `crates/telltale-cache/src/lib.rs` |
| 3596 | done (`crates/dedens-proto/src/rdata/mod.rs`) | `crates/telltale-policy/src/local.rs` |
| 3597 | done (`crates/dedens-proto/src/rdata/opaque.rs`) | partial: `TYPEnnn` names (`crates/telltale-proto/src/consts.rs`) |
| 4033, 4034, 4035 | partial (`crates/dedens-dnssec/src/validator/`) | via hickory (DNS-011 P0) |
| 4343 | partial (`crates/dedens-proto/src/name.rs`) | `crates/telltale-cache/src/entry.rs` |
| 4509 | done (`crates/dedens-dnssec/src/crypto/digest.rs`) | via hickory |
| 4648 | partial (`crates/dedens-proto/src/text/encoding.rs`) | `crates/telltale-net/src/doh.rs` |
| 5001 | done: option format (`crates/dedens-proto/src/edns/mod.rs`) | served (`crates/telltale/src/pipeline.rs`, DNS-021 P2) |
| 5011 | partial: REVOKE (`crates/dedens-dnssec/src/rrsig/verify.rs`) | no; spec `03-resolution-pipeline.md` says yes |
| 5155 | partial (`crates/dedens-dnssec/src/denial/nsec3.rs`) | via hickory |
| 5358 | partial (`crates/dedens-server/src/access.rs`) | partial: allow list (`crates/telltale-policy/src/lib.rs`) |
| 5452 | partial (`crates/dedens-net/src/exchange.rs`) | `crates/telltale-recursor/src/net.rs` |
| 5702 | partial (`crates/dedens-dnssec/src/crypto/verify.rs`) | via hickory |
| 5891, 5895 | CLI (`apps/dedens/src/idn.rs`) | partial: list parsing (`crates/telltale-filter/src/parse/`) |
| 5936 | partial: refused (`crates/dedens-server/src/pipeline/mod.rs`) | refused (`crates/telltale/src/pipeline.rs`) |
| 6570 | partial (`crates/dedens-net/src/doh.rs`) | no |
| 6605 | done (`crates/dedens-dnssec/src/crypto/verify.rs`) | via hickory |
| 6672 | partial (`crates/dedens-proto/src/name.rs`) | partial: followed (`crates/telltale-recursor/src/msg.rs`) |
| 6690, 7252, 7959, 8132 | partial (`crates/dedens-net/src/coap/`) | no |
| 6840 | partial (`crates/dedens-cache/src/response.rs`) | `crates/telltale-upstream/src/dnssec.rs` |
| 6891 | partial (`crates/dedens-proto/src/edns/mod.rs`) | `crates/telltale-proto/src/edns.rs` |
| 6895 | partial (`crates/dedens-proto/src/text/mod.rs`) | no |
| 7344, 8078 | partial: record formats (`crates/dedens-proto/src/rdata/ds.rs`) | no |
| 7646 | done (`crates/dedens-dnssec/src/anchor.rs`) | `crates/telltale/src/pipeline.rs` |
| 7766 | partial (`apps/dedensd/src/serve/tcp.rs`) | `crates/telltale-net/src/tcp.rs` |
| 7828 | partial: client (`crates/dedens-net/src/tcp.rs`) | no |
| 7830, 8467 | done (`crates/dedens-server/src/reply.rs`) | no |
| 7858 | partial (`crates/dedens-net/src/tls.rs`) | `crates/telltale-net/src/tls.rs` |
| 7871 | partial: format, scoped answers not cached (`crates/dedens-proto/src/edns/subnet.rs`) | partial: no pass-through, scope ignored (`crates/telltale-upstream/src/upstream.rs`) |
| 7873, 9018 | partial (`crates/dedens-server/src/cookie.rs`) | no |
| 8080 | partial: no Ed448 (`crates/dedens-dnssec/src/crypto/verify.rs`) | partial: no Ed448, via hickory |
| 8310 | partial (`crates/dedens-net/src/tls.rs`) | partial: strict, SPKI pins (`crates/telltale-upstream/src/tls.rs`) |
| 8482 | partial (`crates/dedens-server/src/reply.rs`) | `crates/telltale/src/pipeline.rs` (DNS-019 P0) |
| 8484 | partial: HTTP/3 (`crates/dedens-net/src/doh.rs`) | `crates/telltale-net/src/doh.rs` (DNS-003 P0) |
| 8659 | done (`crates/dedens-proto/src/rdata/caa.rs`) | partial: type number only |
| 8767 | partial (`crates/dedens-cache/src/cache.rs`) | partial: no EDE 19 (`crates/telltale/src/pipeline.rs`) |
| 8906 | done: client (`crates/dedens-net/src/exchange.rs`) | no |
| 8914 | done (`crates/dedens-proto/src/edns/ede.rs`) | partial: 9, 16, 19 never sent (DNS-013 P0) |
| 8976 | partial: a test of the `uri.arpa.` zone | no |
| 9077 | partial (`crates/dedens-dnssec/src/denial/mod.rs`) | partial (`crates/telltale-upstream/src/nsec.rs`) |
| 9110, 9111 | partial (`crates/dedens-net/src/doh.rs`) | partial: `Cache-Control` (`crates/telltale-net/src/doh.rs`) |
| 9114 | partial (`crates/dedens-net/src/http3.rs`) | `crates/telltale-net/src/doh3.rs` |
| 9180, 9209, 9230 | `crates/dedens-odoh/src/lib.rs`, `apps/dedensd/src/odoh/proxy.rs` | no |
| 9221 | partial (`apps/dedensd/src/serve/quic.rs`) | no |
| 9250 | partial (`apps/dedensd/src/serve/quic.rs`) | `crates/telltale-net/src/doq.rs` |
| 9276 | partial (`crates/dedens-dnssec/src/crypto/budget.rs`) | via hickory |
| 9460, 9461 | partial (`crates/dedens-proto/src/rdata/svcb.rs`) | partial: type numbers only |
| 9520 | partial (`crates/dedens-cache/src/cache.rs`) | partial: fixed 5 s |
| 9619 | done (`crates/dedens-proto/src/message.rs`) | `crates/telltale-proto/src/query.rs` |
| 9718 | done (`crates/dedens-dnssec/src/root.ds`) | no |
| 9824 | partial (`crates/dedens-dnssec/src/denial/mod.rs`) | no |
| 9904 | partial (`crates/dedens-dnssec/src/crypto/digest.rs`) | via hickory |
| 9905 | partial: SHA-1 validated (`crates/dedens-dnssec/src/crypto/verify.rs`) | partial: SHA-1 validated |
| 9953 | partial (`crates/dedens-net/src/coap/dns.rs`) | no |
| DNSCrypt, DNS stamps drafts | `crates/dedens-dnscrypt/`, server and client (D97, D102) | client, stamps 0x01-0x04 and 0x81 (`crates/telltale-upstream/src/dnscrypt.rs`) |

Theirs outside this list: RFC 6147 (DNS64), 9156 and 8109 (recursor), 8198 (NSEC only), 6761 and 6303
(`crates/telltale-policy/src/special.rs`), 5424 (syslog), dnstap, PROXY protocol v2. RFC 9462 (DDR) is in their spec,
not their code.

## Left out by scope

Their product beyond a DNS server; none is a dedens goal (D1: a library, a CLI and a server).

- Web UI: `ui/`, a Svelte app served by `crates/telltale-api/src/ui.rs` (API-005).
- Per-device query log, live tail, stage timings and explanations: `crates/telltale-store/src/qlog/`,
  `crates/telltale/src/tail.rs`, `crates/telltale/src/explain.rs` (OBS-003, OBS-008).
- Device naming: OUI table, passive mDNS, DHCP leases from routers: `crates/telltale/src/identify.rs`,
  `crates/telltale/src/mdns.rs`, `crates/telltale/src/routers.rs`.
- Groups, schedules, pause, safe search, blocked services: `crates/telltale-policy/src/clients.rs`,
  `crates/telltale-config/src/schedule.rs`, `crates/telltale-config/src/safesearch.rs`,
  `crates/telltale-config/src/services.rs` (FLT-005, FLT-009 to FLT-012).
- What-if replays of the query log and shadow lists: `crates/telltale/src/simulate.rs`, `crates/telltale/src/shadow.rs`
  (OBS-024, OBS-018).
- Dashboards, analytics, anomaly and DGA detection, SLOs, alerts by mail and webhook: `crates/telltale-api/src/`,
  `crates/telltale-telemetry/src/anomaly.rs`, `crates/telltale/src/alerts.rs`.
- REST API with OpenAPI and OIDC: `crates/telltale-api/src/lib.rs`, `crates/telltale-api/src/auth/oidc.rs` (API-001,
  API-004).
- MCP tools, with plans and approvals: `crates/telltale-api/src/mcp.rs`, `crates/telltale/src/mcp_stdio.rs`.
- Cluster with witness failover, signed snapshots, staged rollouts, drills: `crates/telltale-cluster/`,
  `crates/telltale/src/rollout.rs`, `crates/telltale/src/drill.rs` (CLU-001 to CLU-014).
- Configuration from Git: `crates/telltale-git/`, `crates/telltale/src/gitsource.rs` (OPS-005).
- Kubernetes workloads as clients: `crates/telltale/src/kubernetes.rs` (FLT-017).
- Pi-hole and Technitium import: `crates/telltale/src/pihole.rs`, `crates/telltale/src/technitium.rs`.
- Backups, audit log, maintenance mode, self-update: `crates/telltale/src/backup.rs`,
  `crates/telltale-store/src/state/audit.rs`, `crates/telltale/src/maintenance.rs`.

## Gaps

Ranked by how much they matter to a DNS server's users.

dedens lacks:

1. A Prometheus exporter and health endpoints: counters exist, nothing exports them (D30).
2. DoH over HTTP/2: most DoH clients (browsers, OSes) ask HTTP/2, dedens serves HTTP/3 only (D84).
3. Conditional forwarding: a domain or reverse zone sent to its own servers.
4. Server choice and upstream health: in order only, no breaker, no fastest or parallel.
5. Local records beyond A, AAAA, PTR, and authoritative local zones from the zone parser dedens already has.
6. A recursive resolver (planned `dedens-resolver`).
7. A query log: dnstap, or JSON lines.
8. Per-client policy: groups, client ids from DoH paths or SNI.
9. A per-client query rate over TCP, TLS, QUIC and HTTPS (RRL covers UDP and DoC).
10. Blocklist formats: AdBlock syntax and regex.
11. Graceful drain on shutdown (D157 closes the QUIC connections and exits, the queries in flight dropped).
12. Cache persistence and popularity prefetch.
13. Rewrites, DNS64, special-use names, response address filtering against rebinding.
14. PROXY protocol v2, upstream proxies (SOCKS5), exec plugins.
15. An arm/v7 image, a Helm chart, a compose file.

TelltaleDNS lacks:

1. DNS cookies and response rate limiting: its UDP answers can be aimed at a spoofed victim, bounded only by a
   per-source rate.
2. EDNS padding of queries and replies.
3. A DNSCrypt server, ODoH (target, proxy, client), DNS over CoAP; DNSCrypt without PQ.
4. A validator of its own: DNSSEC is hickory's, off by default, DNSKEY and DS left to clients without DO.
5. Per-client work budgets: one client can spend the 4096 global upstream permits.
6. Panic isolation: `panic = "abort"`, one bug ends the server.
7. A privilege drop in the binary, and a deny access list.
8. RFC 9520 failure holds with backoff, EDE 19, compact denial (RFC 9824), RFC 9718 anchors.
9. Formal and concurrency checks: Kani, Verus, loom, network simulation, mutation testing, CodeQL.
10. Test data from real captures: theirs is written by hand.
11. deb and rpm packages, man pages, licences of dependencies.
12. A full zone file parser and name compression beyond the question.
