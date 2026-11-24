# Architecture

## Crates

| Path | Role | I/O |
|---|---|---|
| `crates/dedens-proto` | Wire format and zone-file text: messages, names, records, EDNS | none (sans-IO) |
| `crates/dedens-cache` | Response cache for the server: sharded, serve-stale; its byte-budgeted `Store` (D193) | none, time passed in |
| `crates/dedens-resolver` | Recursive resolver: the iteration (D191), a response scrubbed to what the zone asked may say, into ranked `RRsets` (D192); the `RRset` cache (D193), the infra cache of authoritative servers (D194); the answer validated by `dedens-dnssec`, its questions iterated (D197) | none (sans-IO), time and randomness passed in |
| `crates/dedens-server` | Server core: client access lists (D91), signed requests and zone access lists (D211), UDP and DoC rate limit and Server Cookies (D113), client budgets (D117), the stage pipeline and the replies it builds itself, the recurse stage and the zones it serves locally (D195), the authoritative stage answering from `dedens-zone`'s zones (D208) | none (sans-IO) |
| `crates/dedens-plugins` | Plugin stages (D54): hosts, blocklist | none (sans-IO) |
| `crates/dedens-dnssec` | DNSSEC validation (D69): signatures, denial of existence, chain of trust and the verdict on a response; IANA's signed root anchors (D127, `fetch-anchors`); the root's key rollover by RFC 5011 (D200) | none (sans-IO), time passed in |
| `crates/dedens-zone` | A zone for the authoritative phase (D204): zone text loaded into an immutable `Zone`, its names in canonical order with the delegations, DNAMEs, wildcards and empty non-terminals marked, checked per RFC 1035 §5.2 and RFC 2181 §10.1, bounded by `Limits`; changesets between versions (`Zone::diff`, `Zone::apply`) and their journal file (D207); an UPDATE made into a changeset (`Zone::update`, D216); `Zone::answer` (D206): the answer to a question, RFC 1034 §4.3.2 with wildcards, DNAME and glue, filled into a `Message`, with DO the signatures and NSEC or NSEC3 proofs of a pre-signed zone (D209, hashing through `dedens-dnssec`) | the journal's file (blocking), `$INCLUDE` through a callback |
| `crates/dedens-tsig` | TSIG (D205): `Key`, `Keyring`, `Algorithm` (hmac-sha1, -256, -384, -512), the server's `verify_request` and `ResponseSigner`, the client's `sign_request` and `ResponseVerifier` for a request, a response or a TCP stream (RFC 8945) | sans-I/O: bytes and the clock in, bytes out |
| `crates/dedens-roots` | IANA's root hints and TLD list (D126): bundled, and read from a fresh copy | none (sans-IO) |
| `crates/dedens-odoh` | Oblivious DoH (RFC 9230), experimental (D69, D78): configurations, message encryption | none (sans-IO) |
| `crates/dedens-dnscrypt` | DNSCrypt (draft-denis-dprive-dnscrypt), experimental (D97, D101): certificates, query and response encryption for both classical systems and the X-Wing one (PQDNSCrypt, with resumption tickets) | none (sans-IO), time and randomness passed in |
| `crates/dedens-net` | UDP, TCP, TLS, QUIC, HTTP/3 (DoH, D83) and CoAP (DoC, D81) transports on compio over sans-IO cores; the client's pools, its authoritative mode for the recursive resolver (D190), and `dedensd`'s serving loop behind the `Io` seam (D134, D182); Oblivious DoH, `odoh` feature (D79); DNS stamps (D102) and the DNSCrypt client over them (D98), `dnscrypt` feature; `resolv.conf`; the zone transfer client, AXFR and IXFR signed by `dedens-tsig` into a `dedens-zone` zone or changesets (D210) | sockets, timers |
| `crates/dedens-scenario` | Query files: queries, options, expectations; the JSON and YAML report | none |
| `crates/dedens-bench` | Benches (divan) of the workspace, against hickory-proto, `domain`, Go's `miekg/dns`, Unbound; `dedensd` under dnsperf (`just bench-dnsperf`), and against TelltaleDNS, Unbound, CoreDNS, Knot and NSD (`just bench-compare`); the cache's hit ratio (`examples/hit_ratio.rs`, D116) | none |
| `crates/dedens-testkit` | Test-only (D161): `testdata/` read and decoded, the RFC examples' keys, the test certificates, the loopback responder of the binaries' tests, the recursive resolver's captured resolutions and their replay (`recursion`, D188) | files, sockets (`responder`) |
| `crates/dedens-sim` | Simulation tests (D133, D134, D182, D189): the sans-IO server core, `dedensd`'s serving loop and `dedens-net`'s client, pools included, as hosts of a seeded turmoil network, beside the captured Internet's authoritative servers and `dedensd` serving zones (D208) | simulated |
| `crates/dedens-repo` | The repository checks of the gate (D140, D163), its tests alone: decisions, RFC coverage, `CLAUDE.md` links, crates' `clippy.toml`, pinned Rust | files (`git ls-files`) |
| `apps/dedens` | The dig-like CLI; a library its binary and `fuzz/` call (D181) | via `dedens-net`, files |
| `apps/dedensd` | The server: threads and sockets around `dedens-server`, upstream via `dedens-net`; drops root once bound (D122); a library its binary and `fuzz/` call (D181) | sockets, files, HTTP (lists) |
| `deploy/` | What a release ships beside the binaries (D153, D156, D158): the image's `dedensd.yaml`, the deb and rpm packages' files (systemd unit, sysusers, maintainer scripts, man pages that `just man` writes and each binary's tests compare with its command line), the licence report's `about.toml` | none |
| `fuzz/` | libFuzzer targets of the parsers of outside data, the binaries' included (D181), own workspace | none |
| `testdata/` | Real data the tests, benches, fuzz targets and simulations share: captures, RFC example zones, lists (D161) | read as files |

## Data flow

- Client (`apps/dedens`): `Options::query` → `dedens-net` (Oblivious DoH through `Client::exchange_oblivious`, D79;
  DNSCrypt through `Client::exchange_dnscrypt_via`, D98; `+trace` hop by hop in `src/trace.rs`, D40) →
  `Message::decode` → with `+validate`, `src/validate.rs` over `dedens-dnssec` (D76) → `Report::exchanged` →
  `src/output.rs` (D37), with any `Violation` shown. `+tld`: IANA's RDAP server over HTTPS (`src/run/tld.rs`), its
  answer read by `src/rdap.rs`, a 404 explained by `dedens-roots` (D129); `+rdap`: the TLD's server from IANA's
  bootstrap file, the client and printer both share (`src/run/rdap.rs`, D130).
- Server, a query: `apps/dedensd/src/serve/` (a module per transport, D65, D66, D81, D84; ODoH in
  `apps/dedensd/src/odoh/`, D79, D94; DNSCrypt in `apps/dedensd/src/dnscrypt/` and `serve/dnscrypt.rs`, D99) →
  `crates/dedens-server/src/access.rs` (D91) → `Query::read` → `cookie.rs` and `rrl.rs` (D113) → the TSIG verified,
  the reply signed (`pipeline/signed.rs`, D211) → the stage pipeline (`pipeline/`, D23) of stages `authoritative.rs`
  (D208, its zones loaded and kept across reloads by `apps/dedensd/src/zones.rs`, each zone's transfer, notify and
  update lists in `zone_access.rs`, D211; the access lists past it), `plugin.rs`, `cache.rs` and `forward.rs` or
  `recurse/` (D195; `apps/dedensd/src/serve/recurse.rs` steps the resolution, `dedens-resolver`, over `dedens-net`'s
  authoritative mode, D190); a cache hit is copied and patched in place (`dedens-cache`, D116), every reply fitted to
  the query by `reply.rs` → send (UDP: the socket's `Outbox`, D123).
- Server, an UPDATE (D216): `pipeline/update.rs` reads it into `dedens-proto`'s `Update`, finds its zone, checks the
  zone's `update` list → `Step::Update` → `apps/dedensd/src/updates.rs` queues it to the reload thread
  (`reload.rs`), which makes it with `Zone::update` (`dedens-zone`), saves the zone and its journal in `state_dir`
  (`zones.rs`), rebuilds the pipeline, and answers → `Pipeline::updated` writes and signs the reply.
- Server, a response from upstream: `Message::decode` (D28) → `forward::usable` → with `dnssec: validate`,
  `validate.rs` (D77; its cost: `budget.rs`, D117; questions in flight shared: `apps/dedensd/src/flights.rs`, D86)
  → `Cache::insert` or `Cache::insert_checked`, encoded once there and served as a hit from then on (D43).
- Server, prewarm: a cache stage's `prewarm` names → `Pipeline::with_prewarm` (`crates/dedens-server/src/pipeline/prewarm.rs`)
  → one task of thread 0 (`apps/dedensd/src/serve/prewarm.rs`) asks each through `Pipeline::prewarm`, as a prefetch,
  when `Cache::refresh` says (D96).
- Zone files: `ZoneReader` → `DecodedRecord`s; `$INCLUDE` goes back to the caller, which `dedens-zone`'s `Zone::load` calls through its callback to build and check a `Zone`.

## Documents

- [`docs/decisions/`](docs/decisions/README.md): every design choice and its reason (`Dn`), a file per section and
  an index.
- [`docs/TODECIDE.md`](docs/TODECIDE.md): open questions with proposed defaults.
- [`tests/interop/`](tests/interop/odoh.py): `dedensd` as an Oblivious DoH target for Cloudflare's `odoh-rs`
  (`just odoh-interop`, by hand, needs `uv` and the network); `just odoh-live` asks public targets (D79).
- [`docs/benchmarks.md`](docs/benchmarks.md): measurements behind the performance decisions.
- [`docs/alloc-security.md`](docs/alloc-security.md): what each candidate allocator stops (D152).
- [`docs/providers/providers.yaml`](docs/providers/providers.yaml): public resolvers and their endpoints,
  checked by `just providers` (D67).
- [`docs/blocklists/blocklists.yaml`](docs/blocklists/blocklists.yaml): published blocklists and their
  formats, checked by `just blocklists` (D87).
- [`docs/rfc/coverage.md`](docs/rfc/coverage.md): each RFC's status, code and tests; the RFC texts are in
  `docs/rfc/archive/`, the list in `docs/rfc/list.md`.
- [`docs/comparison/`](docs/comparison/README.md): dedens against other DNS servers, feature by feature, each cell
  citing code; TelltaleDNS first.
