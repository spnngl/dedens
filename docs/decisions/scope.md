# Scope

Decisions; the rules and the index are in [`README.md`](README.md).

- D1 Crates per [`ARCHITECTURE.md`](../../ARCHITECTURE.md), all on `dedens-proto`. CLI and server are separate
  binaries.
- D2 (amended by D60, D69) Order: unencrypted core DNS first (wire format, UDP, TCP), then DNSSEC and encrypted transports (DoT, DoH,
  DoQ). A stub resolver and CLI first; forwarder, recursive and authoritative servers follow.
- D3 Own wire format, for full control of RFC behaviour and speed. hickory-dns and NLnet Labs' `domain` are
  reference code only.
- D4 Runtime: compio, features `io-uring` and `polling`: io_uring on Linux, polling at runtime where io_uring
  is blocked (containers, seccomp), kqueue on macOS, rustls and QUIC ready. Rejected: tokio-uring (dead since
  2024-05), monoio (5 commits a year), glommio (dead since 2025-04), tokio's `io-uring` feature (files only), raw
  `io-uring` (we would write a runtime). Fallback: tokio. Risk: compio is 0.x, contained by D5.
- D5 `dedens-proto` is sans-IO, so a runtime change touches one crate and the server reuses the codec as is.
- D160 (builds on D1, D159; amended by D161) A library crate exports each public item at one path: its modules are
  private and `lib.rs` re-exports their public items at the root, one sorted `pub use` list, as ripgrep's `grep-*`
  crates. Exceptions, each a public module whose items are not re-exported: `dedens-net` keeps every module public, as
  several of its items share a name (`Exchange` x2, `Options`, `Response`, `Failure`, `Link`); `dedens-proto` keeps
  `rdata` and `edns` (`rdata::RData`, `edns::Edns`; `edns::Option` would shadow `std`) and `dedens-dnssec` keeps
  `crypto`, `rrsig` and `denial`, families a reader names, and flattens `anchor` and `validator`. Every other library
  crate is flat. A name read at the root carries what the module gave it: `ZoneEntry`, not `text::Entry`; an error is
  `<Thing>Error` (`SubnetError`, `CookieError`). A crate re-exports none of its dependencies' items (`Transport` is
  `dedens_proto::Transport` only). The workspace lint `unnameable_types` flags a type the API hands out that no path
  names, as an item of a private module the root forgot. Why: an item reachable at two paths gets imported both ways
  (`Transport` was imported from four), and a reader cannot tell they are one item. Rejected: every module public with
  no re-export (the paths repeat the type, `name::Name`); a glob `pub use` (hides what is exported).
- D6 Linux and macOS. Stable pinned in `rust-toolchain.toml` and bumped by Renovate, so new lints arrive as a
  PR, not a red CI; MSRV 1.95. One nightly pinned by date in the justfile, bumped by hand with RAPx, for
  rustfmt, `-Z` flags and RAPx only: an unpinned nightly reformats code on its own.
- D150 (builds on D6; amended by D166) Every build links with lld, Rust's own, from rustup's toolchain: nothing to install. It relinks
  the debug `dedensd` on Linux 3.6 times faster than GNU ld (2 s against 7 s); on macOS Apple's `ld` is 0.2 s faster;
  the release build is codegen's and does not move ([`benchmarks.md`](../benchmarks.md)). The mechanism differs by target,
  for no stable flag selects lld on all of them: `x86_64-unknown-linux-gnu` has no entry, rustc (1.90) links it with its
  bundled `rust-lld` unasked; `aarch64-apple-darwin` and `aarch64-unknown-linux-gnu` set
  `linker = ".cargo/lld-cc"` in `.cargo/config.toml`, a short wrapper that runs `cc -fuse-ld=lld` with rustc's
  `gcc-ld` directory (`ld.lld`, `ld64.lld`) first, so the `cc` driver still finds the target's runtime and SDK. The
  musl targets get theirs in D151. A `linker` is not `rustflags`: RUSTFLAGS in the environment replaces
  the config's `rustflags` (loom, cargo-fuzz, cargo-careful, cargo-llvm-cov and RAPx set it), never `linker`. Each
  recipe's binaries were read for the linker (ELF `.comment` `Linker: LLD`, Mach-O `LC_BUILD_VERSION` tool 4), build
  scripts and proc macros included; hardening is unchanged ([`benchmarks.md`](../benchmarks.md)). Not reached: Kani on
  macOS builds host artifacts through `-Zhost-config`, which ignores `[target.<host>]`, so its build scripts link with
  Apple's `ld` (no binary of ours); the `aarch64-unknown-linux-gnu` entry is the macOS mechanism, run by no job
  (the arm64 runner builds musl, D151). A build then fails loudly, not silently with another linker, where `rust-lld` is
  missing (Homebrew's `rustc`: put rustup's `cargo` first) or too old for the SDK (macOS 27's: `SDKROOT` of a 26 SDK,
  [`TODECIDE.md`](../TODECIDE.md)). Rejected: `-fuse-ld=lld` in `rustflags` or `-C link-arg` (RUSTFLAGS replaces it; needs
  a system `ld.lld`), `-C linker-features=+lld` and `-C link-self-contained=+linker` (nightly), `-C linker=rust-lld`
  (macOS records SDK 11.0 for the one in use), a `[host]` table (unstable), mold (an install, no macOS).
- D166 (amends D150) The macOS targets link with Apple's `ld`, rustc's default through `cc`: `.cargo/config.toml`
  drops its `aarch64-apple-darwin` entry and has no `x86_64-apple-darwin` one, as before. The Linux targets keep lld
  (D150, D151). Why: Apple's SDK `.tbd` format runs ahead of the lld rustup's toolchain ships. The `libSystem.tbd` of
  macOS 27's SDKs names the target `arm64e.x1-macos`, which the `rust-lld` of stable 1.99.1 (LLVM 23.1.1) does not
  know, so every link failed on a Mac whose default SDK is a 27 one: `rust-lld: error: could not load TAPI file at
  /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib/libSystem.tbd: malformed file`. Apple's `ld` reads its
  own SDK, and lld bought nothing there: Apple's `ld` relinks the debug `dedensd` 0.2 s faster, the release build does
  not move ([`benchmarks.md`](../benchmarks.md)). D150's loud failure where `rust-lld` is missing is Linux's alone; a
  macOS binary records Apple's `ld` (Mach-O `LC_BUILD_VERSION` tool 3). Rejected: requiring a newer lld (no stable
  carries LLVM 23.1.4, the pinned nightly's, which reads the 27 SDK; the next SDK can move ahead again), `SDKROOT` of
  a 26 SDK (D150's workaround: a setting in each shell, on an SDK Apple stops shipping), `lld-cc` falling back to `ld`
  when `rust-lld` fails (two linkers, the switch silent).
- D151 (builds on D6, D150; amended by D152) The Linux binaries we ship are static PIE on `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl`: one file, no libc to match, none of glibc's NSS and `dlopen` surface. glibc stays for
  development and for the tools that need it (sanitizers, fuzzing, Kani, loom, mutants): `just check` is unchanged.
  `just musl <target> [cargo arguments]` builds and tests (the suite by default) natively in `rust:<channel>-alpine` of
  the host's architecture, under `container` (macOS: podman's Linux VM, so aarch64), with no cross toolchain; the CI
  job `musl`, in the gate, runs the suite then dedensd's root `privileges` test on `ubuntu-26.04` and
  `ubuntu-26.04-arm`. The libc and libunwind are those of rustc's target (musl, self-contained), not Alpine's; Alpine
  supplies `gcc` (ring's C and assembly), `git` and `procps-ng` for the tests (BusyBox's `ps` lacks `-p`), and `lld`:
  Rust's has no zlib and Alpine's C objects (`crti.o` of the failing link) have zlib-compressed debug sections, so
  `lld-cc` uses the system's lld there. x86_64 links static-pie unasked; rustc's target spec of aarch64 lacks `static-position-independent-executables`
  (`-static -no-pie` with `crt1.o`: an `EXEC` at a fixed address, found by reading the first binary), so `.cargo/lld-cc`
  swaps in `rcrt1.o`, `crtbeginS.o`, `crtendS.o` and `-static-pie`, as rustc does for x86_64, and the config sets
  `relocation-model=pic`; drop it when the spec has the flag. Read on release `dedensd` and `dedens` of both
  architectures (`readelf`, Alpine's binutils): `DYN`, `FLAGS BIND_NOW`, `FLAGS_1 NOW PIE`, `GNU_RELRO`, `GNU_STACK`
  `RW`, no `INTERP`, no `NEEDED`, `Linker: LLD 22.1.3`; x86_64 7.6 MB and 6.3 MB. The suite passes on both
  (151 test binaries, and the root test, on each). The x86_64 binary was run on the VPS (AlmaLinux 10.2, glibc, kernel
  6.12), each check passing: UDP, TCP and cache; DoT and DoH forwarding with the host's trust store, and a wrong
  certificate name refused (SERVFAIL); a 223,594-name blocklist downloaded through musl's resolver (`getaddrinfo`) and
  blocking its names; `io_uring` (`kernel.io_uring_disabled=0`) and, with it `2` (the host's), the `poll` fallback;
  root dropping to uid 99 from port 53 with no capability and `NoNewPrivs`. Differences from glibc: `getpwnam` reads
  `/etc/passwd` only, no NSS, so a `user:` name defined elsewhere (AlmaLinux's `nobody`, `nss-altfiles`, LDAP) is
  "no user named" and an id works (D122); musl's allocator is measured in D152; the trust store is the
  host's (`rustls-platform-verifier`), so an image holds one ([`TODECIDE.md`](../TODECIDE.md)). Rejected: cross-compiling
  from glibc (a cross `gcc` for ring, `musl-tools`), `cross` and `cargo-zigbuild` (a tool each), dynamic musl.
- D152 (amends D151; amended by D154; builds on D15) The musl binaries kept musl's own allocator (mallocng), until D154
  chose mimalloc's secure mode. The rule, fixed before measuring (plan README, now [`alloc-security.md`](../alloc-security.md)
  and "Allocators" in [`benchmarks.md`](../benchmarks.md)): among candidates passing the gates (musl and lld build, tests,
  a release in the last 12 months, no file opened after the first query, a licence `deny.toml` allows), the best
  security rank wins if, in every dnsperf mode and core count, its median per-round queries/s ratio is 0.90 or more, its
  p99 is within 25 % of the fastest and its peak RSS within 25 % of the lowest; else the next. x86_64 VPS, 8 shuffled
  paired rounds, defaults, a 1 h soak of `mi` and `mi-min` (the best by speed and RSS rank sum). Result: no candidate
  passes, and the rule does not say what then; keeping the status quo was a judgment, which D154 replaced. mallocng: the safest (20 of 20 runs stop 10 of the plan's 12 probe cases and the
  attacker gains nothing in the other two; 1,084 lines, MIT), the leanest (churn peak 94 MiB) and the slowest (median
  ratio 0.68, 0.53 to 0.80 by cell; p99 1.3 to 2.6 times the lowest; 1.3 to 16 times the cost of an allocating
  operation). mimalloc `MI_SECURE=4` is second: no gain for the attacker, but double and interior frees are ignored,
  1-byte overflows missed on 65 of 256 sizes, ratio 0.89 and a churn peak 94 % over mallocng's. mimalloc and its
  `MI_SECURE=1` build let the attacker gain in 5 and 4 cases. jemalloc fails the licence gate (its C is BSD-2-Clause,
  not in `deny.toml`'s list), has no hardening and starts 37 MiB on 3 threads. tcmalloc was dropped before measuring:
  upstream supports neither musl nor macOS, and its crate's last release (June 2025) was over 12 months old. Limits: one
  session on a shared host, x86_64 only (the probe ran on aarch64: what an allocator catches does not depend on the
  ISA), defaults untuned. The experiment is the tag `alloc-experiment-2026-11-06` (`build/alloc-experiment`, code
  `d46bd0e`), the probe `alloc-security-2026-11-06` (`crates/dedens-bench/alloc-probe/`). Its allocator features
  exclude one another, so `--all-features` cannot build it: a design that lands an allocator names it per target.
- D154 (amends D152; builds on D15, D151) The musl binaries, `dedensd` and `dedens`, use mimalloc with `MI_SECURE=4`
  (the `mimalloc` crate's `secure` feature: guard pages, randomised and encoded free lists) as their `#[global_allocator]`,
  a `[target.'cfg(target_env = "musl")'.dependencies]` entry and four lines in each `main.rs`; glibc, macOS and every
  tool build (careful, Miri, fuzz, loom, Kani, mutants) keep the system allocator. Chosen by the human over mallocng
  (D152's numbers: the rule selected none): the attacker gains nothing in any probe case, as with mallocng, at 0.89 of
  the fastest against mallocng's 0.68 and a lower p99. Paid: a churn peak of 184 MiB against 94, 0.2 MB of binary, 15,837
  lines of C built by `cc` (Alpine's gcc, already there for `ring`), and what mallocng alone stops: a double or interior
  free is ignored, not aborted, and an overflow of 1 byte goes unseen on 65 of 256 sizes. mimalloc's `options.c` embeds
  `__DATE__` and `__TIME__`, so the `Containerfile` sets `SOURCE_DATE_EPOCH=0` to keep the build reproducible (D153: without it two builds differed
  by that string). Read: the suite passes on both musl targets (the `musl` job), `just release` builds twice identical on
  both, and the image on the VPS answers UDP, TCP and DoT as uid 10001 with no capability and blocks a listed name. Two
  tests of that suite are flaky whatever the allocator (each failed in a run and passed on rerun):
  `serve::isolate::tests::the_hook_logs_the_panics_no_catch_has` (the panic hook is process-wide) and `a_client_over_its_share_cannot_shed_another_client`
  (1 run in 400: two networks hash to one of 256 buckets). Rejected:
  mimalloc's other builds (`MI_SECURE=1` and the default let the attacker gain, D152), jemalloc (D152).
- D153 (builds on D57, D122, D150, D151; amended by D156, D158) A tag `vX.Y.Z` pushed by the human publishes, from `release.yml` once
  `ci.yml`'s gate has passed on the tagged commit (by hand it builds and attests, and publishes nothing unless on a tag
  with `publish` ticked): per architecture (x86_64, aarch64) an archive of `dedensd`, `dedens` and the
  license, with `SHA256SUMS`, each attested for its build provenance (`actions/attest-build-provenance`: `gh
  attestation verify`) and held by a GitHub release; and `ghcr.io/<owner>/dedensd:<tag>`, both architectures under that
  tag, attested too; the job that builds the image checks its `dedensd` is the archive's, byte for byte. Each architecture builds on its own runner, from the `Containerfile`: `rust:<channel>-alpine` by
  digest (Renovate keeps it; `repo.rs` checks its tag is `rust-toolchain.toml`'s channel), `cargo auditable build
  --release --locked` (the dependency list in the binary: `cargo audit bin` reads it; it survives `strip`), the
  baseline CPU, nothing of `target-cpu`. Reproducible: the paths are constant in the container and
  `.cargo/config.toml` remaps the workspace and `CARGO_HOME` (in `rustflags`, which `RUSTFLAGS` would replace), so no
  path of the machine is in a binary; `just release` builds twice with no cache, fails when the two differ or a path
  shows, and the job runs it. `SOURCE_DATE_EPOCH` is not set: nothing in the build reads a clock. The claim is the
  binaries, and the archives built from them sorted, with no owner or time; not the image layers, and not across
  days: Alpine's `lld` and `ca-certificates` are the repository's current ones (the ELF `.comment` names the linker's
  version). The image is `FROM scratch`: `dedensd`, the CA bundle of `ca-certificates` (D57: the host's store, which
  a `scratch` image lacks), a `passwd` and `group` naming uid 10001, `/var/cache/dedensd` (downloads) owned by it,
  `deploy/dedensd.yaml` (a caching forwarder over DoT) read-only; no shell, no package manager, and `USER`
  10001 from the first instruction. Port 53 binds through the runtime's `net.ipv4.ip_unprivileged_port_start` (Docker
  sets it to 0; rootless Podman on the VPS leaves 1024 and needs `--sysctl net.ipv4.ip_unprivileged_port_start=53`; with
  any other, a published high port), so D122's drop has nothing to do there and the
  config sets no `user:`; the drop and its root tests stay for hosts that start `dedensd` as root. Rejected: an
  Alpine or distroless final stage (more than the binary needs), `USER root` with D122's drop (root and capabilities
  in the image for the first milliseconds, and a runtime that drops `CAP_SETUID` breaks it), `setcap` on the binary
  (a file capability grants nothing under `no-new-privileges`), a single multi-arch build under QEMU (slow, and the binaries of the
  native build are the ones tested). Read on the VPS (x86_64, rootless Podman 5.8.2): `just release` builds twice
  identical, `just image` runs `dedensd` as uid 10001 (`CapEff` 0), `exec` of a shell fails (none in the image), and with
  a mounted config it answers UDP and TCP, forwards over DoT with the image's CA bundle, downloads a 222,630-name list
  into `/var/cache/dedensd` and answers a listed name NXDOMAIN with EDE 15; a client outside the private networks is
  REFUSED until `access:` allows it (D91).
- D155 (builds on D14, D135, D141) `deny.toml` ignores RUSTSEC-2026-0441, `pin-utils` unmaintained (repository archived
  2026-10-01, no successor release): its one path is `loom` 0.7.2, the latest, which `compio-executor` takes under
  `cfg(loom)` and `dedensd` under `cfg(dedens_loom)` (`just loom`, D135), so no shipped build compiles it. Drop the
  entry when `loom` stops depending on `pin-utils`; cargo-deny warns once the advisory no longer matches: done with
  `loom` 0.7.3 (2026-11-12), which no longer depends on it. Rejected:
  `[graph] targets` limited to the shipped targets (it would drop `loom` from the graph, and with it the licence and
  ban checks of every test-only crate).
- D156 (amends D153; builds on D122, D151; amended by D158) The release also holds a deb and an rpm of `dedens` and of `dedensd` per
  architecture, packed by nfpm (`goreleaser/nfpm` by digest) from the very binaries of the archives (`just packages`,
  from `deploy/packages/`), in `SHA256SUMS` and attested with them. Version `X.Y.Z-1`, Cargo.toml's, which a tag must
  name (`vX.Y.Z`); a changelog of one entry pointing at the release; each file's time the commit's, so the same commit
  makes the same packages (twice identical on macOS). `dedensd` in `/usr/sbin`, run by a systemd unit the package
  neither enables nor starts: as user `dedensd` (`sysusers.d`, `useradd` without systemd) from the start, with
  `CAP_NET_BIND_SERVICE` only, `NoNewPrivileges`, `ProtectSystem=strict`, `@system-service` (it allows io_uring; a
  refused call gets `EPERM`, not a kill), `CacheDirectory` for downloads, `LimitNOFILE` 524288 (systemd's soft 1024 is
  short of a server's sockets), `Type=exec`, before `nss-lookup.target`; so no `user:` (D122). Its config, kept across
  upgrades: a caching forwarder over DoT on `127.0.0.1:53` only, not `[::1]` (on the VPS, without IPv6, the start
  failed). An upgrade restarts a running service, a removal stops and disables it, leaves the user, the cache and the
  edited config; a failing `systemctl` (a chroot without a bus) fails no script. `lintian` and `rpmlint` fail the job on
  an error; rpmlint's `no-signature` and `statically-linked-binary` are filtered (`deploy/packages/rpmlint.toml`). Then
  each deb is installed on a fresh runner, started and asked over UDP and TCP, and each rpm in AlmaLinux 10, its config
  validated and `rpm --verify` clean. The image is pushed only once both passed. Not signed with GPG, and no apt or dnf
  repository: the attestation and `SHA256SUMS` cover them. Rejected: cargo-deb and cargo-generate-rpm (two tools, each
  building again), `DynamicUser` (its uid changes, and a TLS key or list given to `dedensd` needs a fixed one). Read on
  the VPS (AlmaLinux 10, systemd 257): installed, started, asked over UDP and TCP via DoT, uid 980, `CapEff` 0x400,
  seccomp on, io_uring when the sysctl allows it, a reload downloads an 87,809-name list into `/var/cache/dedensd` and
  answers a listed name NXDOMAIN with EDE 15; `systemd-analyze security` 1.7 OK.
- D157 (builds on D55, D64, D121, D122, D153) `dedensd` ends on SIGTERM or SIGINT, as `docker stop`, systemd and
  Ctrl-C ask: it logs `dedensd ends: stopped` with the signal and exits with success at once. Nothing is to flush: the
  cache lives in memory, a list and its `ETag` are replaced atomically (D64), a query in flight is dropped as a lost
  packet. As PID 1 of the image (D153) the kernel drops a signal without a handler, so a stop waited out the grace
  period, 10 to 30 s, then SIGKILL. The handler is `signal-hook`'s, as SIGHUP's (D55), on a thread started after root
  is dropped (D122). Rejected: draining the connections first (a client asks again, as for a lost packet); `docker
  run --init` (each user would have to know).
- D158 (amends D153, D156; builds on D14, D32) Each shipped binary travels with the licences of the crates it links,
  as MIT, BSD and ISC ask: `THIRD-PARTY-dedens.txt` and `THIRD-PARTY-dedensd.txt`, written by cargo-about (pinned in
  the Containerfile) from the sources just built, offline, for the musl targets without build and dev dependencies
  (`deploy/about.toml`, the licences `deny.toml` accepts; `deploy/about.hbs`). They are in the archive, beside
  `LICENSE`, and in each package (`/usr/share/doc/<package>/` in the deb, `/usr/share/licenses/<package>/` in the
  rpm); the image has `dedensd`'s and `LICENSE` in `/usr/share/licenses/dedensd/`, checked equal to the archive's.
  `just release` builds them twice and compares, as the binaries. The packages also carry a man page, `dedens.1` and
  `dedensd.8`, made by `clap_mangen` from the command line without its version (the package has it), kept in
  `deploy/packages/man/` and checked against it by a test of each binary (`just man` writes them); `just packages`
  gzips them (rpmlint told so by `CompressExtension`; a `doc` of the rpm). A deb is also installed in an Ubuntu
  container without systemd, as in a chroot: `useradd` makes the user, a purge removes the configuration. Rejected: a notice in the repository (it would
  drift from `Cargo.lock`); pages made at build time (a generator in the image, or a hidden command in the binary).
- D69 (amends D2; amended by D71, D74, D75, D76, D78, D79, D80, D97) DNSSEC comes before the recursive resolver, as a validating stub and forwarder: `dedens`
  and `dedensd`'s forward stage validate the answers of an upstream they do not trust to have validated, and
  only the validator's verdict (secure, insecure, bogus, indeterminate) reaches the cache and the reply. The
  code is `dedens-dnssec`, sans-IO, the clock passed in. ODoH (RFC 9230) and DoC (RFC 9953) are experimental:
  `dedens-odoh` and the `odoh` and `doc` Cargo features, off by default and forwarded from `dedens-net` to
  both binaries, so a default build carries neither (`just check` builds with all features). Text forms: the
  DNSSEC record types print as their mnemonic and parse from it or from `TYPEn` (RFC 3597); algorithm,
  digest and NSEC3 hash numbers (`SecAlgorithm`, `DigestType`, `Nsec3HashAlgorithm`) print as their IANA
  mnemonic and parse from it or from the bare number, which zone text writes. Open questions this phase
  leaves: [`TODECIDE.md`](../TODECIDE.md). Steps: `plan/4-dnssec-experimental/`.
- D71 (amends D69; amended by D73, D106) DNSSEC crypto is `dedens_dnssec::crypto` on `ring`, which is already in the lock
  through rustls, and `data-encoding` for test and bench data. Policy, after RFC 9904 §3 and RFC 6840 §5.2: validated
  are RSASHA1 and its NSEC3 alias (5, 7), RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13),
  ECDSAP384SHA384 (14), Ed25519 (15); DS digests SHA-1, SHA-256, SHA-384 (1, 2, 4). Unsupported, so the zone or
  delegation is insecure (EDE 1 and 2): RSAMD5, DSA (1, 3, 6), GOST (12, DS digest 3), Ed448 (16, `ring` has
  none), GOST 2012 (23), SM3 (DS 6), private and unknown codes. SHA-1 signatures stay validated, as RFC 9905 §2
  tells implementations, though it tells operators to treat them as unsupported: too many signed zones still
  use them (README item 3); [`TODECIDE.md`](../TODECIDE.md) holds the switch. RSA keys: RFC 3110 §2, modulus 1024
  to 4096 bits (`ring`'s `_1024_8192` variants, capped at RFC 3110 §2's 4096 where ring allows 8192), exponent
  odd, 3 to 2^33 (`ring`'s bounds); anything else, the 512-bit keys of RFC 5155 Appendix A and RFC 5702 §6.1
  included, is an unusable key. Accepted deviation from RFC 3110 §2: the reader takes leading zeros in the
  exponent and in the modulus, and a three-octet exponent length where the exponent is short, as the zones in
  the wild publish such keys and `ring` takes the key all the same.
  `ring` does not tell a refused key from a bad signature: an ECDSA point off the curve and an Ed25519 key that
  is no curve point are reported as a bad signature (tested). A bad signature is therefore not proof of a
  forged answer, and an unusable key is the verdict of the validator (step 04), not of `crypto`: a key no
  signature can use is no key, so the algorithm counts as unsupported and the data as unsigned for it (RFC 6840
  §5.2), and `supported` tells that case from a refusal of the algorithm. `Budget` bounds the work of one
  validation, spent before each `verify` and `nsec3_hash` by the caller: 64 signature verifications and 8192
  NSEC3 hashes (`iterations + 1` per name). Sized from `benchmarks.md`: 64 verifications cost at most 22 ms
  (P-384, the slowest) where a chain of five zones needs about 20; 8192 hashes are 0.75 ms and cover 54 names
  at 150 iterations, where a denial proof hashes about a dozen. An exhausted counter stays exhausted; the
  caller picks the verdict (RFC 9276 §3.2: insecure or SERVFAIL for NSEC3; bogus for signatures, as the
  KeyTrap guidance has it), `crypto` only refuses. Signature examples are verified here from signed data built
  by hand from the RFC text in `dedens_testkit::dnssec`, test-only; `verify`, `key_tag`, `ds_digest` and
  `nsec3_hash` have the fuzz target `dnssec_crypto`. Rejected: aws-lc-rs (a C build, a second backend beside
  rustls's), RustCrypto crates (more dependencies for what `ring` does; Ed448 alone would justify one, see
  TODECIDE), a `Budget` of wall-clock time (not reproducible, and the clock is passed in, D69).
- D72 Trust anchors are `dedens_dnssec::TrustAnchors`: DS or DNSKEY records per zone (RFC 4035 §4.4),
  and negative trust anchors (RFC 7646). The root's are bundled as `crates/dedens-dnssec/src/root.ds`, DS text
  that `just root-anchors` writes from IANA's `root-anchors.xml`: the `KeyDigest` entries valid at that moment
  (RFC 9718 §2.2), by an awk script, as the file is flat and a Rust XML parser would be a dependency for one
  file. The CMS signature of §3.2 is not checked: the file and its `.p7s` come from the same site, so the
  check proves nothing the HTTPS fetch does not; the test is that every bundled DS matches a key of the
  captured root DNSKEY RRset (`tests/anchor.rs`), and the key tags are the two of RFC 9718 §2.2. A user's
  anchors are zone text read by `ZoneReader`, the fuzz target `parse_trust_anchors` feeding the checks above it, as
  Unbound's `trust-anchor-file`: absolute owners, class IN only, TTL defaulted to 0, DS and DNSKEY only (a CDS
  or CDNSKEY is not an anchor), no `$INCLUDE` (the library reads no file), at least one record (an empty set
  would call every answer insecure). Each error names its line (`ZoneReader::line` was added to `dedens-proto`
  for it). An NTA lives on `TrustAnchors`, `negative(name)` being true at and below it unless a deeper positive
  anchor restarts validation (RFC 7646 §1.1's example); at the same depth the NTA wins, as the operator added
  it to override. An NTA has no end time, though RFC 7646 §2.1 asks implementations to allow one: it lasts as
  long as the value does, and the caller drops it by building the anchors anew; [`TODECIDE.md`](../TODECIDE.md)
  holds the rest. Anchors are fixed while running: RFC 5011 stays in TODECIDE.
- D73 (amends D71) `dedens_dnssec::rrsig` authenticates one `RRset` and one DNSKEY `RRset`, sans-IO; chain walking
  and denial are 05 and 06. `RrSet::group` builds `RRset`s from a section (owner, class, type; RFC 2181 §5.2:
  TTL the minimum); `Signature` and `Key` borrow the RRSIG and DNSKEY records of an `RRset`, a DNSKEY whose
  protocol is not 3 being opaque, so never a `Key`. `verify(rrset, sig, key, now, budget)` checks RFC 4035 §5.3.1
  in this order, the cheap checks first and nothing allocated before they pass: coverage (owner, class, type);
  the signer at or above the owner, and not the owner for a DS (it belongs to the parent, RFC 4035 §2.4: the
  child's own signature on it is the child vouching for itself) and the owner for a DNSKEY (§5.2); the labels
  field neither above the owner's count (a leading `*` not counted) nor below the signer's (the expansion of a
  wildcard of a zone above the signer's); algorithm supported; the key is the signer's, of the algorithm and
  key tag; REVOKE (RFC 5011 §7); zone key bit; the validity window in serial arithmetic (RFC 1982; edges
  inclusive, no skew, `now` is Unix seconds truncated to 32 bits); then one `Budget` verification and the
  signature. The kept TTL is the least of the `RRset`'s, the RRSIG record's, the original TTL and the seconds to
  expiration (RFC 4035 §5.3.3). A wildcard expansion (labels below the owner's) is verified against `*.` and the
  rightmost labels, and `Verified::wildcard` returns the closest encloser; `Verified` is `must_use`, because a
  wildcard answer proves nothing about the absence of a closer name, which 06 asks 05 to prove (RFC 4035
  §5.3.4). Zone cuts are the caller's (06): `verify` knows the signer is above the owner, not that its DNSKEY
  `RRset` is of the zone that holds the `RRset`; the caller picks the keys of the parent for a DS, of the child
  for its apex DNSKEY, and of the zone below which the owner is not delegated further for the rest (a NS
  `RRset` or glue under a cut is not signed by the child, RFC 4035 §2.2). `verify_any` tries every covering
  RRSIG against every key of its signer, key tag and algorithm, and stops at the first success (RFC 6840 §5.4:
  one valid RRSIG is enough, the others disregarded). An RRSIG whose algorithm is not supported is disregarded
  whatever the keys (RFC 6840 §5.12), and so is the key no signature can use (D71, the 512-bit RSA key):
  `verify_any` never says "unsupported". Which algorithms a zone is signed with is for its DS records (RFC 4035
  §5.2, RFC 6840 §5.11), so only `trusted_keys` can find a zone insecure; otherwise one forged RRSIG of an
  unknown algorithm beside a forged answer would downgrade a signed zone to insecure. This replaces D71's
  "an unusable key makes the algorithm unsigned" for RRsets: an `RRset` whose RRSIGs are all disregarded is
  `NoSignature`, bogus once its zone is known to be signed; a DS or DNSKEY of an unsupported algorithm is what
  makes it insecure. A pair tried by `verify` alone still says `UnsupportedAlgorithm`. KeyTrap: at most 8
  failures per `RRset` (`MAX_FAILED`, as Unbound's `MAX_VALIDATE_RRSIGS`), counting every RRSIG or RRSIG and key
  pair that fails for whatever reason, cheap or costly, but the lack of a key (an RRSIG without a key costs
  nothing and a zone may sign with keys we were not given); then `TooManyFailures`. The canonical RDATA is built
  once per `RRset` and the owner and signed data once per RRSIG, not per pair. The shared `Budget` of D71
  bounds the whole validation, its exhaustion its own error, bogus (the KeyTrap guidance). With none
  succeeding the error returned is the closest to a success, in `SigError::rank` order. `trusted_keys(dnskeys,
  sigs, ds, now, budget)` counts the DS records whose digest type and algorithm are supported (else
  `UnsupportedDigest` or `UnsupportedAlgorithm` when none counts, which `SigError::is_unsupported` tells: the
  zone is insecure, RFC 4035 §5.2, RFC 6840 §5.2), ignores every SHA-1 DS of the `RRset` when it holds a DS of
  a stronger digest (SHA-256 or SHA-384) that counts, whatever key each names (RFC 4509 §3 speaks of the DS
  `RRset`: a SHA-1 second preimage of one key's DS then vouches for no key; rejected: ignoring it only beside a
  stronger digest of its own key, which leaves that open), indexes the DS records by key tag and algorithm once,
  matches each DNSKEY by digest against those of its tag and algorithm only, and requires the DNSKEY `RRset` to
  verify by one of those keys (RFC 4035 §5.2). A zone can publish many keys of one tag before its `RRset` is
  authenticated, so more than 8 keys that match a tag and no digest are `TooManyFailures`; a DS that matches no
  key is `NoKeyForDs`, bogus. Every
  `SigError` maps to one EDE code (RFC 8914 §4) through `SigError::ede(&RrSet)`, whose text names the `RRset`
  and the key tag: 1, 2, 6, 7, 8, 9 (missing and revoked keys), 10, 11, 25. Canonical form (RFC 4034 §6, RFC
  6840 §5.1) lowercases the owner and the names in the RDATA of the types of RFC 4034 §6.2 (NSEC's next name
  apart, the RRSIG's signer included; A6 left out, historic, RFC 6563), sorts the RDATA as unsigned bytes and
  drops duplicates (§6.3). The name layouts are a table in `rrsig/canonical.rs`, not those of `RData::Opaque`:
  that list says where compression pointers may occur (RFC 3597 §4), and DNAME and KX are not in it.
  `WireRdata::wire` (`dedens-proto`) returns the RDATA uncompressed for it. Tests: RFC examples and the 00b
  captures, every signed `RRset` of them verifies, and fails 1 s after expiration, 1 s before inception and
  with a byte of RDATA flipped (`tests/rrsig.rs`); `benchmarks.md` has the cost of a whole `verify`;
  the fuzz target `rrsig_verify` runs the grouping, `verify_any` and `trusted_keys` over the records of any
  message and asserts that no input makes data insecure. RFC 8080 §6.1's Ed25519 RRSIG says 3 labels for
  `example.com.`, which has 2: as an `RRset` it is `BadLabels` (RFC 4035 §5.3.1), and `crypto` checks the
  signature over its bytes (`tests/algorithms.rs`).
- D74 (amends D69; amended by D106) Denial of existence is `dedens_dnssec::denial`, pure set logic over NSEC and NSEC3
  records the caller verified, each signed by the zone's `apex` (step 06 checks; this trusts them and the module docs list
  what it owes). `prove` answers a question that got a name error, no data or a referral, `prove_wildcard_answer` one
  that got a wildcard expansion (the RRSIG's label count gives the next closer name); the result is a `Fact`
  (`NameError { compact }`, `NoData`, `WildcardNoData`, `WildcardAnswer`, `InsecureDelegation`) with the TTL of the
  proof, the least of the records used (RFC 9077 §3), or an `Unproven` reason: the caller picks the verdict, as for
  `Budget` (D71). A DS question's `NoData` is the parent's: an NSEC or NSEC3 with SOA is the child's and proves
  nothing of the delegation (`FromChildApex`, RFC 4035 §5.2, RFC 6840 §4.4), and NS without DS and SOA, or an
  opt-out span, is `InsecureDelegation`, which is also the proof of a referral to an unsigned child (RFC 5155
  §8.9). Per RFC 6840 §4.1 an NSEC or NSEC3 at a delegation proves no name below it nor a type at its owner but
  DS, and one with DNAME proves no name below its owner. The CNAME bit counts in every no data (§4.3). NSEC3
  records are used when the response has usable ones (SHA-1, flags 0 or 1, owner one 32-digit base32hex label below
  the apex), NSEC otherwise; the records of more than one parameter set (iterations, salt) are
  `ConflictingNsec3Parameters`, for the caller to make bogus (RFC 5155 §8.2 allows it; no order of records picks
  the set). `Name` has no order: canonical order (RFC 4034 §6.1) is private to `denial`. NSEC3 hashes are paid from
  the `Budget`, one per name a proof tries, none kept between calls. Iterations above `MaxIterations`, default 150
  as Unbound and BIND (RFC 9276 §3.2 recommends 0 but tells validators to accept some; the limit is a parameter),
  are `IterationsAboveLimit` in any record's set, refused before any hashing: the response is insecure, with EDE 27
  (`info_code`). Compact denial (RFC 9824): an NSEC or NSEC3 matching the name with NXNAME in its bitmap is a
  `NameError { compact: true }` for any type, so 06 and 08 tell it from an NXDOMAIN (the response is NOERROR,
  §3.3); NXNAME is never a question to answer, `NxnameQuery` carries EDE 30 (§3.5). A proof over a next closer
  name that an opt-out NSEC3 covers is `Proof::opt_out` (RFC 5155 §9.2: the name may be an unsigned delegation, so
  no AD; Unbound does the same): set for a name error, wildcard no data and wildcard answer, never for a name the
  records match. A DS question whose next closer name is in an opt-out span is an `InsecureDelegation` even when the
  response also proves the wildcard absent. Tests: RFC 4035 Appendix B (the Appendix A zone, in `testdata/zones/`),
  RFC 5155 Appendix B, RFC 6840 §4, RFC 9276, RFC 9824, and every negative capture of `testdata/dnssec/`; the proptests
  check that against a whole NSEC or NSEC3 chain each name or hash is matched or covered by exactly one record. Fuzz
  target `denial`: any records and question through `prove` and `prove_wildcard_answer` under every ancestor of the
  name as the apex.
- D75 (amends D69; amended by D86, D106, D176) The validator is `dedens_dnssec::Validator`, sans-IO:
  `Validator::new(TrustAnchors, Limits)` (shared, `Clone`, `Send + Sync`) and `start(question, response, now) ->
  Validation` for the final answer to a question, `start_referral` for a referral. The caller drives a `Validation`:
  `step()` is `Next::Ask(question)`, to send with RD, DO and CD set (RFC 6840 §5.9) and give back with
  `answer(Some(response))` or `answer(None)` (a failed query), or `Next::Done(Verdict)`. `step`, not `next`, and `now`
  once at `start`, not per call (the plan's sketch): a validation is one instant, so a chain cannot straddle a signature's
  expiry, and `Iterator::next` would mislead. `now` is `u64` Unix seconds, as the cache and the pipeline count seconds
  from any origin; the signatures take it modulo 2^32 (RFC 4034 §3.1.5, serial arithmetic, D73). A response that is no
  complete answer to the question (not its one question, in class IN, TC set) is `Indeterminate` at once, as an answer to
  one of the validator's own questions is, which also makes a truncated DS or DNSKEY answer indeterminate, never bogus
  (RFC 1035 §4.1.1). `Verdict` is RFC 4035 §4.3 with two more: `Secure { ttl }`, `Incomplete { next, ttl }`, `Referral {
  child, delegation }`, `Insecure { reason }`, `Bogus { ede }`, `Indeterminate { ede }`; `ede()` the code and text to
  attach (RFC 8914), the text of an insecure reason included.
  What Secure covers: every `RRset` of class IN in the answer and the authority section is authentic (RFC 4035
  §3.2.3, RFC 6840 §5.8), what the response lacks is proven absent, and the rcode agrees with the proof (a name error
  is NXDOMAIN, or NOERROR when compact, RFC 9824; no data is NOERROR; NXDOMAIN with an answer is bogus). It does not
  cover the additional section, other classes, the sets off the name path (Bailiwick, below), or the unsigned CNAME a
  DNAME synthesizes (RFC 6672 §5.3.3). `covered(&Message)` is the one definition of what Secure covers:
  the response cut to the records it is about, computed with the validator's own predicates (the same `Parsed` and
  `synthesized`), so the two cannot drift; a caller hands out or shows `covered` of a secure response, never the
  response. It drops the additional section, other classes, the sets off the path, the RRSIGs that sign nothing,
  and the RRSIG of the CNAME a DNAME makes, which stays: the validator skips verifying that CNAME set only when
  every record of it is the one the DNAME makes (RFC 4035 §4.8 lets the resolver return it; a client that does not
  synthesize it would otherwise lose the answer), so another record in it is checked as any CNAME: unsigned,
  bogus. Secure is not the AD bit: the upstream's AD is never read, and the caller sets AD
  from `Secure` alone. A CNAME chain that stops before the type asked, with no denial, is authentic as far as it
  goes: `Incomplete`, the caller chases `next`, and it is never AD. A referral is no answer: judged as the final
  answer it is bogus (its NS records are unsigned, nothing denies the type) or insecure, so a forged referral has
  no way to secure; `start_referral` judges only the delegation, by the DS records of the child or their proven
  absence, and says `Referral` with `Signed` or `Unsigned { reason }`, never `Secure`, so no TTL and no AD come of
  it. A referral that answers one of the validator's DS questions is read as any DS answer: its DS or its
  proof, else bogus. `Referral { Signed }` is a verified DS `RRset` with a record of a supported algorithm and
  digest (else `Unsigned { UnsupportedAlgorithm | UnsupportedDigest }`, RFC 4035 §5.2, RFC 6840 §5.2); the NS
  records and the glue are unauthenticated and that the sender is the parent is not proven, so the caller treats
  a referral as a hint to follow. `Incomplete.next` is the server's: the caller bounds its CNAME chasing and takes
  no 0x20 entropy from it.
  Bailiwick: only the `RRsets` of the answer section at a name the answer passes through (the question's name and
  the targets of its CNAME and DNAME chain, or the owner of a DNAME above one) and those of the authority section
  at or above such a name are walked and verified; the others are out of bailiwick, change no verdict, and are
  cut by `covered`, as the additional section is. The chain of trust is walked top-down from the closest anchor to the owner of each `RRset` (the name asked for a
  DS, the parent's apex): the DS of each label, then where there is a zone its DNSKEY (RFC 4035 §5.2). The walk
  goes to the owner (RFC 4035 §5.3.1), never to the signer a signature names, so a rewritten signer cannot pick
  the keys, an `RRset` signed by an ancestor's keys is bogus, every RRSIG is tried (a junk one first costs
  nothing) and a forged signer cannot turn bogus into insecure. Signatures are grouped by owner and type
  covered once per response, and the first bogus `RRset` ends the check, so junk costs no more than its size. It
  costs one DS question per label below the last zone, which the key cache (D86) pays once; an IPv6 reverse name
  of 34 labels (a real capture, `ip6_ptr`) takes about 40 questions and 80 signature checks. A DS RRset is verified by the parent's keys and then
  vouches for the DNSKEY RRset (`trusted_keys`); no DS is the parent's NSEC or NSEC3 proof (D74): an insecure
  delegation (insecure, `UnsignedDelegation`), or no cut (the name is in the parent's zone). A DS question at a
  name that is a CNAME (or below a DNAME, or a wildcard CNAME) gets the CNAME: if it verifies, the name is no cut.
  Data below an insecure zone, at or below a negative anchor (D72, RFC 7646 §2, nothing asked), or with no anchor
  above it, is insecure. Unsigned in a secure zone, or in a zone the keys of which are not its owner's, is bogus
  (EDE 10, 6); every NSEC, NSEC3 and SOA of the authority section must verify, or the response is bogus, each with the keys of
  the zone that signed it among the zones the response is about (a wildcard answer of one zone and the no data
  of another carry proofs of both). A wildcard
  expansion also needs the no-closer proof of `prove_wildcard_answer`, else bogus (RFC 4035 §5.3.4). An opt-out
  proof, in a denial, a wildcard answer or the DS of a delegation, is insecure, `OptOut`, never secure (RFC 5155
  §9.2): `testdata/dnssec/README.md` says so of `google_com_ds`, `edgekey_net_ds`, `nxdomain_nsec3_optout` and
  `nxdomain_nsec3_salt`. Only verified NSEC and NSEC3 records signed by the zone reach `denial`. A negative proof
  lasts at most three hours and the SOA's TTL and MINIMUM (RFC 9077 §3.4), and the keys' TTL. Failures: a
  signature or DS that fails is bogus with `SigError::ede`; a DS no key matches, bogus with EDE 9; an unsupported
  algorithm or digest in a DS is insecure with EDE 1 or 2 (D71, RFC 6840 §5.2; RRSIGs of unknown algorithms are
  disregarded, D73); NSEC3 iterations above `Limits::iterations` (`MaxIterations`, default 150, D74) are insecure
  with EDE 27; `ConflictingNsec3Parameters`, a missing or contradictory proof and any other `Unproven` are bogus
  (EDE 12, 6); an exhausted `Budget` (D71, shared by the whole validation) is indeterminate, never bogus (it says nothing
  of the data: a long walk spends it) and never insecure (a forger would downgrade by spending it), and never
  stored in a zone's outcome. Its default here is 128 signature checks, where `Budget::default` has 64: the 34 DS
  proofs of the reverse name above need about 80. Limits are `Indeterminate`: more than `Limits::questions` (64)
  questions, a name more than `Limits::depth` (127, a name's most) labels below its anchor (counted from the anchor, so the order of
  the questions changes nothing; EDE 5), a question the caller could not answer (EDE 22), a response with an
  rcode but NOERROR and NXDOMAIN (EDE 5), NXNAME asked (EDE 30). Each zone's outcome (secure keys with their TTL,
  insecure, bogus) is written by one private function, `settle`, and read by one other, `zone_of`; delegations are
  not cached apart from them and an indeterminate outcome is never written, so D86's cache goes there and holds
  only what the data decides. `Validation::cost() -> Cost { questions, verifications, nsec3_blocks }` (additive,
  `#[non_exhaustive]`) is what the validation spent so far of those limits, for a caller that bounds what a
  client's query costs across validations, as D77 does. Not done: the SHA-1 switch (TODECIDE: it needs a filter in
  `rrsig`). Opt-out wildcards: the TLDs `ph` and `ws`
  serve a wildcard whose proof of the next closer name is an opt-out NSEC3, and their wildcard answer and no data are
  insecure (RFC 5155 §9.2), as 8.8.8.8, 9.9.9.9 and 1.1.1.1 (no `ad`) and BIND's `delv` (unsigned answer) say; a
  wildcard under NSEC (`internet.nl`) is secure, as they and `delv` say. Found by the captures: the DS of a name that
  does not exist under an opt-out span is an NXDOMAIN with the proof of an insecure delegation (RFC 5155 §8.6), which
  was bogus and is insecure now (an NSEC proof of one stays bogus under NXDOMAIN: the name is there). Not
  agreeing: 8.8.8.8 answers SERVFAIL (EDE 12) for the DS of `wildcard-test.internet.nl`, whose proof `delv` and
  1.1.1.1 and 9.9.9.9 (`ad`) accept, as the validator does (RFC 4035 §3.1.3.4). Tests: `tests/validator.rs`, a scripted caller that
  answers from the captures at `captured_at`: every capture with the verdict of its README, forged referrals,
  signers, rcodes, authority records, CNAME and DNAME hops, DS denials, mixed-case names, truncation. Fuzz target
  `validate`: any bytes as the response, its questions answered from the captured chains, whole, cut or with a bit
  flipped; seeded by the captures.
- D77 (amends D41, D43, D45; builds on D75; amended by D86, D90, D93, D106, D114, D117, D124) A forward stage validates with `dnssec: validate` (default
  `off`; `off` is read for the boolean YAML makes of it); `trust_anchors: FILE` (zone text of DS or DNSKEY records, else
  the bundled root) and `insecure: [names]` (negative anchors, RFC 7646) only with it, else the configuration is refused.
  One `Validator` per stage, built by `config/upstream.rs` at each read; a reload keeps the one of a stage whose validation is
  unchanged, the tag of its anchors file text and negative anchors the same (D55, D86). The wall clock is
  the caller's (`Validating::new(validator, clock)`, Unix seconds): the pipeline's `now` is a monotonic `u32`.
  The glue is `dedens-server`'s `validate.rs`: `Check` owns a `Validation` and the client's answer, and the
  pipeline turns each `Next::Ask` into a `Step::Upstream` whose `Upstream::request()` is the validator's question
  (RD, DO and CD, no client option, AD clear: RFC 4035 §4.6, RFC 6840 §5.9) and which goes to the server that
  answered the last question: one that failed is not asked again by the same query, so a dead server costs one
  question's patience (`tries`/`timeout_ms` of D45), not each one's. So `serve/` is unchanged. A validating
  stage's query for the client's own question also carries CD and DO whatever the client set; a client with CD (or
  a question not of class IN) is answered unvalidated, AD clear, from a plain forwarder's query (the client's AD
  and CD, RFC 6840 §5.7; upstream's AD is not read). Every
  validation question is an upstream query of its own and counts as one (`dedens_validation_questions_total`); none
  is read from or written to the answer cache, and each answer is untrusted input to the validator. A key cache
  (06b) slots into `Validating`, not the pipeline. Prefetch and stale refresh validate as any query.
  Verdicts (`dedens_validations_total{verdict}`): AD is set by `Secure` alone, never from the upstream's bit, and
  only for a client with DO or AD (RFC 6840 §5.8). A secure response is cut by `covered` (D75) to
  what the verdict covers before it is served or cached: the additional section, other classes, the sets the
  validator ignores and the RRSIGs that sign nothing are dropped (RFC 4035 §3.2.3); the CNAME a DNAME makes stays.
  Every TTL is capped at the verdict's. `Incomplete`: the answer of
  `next` is validated apart, at most 8 names a query (`MAX_CHASES`, as `dedens`; `next` is the upstream's, not 0x20 entropy, and
  dedensd sends no 0x20); the chain's answer is then delivered insecure, AD clear, cached at most as long as the
  incomplete part, whatever the second verdict, but bogus and indeterminate end it, and a ninth name is
  indeterminate. All the questions of a query, the chase included, are at most 64 (`MAX_QUESTIONS`; the
  validator's `Limits` bound each validation separately): past it the verdict is indeterminate.
  Cost (`validate.rs`, `Allowance`): D75 bounds one validation, but a client can send many cheap queries that each
  walk a chain, and a chase starts a validation for each name (up to 9 × 128 signature checks). A unit is a question
  upstream (the client's too), a signature check, or 4096 NSEC3 hashes (`Validation::cost`): about 10 µs on the
  common algorithms, 340 µs on a P-384 one, the worst a unit stands for (`benches/dnssec.rs`, `benchmarks.md`). One
  query costs at most `Allowance::per_query` (256), the sum over its chase: past it the verdict is indeterminate
  (EDE 5, validation ran, failure held as any). All the queries share a token bucket in `Validating` (clones share
  it; `Validating::allowing`; defaults: `per_second` 10 000, `burst` 20 000): `Pipeline::query`, before the client's
  question is sent, takes a unit if the bucket has one left, and the query that finds none is answered SERVFAIL
  with EDE 14 (Not Ready) and nothing is asked, decoded or validated (`dedens_validations_total{verdict="shed"}`);
  the work of the validations is charged to it as it runs, so it can go into debt (at most the in-flight queries'
  `per_query` each) and is refilled by the clock of `Validating` (a clock gone back refills nothing). Shed is not
  failed: nothing is held in the cache, or a flood would fail the names it asks for, and the client may ask
  again; a refresh that finds the bucket empty is not made, the reply stands. EDE 14, not 22/23 (those claim an
  upstream or network failure, none was tried, and a client's resolver retries elsewhere and moves the flood), nor
  5/6 (no DNSSEC verdict was reached). Each client network has a share of it too (D117); the bucket
  here is the global one. A hit in the cache stage costs no unit, a client with CD
  none; a warm validation (D86) two. Measured: `serve_shed` 0.11 µs, `serve_warm` 6.2 µs, `serve_cold` 110 µs, no
  slower from 1 to 8 threads (`benchmarks.md`). Tests: `tests/dnssec.rs` of `dedens-server`, `a_validation_reports_what_it_cost`
  in `dedens-dnssec/tests/validator.rs`. `Insecure`: AD clear, cached as it came, for at most `max_insecure_ttl` (D93). `Bogus`: SERVFAIL with the EDE code
  (RFC 8914; the code only: the OPT of a reply carries no text), and the response cached for `Config::bogus_ttl`
  (60 s, Unbound's `val-bogus-ttl`; RFC 4035 §4.7: small, assigned), never served stale; a hit answers
  SERVFAIL+EDE without validating, a client with CD gets the data (RFC 4035 §3.2.2: the cache stores it under the CD
  key as well, `Checked::Insecure`); a prefetch or stale refresh that turns bogus is dropped, not stored: bad data does
  not replace good data still in the cache. `Indeterminate`: SERVFAIL with EDE, not cached: the failure hold of D43 (RFC 9520)
  starts, which may outlast 60 s once repeated. A question unanswered by every server is indeterminate, not bogus.
  Cache: an entry records `Checked` (`Unchecked`, `Secure`, `Insecure`, `Bogus(code)`) beside the response; a hit
  sets or clears AD from it (only `Secure` sets it, D114; clear on a secure entry served stale: expired data is no longer vouched for by the
  signatures), and nothing else of DNSSEC is in the cache. A reload keeps the cache stage only while every forward
  stage validates the same way (`Validating::tagged`: dnssec mode, trust anchor text, negative anchors, set by
  `config/upstream.rs`): else entries from another validator, or none, would be served under the old AD and verdicts. It stores each response whole under the
  client's key (DO and CD bits), so the RRSIGs are in a DO client's entry and out of the others' (RFC 4035 §3.2.1,
  §4.5: one atomic entry per answer): no per-RRset storage. Not done (TODECIDE): the BAD-cache threshold of RFC 4035
  §4.7, an EDE on a cached insecure answer or `InsecureReason::info_code()`, an EDE 22/23 for an upstream SERVFAIL, a
  validation deadline, aggressive use of NSEC (RFC 8198). `Forward` no longer implements `PartialEq` and `Eq`: it
  holds the validator's closure. Tests: `tests/dnssec.rs` of `dedens-server` (upstream answers the captures of `dedens-dnssec` at `captured_at`),
  `dedens-cache/tests/checked.rs`, the configuration tests of `config/`; bench `hit_secure` of `benches/server.rs`.

- D76 (amends D32, D34, D37, D40, D69; amended by D86) `dedens +validate` is a validating stub resolver (RFC 4035 §4.9, RFC 4033 §5):
  the server is a transport, never trusted. `validate` is an `Options` field, so a query file carries it, and it
  sets DO and CD on the query (the response is wanted even when it is bogus, RFC 6840 §5.9; RD stays as the user
  has it) and gives `dedens_dnssec::Validator` the response: `apps/dedens/src/validate.rs` is the glue, a loop
  `step()`, send, `answer()` (D75). Each `Next::Ask` goes to the same server over the same transport, with the
  query's own options (UDP with the TCP fallback, TLS, QUIC, HTTPS, CoAP, ODoH proxy), and an unanswered or
  unreadable one is `answer(None)`. One `Validator` per set of anchors in a run, shared by its queries and its key
  cache (D86), so only a query that finds no zone known asks the chain, one DS question per label (`-v` traces each
  question). The
  upstream's AD bit is never read: the human report names it `AD set by the server` once a verdict is shown, apart
  from the verdict. Only `Secure` is shown as validated, and then only what it covers (D75): the report of a
  secure response is `covered` of it, as dedensd serves it, and the expectations (D34) are checked against it; `--save-wire` keeps the response as received. `Incomplete { next }` is chased: `next` is
  asked of the same server and validated on its own, at most 8 times (`MAX_CHASES`), then indeterminate; the verdict is that of
  the last answer, never an AD of the first. `Referral` cannot come of `start`; a `Referral` or `Incomplete`
  that reaches the report is indeterminate. `--trust-anchor FILE` (DS or DNSKEY records in zone text,
  `TrustAnchors::read`, D72) replaces the bundled root anchors, `--insecure NAME` (repeatable, `insecure:` a list
  in a file) adds negative trust anchors (RFC 7646, no end time, TODECIDE); each of them turns validation on unless
  `+novalidate` says otherwise, so an anchor file is never silently ignored. `+noedns`, `+nodnssec` and `+nocd`
  with validation, and `+trace` with it (a trace does not follow CNAMEs or ask a chain, D40), are usage errors,
  as D32 does for options needing EDNS; a file whose `expect` has `dnssec` for a query that does not validate
  is an error at load. `DEDENS_NOW` (Unix seconds) replaces the clock of validation, as `DEDENS_ROOTS` does the
  roots, for tests. The report has a `dnssec` object, `status` (`secure`, `insecure`, `bogus`, `indeterminate`),
  `ede` (`code`, `purpose`, `text`, as an EDE option of the response) and `reason` (an insecure verdict's words),
  in JSON and YAML; the human format ends with one line, green when secure, plain when insecure, red with the
  EDE when bogus or indeterminate; `+short` prints nothing of it but a line to stderr for the last two, like a
  violation. The expectation `dnssec: secure|insecure|bogus|indeterminate` (D34) fails the query as any other,
  exit 1. Exit codes stay D33's: a bogus response alone exits 0, since the verdict is the answer the tool
  gives. Tests: `apps/dedens/tests/validate.rs` against the captures of `testdata/dnssec` at their
  `captured_at`: secure, insecure and bogus in each format, the questions asked, a wrong or a right anchor file,
  a negative anchor, the expectation, the usage errors; by hand against 1.1.1.1, `cloudflare.com` is secure and
  `dnssec-failed.org` bogus with EDE 9.

- D86 (amends D75, D76, D77; amended by D92) The key cache: what a `Validator`'s validations learn of zones is kept
  for the validations after them, in `validator/cache.rs`. It is written by `settle` and read by `zone_of` (D75), nothing
  else, so the rules for what goes in live in one place, `Zone::lifetime`. It is inside the `Validator` behind a
  `Mutex` (the `Validator` stays `Clone`, `Send + Sync`; clones share it), and anchors and limits are fixed for a
  validator, so a change of trust anchors or negative anchors is a new `Validator` with an empty cache, and nothing
  stale outlives it; a reload that changes neither keeps the `Validator`, so the keys stay (`config/sources.rs` compares the
  tag it gives `Validating`, as it does for the answer cache, D77). API, additive fields only: `Limits::key_cache` (`usize`, entries per table, default 4096; 0
  turns the cache off) and `Limits::key_cache_bytes` (`usize`, default 4 MiB); `Limits { .., ..Limits::default() }`
  as before. `Limits` is not `#[non_exhaustive]`: the integration tests and the callers of steps 07 and 08 build it
  as a struct literal with `..Limits::default()`, which `#[non_exhaustive]` forbids outside the crate; a literal
  without the `..` breaks with any new field. `Validation::start` takes the time as before: it is the cache's
  clock too, so there is no clock inside.
  Kinds and TTLs. Secure keys: the TTL `keys_from_ds` and `anchor_keys` give, the least of the verified DNSKEY
  `RRset`'s, the DS `RRset`'s and the signatures' remaining validity (RFC 4035 §5.3.3, RFC 2181 §8), and no more
  than a day, whatever the signatures allow (Unbound's `cache-max-ttl` 86400: a key rolled over or a DS removed
  waits no longer; the same cap holds for every kind). Insecure
  (unsigned delegation, opt-out, unsupported algorithm or digest, NSEC3 iterations above the limit): the TTL of the
  proof, that of a denial held to the keys' and RFC 9077 §3.4's three hours (an opt-out proof's TTL lacked both
  until now: nothing read it). A name that is no zone cut (a proven absence of DS, or a verified CNAME or DNAME)
  is kept with the TTL of that proof, with the insecure zones. Bogus: 60 seconds
  (Unbound's `val-bogus-ttl`), for a zone only, by name (superseded by D92). A hit gives the TTL it has left, so what
  is derived from it never outlives it, and a hit is never written back, so reading renews nothing.
  Never kept: an indeterminate outcome or one of the budget (D71), nor `Failure::Transient`: a bogus verdict that
  says nothing lasting of the zone: every bogus found before the zone's keys were reached (a DS that fails, a
  denial that does not hold), the signature limit of D73 (`TooManyFailures`), a DNSKEY answer that is empty,
  missing, unsigned, of keys no signature names, expired or not yet valid (`SigError::is_proven` is false: any
  answer can lack those, and a replay repeats them), any bogus resting on the response `start` was given
  (`Validation::seeded`: the caller's, however fetched) (superseded by D92: no failure is kept), and any outcome
  inherited from the parent zone (`Zone::Beneath`, recomputed from its entry); nor what a trust anchor decides (no
  anchor, negative anchor), which is the `Validator`'s own and costs nothing to find. A validation keeps what it settled in its own map as
  before (so no step spends the budget twice) and copies a hit into it, so that it sees one outcome whatever the
  cache does meanwhile.
  Time: an entry is a hit while `at <= now < at + ttl`, `at` the time given to the validation that wrote it. A `now`
  before `at` (the clock gone back) is a miss, never a longer life.
  Poisoning. Secure, insecure and no-cut entries come of verified data only: a signature under keys that a DS or
  an anchor vouches for, a denial bound to the name asked, so what an attacker sends is either true (then it is what
  an honest answer gives) or no entry. One validation's forged DS, signature or denial changes no other
  (`tests/validator.rs`). The one thing a forged answer can still do is the bogus zone, and only for two facts:
  the DNSKEY answer to the validator's own question under an authentic DS or anchor either lacks the key the DS
  digests (`NoKeyForDs`) or has a signature by that key that does not check (`BadSignature`). Whoever answers that
  question can say so, as it could for its own validation: no answer is authenticated before its keys are, and a
  sans-IO validator does not retry another server or TCP as Unbound's iterator does before it stores the failure
  (no `Next::Retry`: TODECIDE has the cost and the case for it). The entry is kept to what limits the harm: 60 s,
  fixed, never renewed by a hit, one zone (the name of the zone that failed, not its children's names)
  (superseded by D92: no bogus zone is kept).
  Bound: three tables by kind, keys of secure zones, names (no zone cut, insecure zone) and bogus zones, each with
  its own entry bound (`key_cache`) and its share of `key_cache_bytes` (half, a quarter, a quarter) (superseded by
  D92: two tables, half each), each evicting
  its least recently used entry (a hit is a use; an expired entry is dropped when read; a `HashMap` and a `BTreeMap`
  by tick, so insert, hit and eviction are logarithmic under the lock, never a scan). A flood of names under a zone
  of an attacker, each with a proof of no DS and the longest TTL it can have, evicts names, never keys; the TTL
  decides nothing about eviction. An entry costs 256 bytes, its name twice (the slot and its recency entry), the owner again and each
  key as its struct and bytes for a secure zone, each allocation with 16 more (an estimate of what the allocator holds,
  not a measurement), and a zone whose keys cost more than 16 KiB (a DNSKEY `RRset` padded with keys no DS names: the signature covers them all, and every key of
  the set is trusted, so the set cannot be cut to the keys a DS names) is used by the validation that found it
  and not kept: an attacker pins no more than 16 KiB for each name of a zone it signs, and no more than 2 MiB of
  keys all told by default. At the 4 MiB default a real set (two or three keys, about 1 KiB on the wire, about 1.5 KiB as cost) leaves room for
  some thirteen hundred zones; a resolver for more raises `key_cache_bytes`.
  Rank: an entry of a weaker kind never replaces a live one of a stronger (keys over names over bogus), so a
  forged answer, or a denial replayed while its signatures last, cannot unseat the keys of a zone, nor a bogus
  entry a proof of insecurity; once the keys expire the name is free (the bogus rank superseded by D92). The price
  is that a real change (a DS removed, a zone made insecure) waits for the keys' TTL, at most a day, as for any
  cache of keys.
  Known and left: a CD=1 answer found bogus is stored as insecure for 60 s (`insert_checked`), over a fresher entry
  of the same key, the same upstream data; and the SOA owner of a negative answer is not checked as the zone's apex, so
  it sets only the negative TTL, which the cache caps.
  A `Mutex`, not an `RwLock` or shards: a validation runs only for a response the response cache lacked, the lock is
  held for one lookup or insert, never across a signature check, and `validate_warm` at 8 threads
  slows 5x against the lock-free `validate_cold`'s 2.2x (`benchmarks.md`: in a tight loop of 4.6 µs validations the
  lock shows, which real validations, far fewer than one per cache miss, do not). Measured: a warm validation of
  `alg8_a` is 4.6 µs against 106 µs, asking no question (the first figures, 54 and 168 µs, counted a file read
  of the bench). Singleflight (`apps/dedensd/src/flights.rs`, the layer that sends): the questions of the validator
  (`Upstream::probe`, not the client's own) in flight are keyed by server, UDP or not (a truncated UDP answer is
  no TCP one) and question, in a map shared by the threads and kept across reloads (`Current`). The first query to
  need one sends it; the others wait for its response and hand it to `Pipeline::receive` as their own. The sender
  publishes after its own `receive`, which settles what the response proved in the key cache, so a query that
  asks after finds the zone cached; one that was already walking the zone verifies it again (a pending zone in the
  validator would make `step()` wait, which the sans-IO validator does not say: TODECIDE). A sender that fails
  to send, or is cancelled, frees the others to ask; one whose server did not answer hands the others that
  failure, as theirs. The validator crate is unchanged. Tests: `flights.rs` unit tests, `tests/flights.rs` of
  `dedensd`: 8 clients make one DNSKEY question of the root, not 8.
  Tests: `tests/validator.rs`, a warm validation asks none, the entry holds for its TTL and not a second more, a
  clock gone back, an answer nobody gave, an exhausted budget and a forged DS are not kept, a bogus zone is held 60 s
  and not renewed (superseded by D92), a DNSKEY answer that proves nothing, or that `start` was given, is never
  kept, insecure and no-cut entries are kept, a negative anchor is its validator's own, clones and threads;
  `validator/cache.rs`, the flood, LRU order, bytes and the entry limit, rank, the day and the clock gone back. Fuzz target `validate`: a new
  validator per input, the validation run twice with the same answers (picked by question), the second from the
  cache of the first, and the two verdicts agree unless one is indeterminate.

- D92 (amends D86) The key cache keeps no bogus zone: its tables are two, keys and names. A validation that fails
  at a zone's keys settles it in its own map as before (no step spends the budget twice), and the next
  validation walks the zone again. Gone with the table: `Kind::Bogus`, `BOGUS_TTL`, `Failure::Transient`
  (now a bogus verdict, as any), `Unusable::undecided`, `Validation::seeded` and `SigError::is_proven`, which
  only decided what the table could store; `key_cache_bytes` is half for keys and half for names (the names
  table doubled, the keys' share is as it was). The response cache keeps a bad answer for `Config::bogus_ttl`
  (D77), per question, never served stale.
  Why. A DNSKEY answer is no authenticated one before its keys are, and whoever sends it, a server of the
  stage, a forger or a replay, can lack the key the DS digests or break the signature of that key. The 60 s
  entry made that one answer the verdict of every validation under a sound zone: a one-answer denial of the zone
  for a minute, to every client. Unbound stores the failure only after it tried its other servers; the sans-IO
  validator cannot, and `Next::Retry` would add a variant every caller of `step()` matches (`dedens`,
  `dedens-server`, the fuzz target), a retry state per zone, and a way to ask a server other than the one that
  answered (an `Upstream` knows its next server only after a failure; a stage of one could only repeat over TCP).
  Less code wins: with no entry, a lie costs the validation it was told to, and the next one asks again.
  Revisit `Next::Retry` when a deployment forwards to several servers, one of which lies or breaks, and a bogus
  zone shows in its logs.
  Cost. A zone bogus to everyone is walked by each validation under it: for `rhybar.cz` (its DS matches none of
  its keys; the keys of `cz` cached) 2 questions, the DS and the DNSKEY, and one signature check, the same every
  time (`tests/validator.rs`). The validator's questions never use the answer cache (D77), so each query for a
  name under such a zone costs those 2 upstream questions, whatever the response cache holds; only concurrent
  ones share them (singleflight, D86). The response cache holds the bad answer 60 s per question, so with a cache
  stage a client asking the same question costs one walk a minute; without one, every query does. RFC 4035 §4.7:
  a resolver with a BAD cache "MUST take steps to prevent the cache from being useful as a denial-of-service attack
  amplifier". Here the bad answer's TTL is small and assigned (`bogus_ttl`), and what an attacker can make a
  query cost is bounded: by the questions, budget and failed checks of one validation (`Limits::questions`,
  `budget`; D73, D75) and by the allowance of all of them (`Allowance`, `per_second`, D77), a flood of different
  names paying it as any uncached query does. Not met: §4.7's threshold of failures before a bad answer is
  served from the cache (TODECIDE, D77).
  Tests: `validator/cache.rs`, a failure and a name inherited are kept nowhere; `tests/validator.rs`, a bogus zone
  is asked again each time and the sound zones around it keep their keys, repeated walks under a bogus zone cost
  2 questions and 1 check each, a failure an answerer can force is the validation it lied to and no other, and
  the DNSKEY answers that prove nothing or that `start` was given are never kept (D86, as before). `validate_*`
  and `serve_*` do not move (`benchmarks.md`, run before and after).
- D176 (amends D75) A NOERROR response to a question of type RRSIG whose answer section holds an RRSIG record
  owned by a name of its chain (the name asked, or a CNAME or DNAME target from it; names compared without case)
  is `Insecure { reason: RrsigQuery }`: RRSIG records are not signed (RFC 4035 §2.2), and the validator parts
  them from the sets they sign, so the answer had no set of the type asked and no denial of it, and a signed name
  came out bogus (SERVFAIL, `NSEC_MISSING`). Insecure, not `Indeterminate`: the data is served, without AD
  (`dedensd`) and not shown as validated (`dedens +validate`), and no extended error is attached. Any other
  response to it, a name error or one without such RRSIG records, is judged as for any type, so its denial is
  proven: a name error's proof holds for every type, and a no data of RRSIG at a signed name fails, its bitmap
  having RRSIG. Rejected: verifying each RRSIG by the set it covers, which the response does not hold; insecure
  whatever the response holds, which took a forged name error or empty answer without a proof.
