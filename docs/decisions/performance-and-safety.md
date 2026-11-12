# Performance and safety

Decisions; the rules and the index are in [`README.md`](README.md).

- D14 Bar: no slower than hickory-proto; target: faster than `domain`. Baselines run in the same benches:
  hickory-proto, `domain` and Go's `miekg/dns` (the codec of CoreDNS), in `crates/dedens-bench` as regular
  dependencies so `cargo deny` checks them; Unbound's C codec, built from a pinned release by
  `just bench-unbound`. `unsafe` only where a profile shows bounds checks matter. `Message::decode_reusing`
  decodes without allocating once warm; the server decodes each upstream response once with `Message::decode`
  (D46).
- D15 `unsafe` is a hot-path tool: the bench first, then Miri and RAPx. Every crate root has
  `#![forbid(unsafe_code)]`, which nothing below can override; a crate opting in replaces it with the
  workspace's `deny` (`Cargo.toml`) and allows `unsafe_code` on the one module of the measured hot path.
- D16 Checks beyond the gate, each added with its trigger: Miri with the first `unsafe`, loom with the first
  hand-written concurrent structure, cargo-semver-checks with the first crates.io release, fuzzing with the
  first fuzz target. RAPx weekly, outside the gate: it builds on rustc internals and breaks on unrelated
  nightly changes.
- D103 (amended by D142) Mutation testing (cargo-mutants), outside the gate: `just mutants` for whole packages, local, as it takes
  hours (5510 mutants in the workspace, about 10 s of build each); `just mutants-diff` for what a branch changes,
  also run on each pull request by the `mutants` workflow, informational: the `gate` job does not need it.
  Both test the committed HEAD in a worktree of their own with `--in-place`: the build stays warm from one
  mutant to the next, and a killed run's leftover mutant never reaches the working tree. `--iterate` tests again
  only what the last run did not catch. Tests run under nextest: a warm run of `dedensd`'s took 11.4 s against
  24.2 s with `cargo test`, the other packages within 0.8 s (2026-11-01); nextest runs no doctest, so a mutant
  only a doctest catches shows as missed, the safe direction. A missed mutant no test can observe, or one that
  hangs the tests (240 s each), is skipped in `.cargo/mutants.toml`, with its reason, matched by function and
  change, never by line. Rejected: a
  scheduled whole-workspace run in CI, which would need a dozen shards to fit GitHub's 6 h job limit.
- D141 (builds on D16) Scheduled checks. Fuzzing: `fuzz.yml` runs each night every target in a job of its own (a
  matrix over `fuzz/fuzz_targets/`, `fail-fast: false`, so a crash stops its own target only), five minutes with
  libFuzzer's `-fork` on every core of the runner, from that target's corpus; `just fuzz-cmin` (`-merge=1`) then
  keeps the inputs that add coverage, saved under a key per run, after a crash too; a crash uploads that target's
  inputs. The recipes name the host's target: cargo-fuzz defaults to the one it was built for, musl when
  install-action falls back to cargo-binstall, where AddressSanitizer cannot link (every job failed so, 2026-11-01
  to 11-03). Before: the 25 targets in turn on one core, 60 s each, the first crash skipping the rest, the corpus
  only growing. Advisories:
  `advisories.yml` runs `just deny advisories` each day: an advisory against a crate no pull request touches would
  otherwise wait for the next pull request. Rejected: `rust-audit-check-action` (cargo-audit reads the RustSec
  database cargo-deny already reads, and wants to write issues); a toolchain action (`just toolchains` reads
  `rust-toolchain.toml` and the pinned nightly); Depot's shards of one target merged by a later job (a job per
  target already spreads the work, and each merges its own corpus).
- D142 (amends D103) The pull request's mutants in shards, for pull requests changing Rust, manifests, the lock
  file, `.cargo/mutants.toml`, the justfile or the workflow: a `plan` job lists the diff's mutants without building
  (`--list`) and asks for one shard per 40, up to 8 (the account runs 20 jobs at once, `ci.yml` about 8), warning
  past 4000 (about 40 s each fills a shard's 350 min, under hosted runners' 6 h); each shard job runs `just mutants` over the plan's diff, so
  all agree on the list, with `--shard k/n` (cargo-mutants' default `slice`: neighbouring mutants, so warm
  incremental builds) and `--baseline=skip`, as `ci.yml`'s `just check` runs the unmutated tests of the same commit;
  a `summary` job lists every shard's missed and timed-out mutants on the run's page (GitHub shows 10 of
  cargo-mutants' annotations per step). A shard with one fails (red), still outside the gate. Before: one job,
  every mutant in turn, 120 min at most, the outcomes in an artifact only.
- D168 (builds on D103) Stale mutants exclusions fail: `just mutants-stale` lists every mutant without the
  configuration (`--list --no-config`, no build) and names each `exclude_re` pattern matching none and each
  `exclude_globs` glob matching no file (`--list-files --file`), failing if any; the pull request's `mutants`
  workflow runs it in a `stale` job, as informational as the shards. A moved or renamed function leaves its pattern
  behind, and nothing showed it but its mutants coming back. Perl matches the names, reading the patterns used as the
  `regex` crate does: cargo-mutants 27.1.0's `--re` keeps every struct field deletion whatever the pattern, so a
  stale one would still list mutants. Rejected: a test in `just check`, which would need
  cargo-mutants installed for the gate.
- D22 (amended by D114, D116, D118, D124) Response cache (`dedens-cache`, sans-IO, time passed in as seconds): one cache shared by compio's
  per-core threads, `Mutex` shards picked by keyed SipHash (no collision flooding). Own code, not
  `moka`/`quick_cache`: slab shards with S3-FIFO eviction under a byte budget (a scan of one-time names leaves
  popular ones; a ghost queue of evicted hashes sends a key asked again to main). Whole responses only; an
  RRset cache comes with the recursive resolver. Key: lowercased question, type, class, DO, CD, of standard
  queries only (QR clear, opcode QUERY), not meta types (RFC 6895 §3.1; ANY is cached). `insert` takes the
  client's query and the response the forwarder decoded, never decoding again; the caller asks upstream with
  the query's DO and CD. Checked (RFC 2308, no TC, no violations, no client subnet scope above 0, RFC 7871
  §7.3.1) and encoded once without OPT, its TTL offsets (and the cuts of D116) after it in the same allocation. Negative (NXDOMAIN, or no
  answer of the type asked, after any CNAME chain) only with an SOA at or above the chain's last name, and the
  chain's TTLs within the negative TTL (RFC 2308 §2, §5). A hit copies and patches ID, flags (AA and Z clear, AD
  only when asked), question case and TTLs, never above the stored TTL; one too large for the buffer is cut to it in the same way (D116). Serve-stale (RFC 8767: 30 s answer TTL, 3 days kept) and failure holds (RFC
  9520: 5 s doubling to 300 s, 30 s with stale data, never above 300 s; a failure during a hold does not count, a
  quiet spell over 300 s starts over); the caller decides when stale data may answer.
- D140 (builds on D16; amended by D161, D162, D163, D171) Repository checks in the gate,
  `crates/dedens-repo/tests/repo.rs` (D163), over the tracked files (`git ls-files`: a tree walk would need a skip
  list for `plan/`, `target/` and the rest of `.gitignore`). A decision cited in a tracked text file, anywhere (an
  extension of `CITING_EXTENSIONS`, or none: `justfile`, `Containerfile`; every file of `deploy/`; not RFC archives
  or captured data), is defined in a section file of `docs/decisions/`, once, a range such as `D64-D66` expanded. A
  header's `amends`, `supersedes` or `narrows` is matched by the other's `amended by`, `superseded by` or `narrowed by`,
  and the reverse; a supersession of a scope (`superseded by D113 for UDP`) is one still, since the two sides name each
  other; `builds on` and `completes` are one-sided, and a clause naming decisions in another form fails. Every path in a
  Code or Tests cell of `docs/rfc/coverage.md` exists (braces and a `*` in the last component allowed), every
  RFC a test file cites in its module docs has a row naming the file (D162), every `AGENTS.md` has its `CLAUDE.md`
  symlink, a crate's `clippy.toml` starts with the root one (D134: clippy reads the nearest alone), and the
  `Containerfile` builds from the Rust `rust-toolchain.toml` pins (D153). Each check runs once on a small broken input in the same file. No `syn`: nothing here parses Rust, string
  matching does it, with no new dependency. Not checked: that a row's status is true.
- D138 (builds on D14, D16) Profiles are sampled, never instrumented. `just profile <bench> [filter]` runs a bench
  target under samply (launching needs no `samply setup`), the bench profile's line tables giving the names; `DEDENS_PERF=1
  just bench-dnsperf` runs the working tree's `dedensd` under `perf record --call-graph dwarf` in the container, built
  with `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only` and `CARGO_PROFILE_RELEASE_STRIP=false` over the release profile.
  Both write to `target/profile/` (git-ignored with `target/`): `<bench>[-<filter>].json.gz` for `samply load`,
  `<mode>.txt` for perf's report (the data stays in the container). Local, no CI job; a missing samply stops the recipe
  with its install command. A profile splits a total into functions and records no result: the queries per second of a
  profiled server are not kept, and a claim of speed is still a bench (D14). Rejected: hotpath, which instruments each
  measured function at about 40 ns a call against the 84-185 ns of a cache hit, needs a feature in each crate (doubling
  `just hack`), and brings a counting allocator that collides with the benches'.
- D143 (builds on D16; amended by D161) Unused dependencies fail the gate: `just check` runs cargo-shear
  (`--locked --deny-warnings`) over the workspace and over `fuzz/`, a workspace of its own. It parses the sources with
  rust-analyzer's parser and builds nothing: 0.3 s each (2026-11-03). A false positive goes in the package's
  `[package.metadata.cargo-shear] ignored`, its reason beside it; cargo-shear reports an entry that suppresses
  nothing. One kind left: `dedens-bench`'s dependencies, regular ones the benches alone use (D14). The other, a
  dependency of a module another package holds, reached by `#[path]`, which cargo-shear does not read (rcgen in
  `dedens` and `dedensd`, data-encoding in `dedens-bench`), went with those modules (D161). Rejected:
  cargo-udeps (nightly, builds every target), cargo-machete (regular expressions over the sources).
- D161 (amends D140, D143, D160; builds on D14, D16) Test data read by more than one package lives at the root, in
  `testdata/`: `proto/` and `dnssec/` (the captures of `just capture` and `just capture-dnssec`), `zones/` (the RFC
  example zones), `odoh/`, `doh/` and `coap/` (with their capture scripts) and `plugins/` (published lists), moved byte
  for byte. Data one package reads stays in it. The test-only crate `dedens-testkit` (`publish = false`) names it:
  `path` gives a file of `testdata/`; an `include_bytes!` names the file itself; `captured`, `message` (a capture
  decoded without a violation), `query` (a capture's question under an ID), `hex`, `dns` and `zone` replace the
  copies each crate's tests kept; `dnssec` holds the DNSSEC captures (`capture`, `response` decoded) and by question
  (`Captures`), their `captured_at`, and the RFC examples' keys and signatures with the data an RRSIG signs, which
  `benches/dnssec.rs` of `dedens-bench` reached by `#[path]`. The feature `certificates` adds the TLS certificates the encrypted transports' tests make (D60), on
  `dedens-net`, compio and rcgen, which `dedens` and `dedensd` included from `dedens-net`'s tests by `#[path]`; the
  default build depends on `dedens-proto` and data-encoding (the RFC examples' base64) alone. The feature `responder`
  adds the loopback server the tests of `dedens` and `dedensd` query, one for both where each kept its own: it serves
  the captures named over UDP and TCP, TLS, QUIC or HTTP/3 (Oblivious `DoH` and CoAP with `odoh` and `doc`), matches a
  question by its name without case and its type, answers with the query's ID and question, and keeps every query with
  its transport. A package reads the data through the kit, never through another package's directory
  (`../dedens-*/tests/`), which tied each test to where another crate kept its files, and no test includes another
  package's file by `#[path]`. cargo-mutants skips the kit, test code as `tests/` is (`.cargo/mutants.toml`). The kit's
  public modules are one per concern, as D160's exceptions: `dnssec`, and `certificates` and `responder` behind their
  features; none is re-exported, so each item has one path. The unit tests of `dedens-proto` get another build of the
  crate than the kit links and take paths and bytes from it; those of `dedens-dnssec` take `zone`'s records, of the one
  `dedens-proto` both link, the kit not depending on `dedens-dnssec`. Cargo unifies features over a workspace build, so
  in `just check` `dedens-proto`'s tests link `dedens-net` too: the build without the network stack holds per package
  (`cargo test -p dedens-proto`), not in the workspace's. `testdata/` is one of the folders D140 reads for decisions and
  one a coverage path may start at. Rejected: data kept in its first reader with the others reaching in (the paths it
  replaced).
- D162 (amends D13, D133, D140, D159; amended by D170) A package's integration tests are one binary,
  `tests/tests.rs` (`autotests = false` and one `[[test]]`, as ripgrep), with a module per topic, not a file per
  RFC: 129 test binaries each linked their crate's dependencies (21 linked compio, rustls and quinn in `dedens-net` alone), and the link dominated an
  incremental test build: 14 binaries take it from 16-17 s to 5-6 s after a change to `dedens-proto`, and `target/`
  from 5.7 to 3.7 GB (`docs/benchmarks.md`). A topic module cites in its docs the RFCs and sections it tests, and
  each test of an RFC section keeps the section in its name (`s4_1_4_...`); a topic gathering several RFCs gives each
  its own inner module or a `// --- RFC NNNN ---` part. The shared helpers are the module `util` (was `common/`), one
  copy linked once, so the `tests` binary has no `dead_code` allowance; a test file that needed a feature is a
  `#[cfg(feature)]` module. A test that sets its own `#[global_allocator]` (`dedens-cache`'s `allocations.rs` and
  `memory.rs`) keeps its binary: the allocator is the process's. Those two binaries, and the benches that include
  `util` by `#[path]` (`dedensd`'s `doh3.rs` and `udp.rs`), use part of it, under `#[expect(dead_code)]`. D140's
  coverage check reads the RFCs a file with tests cites in its module docs, where it read `tests/rfcNNNN.rs` names.
  A simulation family (D133) is a module of `dedens-sim`'s binary, its 2 s budget the module's, and
  `seed::in_two_processes` names the test by its module path. Commands name the binary and a module filter:
  `cargo test -p dedensd --test tests -- --ignored privileges::`. Rejected: a folder per topic with a file per RFC
  (the RFC is the module docs' and the test names'), a binary per file (the link time this removes).
- D163 (amends D140) The repository checks are a package of their own, `crates/dedens-repo`: they check the
  repository, not benchmarks, and a reader looks for them by name. `tests/repo.rs` moved from
  `crates/dedens-bench/tests/` unchanged, still finding the root at `CARGO_MANIFEST_DIR/../..`; the library is empty
  (a package needs a target) and the package depends on nothing, so `cargo test -p dedens-repo` builds `std` alone
  where `dedens-bench`'s tests built the benches' dependencies. Its binary is D162's form, `tests/tests.rs` with the
  module `repo`, as `dedens-bench` is left with `zone`: a lone `tests/repo.rs` binary would be a second layout for a
  package of one topic. `cargo test --workspace` runs it, so the gate is unchanged. Rejected: an `xtask` (a command
  to remember, outside `cargo test`).
- D170 (amends D162; builds on D161) `dedensd`'s benches include by `#[path]` its tests' harness alone,
  `tests/util/server.rs`: the running `dedensd` and its configuration files, a private module of `util` whose items
  `util` re-exports, so the tests name one path. The harness stays out of `dedens-testkit`: it spawns
  `CARGO_BIN_EXE_dedensd`, which Cargo sets for this package's tests and benches alone, and no other package starts
  `dedensd`. The query a bench sends is built from `dedens_testkit::message`. Rejected: the harness in the kit, the
  binary's path a parameter of each start (one package's helper in the kit of several, D161); a library target in
  `dedensd` for its benches (a public surface for test code); the benches including all of `util`.
- D171 (amends D140) The decisions are a file per section in `docs/decisions/`, moved verbatim from the one file
  they were, with an index, `docs/decisions/README.md`: the rules of a decision, then a line per decision in
  number order with its section file, a gist, and its header's `amended by`, `superseded by` and `narrowed by`.
  An agent reads the index, then the sections its task touches: the one file was read before any task, 2882 lines,
  about 75k tokens (bytes / 4); the index is about 4k, a section 0.3k to 31k (Server), six of the nine under 5k.
  D140's checks read every section file, and the index holds one line per decision, in number order, naming the
  file that defines it and repeating those three clauses of its header. Rejected: a one-line index atop the one file
  (a detail still opens 75k tokens); a file per decision (155 files to name and link, a section's neighbours apart).
- D144 (builds on D16) The tests under cargo-careful, outside the gate: `just careful address` runs the workspace's
  tests on a standard library rebuilt with its debug assertions and UB checks, under AddressSanitizer, in
  `deep.yml` on each pull request, informational: a `careful` job per package (`just careful address <package>`),
  2 h each, as the whole workspace in one job outlasted 60 min (dedens-net's `tcp.rs` walks all 65 536 IDs). Our code has no `unsafe` (D15), so Miri has
  nothing of ours to check, and it runs neither io_uring's system calls nor ring's assembly; the `unsafe` is in
  the dependencies (compio's io_uring driver, rustls and ring, quinn-proto, flume), and careful reaches it through
  the real tests. Leak checks are off: a leak is no memory error. The sanitizer is Linux-only: cargo-careful's
  sanitized builds fail to link on macOS, where `just careful` runs without one: from cold, about 7 min for the
  1799 tests, all passing (2026-11-03). Its own target dir: the checked standard library rebuilds every crate.
- D145 (builds on D16; amended by D179) Kani proves dedens-proto's wire decoders for every small input, weekly and manual, outside
  the gate (`kani.yml`, `just kani`); the proofs are `crates/dedens-proto/src/proofs.rs`, under `cfg(kani)`, so
  they reach the crate's own decoders. `name_decoding`: a name read at any position past the header of any
  message of up to 12 more bytes, compressed or not, never panics, stops (Kani checks every loop's bound) and
  ends inside the input. `header_peeking`: any input of up to 13 bytes. `header_round_trip`: every 12-byte
  header encodes back to itself. Fuzzing samples inputs of any length; Kani covers every input within its bounds,
  edges included. The bounds follow the cost: 12 bytes take 8 min, a try at 20 did not end in 20; at 14 bytes,
  `Message::decode` was still unrolling every RDATA decoder after 30 min and stays with the fuzzer. Headers take
  3-5 s, `just kani` 8 min (2026-11-03, a loaded laptop). Weekly, not in the gate: minutes a proof, and a nightly
  and CBMC of Kani's own (`just kani-install`).
- D146 (builds on D16) CodeQL's Rust queries, weekly and manual, outside the gate: `codeql.yml` extracts the
  sources without building them (`build-mode: none`) and runs the default suite, whose taint tracking follows
  outside data to where it sizes an allocation, names a path, reaches a log or disables a certificate check:
  data flow across functions, which clippy's lints do not follow. Alerts go to the repository's Security tab, not
  to pull requests: the queries change with each release of the action, and a new one must not block unrelated
  work.
- D178 (builds on D103) The gate runs the tests under cargo-nextest: `just check` runs `cargo nextest run
  --workspace --all-features`, then `cargo test --workspace --all-features --doc`, as nextest runs no doctest. A
  process per test: warm, the workspace's 1920 tests took 33.8 s and the doctests 5.8 s, against 48.6 s for
  `cargo test` (Apple M5, 2026-11-11); a test that aborts its process ends no other test. `.config/nextest.toml`
  kills a test still running after 2 min (the slowest took 17.7 s), where a hang held the job to its 45 min; the
  `ci` profile (`NEXTEST_PROFILE=ci` in `ci.yml`) reports every failure, not the first. No retries: a test that
  passes on a second try still failed once. `dedensd`'s test servers start one at a time under a file lock in the
  temporary directory, not a mutex, which held within one process only. Under cargo-mutants (D103) the same kill
  ends a mutant's hung test at 2 min, a failure, before the run's 240 s timeout. nextest builds through `cargo test
  --no-run`, so the Privileges step's and `just sim-time`'s `cargo test` builds (D164) reuse its artifacts. The musl
  suite (`rust:alpine` has no nextest), careful, loom and sim-time keep `cargo test`. Rejected: `cargo test`
  alone (an abort ends its binary's other tests; slower).
- D179 (amends D145; builds on D103) Kani proves code outside dedens-proto's decoders too, beside it: a
  `#[cfg(kani)] mod proofs` in the module whose private items it reaches, `crates/dedens-proto/src/proofs.rs` for its
  public API. Each proof, its bound and its time (Apple M5, 2026-11-11): `zero_bytes` of the name table against its
  spec for every `u64` (0.1 s); `Edns::append`, the cache-hit path, into any buffer of 25 bytes: it fits exactly when
  RFC 6891 §6.1.2 allows, adds 1 to ARCOUNT and writes the record, else changes nothing (9 s); a client subnet of up to
  8 bytes decodes and encodes back (RFC 7871 §6, 3 s); NSEC type bit maps of up to 6 bytes, `contains` agreeing with
  `types` (RFC 4034 §4.1.2, 4.6 min); `covers` on chains of up to 4 `u8` owners, each other value covered by exactly
  one link (RFC 4034 §4.1.1, 1 s), which holds for any total order, while `canonical_cmp` being one stays unproven;
  the cache's `whole_cut` against its spec on 3 bytes of bits (6 s); a CoAP option nibble for every `u32` (RFC 7252
  §3.1, 0.3 s); ODoH's message and plaintext of up to 8 bytes parse and encode back (RFC 9230 §6.1, 9 s and 15 s).
  Dropped, over 10 min: the name table's `add`, `find` and `truncate` (3 names in one home group, the comparison
  with the message stubbed: no end in 15 min, 19 million variables, as every slot of 256 is symbolic), and a parsed
  CoAP message writing back its bytes (no end in 10 min at 8 bytes: each option a `Vec`), left to the fuzzer. `just
  kani <package>` runs a package's proofs; `kani.yml` a job per package holding a `#[kani::proof]`. `just kani-fast`
  runs those of under a minute, listed in it, on each pull request in `deep.yml`, informational (68 s warm, against
  12 min for dedens-proto's 7 alone); a name matching no proof fails it. A slice compared at a symbolic length
  needs `#[kani::unwind]`: without it CBMC unrolls `memcmp` without end. `--harness` picks each proof whose path
  holds the name; `--exact` with the path picks one. cargo-mutants skips every `proofs::` function, built only
  under `cfg(kani)`. Tried with `-Z stubbing` (unstable) and dropped, the whole message left to the fuzzer:
  walking a message, `Name::decode` standing in by what `name_decoding` proves, ran out of memory at 11 bytes past
  the header, its 1.3 million steps the same at 2 bytes, as CBMC unrolls each section's loop and its `zerocopy`
  reads whatever the bytes; adding `Message::decode`'s budgets and vectors, RDATA and options standing in too, did
  not end in 50 min; two names of up to 2 one-byte labels compressed and read back did not end in 50 min, every
  hash colliding.
- D180 (builds on D16) Verus proves the reading of a name for every input, where Kani stops at 12 bytes (D145):
  `scan` in `crates/dedens-proto/src/name.rs`, the loop of `Name::decode` (RFC 1035 §4.1.4) taken out of
  `decode_with`, ends (each label moves the position towards its limit, each pointer moves the bound back), never
  panics nor overflows, and a name it returns ends past its start and within the input, is 1 to 255 bytes long
  uncompressed, and is the bytes from its start to where the reader resumes when it has no pointer: the fallbacks of
  `decode_with` never run. Its length is that of the name `uncompressed`, a spec function, reads there: RFC 1035
  §4.1.4's labels and pointers, each pointer below the previous target as D9 requires. `unpack`, which copies out a
  name with pointers (`Name::to_wire`), returns that name for any `msg` and `start` `scan` accepted, so the copies of
  a decoded name are its RFC 1035 decompression; the step from `scan` to `unpack` goes through `Repr::Packed`,
  built only from what `scan` returns, which Verus does not follow. `uncompressed` is trusted, as any specification:
  the proofs are worth what it is. `just verus` checks it all in 20 s from cold (Apple M5, 2026-11-12), outside the
  gate, and `deep.yml`'s `verus` job on each pull request, informational. The specifications are
  `#[cfg_attr(verus_only, verus_spec(..))]` on the Rust as it is, the hints `#[cfg(verus_only)] proof! {..}`: a
  build without Verus has neither them nor vstd, a dependency under `cfg(verus_keep_ghost)`, which `just verus` sets
  in `RUSTFLAGS` (cargo picks the dependencies from there, not from Verus's driver); the verifying build alone
  enables `proc_macro_hygiene` (attributes on loops). `msg.len() <= isize::MAX`, true of any slice, is assumed, as
  Verus does not know it. Message decoding as fast after the change (`decode_dedens` 118.9 ns against 118.7 ns for
  an A answer), the `message` benches within noise after `unpack`'s. The release is pinned in the justfile, its own rustc installed beside ours, so the stable pin does not wait for Verus; Renovate bumps it
  (`loose` versioning: `0.<date>.<commit>`) and leaves vstd alone, as its crates.io versions include those of
  Verus's rolling releases: vstd moves by hand to the version `cargo verus toolchain list` gives, and `just verus`
  (`--check-toolchain`) fails on any other. Rejected: Creusot (its creusot-std is LGPL, which `deny.toml` refuses;
  opam and Why3 to install; a specification for each call outside the crate), Flux (a prototype without releases,
  a git dependency without a licence), Aeneas with Charon (proofs written by hand in Lean, broken by each change of
  the Rust, and no one to own them; Charon alone checks nothing), MIRAI (unmaintained since 2025-03; its
  nightly-2025-01-10 cannot build edition 2024), Kani on whole messages (D179).
