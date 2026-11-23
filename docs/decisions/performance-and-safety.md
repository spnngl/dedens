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
  (`--list`) and asks for one shard per 40, up to 8, 4 at a time (the account runs 20 jobs at once and `ci.yml`'s
  `gate` must find one free, `.github/AGENTS.md`), warning
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
  chain's TTLs within the negative TTL (RFC 2308 §2, §5). The chain is followed for every type asked but CNAME and
  ANY (RFC 1034 §3.6.2), DNAME included: below a DNAME's owner the CNAME it makes restarts the query at its target
  whatever the type (RFC 6672 §3.2 step 3C), so a DNAME question there is answered, or denied, at the chain's end. A hit copies and patches ID, flags (AA and Z clear, AD
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
  its transport. Its delays (`delayed`, `slow`) are wall-clock time, slept by the thread that answers: every test that
  delays drives a `dedensd` process, whose timers run on the system clock in a process no injectable clock reaches, and
  checks how those timers meet a late answer; the library's own timers are tested on `dedens-sim`'s clock (D133).
  Rejected for those delays: an injectable clock or an order the test releases (the clock is `dedensd`'s, and what
  the answer must come after happens inside it). A receive error other than an interrupted call or an earlier
  datagram's ICMP error panics its thread, where it had stopped the server unsaid. A package reads the data through
  the kit, never through another package's directory
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
  20 min each, as the whole workspace in one job outlasted 60 min (dedens-net's `tcp.rs` walks all 65 536 IDs);
  the slowest, dedens-sim, took 7 min in each of 15 runs (2026-11-20), where 2 h let a hung test hold a runner. Our code has no `unsafe` (D15), so Miri has
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
  `cargo test` (Apple M5, 2026-11-11). On the `check` job, the tests without doctests (`cargo test`: from its first
  test binary to the doctests; nextest: its summary), two runs each: `ubuntu-26.04` 138 and 163 s under `cargo test` (c1af86c, d10eec2), 86 and 105 s under nextest (ae0348e,
  440e39d, 1924 and 1971 tests); `macos-26` 109 and 134 s against 98 and 138 s, a runner too uneven to tell. A
  test that aborts its process ends no other test. `.config/nextest.toml`
  kills a test still running after 2 min (the slowest took 17.7 s), where a hang held the job to its 45 min; the
  `ci` profile (`NEXTEST_PROFILE=ci` in `ci.yml`) reports every failure, not the first. No retries: a test that
  passes on a second try still failed once. `dedensd`'s test servers start one at a time under a file lock in the
  temporary directory, not a mutex, which held within one process only. Under cargo-mutants (D103) the same kill
  ends a mutant's hung test at 2 min, a failure, before the run's 240 s timeout. nextest builds through `cargo test
  --no-run`, so the Privileges step's and `just sim-time`'s `cargo test` builds (D164) reuse its artifacts. The
  `coverage` job's `just cov` runs `cargo llvm-cov nextest` too: under `cargo test`, a test spawning a process
  while another dropped a compio runtime with a receive in flight let the kernel write into freed memory (the child
  holds the ring open; compio-driver frees the buffers on `close`), and `dedensd`'s whole test binary died on
  `free(): corrupted unsorted chunks` or SIGSEGV, naming no test, in 3 of 176 runs. The numbers hold: dedens-proto's 95.41 % of regions either way, 97.45 % of
  lines under `cargo test`, 97.49 % under nextest (2026-11-15). The musl suite (`rust:alpine`
  has no nextest), careful, loom and sim-time keep `cargo test`. Rejected: `cargo test` alone (an abort ends its
  binary's other tests; slower).
- D179 (amends D145; builds on D103) Kani proves code outside dedens-proto's decoders too, beside it: a
  `#[cfg(kani)] mod proofs` in the module whose private items it reaches, `crates/dedens-proto/src/proofs.rs` for its
  public API. Each proof, its bound and its time (Apple M5, 2026-11-11): `zero_bytes` of the name table against its
  spec for every `u64` (0.1 s); `Edns::append`, the cache-hit path, into any buffer of 25 bytes: it fits exactly when
  RFC 6891 §6.1.2 allows, adds 1 to ARCOUNT and writes the record, else changes nothing (9 s); a client subnet of up to
  8 bytes decodes and encodes back (RFC 7871 §6, 3 s); NSEC type bit maps of up to 6 bytes, `contains` agreeing with
  `types` (RFC 4034 §4.1.2, 4.6 min); the cache's `whole_cut` against its spec on 3 bytes of bits (6 s); a CoAP option nibble for every `u32` (RFC 7252
  §3.1, 0.3 s); ODoH's message and plaintext of up to 8 bytes parse and encode back (RFC 9230 §6.1, 7 s and 13 s,
  2026-11-20).
  Dropped, over 10 min: the name table's `add`, `find` and `truncate` (3 names in one home group, the comparison
  with the message stubbed: no end in 15 min, 19 million variables, as every slot of 256 is symbolic), and a parsed
  CoAP message writing back its bytes (no end in 10 min at 8 bytes: each option a `Vec`), left to the fuzzer. `just
  kani <package>` runs a package's proofs; `kani.yml` a job per package holding a `#[kani::proof]`. `just kani-fast`
  runs those of under a minute, listed in it, on each pull request in `deep.yml`, informational (68 s warm, against
  12 min for dedens-proto's 7 alone); a name matching no proof fails it. A slice compared at a symbolic length
  needs `#[kani::unwind]`: without it CBMC unrolls `memcmp` without end. A `Vec::with_capacity` of a symbolic
  length is an object of unknown size to CBMC: sized from the parsed lengths, ODoH's two proofs passed 2 GB in a
  minute and ran out of memory on the runner in 5; their buffers start empty under `cfg(kani)`, the bytes the same.
  `--harness` picks each proof whose path
  holds the name; `--exact` with the path picks one. cargo-mutants skips every `proofs::` function and `src/proofs.rs`, built only
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
  the proofs are worth what it is. In `crates/dedens-dnssec/src/denial/names.rs`, `one_link_covers`: in a chain of
  owners in order, of any length and under any strict order (irreflexive, transitive), a name is covered by exactly
  one link unless it sorts alike an owner, which none covers (RFC 4034 §4.1.1, RFC 5155 §1.2); `covers` is that test
  of a link wherever `<` is the type's order. That canonical order (`Ord` of `Name`, RFC 4034 §6.1) is a strict one
  stays unproven. Kani's proof of `covers`, on chains of up to 4 `u8` owners (D179), is dropped for it. `just verus` checks it all in 20 s from cold (Apple M5, 2026-11-12), outside the
  gate, and `deep.yml`'s `verus` job on each pull request, informational. The specifications are
  `#[cfg_attr(verus_only, verus_spec(..))]` on the Rust as it is, the hints `#[cfg(verus_only)] proof! {..}`: a
  build without Verus has neither them nor vstd, a dependency under `cfg(verus_keep_ghost)`, which `just verus` sets
  in `RUSTFLAGS` (cargo picks the dependencies from there, not from Verus's driver); the verifying build alone
  enables `proc_macro_hygiene` (attributes on loops). `msg.len() <= isize::MAX`, true of any slice, is assumed, as
  Verus does not know it. Message decoding as fast after the change (`decode_dedens` 118.9 ns against 118.7 ns for
  an A answer), the `message` benches within noise after `unpack`'s. The release is pinned in the justfile, its own rustc installed beside ours, so the stable pin does not wait for Verus; Renovate bumps it
  (`loose` versioning: `0.<date>.<commit>`) and leaves vstd alone, as its crates.io versions include those of
  Verus's rolling releases: vstd moves in the same pull request, by `fuzz-lock.yml`'s `just vstd-sync`, to the
  version Verus's toolchain manifest for the release names (`source/cargo-verus/toolchain-manifests/`, what
  `cargo verus toolchain list` reads), and `just verus` (`--check-toolchain`) fails on any other. Until Verus
  merges the release's manifest the job fails, and a rerun moves vstd. Rejected: Creusot (its creusot-std is
  LGPL, which `deny.toml` refuses; opam and Why3 to install; a specification for each call outside the crate), Flux (a prototype without releases,
  a git dependency without a licence), Aeneas with Charon (proofs written by hand in Lean, broken by each change of
  the Rust, and no one to own them; Charon alone checks nothing; the way back is Kani's `-Z lean`, which writes the
  LLBC Aeneas reads with no second toolchain), MIRAI (unmaintained since 2025-03; its
  nightly-2025-01-10 cannot build edition 2024), Kani on whole messages (D179).
- D181 (builds on D141, D154, D170; amended by D182) The parsers of outside data in the two binaries are fuzzed through a library
  target of each app: `src/lib.rs` holds the crate `src/main.rs` held, and `src/main.rs` keeps the allocator of a
  musl build (D154) and calls the library's `main`. Each library makes public `main` and one entry per parser,
  nothing else: `dedens::parse_args` reads a command line as `dedens` does (`Cli::try_parse_dig`, the usage error
  returned, not exited with); `dedensd::read_config` reads a configuration and builds it as the start does, unless
  it names a file to read (the TLS certificate and key, `upstream_ca`, a stage's `file` or `trust_anchors`, the saved
  copies of `urls`), as a fuzz input must not open the paths it names (`/dev/zero` or a FIFO hangs the run, a real
  file differs between machines). `fuzz/` drives them as `parse_command_line`, arguments between NUL bytes as the
  kernel passes them, and `read_config`, seeded by the command lines of the docs and the CLI's tests
  (`fuzz/seeds/command_lines.txt`) and by `dedensd`'s configurations (the image's, the packages', those of
  `fuzz/seeds/dnscrypt.yaml` and `odoh.yaml`, the examples of its config module). The unit tests move into the library target: `just loom` and `just man` name `--lib`. D170's
  benches keep including their harness: the library exposes no test helper. Rejected: `#[path]` includes from
  `fuzz/` (each parser reaches much of its crate through `crate::` paths, and a moved module breaks the fuzz build
  only); the parsers moved into a library crate (the configuration reaches the lists, the downloads, the privileges
  and ODoH: a crate of half a binary); a library of the parser modules alone (the same reach, each item it holds
  made `pub` for the binary); a `fuzz` feature gating the two entries (a feature `just hack` builds in every
  combination, for two functions).
- D183 (builds on D14, D138; amended by D201) `dedensd` is measured against TelltaleDNS, Unbound and CoreDNS by one harness,
  `just bench-compare <mode> [cores]` (`crates/dedens-bench/dnsperf/compare.sh`, its measuring half `compare.py`),
  on Linux, its numbers in `docs/benchmarks.md` ("Against TelltaleDNS, Unbound and CoreDNS") with each run's JSON
  in `docs/comparison/results/`. Fairness rules:
  - Same work: every server forwards to one neutral upstream, Knot DNS serving a root zone of one wildcard (signed
    with ECDSA P-256 and NSEC3 without iterations for `dnssec`), so no server recurses or reaches the Internet; the
    queries are TelltaleDNS's own corpora (`bench/corpus.py` at its tag, hashes in `compare/corpora.sha256`), the
    blocklist the first million names of a pinned HaGeZi list.
  - Same versions for a session: each the last tag, built from source by the script (the working tree's
    `dedensd`), raised by hand before a run, never between runs; the JSON records them, the host and the configs'
    hashes.
  - Same machine share: each server alone in its container on its own cores (threads set to that count),
    dnsperf and Knot on others, host networking; `taskset` where rootless podman has no `cpuset`, which the JSON
    names. No seccomp filter in any container: the engines' default one refuses `io_uring`, and `dedensd` is
    measured on it as it ships on Linux, a start on its `poll` fallback (D107) failing the run.
  - Two configurations each: shipped (as its project ships it) and lean (what the others lack turned off:
    logs, metrics, APIs), so neither a default nor a tuning decides alone.
  - Right answers first: a server fails the run unless it answers the check pass with the mode's rcode, nothing
    lost, and a sample equal to Knot's (DNSSEC: AD set); a server answering SERVFAIL (`broken`) must fail it.
  - A run is void when something other than the server limits it: Knot or, at saturation, dnsperf over 90% busy, a
    held rate 1% short (a run that sent its whole corpus, in the modes from a cold cache, less 0.25 s for its last
    answers: dnsperf counts that wait), 1% lost or of another rcode; a saturation run losing 1% is rerun 10% lower, twice at most.
  - Rounds alternate the servers' order; medians of the valid runs, with their range; latency and CPU a query
    compared at one common rate (half the slowest median), and at half each server's own. An A/A run (each server
    twice) gives the spread under which a difference is noise.
  Rejected: TelltaleDNS's `bench/run.sh` (one target, its own corpora and a fixed rate; kept as `crosscheck`);
  public resolvers or the Internet as upstream (its latency and its changes measured, not the servers; D201's
  recursive modes resolve from a root of Knot authorities of their own);
  one tuned configuration each (who tunes decides the outcome); a single run per server (±30% between sessions,
  `crates/dedens-bench/AGENTS.md`).
- D187 (builds on D6, D141, D144) The pinned nightly is nightly-2026-11-17, with RAPx 0.7.75 (0.7.71, the one
  before, does not build on it: rustc's internals moved). Since nightly-2026-11-14 rustc's frontend runs 2 threads
  by default, and the nightly's builds keep that default: the fuzz targets' (D141) and cargo-careful's (D144).
  On an Apple M5 of 10 cores, no `--jobs-frontend` of 1, 4 or 8 beats it by more than the noise (1.15) in the round
  least loaded: `cargo check --workspace` 1.01 to 1.04, the fuzz build at most 1.00, the careful build of
  dedens-proto 1.146 at 8 threads (`docs/benchmarks.md`, "Parallel frontend"); CI's runners have 3 and 4 vCPUs.
  Releases are built on stable (D153), whose frontend stays sequential: their reproducibility is untouched. If a
  nightly build crashes or a fuzz or careful finding does not replay, rerun it with
  `RUSTFLAGS="-Zunstable-options --jobs-frontend=1"` (cargo-fuzz and cargo-careful append to `RUSTFLAGS`, careful
  in its sysroot too); a cause found in the parallel frontend puts that flag in the recipe. Rejected: the parallel
  frontend on stable through `RUSTC_BOOTSTRAP=1` (nightly features in the compiler that builds the releases and
  runs the gate, against D6's stable toolchain and D153's reproducible build); `--jobs-frontend` in
  `.cargo/config.toml` (stable reads it too and refuses `-Z` flags); a count above 2 in the recipes (within the
  noise, more CPU time and memory).
- D188 (builds on D10, D40, D126, D161, D162; amended by D197) The recursive resolver's test data is real resolutions from the root
  servers in `testdata/recursion/`, one YAML file per name, captured by `just capture-recursion [ids]`: the example
  `capture_recursion` of `dedens-testkit` (its network crates dev-dependencies) iterates as `+trace` does (D40) from the bundled
  root hints (D126), primes (RFC 8109 §3), asks each zone's DS at its parent and DNSKEY at the zone, follows referrals
  (glue within the parent zone, RFC 9471 §2.1-2.2; other server names resolved from the root) and CNAME chains (a
  DNAME's synthesised CNAME included), and records every exchange. Each question goes to one server of each family,
  the first in address order that answers, so a recapture asks the same servers while they stay; queries set DO alone
  (no RD, cookie or 0x20) with a 1232-byte payload (D10, RFC 9715 §3.2), and a truncated response is asked again over
  TCP. A file: `captured_at` (Unix time of the run's end, the "now" of the signatures, as `testdata/dnssec/`), the name
  and type, then each exchange: server address, zone asked as, question name and type, query flags, transport (`udp`
  or `tcp`), response bytes in base64. The cases (`testdata/recursion/README.md`): priming, signed names under com and
  nl, an unsigned name, a CNAME chain across three zones, a DNAME, a glueless delegation, NXDOMAIN and NODATA signed
  and unsigned, NXDOMAIN by NSEC3, an answer over 1232 bytes, an answer to an RRSIG question (D192); no zone served
  by IPv6 servers alone was found. The recipe replaces only the files of a run that succeeded; a recapture keeps the
  cases, not the bytes. The signatures of a capture end within days of it (D197), so no test validates a capture on
  the real clock: `just captures-expiry` (the example `signature_expiry`) prints each capture's days to the end of
  its earliest RRSIG, `just recapture-signed` captures `testdata/recursion/` and `testdata/dnssec/` anew, and the
  check `each_capture_is_signed_at_its_time` (`dedens-testkit`) holds each capture signed at its own time. The feature
  `recursion` of `dedens-testkit` (on serde and serde-saphyr; the default build stays as D161 left it) reads them
  (`Resolution`) and replays them in memory (`Authorities`): by server address and question (name without case, type),
  the response over the transport asked when there is one, under the query's ID and question; anything else gets
  REFUSED, so a resolver under test that picks a server never asked moves on as from a lame one. YAML through serde
  adds no parser of outside data: no fuzz target. Rejected: a `dedens` flag (CLI surface for a test tool; `+trace`
  stays dig's, D40); the `.bin` files and `capture.yaml` of `testdata/dnssec/` (a resolution is an ordered list of
  exchanges, each needing its server and zone); a server per capture listening on loopback (the resolver's tests
  drive its I/O themselves; a socket front over `Authorities` can come with them).
- D201 (amends D183, D195; builds on D192, D197, D198) The recursive resolver is measured against Unbound by
  `just bench-compare recurse` and `recurse-dnssec` (`compare.sh`, `compare.py`, the files `compare/recurse-*`), on a
  mini Internet of our own, not the Internet (D183's rejection stands: its latency and its changes would be measured,
  not the servers):
  - Three Knot DNS processes in one container, each serving one zone on its own loopback address, port 53, so that
    none knows another's zone and a resolver finds a zone only by being referred: the root `.` on 127.0.0.2, `bench.`
    on 127.0.0.3 (`ns.nic.bench.` glued in the root's zone), `recurse.bench.` on 127.0.0.4 (`ns.recurse.bench.`
    glued in the TLD's), a wildcard `*` A and AAAA in the last. A miss of a cold cache walks root, TLD and zone as a
    name under a TLD does; the next ones ask the zone's server alone, one question each. `recurse-dnssec` signs the
    three (ECDSA P-256, NSEC3 without iterations, as D183), DS records in the parents from keys made first by `keymgr`,
    so every answer is a wildcard expansion with its NSEC3 proof, validated from the root's key-signing key.
  - The queries: a million unique names `u{i:06x}.recurse.bench A`, made by `compare.py` (its hash in
    `compare/corpora.sha256`), each server started cold and given each name once: no cache hit. TelltaleDNS's
    corpora hold names under public TLDs, which no zone of ours could answer.
  - The servers resolve from a root hints file naming `a.root.` (127.0.0.2): `root_hints` in `dedensd`'s `recurse`
    stage (new: a `named.root`-style file in place of the bundled root and TLD hints, D195), `root-hints` in
    Unbound. `dedensd` lets the resolver ask loopback authorities (`query_local_addresses`, one line of
    `compare/dedensd-recurse.yaml`); Unbound has `do-not-query-localhost: no`. The sysctl
    `net.ipv4.ip_unprivileged_port_start` must be 53 or less, which the run checks. The rest is D183's: same
    versions, a share of the machine each, lean and shipped configurations (one file each here), right answers first
    (the sample equal to the zone's Knot's, AD set for `recurse-dnssec`), void runs, a common rate, A/A. `dedensd-8mib`
    (caches at Unbound's sizes) is a server of these modes too, as in D183.
  - Not measured: TelltaleDNS (its `recursive://` upstream has the 13 root addresses built in, no setting to point it
    at ours) and CoreDNS (no recursion).
  - Also recorded: the questions each authority answers per client question over the check pass (Knot's `mod-stats`),
    and the server's CPU split in user and system time.
  - Criterion: `benches/resolution.rs` (one resolution step with the delegations cached, and from empty caches, on
    the capture `signed-com`); the scrubbing of a referral is `benches/scrub.rs` (D192).
  Rejected: real TLD names (the 1000 parents of TelltaleDNS's miss-heavy corpus under eight TLDs would need as many
  zones); one Knot with the three zones at one address, which answers from the closest zone whatever the server asked, so no referral is ever walked; the
  real root servers' addresses on loopback aliases (root rights, and `dedensd`'s bundled TLD hints would send it
  below the root); patching TelltaleDNS to read hints (a fork measured, not its tag).

- D203 (builds on D161, D162, D188; amended by D209) The authoritative server's test data is captured from Knot DNS 3.6.2 and NSD 4.15.4
  (images from `testdata/authoritative/Containerfile`, NSD built from its tarball by checksum; `just
  authoritative-images`) and from public servers, in `testdata/authoritative/` (README beside), by `just
  capture-authoritative [stages]`: the example `capture_authoritative` of `dedens-testkit`, read through its feature
  `authoritative` (`Answers`, `Recording`). No BIND, and no byte invented. The stage `signed` (`just
  capture-signed`, outside the defaults, for its keys are new each run) has Knot's `kzonesign` sign an RFC 5155
  Appendix A-like zone with an NSEC3 chain at a pinned time (D209).
  - Sources: AXFR of the root zone (ICANN, then root servers) and of `zonetransfer.me.` (a zone published for it), as
    text (`zones/`) and as the transfer's messages; the zones of `testdata/zones/` served by both servers, one
    server run per zone (three of them are `example.`), each answering a fixed list of questions (the README's
    rules) over UDP at 1232 and 512 bytes, without EDNS, and TCP, with and without DO, kept as bytes beside the
    other's; Knot behind a recording proxy for what a client sends and it answers or sends: AXFR and IXFR signed
    (hmac-sha256) and not, with a wrong secret, an unknown key, a clock 600 s off (BADSIG, BADKEY, BADTIME), UPDATE
    with each prerequisite form met and unmet, adds, deletes, refused ones, NOTIFY (at an NSD). The IXFR between two
    root serials is Knot loading the root zone of serial 2026111401 (the Wayback Machine's copy of
    `internic.net/domain/root.zone`, the root changing twice a day) and then the current one with `zonefile-load:
    difference`; both texts are kept. Knot refuses the ISI zone of RFC 1035 (MB and MG, obsolete) and both refuse the
    zone of every type: those get no reference answers.
  - Comparison rules, for the steps that check an answer against the captures: the RRsets of a section are compared
    as sets, TTLs exact, order within and across RRsets ignored; header flags and RCODE equal; OPT present or not as
    in the capture (the UDP payload size is the server's own); the additional section by the answer algorithm's
    own decision; a response truncated in either is compared on TC alone, and the other must fit the limit of the
    query. Any difference not listed below fails.
  - The differences between the two servers, and the answer `dedensd` gives (the RFCs leave most choices to the
    server): (1) NSD adds the apex NS RRset (with its RRSIG under DO) to the authority section of positive answers,
    and its addresses to the additional; Knot does not; RFC 1034 §4.3.2 asks for neither; `dedensd` follows Knot.
    (2) Additional addresses of NS and MX targets: Knot adds A and AAAA, NSD often the A alone, at 512 bytes each
    keeps a different one; `dedensd` adds both, with their RRSIGs under DO (RFC 3596 §3, RFC 4035 §3.1.1), the answer
    algorithm's decision says what is dropped. (3) `ANY`: each gives one RRset (RFC 8482 §4.1), Knot the one of the lowest type, NSD
    the SOA at the apex; `dedensd` follows Knot, a rule needing no choice among types. (4) `RRSIG`: Knot answers
    the signatures of that one RRset, NSD all the name's; RFC 8482 §7 leaves RRSIG queries unspecified; `dedensd`
    follows Knot, as for `ANY`. (5) NODATA at a wildcard's own name under NSEC3: NSD adds a covering NSEC3 to the
    matching one; RFC 5155 §7.2.3 asks for the match alone, which is Knot's and `dedensd`'s. (6) `NSEC` asked at a
    name a wildcard expands to: NSD adds the NSEC proving that name absent, Knot does not; RFC 4035 §3.1.3.3
    requires the proof in any wildcard answer, so `dedensd` follows NSD. (7) Over 512 bytes, which parts each drops
    before setting TC (RFC 2181 §9) differ; the answer algorithm's decision says. (8) Knot writes the names in NS
    RDATA uncompressed, so its responses are longer: the root's `. NS` with DO at 1232 bytes holds 22 addresses in
    Knot's 1 217 bytes and 26 in `dedensd`'s 1 097; where Knot's additional section has no room for one more
    address (16 bytes), it is compared as the first records of ours, in order (D209).
  - `dedens-proto` reads every capture except the UPDATE messages whose RDATA is empty (class ANY or NONE, RFC 2136
    §2.4, §2.5: an NS of it fails, other types read as invalid RDATA); the step of UPDATE parses them itself.
  - Rejected: BIND (not asked for; no image pinned); one Knot or NSD run for all zones (three are `example.`); the
    ISI zone with its types dropped (a zone edited by hand is no capture); waiting for a second root serial (hours,
    and the capture of the next day would differ).
