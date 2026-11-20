# dedens-bench

Benches of the workspace against hickory-proto, `domain`, Go's `miekg/dns` and Unbound's C codec (D14), and
`dedensd` under dnsperf: the justfile's `bench*` and `profile` recipes and the headers of `dnsperf/run.sh` say how to
run each. A regular crate so that `cargo deny` checks the baselines.

The noise between sessions reaches ±30%: compare a base and a tree in one session, rounds alternating, from executables
copied out of `cargo bench --no-run`. `dedensd`'s numbers that decisions quote come from Linux (`io_uring`, a thread
per core), as macOS runs `poll` on one thread.

A divan bench with `threads` calls `bench`, `bench_refs` or `bench_values`: the `bench_local` ones run one thread
whatever `threads` says, which the `serve_` benches of `benches/dnssec.rs` did until 2026-11-20.

`dnsperf/compare.sh` (`just bench-compare`) measures dedensd against TelltaleDNS, Unbound and CoreDNS
(`docs/comparison/`). Its traps:

- Every server must answer each question as the others do, or the run fails: a new name in `compare.py` belongs
  under a public TLD of `compare/root.zone`'s wildcard, as Unbound answers `test.` and the other RFC 6761 names itself.
- `compare/corpora.sha256` holds the hashes of TelltaleDNS's `bench/corpus.py` output at the pinned tag: raising
  `telltale_version` may change them, and then they are regenerated with that `corpus.py`, never edited by hand.
- TelltaleDNS sets AD only when DO is set, so the DNSSEC sample asks with both.
- Rootless podman without a delegated `cpuset` controller pins with `taskset` inside each container instead; the
  JSON's `pinning` says which.
- The engines' default seccomp filters refuse `io_uring`, and dedensd then serves on `poll` and only logs it
  (D107): every container runs with `seccomp=unconfined`, and a dedensd not on `io_uring` fails the run. The first
  session of step 02 measured `poll` for it unawares.

The `recurse` modes (D201) differ from the others:

- No forwarding: three Knot processes in one container serve a root, a TLD and a signed zone with a wildcard on
  127.0.0.2-4, port 53, so the host's `net.ipv4.ip_unprivileged_port_start` must be 53 or less (the run says so
  and stops; restore it after). The names come from `compare.py`, not TelltaleDNS (`recurse-unique.txt`'s hash in
  `corpora.sha256`); a corpus of names under other zones would find no authority.
- The servers start from `compare/recurse-root.hints`. dedensd's `root_hints` and its commented
  `query_local_addresses` line are in `compare/dedensd-recurse.yaml`: the resolver refuses private addresses
  unless that line is on, and the authorities are loopback ones.
- Only servers with a `recursion` template in `SERVERS` run them: CoreDNS does not recurse, and TelltaleDNS's
  `recursive://` upstream has its 13 root addresses built in (`telltale-recursor`, no setting), so it cannot start
  from a root of ours.
- A DNSSEC run signs the three zones fresh (`keymgr` in the Knot image), DS records and all, and the validators'
  anchor is the root's key-signing key.

The allocator experiment (D152) is not in the tree: check out the tag `alloc-experiment-2026-11-06` for `dnsperf/alloc.sh`,
`dnsperf/alloc-vps/` and the `alloc-*` features, and `alloc-security-2026-11-06` for `alloc-probe/`; each has its AGENTS.md.
