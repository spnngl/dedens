# dedens-bench

Benches of the workspace against hickory-proto, `domain`, Go's `miekg/dns` and Unbound's C codec (D14), and
`dedensd` under dnsperf: the justfile's `bench*` and `profile` recipes and the headers of `dnsperf/run.sh` say how to
run each. A regular crate so that `cargo deny` checks the baselines.

The allocator experiment (D152) is not in the tree: check out the tag `alloc-experiment-2026-11-06` for `dnsperf/alloc.sh`,
`dnsperf/alloc-vps/` and the `alloc-*` features, and `alloc-security-2026-11-06` for `alloc-probe/`; each has its AGENTS.md.
