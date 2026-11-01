# dedens-bench

Benches of the workspace against hickory-proto, `domain` (divan, `benches/`), Go's `miekg/dns` (`go/`, run by
`just bench` when Go is installed) and Unbound's C codec (`unbound/bench.c`, `just bench-unbound`), on the
captured responses and the generated zone (D14). `dnsperf/run.sh` (`just bench-dnsperf`) loads `dedensd` in a
Linux container, the working tree against a git ref, in a mode (`udp`, `tcp`, `forward`, `forward-tcp`, `two-sockets`; see the
justfile). A regular crate so `cargo deny` checks the baselines. `examples/zone.rs` writes the zone for the
benches outside Rust. Record new numbers in `docs/benchmarks.md`.
