# dedens-bench

Benches of the workspace against hickory-proto, `domain` (divan, `benches/`), Go's `miekg/dns` (`go/`, run by
`just bench` when Go is installed) and Unbound's C codec (`unbound/bench.c`, `just bench-unbound`), on the
captured responses and the generated zone (D14). `dnsperf/run.sh` (`just bench-dnsperf`) loads `dedensd` in a
Linux container (`DEDENS_CONTAINER=podman` for Podman; `DEDENS_BACK_CPU` and `DEDENS_LOAD_CPUS` pick the cores on a
host with fewer than eight; `DEDENS_ROUNDS` the rounds, of base and tree alternating), the working tree against a
git ref, in a mode (`udp`, `tcp`, `forward`, `forward-tcp`, `two-sockets`; see the justfile). A regular crate so
`cargo deny` checks the baselines. `examples/zone.rs` writes the zone for the benches outside Rust.
`examples/hit_ratio.rs` replays Zipf draws or a trace (`--trace`) through the cache's eviction (D116). Record new
numbers in `docs/benchmarks.md`.
