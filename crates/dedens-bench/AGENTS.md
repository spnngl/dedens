# dedens-bench

Benches of the workspace against hickory-proto, `domain` (divan, `benches/`) and Go's `miekg/dns` (`go/`, run by
`just bench` when Go is installed), on the captured responses (D14). A regular crate so `cargo deny` checks the
baselines. Record new numbers in `docs/benchmarks.md`.
