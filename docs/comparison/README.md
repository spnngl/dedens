# Comparisons

dedens set against other DNS servers, feature by feature, from their code.

- [`telltaledns.md`](telltaledns.md): [TelltaleDNS](https://github.com/paimonsoror/telltaledns), a Rust
  replacement for Pi-hole and Technitium: listeners, upstreams, cache, DNSSEC, recursion, filtering, local data,
  privacy, abuse limits, operations, packaging, tests, RFCs, and the gaps both ways.

Read on 2026-11-14:

| Server | Version | Commit |
|---|---|---|
| dedens | `main` after v0.1.0 | 4398fb36 |
| TelltaleDNS | v0.6.0, its last tag (2026-10-19) | 940f136 |

How:

- Each cell cites code: a path in the server's repository, and for dedens the decision (Dnn). A TelltaleDNS cell
  adds the requirement id of its `spec/01-requirements.md` and its priority (P0 to P2) when one asks for the feature.
- A requirement is not proof: each claim was read in their code and tests. "spec only" marks what only their spec
  has, "partial" says what is missing, "no" means neither code nor spec.
- RFC rows follow [`../rfc/coverage.md`](../rfc/coverage.md), which holds dedens's status per RFC.
- Features only. Throughput and latency against TelltaleDNS, Unbound and CoreDNS, measured by `just bench-compare`
  ([`compare.sh`](../../crates/dedens-bench/dnsperf/compare.sh), D183), are in
  [`../benchmarks.md`](../benchmarks.md), section "Against TelltaleDNS, Unbound and CoreDNS"; the JSON of each
  run in [`results/`](results/).
- A newer version of either side outdates the cells: read again, and change the table above.
