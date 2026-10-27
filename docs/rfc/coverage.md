# RFC coverage

Where each RFC of [`list.md`](list.md) is implemented and tested. An RFC absent from this table is not started.

Status: `planned` (in the current phases), `partial` (the sections listed are done), `done`.

| RFC | Subject | Status | Code | Tests |
|---|---|---|---|---|
| [1034](https://datatracker.ietf.org/doc/html/rfc1034) | Concepts and facilities | planned | | |
| [1035](https://datatracker.ietf.org/doc/html/rfc1035) | Wire format, presentation format, RDATA | partial: §2.3.4, §3.1, §3.2-3.4 (A NS CNAME SOA PTR MX TXT), §4.1.1-4.1.4 (decoding) | `crates/dedens-proto/src/{name,header,question,record}.rs`, `src/rdata/rfc1035_*.rs` | `crates/dedens-proto/tests/rfc1035.rs` |
| [1123](https://datatracker.ietf.org/doc/html/rfc1123) | Host names, TCP support (§6.1) | planned | | |
| [2181](https://datatracker.ietf.org/doc/html/rfc2181) | Clarifications: TTL, label length, truncation | partial: §8 TTL, §11 label contents | `crates/dedens-proto/src/record.rs` | `crates/dedens-proto/tests/rfc2181.rs` |
| [2782](https://datatracker.ietf.org/doc/html/rfc2782) | SRV | done | `crates/dedens-proto/src/rdata/rfc2782_srv.rs` | `crates/dedens-proto/tests/rfc2782.rs` |
| [3596](https://datatracker.ietf.org/doc/html/rfc3596) | AAAA | done | `crates/dedens-proto/src/rdata/rfc3596_aaaa.rs` | `crates/dedens-proto/tests/rfc3596.rs` |
| [3597](https://datatracker.ietf.org/doc/html/rfc3597) | Unknown RR types | done | `crates/dedens-proto/src/rdata/{mod,rfc3597_opaque}.rs` | `crates/dedens-proto/tests/rfc3597.rs` |
| [4343](https://datatracker.ietf.org/doc/html/rfc4343) | Case insensitivity | partial: §3 (names) | `crates/dedens-proto/src/name.rs` | `crates/dedens-proto/tests/rfc4343.rs` |
| [5452](https://datatracker.ietf.org/doc/html/rfc5452) | Resilience against forged answers | planned | | |
| [6891](https://datatracker.ietf.org/doc/html/rfc6891) | EDNS(0) | planned | | |
| [7766](https://datatracker.ietf.org/doc/html/rfc7766) | DNS over TCP | planned | | |
| [7873](https://datatracker.ietf.org/doc/html/rfc7873) | DNS cookies | planned | | |
| [8482](https://datatracker.ietf.org/doc/html/rfc8482) | Minimal responses to ANY | planned | | |
| [8659](https://datatracker.ietf.org/doc/html/rfc8659) | CAA | done | `crates/dedens-proto/src/rdata/rfc8659_caa.rs` | `crates/dedens-proto/tests/rfc8659.rs` |
| [8914](https://datatracker.ietf.org/doc/html/rfc8914) | Extended DNS errors | planned | | |
| [9460](https://datatracker.ietf.org/doc/html/rfc9460) | SVCB and HTTPS | partial: wire format, §7 keys 0-6, §8 (presentation format and client procedure not yet) | `crates/dedens-proto/src/rdata/rfc9460_svcb.rs` | `crates/dedens-proto/tests/rfc9460.rs` |
| [9619](https://datatracker.ietf.org/doc/html/rfc9619) | QDCOUNT is at most one | planned | | |
