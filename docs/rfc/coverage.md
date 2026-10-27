# RFC coverage

Where each RFC of [`list.md`](list.md) is implemented and tested. An RFC absent from this table is not started.

Status: `planned` (in the current phases), `partial` (the sections listed are done), `done`.

| RFC | Subject | Status | Code | Tests |
|---|---|---|---|---|
| [1034](https://datatracker.ietf.org/doc/html/rfc1034) | Concepts and facilities | planned | | |
| [1035](https://datatracker.ietf.org/doc/html/rfc1035) | Wire format, presentation format, RDATA | partial: §2.3.4, §3.1, §4.1.1, §4.1.2, §4.1.4 (decoding) | `crates/dedens-proto/src/{name,header,question}.rs` | `crates/dedens-proto/tests/rfc1035.rs` |
| [1123](https://datatracker.ietf.org/doc/html/rfc1123) | Host names, TCP support (§6.1) | planned | | |
| [2181](https://datatracker.ietf.org/doc/html/rfc2181) | Clarifications: TTL, label length, truncation | planned | | |
| [2782](https://datatracker.ietf.org/doc/html/rfc2782) | SRV | planned | | |
| [3596](https://datatracker.ietf.org/doc/html/rfc3596) | AAAA | planned | | |
| [3597](https://datatracker.ietf.org/doc/html/rfc3597) | Unknown RR types | planned | | |
| [4343](https://datatracker.ietf.org/doc/html/rfc4343) | Case insensitivity | partial: §3 (names) | `crates/dedens-proto/src/name.rs` | `crates/dedens-proto/tests/rfc4343.rs` |
| [5452](https://datatracker.ietf.org/doc/html/rfc5452) | Resilience against forged answers | planned | | |
| [6891](https://datatracker.ietf.org/doc/html/rfc6891) | EDNS(0) | planned | | |
| [7766](https://datatracker.ietf.org/doc/html/rfc7766) | DNS over TCP | planned | | |
| [7873](https://datatracker.ietf.org/doc/html/rfc7873) | DNS cookies | planned | | |
| [8482](https://datatracker.ietf.org/doc/html/rfc8482) | Minimal responses to ANY | planned | | |
| [8659](https://datatracker.ietf.org/doc/html/rfc8659) | CAA | planned | | |
| [8914](https://datatracker.ietf.org/doc/html/rfc8914) | Extended DNS errors | planned | | |
| [9460](https://datatracker.ietf.org/doc/html/rfc9460) | SVCB and HTTPS | planned | | |
| [9619](https://datatracker.ietf.org/doc/html/rfc9619) | QDCOUNT is at most one | planned | | |
