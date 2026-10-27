# RFC coverage

Where each RFC of [`list.md`](list.md) is implemented and tested. An RFC absent from this table is not started.

Status: `planned` (in the current phases), `partial` (the sections listed are done), `done`.

| RFC | Subject | Status | Code | Tests |
|---|---|---|---|---|
| [1034](https://datatracker.ietf.org/doc/html/rfc1034) | Concepts and facilities | planned | | |
| [1035](https://datatracker.ietf.org/doc/html/rfc1035) | Wire format, presentation format, RDATA | partial: §2.3.4, §3.1, §3.2-3.4 (A NS CNAME SOA PTR MX TXT), §4.1.1-4.1.4 (decoding, compression when encoding) | `crates/dedens-proto/src/{name,header,question,record}.rs`, `src/rdata/rfc1035_*.rs` | `crates/dedens-proto/tests/rfc1035{,_compression}.rs` |
| [1123](https://datatracker.ietf.org/doc/html/rfc1123) | Host names, TCP support (§6.1) | planned | | |
| [2181](https://datatracker.ietf.org/doc/html/rfc2181) | Clarifications: TTL, label length, truncation | partial: §8 TTL, §9 truncation, §11 label contents | `crates/dedens-proto/src/record.rs` | `crates/dedens-proto/tests/rfc2181{,_truncation}.rs` |
| [2782](https://datatracker.ietf.org/doc/html/rfc2782) | SRV | done | `crates/dedens-proto/src/rdata/rfc2782_srv.rs` | `crates/dedens-proto/tests/rfc2782.rs` |
| [3596](https://datatracker.ietf.org/doc/html/rfc3596) | AAAA | done | `crates/dedens-proto/src/rdata/rfc3596_aaaa.rs` | `crates/dedens-proto/tests/rfc3596.rs` |
| [3597](https://datatracker.ietf.org/doc/html/rfc3597) | Unknown RR types | done | `crates/dedens-proto/src/rdata/{mod,rfc3597_opaque}.rs` | `crates/dedens-proto/tests/rfc3597.rs` |
| [4343](https://datatracker.ietf.org/doc/html/rfc4343) | Case insensitivity | partial: §3 (names) | `crates/dedens-proto/src/name.rs` | `crates/dedens-proto/tests/rfc4343.rs` |
| [5001](https://datatracker.ietf.org/doc/html/rfc5001) | NSID option | done | `crates/dedens-proto/src/edns/rfc5001_nsid.rs` | `crates/dedens-proto/tests/options.rs` |
| [5452](https://datatracker.ietf.org/doc/html/rfc5452) | Resilience against forged answers | planned | | |
| [6891](https://datatracker.ietf.org/doc/html/rfc6891) | EDNS(0) | partial: §6 OPT record, options, extended RCODE, §7 OPT kept when truncating (not yet: §6.2 requestor and responder behaviour) | `crates/dedens-proto/src/edns/mod.rs`, `crates/dedens-proto/src/message.rs` | `crates/dedens-proto/tests/rfc6891.rs`, `rfc2181_truncation.rs` |
| [7766](https://datatracker.ietf.org/doc/html/rfc7766) | DNS over TCP | planned | | |
| [7828](https://datatracker.ietf.org/doc/html/rfc7828) | edns-tcp-keepalive option | partial: §3 option format (not yet: connection management) | `crates/dedens-proto/src/edns/rfc7828_keepalive.rs` | `crates/dedens-proto/tests/options.rs` |
| [7830](https://datatracker.ietf.org/doc/html/rfc7830) | Padding option | partial: §3 option format (not yet: §4 padding policy) | `crates/dedens-proto/src/edns/rfc7830_padding.rs` | `crates/dedens-proto/tests/options.rs` |
| [7871](https://datatracker.ietf.org/doc/html/rfc7871) | Client subnet option | partial: §6 option format (not yet: §7 behaviour) | `crates/dedens-proto/src/edns/rfc7871_client_subnet.rs` | `crates/dedens-proto/tests/rfc7871.rs` |
| [7873](https://datatracker.ietf.org/doc/html/rfc7873) | DNS cookies | partial: §4 option format (not yet: §5 client and server behaviour) | `crates/dedens-proto/src/edns/rfc7873_cookie.rs` | `crates/dedens-proto/tests/rfc7873.rs` |
| [8482](https://datatracker.ietf.org/doc/html/rfc8482) | Minimal responses to ANY | planned | | |
| [8659](https://datatracker.ietf.org/doc/html/rfc8659) | CAA | done | `crates/dedens-proto/src/rdata/rfc8659_caa.rs` | `crates/dedens-proto/tests/rfc8659.rs` |
| [8914](https://datatracker.ietf.org/doc/html/rfc8914) | Extended DNS errors | done | `crates/dedens-proto/src/edns/rfc8914_ede.rs` | `crates/dedens-proto/tests/rfc8914.rs` |
| [9460](https://datatracker.ietf.org/doc/html/rfc9460) | SVCB and HTTPS | partial: wire format, §7 keys 0-6, §8 (presentation format and client procedure not yet) | `crates/dedens-proto/src/rdata/rfc9460_svcb.rs` | `crates/dedens-proto/tests/rfc9460.rs` |
| [9619](https://datatracker.ietf.org/doc/html/rfc9619) | QDCOUNT is at most one | partial: §4 decoding flags it (not yet: FORMERR in a server) | `crates/dedens-proto/src/message.rs` | `crates/dedens-proto/tests/message.rs` |
