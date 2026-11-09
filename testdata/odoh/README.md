# ODoH test data

Read by `crates/dedens-odoh/tests/odoh.rs` (and, as seeds, by the fuzz smoke test).

| File | Source | Holds |
|---|---|---|
| `odohconfigs-cloudflare.bin` | `curl https://odoh.cloudflare-dns.com/.well-known/odohconfigs`, 2026-11-01 | One `ObliviousDoHConfigs` (RFC 9230 §5): version 1, X25519 / HKDF-SHA256 / AES-128-GCM, 46 bytes. Served with `cache-control: no-cache, no-store`, `odoh-server-version: 2026.4.0` |
| `odoh-go-test-vectors.json` | `test-vectors.json` of [cloudflare/odoh-go](https://github.com/cloudflare/odoh-go) at `f39fa019b017510690599e895c20cd02ae138742`, MIT, © 2019-2020 Cloudflare, Inc. and Apple, Inc. | One target (`odohconfigs`, the `public_key_seed` it derives from, its `key_id`) and 16 transactions: `query`, `response` (hex; random bytes, not DNS), their `*PaddingLength`, and the `obliviousQuery` and `obliviousResponse` that odoh-go produced |
| `odoh-go-query.bin`, `odoh-go-response.bin` | `obliviousQuery` and `obliviousResponse` of the first transaction of the vector, decoded from hex | Seeds of the fuzz targets, a valid query for the target of the vector and its response |

`public_key_seed` is the IKM of `DeriveKeyPair` (RFC 9180 §7.1.3): `TargetKey::derive` takes it and must give the
config of `odohconfigs`. An `obliviousResponse` carries the response nonce in its key ID field, so a target that
replays that nonce reproduces the response byte for byte (AES-GCM is deterministic).

The vectors hold no ephemeral key to replay, so the client side reads the `obliviousResponse`s through a
context made from the target's secrets (a unit test of `crates/dedens-odoh/src/client.rs`), and encrypts by round trips and the live
exchange recorded in `docs/decisions/transports.md` (D78).

RFC 9180's own vectors (Appendix A.1.1) are in `crates/dedens-odoh/tests/hpke.rs`.
