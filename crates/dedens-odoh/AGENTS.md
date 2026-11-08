# dedens-odoh

Oblivious DNS over HTTPS (RFC 9230), experimental (D69): behind the `odoh` feature of the crates that use it.
Sans-IO: configurations and message encryption; the HTTP exchange lives in `dedens-net`. Decisions: D78.

| File | Holds |
|---|---|
| `src/config.rs` | `Configs` and `ConfigContents` (§5), the key ID (§6.1) |
| `src/message.rs` | `Message`, `MessagePlaintext` (§6.1), padding helpers (§11) |
| `src/client.rs`, `src/target.rs` | `encrypt_query`, `decrypt_response` (§7); `TargetKey`, `decrypt_query`, `encrypt_response` (§8) |
| `src/exchange.rs`, `src/kdf.rs` | `Secrets`: the response key and nonce of §6.2 (`derive_secrets`, as `Secrets::derive`), `seal`, `open`, `aad`; HKDF on `ring` |
| `src/wire.rs`, `src/error.rs` | the TLS-style reader and writer (RFC 8446 §3); `WireError`, `ExchangeError` |
| `tests/rfc9180.rs`, `tests/rfc9230.rs` | the HPKE vectors through `suite`; the RFC 9230 vectors (`testdata/odoh/`) and the round trips |

HPKE comes from the `hpke` crate; `suite` names its types so that tests run RFC 9180's vectors through them.
