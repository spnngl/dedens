# dedens-odoh

Oblivious DNS over HTTPS (RFC 9230), experimental (D69): behind the `odoh` feature of the crates that use it.
Sans-IO: configurations and message encryption; the HTTP exchange lives in `dedens-net`. Decisions: D78.

| File | Holds |
|---|---|
| `src/config.rs` | `ObliviousDoHConfigs` and `ObliviousDoHConfigContents` (§5), the key ID (§6.1) |
| `src/message.rs` | `ObliviousDoHMessage`, `ObliviousDoHMessagePlaintext` (§6.1), padding helpers (§11) |
| `src/client.rs`, `src/target.rs` | `encrypt_query`, `decrypt_response` (§7); `TargetKey`, `decrypt_query`, `encrypt_response` (§8) |
| `src/exchange.rs`, `src/kdf.rs` | the response keys of §6.2 `derive_secrets`, on `ring` |
| `tests/testdata/` | the Cloudflare config and the odoh-go vectors; its `README.md` gives their sources |

HPKE comes from the `hpke` crate; `suite` names its types so that tests run RFC 9180's vectors through them.
