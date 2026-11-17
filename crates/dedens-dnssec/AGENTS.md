# dedens-dnssec

DNSSEC validation, sans-IO (D69): the caller owns the clock, the questions and the sockets. `src/lib.rs` maps the
modules and holds the validator's guide. Cryptography is `ring` alone (D71); `cms` and `x509-cert` only parse
(D127).

- Verus proves `covers` in `src/denial/names.rs` for chains of any length (D180), through `#[cfg(verus_only)]`
  spec and proof functions that only `just verus` checks: a change to `covers` or to them runs `just verus`.
- `src/icannbundle.pem` is a trust root (D127): `just roots` never writes it, and stops when IANA's copy
  differs. `root.ds`, the captured pair in `testdata/dnssec/` and `root-anchors.captured_at` change together, by
  that recipe; `tests/signed_anchors.rs` names their key tags and dates.
- The feature `fetch-anchors` gates `src/anchor/{xml,signature}.rs`: `just check` builds with all features, so
  `just hack` is what shows the crate still builds without it.
