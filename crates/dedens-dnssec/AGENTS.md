# dedens-dnssec

DNSSEC validation, sans-IO (D69): the caller owns the clock, the questions and the sockets. `src/lib.rs` maps the
modules and holds the validator's guide. Cryptography is `ring` alone (D71).

- Verus proves `covers` in `src/denial/names.rs` for chains of any length (D180), through `#[cfg(verus_only)]`
  spec and proof functions that only `just verus` checks: a change to `covers` or to them runs `just verus`.
