# dedens-dnssec

DNSSEC validation, sans-IO (D69): the caller owns the clock, the questions and the sockets. `src/lib.rs` maps the
modules and holds the validator's guide. Cryptography is `ring` alone (D71).
