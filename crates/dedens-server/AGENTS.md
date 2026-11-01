# dedens-server

The server's query pipeline (D23, D41, D43). Sans-IO: `Pipeline::query` returns a `Step`: a reply, a drop, a
reply then a refresh, or an upstream request the caller sends (`apps/dedensd`, with `dedens-net`). Plugin stages
(D54) implement `Plugin`. The stages are tested in `tests/forward.rs`, `tests/cache.rs` and `tests/plugin.rs`;
upstream answers are the captures of `crates/dedens-proto/tests/testdata`.

A forward stage may validate (D77, `src/validate.rs`): the pipeline turns each question of a
`dedens_dnssec::Validation` into a `Step::Upstream`, so `apps/dedensd` needs no change per question. Only `Secure`
sets AD, and the upstream's AD is never read. Its tests, `tests/rfc4035.rs` and `tests/rfc6840.rs`, answer from the
captures of `crates/dedens-dnssec/tests/testdata` at their `captured_at`. Feature `metrics` (D30): the validation
counters, `src/metrics.rs`.
