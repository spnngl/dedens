# dedens-server

The server's query pipeline (D23, D41, D43). Sans-IO: `Pipeline::query` returns a `Step`: a reply, a drop, a
reply then a refresh, or an upstream request the caller sends (`apps/dedensd`, with `dedens-net`). Plugin stages
(D54) implement `Plugin`. The stages are tested in `tests/forward.rs`, `tests/cache.rs` and `tests/plugin.rs`;
upstream answers are the captures of `crates/dedens-proto/tests/testdata`.
