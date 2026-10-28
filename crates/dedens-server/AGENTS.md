# dedens-server

The server's query pipeline (D23, D41, D43). Sans-IO: `Pipeline::query` returns a reply, a drop, or an upstream
request the caller sends (`apps/dedensd`, with `dedens-net`). RFC behaviour is tested per RFC in
`tests/rfcNNNN.rs`, the stages in `tests/forward.rs` and `tests/cache.rs`; upstream answers are the captures of
`crates/dedens-proto/tests/testdata`.
