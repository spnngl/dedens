# dedens-server

The server's query pipeline (D23, D41). Sans-IO: `Pipeline::query` returns a reply, a drop, or an upstream
request the caller sends (`apps/dedensd`, with `dedens-net`). RFC behaviour is tested per RFC in
`tests/rfcNNNN.rs`, the forward stage in `tests/forward.rs`; upstream answers are the captures of
`crates/dedens-proto/tests/testdata`.
