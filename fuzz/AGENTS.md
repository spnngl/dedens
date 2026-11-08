# fuzz

libFuzzer targets, in their own workspace; `src/lib.rs` says how they run. A new target is a function in the module
of `src/` named after the crate it tests, re-exported by `src/lib.rs` and listed in its `TARGETS`, with a one-line
shim in `fuzz_targets/` and a `[[bin]]` in `Cargo.toml`; a token dictionary, if any, at `dicts/<target>.dict`.
`just fuzz <target> <seconds>` runs it on the pinned nightly.
