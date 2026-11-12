# fuzz

libFuzzer targets, in their own workspace; `src/lib.rs` says how they run. A new target is a function in the module
of `src/` named after the crate it tests (`dedens` is `cli`, `dedensd` is `daemon`: a module of a crate's name
would shadow it), re-exported by `src/lib.rs` and listed in its `TARGETS`, with a one-line
shim in `fuzz_targets/` and a `[[bin]]` in `Cargo.toml`; a token dictionary, if any, at `dicts/<target>.dict`.
`just fuzz <target> <seconds>` runs it on the pinned nightly. The seeds of every target are the directories of the
justfile's `fuzz_seeds` and the files its `fuzz-seeds` writes from `seeds/` and elsewhere; `seeds()` in
`src/smoke.rs` reads the same: a new seed goes in both.
