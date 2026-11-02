# fuzz

libFuzzer targets, in their own workspace. Each target is a function of `src/lib.rs` or of a module it re-exports
(`src/coap_doc.rs`, `src/link_format.rs`), listed in `TARGETS`, with a one-line shim in `fuzz_targets/` and a `[[bin]]`
in `Cargo.toml`. `src/smoke.rs` replays the captured responses and their mutations on stable inside `just check`;
`just fuzz <target> <seconds>` runs libFuzzer on the pinned nightly. Dictionaries: `dicts/<target>.dict`.
