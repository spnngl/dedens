# dedens-repo

The repository checks (D140, D163), in the gate through `cargo test --workspace`: `tests/repo.rs` reads the tracked
files (`git ls-files`) and checks decision numbers cited and defined once, their amendments named both ways,
coverage paths and rows, `CLAUDE.md` links, a crate's `clippy.toml` repeating the root one and the `Containerfile`'s
Rust tag. A check is a function of text, run once on a small broken input beside the tree's. `std` only.
