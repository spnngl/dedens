# alloc-probe

What each allocator candidate catches (`docs/alloc-security.md`). A cargo project of its own (`[workspace]` in its
`Cargo.toml`), outside `just check`: it needs `unsafe` (D15) to misuse the heap on purpose. Same crates and versions
as the root `Cargo.lock`, same features as `dedensd`'s `alloc-*`.

- `src/main.rs`: the cases, each run 20 times in a fresh child process; prints Markdown.
- `probe.sh [<build>]`: builds the probe as `just musl` builds `dedensd` (`rust:<channel>-alpine`, lld, the
  repository's `.cargo/config.toml`; glibc references in `rust:1.95`) and runs it in that container. `OUT` (under
  `$HOME` on a Mac) receives `<build>.md` and the `cargo build -vv` log `<build>.log`.
- `strace.sh`: files opened and threads started by each prebuilt `dedensd` (VPS, root for `sysctl`).
