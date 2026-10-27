set shell := ["bash", "-euo", "pipefail", "-c"]

# List recipes.
default:
    @just --list

# The gate of every change: format, lint, docs, tests.
check:
    RUSTFMT="$(rustup which --toolchain nightly rustfmt)" cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
    cargo test --workspace --all-features

# Format with nightly rustfmt (rustfmt.toml uses unstable options).
fmt:
    RUSTFMT="$(rustup which --toolchain nightly rustfmt)" cargo fmt --all

# Every feature combination of every crate builds (cargo-hack).
hack:
    cargo hack check --workspace --all-targets --feature-powerset

# The workspace builds with its `rust-version` (cargo-hack installs that toolchain).
msrv:
    cargo hack check --workspace --all-targets --rust-version

# The workspace builds with the lowest versions its manifests allow; Cargo.lock is restored afterwards.
minimal-versions:
    #!/usr/bin/env bash
    set -euo pipefail
    backup=$(mktemp)
    cp Cargo.lock "$backup"
    trap 'mv "$backup" Cargo.lock' EXIT
    rustup run nightly cargo update -Z direct-minimal-versions
    cargo check --workspace --all-targets --all-features

# Advisories, licenses, duplicate crates and sources (cargo-deny, deny.toml).
deny:
    cargo deny check

# Benchmarks (divan).
bench:
    cargo bench --workspace

# RAPx static analysis, outside the gate. RAPx builds on rustc internals: its version and its nightly move together,
# so bump both by hand.
rapx_version := "0.7.64"
rapx_toolchain := "nightly-2026-10-26"

# Install the pinned RAPx and its nightly. Needs Z3: `brew install z3` or `apt-get install libz3-dev`.
rapx-install:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v brew >/dev/null; then
        z3="$(brew --prefix z3)"
        export Z3_SYS_Z3_HEADER="$z3/include/z3.h" LIBRARY_PATH="$z3/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
    fi
    rustup toolchain install {{rapx_toolchain}} --profile minimal --component rustc-dev,rust-src,llvm-tools-preview
    RUSTC="$(rustup which --toolchain {{rapx_toolchain}} rustc)" \
        rustup run {{rapx_toolchain}} cargo install rapx --version {{rapx_version}} --locked

# RAPx: use-after-free, double free and leaks by default; `just rapx opt` for optimization hints.
# Own target dir: RAPx runs `cargo clean --workspace` before each analysis.
rapx *args="check -f -m":
    CARGO_TARGET_DIR=target/rapx RUSTC="$(rustup which --toolchain {{rapx_toolchain}} rustc)" rustup run {{rapx_toolchain}} cargo rapx {{args}}

# Download every RFC linked from docs/rfc/list.md into docs/rfc/archive/, as plain text from rfc-editor.org.
rfc-archive:
    mkdir -p docs/rfc/archive
    grep -oE "datatracker\.ietf\.org/doc/html/rfc[0-9]+" docs/rfc/list.md | grep -oE "[0-9]+$" | sort -un \
        | xargs -P 8 -I{} curl -fsSL --retry 3 -o docs/rfc/archive/rfc{}.txt https://www.rfc-editor.org/rfc/rfc{}.txt
