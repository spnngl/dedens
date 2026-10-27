set shell := ["bash", "-euo", "pipefail", "-c"]

# Nightly through `rustup which` and `rustup run`, not `cargo +nightly`: these also work when a cargo outside rustup
# (Homebrew) comes first in PATH.

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
