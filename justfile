set shell := ["bash", "-euo", "pipefail", "-c"]

# The one pinned nightly: rustfmt (rustfmt.toml uses unstable options), `-Z` flags and RAPx. RAPx builds on rustc
# internals, so its version and this nightly move together: bump both by hand. Stable is pinned in
# rust-toolchain.toml.
nightly := "nightly-2026-10-26"
rapx_version := "0.7.64"

# List recipes.
default:
    @just --list

# Install the pinned stable (rust-toolchain.toml) and the pinned nightly's rustfmt.
toolchains:
    rustup toolchain install
    rustup toolchain install {{nightly}} --profile minimal --component rustfmt

# The gate of every change: format, spelling, lint, docs, tests.
check:
    RUSTFMT="$(rustup which --toolchain {{nightly}} rustfmt)" cargo fmt --all --check
    RUSTFMT="$(rustup which --toolchain {{nightly}} rustfmt)" cargo fmt --manifest-path fuzz/Cargo.toml --check
    taplo fmt --check
    typos
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
    cargo test --workspace --all-features
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path fuzz/Cargo.toml --lib

# Format Rust (pinned nightly rustfmt) and TOML.
fmt:
    RUSTFMT="$(rustup which --toolchain {{nightly}} rustfmt)" cargo fmt --all
    RUSTFMT="$(rustup which --toolchain {{nightly}} rustfmt)" cargo fmt --manifest-path fuzz/Cargo.toml
    taplo fmt

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
    rustup run {{nightly}} cargo update -Z direct-minimal-versions
    cargo check --workspace --all-targets --all-features

# Advisories, licenses, duplicate crates and sources (cargo-deny, deny.toml).
deny:
    cargo deny check

# Benchmarks (divan).
bench:
    cargo bench --workspace

# Line and region coverage of the tests (cargo-llvm-cov): a summary, not a gate.
cov:
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned stable's own cargo and rustc first: the llvm-tools component belongs to that toolchain.
    export PATH="$(dirname "$(rustup which rustc)"):$PATH"
    cargo llvm-cov --workspace --all-features --summary-only

# Fuzz one target with libFuzzer (pinned nightly, cargo-fuzz), starting from the captured responses, for five
# minutes by default: just fuzz decode_message 60
fuzz target="decode_message" seconds="300":
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned nightly's own cargo and rustc first: cargo-fuzz needs `-Z` flags, and rustup proxies would pick
    # the stable of rust-toolchain.toml.
    export PATH="$(dirname "$(rustup which --toolchain {{nightly}} rustc)"):$PATH"
    cd fuzz
    # The first corpus directory is the one libFuzzer writes to; the captured responses only seed it.
    cargo fuzz run {{target}} "corpus/{{target}}" ../crates/dedens-proto/tests/testdata -- -max_total_time={{seconds}}

# Every fuzz target for `seconds` each, as the scheduled CI job runs them.
fuzz-all seconds="60":
    #!/usr/bin/env bash
    set -euo pipefail
    export PATH="$(dirname "$(rustup which --toolchain {{nightly}} rustc)"):$PATH"
    cd fuzz
    for target in $(cargo fuzz list); do
        cargo fuzz run "$target" "corpus/$target" ../crates/dedens-proto/tests/testdata -- -max_total_time={{seconds}}
    done

# Replay the captured responses plus truncated and bit-flipped variants on stable (part of `just check`).
fuzz-smoke:
    cargo test --manifest-path fuzz/Cargo.toml --lib

# Capture fresh responses from public resolvers into crates/dedens-proto/tests/testdata/.
capture *cases:
    python3 scripts/capture.py {{cases}}

# Install the pinned RAPx and the nightly's rustc internals. Needs Z3: `brew install z3` or
# `apt-get install libz3-dev`.
rapx-install:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v brew >/dev/null; then
        z3="$(brew --prefix z3)"
        export Z3_SYS_Z3_HEADER="$z3/include/z3.h" LIBRARY_PATH="$z3/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
    fi
    rustup toolchain install {{nightly}} --profile minimal --component rustc-dev,rust-src,llvm-tools-preview
    RUSTC="$(rustup which --toolchain {{nightly}} rustc)" \
        rustup run {{nightly}} cargo install rapx --version {{rapx_version}} --locked

# RAPx static analysis, outside the gate: use-after-free, double free and leaks by default; `just rapx opt` for
# optimization hints. Own target dir: RAPx runs `cargo clean --workspace` before each analysis.
rapx *args="check -f -m":
    CARGO_TARGET_DIR=target/rapx RUSTC="$(rustup which --toolchain {{nightly}} rustc)" rustup run {{nightly}} cargo rapx {{args}}

# Download every RFC linked from docs/rfc/list.md into docs/rfc/archive/, as plain text from rfc-editor.org.
rfc-archive:
    mkdir -p docs/rfc/archive
    grep -oE "datatracker\.ietf\.org/doc/html/rfc[0-9]+" docs/rfc/list.md | grep -oE "[0-9]+$" | sort -un \
        | xargs -P 8 -I{} curl -fsSL --retry 3 -o docs/rfc/archive/rfc{}.txt https://www.rfc-editor.org/rfc/rfc{}.txt
