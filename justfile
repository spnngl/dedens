set shell := ["bash", "-euo", "pipefail", "-c"]

# The one pinned nightly: rustfmt (rustfmt.toml uses unstable options), `-Z` flags and RAPx. RAPx builds on rustc
# internals, so its version and this nightly move together: bump both by hand. Stable is pinned in
# rust-toolchain.toml.
nightly := "nightly-2026-10-26"
# A commit of RAPx's main: its fix for async closures (safer-rust/RAPx#319) is in no release yet (0.7.65 predates it).
# Back to a crates.io version once one has it.
rapx_rev := "8d9d0a2f0389f48891b9e8bd3321a70a932e2e90"
# renovate: datasource=github-tags depName=NLnetLabs/unbound extractVersion=^release-(?<version>.*)$
unbound_version := "1.26.2"

# List recipes.
default:
    @just --list

# Install the pinned stable (rust-toolchain.toml) and the pinned nightly's rustfmt.
toolchains:
    rustup toolchain install
    rustup toolchain install {{nightly}} --profile minimal --component rustfmt

# The gate of every change: format, spelling, lint, docs, tests.
check: (rustfmt "--check")
    taplo fmt --check
    typos
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
    cargo test --workspace --all-features
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
    cargo test --manifest-path fuzz/Cargo.toml --lib

# Format Rust (pinned nightly rustfmt) and TOML.
fmt: rustfmt
    taplo fmt

# `cargo fmt` of the workspace and fuzz/ with the pinned nightly's rustfmt.
[private]
rustfmt *args:
    #!/usr/bin/env bash
    set -euo pipefail
    rustfmt="$(rustup which --toolchain {{nightly}} rustfmt)"
    RUSTFMT="$rustfmt" cargo fmt --all {{args}}
    RUSTFMT="$rustfmt" cargo fmt --manifest-path fuzz/Cargo.toml {{args}}

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
    cargo deny --manifest-path fuzz/Cargo.toml check

# Benchmarks against other DNS libraries (D14): Rust ones with divan, then Go's miekg/dns, the codec of
# CoreDNS, when Go is installed. Unbound: `just bench-unbound`.
bench:
    cargo bench --workspace
    if command -v go >/dev/null; then cd crates/dedens-bench/go && go test -run '^$' -bench . -benchmem; fi

# Unbound's C codec on the inputs of `just bench` (D14). Builds the pinned release once in target/unbound: needs
# a C compiler, make, bison, flex and the OpenSSL and expat headers.
bench-unbound:
    #!/usr/bin/env bash
    set -euo pipefail
    out="$(pwd)/target/unbound"
    src="$out/release-{{unbound_version}}"
    if [ ! -f "$src/.libs/libunbound.a" ]; then
        rm -rf "$src"
        git clone --quiet --depth 1 --branch "release-{{unbound_version}}" https://github.com/NLnetLabs/unbound.git "$src"
        flags=(--disable-flto)
        if command -v brew >/dev/null; then flags+=("--with-ssl=$(brew --prefix openssl@3)"); fi
        if [ "$(uname)" = Darwin ]; then flags+=("--with-libexpat=$(xcrun --show-sdk-path)/usr"); fi
        (cd "$src" && ./configure "${flags[@]}" >/dev/null && make -j"$(getconf _NPROCESSORS_ONLN)" libunbound.la >/dev/null)
    fi
    # The libraries libunbound links, without libtool's -R run paths.
    libs=$(sed -n "s/^dependency_libs='\(.*\)'$/\1/p" "$src/libunbound.la" | sed 's/-R[^ ]*//g')
    cc -O2 -I"$src" -DBENCH_DIR="\"$(pwd)/crates/dedens-bench\"" crates/dedens-bench/unbound/bench.c \
        "$src/.libs/libunbound.a" $libs -o "$out/bench"
    cargo run --quiet --release -p dedens-bench --example zone > "$out/zone.txt"
    "$out/bench" "$out/zone.txt"

# dedensd under dnsperf on Linux (io_uring) in a container, the working tree against `base`, in `mode`: udp or tcp
# from the cache, forward or forward-tcp to a second dedensd without one: just bench-dnsperf HEAD~1 tcp
bench-dnsperf base="HEAD" mode="udp":
    docker run --rm --security-opt seccomp=unconfined -v "$(pwd):/src:ro" -v dedens-dnsperf-cargo:/usr/local/cargo/registry \
        -v dedens-dnsperf-target:/target rust:1 bash /src/crates/dedens-bench/dnsperf/run.sh {{base}} {{mode}}

# Line and region coverage of the tests (cargo-llvm-cov): a summary, not a gate.
cov:
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned stable's own cargo and rustc first: the llvm-tools component belongs to that toolchain.
    rustc="$(rustup which rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    cargo llvm-cov --workspace --all-features --summary-only

# Fuzz one target with libFuzzer (pinned nightly, cargo-fuzz), starting from the captured responses, for five
# minutes by default: just fuzz decode_message 60
fuzz target="decode_message" seconds="300":
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned nightly's own cargo and rustc first: cargo-fuzz needs `-Z` flags, and rustup proxies would pick
    # the stable of rust-toolchain.toml.
    rustc="$(rustup which --toolchain {{nightly}} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    cd fuzz
    # The first corpus directory is the one libFuzzer writes to; the captured responses and zone files only seed it.
    mkdir -p "corpus/{{target}}"
    # A target with a token dictionary in dicts/ gets it.
    dict=""
    if [[ -f "dicts/{{target}}.dict" ]]; then dict="-dict=dicts/{{target}}.dict"; fi
    cargo fuzz run {{target}} "corpus/{{target}}" ../crates/dedens-proto/tests/testdata ../crates/dedens-proto/tests/zones ../crates/dedens-dnssec/tests/testdata -- -max_total_time={{seconds}} $dict

# Every fuzz target for `seconds` each, as the scheduled CI job runs them.
fuzz-all seconds="60":
    #!/usr/bin/env bash
    set -euo pipefail
    rustc="$(rustup which --toolchain {{nightly}} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    cd fuzz
    for target in $(cargo fuzz list); do
        mkdir -p "corpus/$target"
        dict=""
        if [[ -f "dicts/$target.dict" ]]; then dict="-dict=dicts/$target.dict"; fi
        cargo fuzz run "$target" "corpus/$target" ../crates/dedens-proto/tests/testdata ../crates/dedens-proto/tests/zones ../crates/dedens-dnssec/tests/testdata -- -max_total_time={{seconds}} $dict
    done

# Replay the captured responses plus truncated and bit-flipped variants on stable (part of `just check`).
fuzz-smoke:
    cargo test --manifest-path fuzz/Cargo.toml --lib

# Capture fresh responses from public servers into the directory `dir`: the queries of its capture.yaml, or
# those with the ids given.
[private]
capture-to dir *ids:
    cargo run -p dedens -- -f {{dir}}/capture.yaml --save-wire {{dir}} {{ prepend("--only=", ids) }}

# Capture fresh responses into crates/dedens-proto/tests/testdata/: the queries of its capture.yaml, or those
# with the ids given.
capture *ids: (capture-to "crates/dedens-proto/tests/testdata" ids)

# Capture the DNSSEC set of crates/dedens-dnssec/tests/testdata/ anew: every query of its capture.yaml, and
# `captured_at`, the Unix time of the run's end (signatures made on demand start at the time of the query). The
# directory is replaced only when every query succeeded: new bytes, same coverage.
capture-dnssec:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=crates/dedens-dnssec/tests/testdata
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    cp "$dir/capture.yaml" "$tmp/"
    {{just_executable()}} capture-to "$tmp"
    date +%s > "$tmp/captured_at"
    rm -f "$dir"/*.bin
    cp "$tmp"/*.bin "$tmp/captured_at" "$dir/"

# Ask every public resolver of docs/providers/providers.yaml over the network, IPv4 and IPv6 (D67).
providers:
    cargo test -p dedens --test providers -- --ignored --nocapture

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
    rustc="$(rustup which --toolchain {{nightly}} rustc)"
    RUSTC="$rustc" rustup run {{nightly}} cargo install --git https://github.com/safer-rust/RAPx --rev {{rapx_rev}} rapx --locked

# RAPx static analysis, outside the gate: use-after-free, double free and leaks by default; `just rapx opt` for
# optimization hints. Own target dir: RAPx runs `cargo clean --workspace` before each analysis.
rapx *args="check -f -m":
    #!/usr/bin/env bash
    set -euo pipefail
    # The nightly's own cargo first in PATH: RAPx calls `cargo`, which `rustup run` leaves to a Homebrew cargo
    # ahead in PATH, and the dependencies it builds don't load in RAPx's rustc.
    rustc="$(rustup which --toolchain {{nightly}} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    CARGO_TARGET_DIR=target/rapx RUSTC="$rustc" rustup run {{nightly}} cargo rapx {{args}}

# Download every RFC linked from docs/rfc/list.md into docs/rfc/archive/, as plain text from rfc-editor.org.
rfc-archive:
    mkdir -p docs/rfc/archive
    grep -oE "datatracker\.ietf\.org/doc/html/rfc[0-9]+" docs/rfc/list.md | grep -oE "[0-9]+$" | sort -un \
        | xargs -P 8 -I{} curl -fsSL --retry 3 -o docs/rfc/archive/rfc{}.txt https://www.rfc-editor.org/rfc/rfc{}.txt

# Refresh IANA's root hints, bundled for `dedens +trace`.
root-hints:
    curl -fsSL --retry 3 -o apps/dedens/src/named.root https://www.internic.net/domain/named.root
