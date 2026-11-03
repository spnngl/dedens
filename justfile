set shell := ["bash", "-euo", "pipefail", "-c"]

# The one pinned nightly: rustfmt (rustfmt.toml uses unstable options), `-Z` flags and RAPx. RAPx builds on rustc
# internals, so its version and this nightly move together: bump both by hand. Stable is pinned in
# rust-toolchain.toml.
nightly := "nightly-2026-10-26"
# A commit of RAPx's main: its fix for async closures (safer-rust/RAPx#319) is in no release yet (0.7.65 predates it).
# Back to a crates.io version once one has it.
rapx_rev := "8d9d0a2f0389f48891b9e8bd3321a70a932e2e90"
# Kani brings a nightly and CBMC of its own (`just kani-install`).
# renovate: datasource=crate depName=kani-verifier
kani_version := "0.68.0"
# renovate: datasource=github-tags depName=NLnetLabs/unbound extractVersion=^release-(?<version>.*)$
unbound_version := "1.26.2"
# The container engine of `bench-dnsperf`: `DEDENS_CONTAINER=podman just bench-dnsperf`.
# `DEDENS_ROUNDS=5` sets its rounds.
container := env("DEDENS_CONTAINER", "docker")

# List recipes.
default:
    @just --list

# Install the pinned stable (rust-toolchain.toml) and the pinned nightly's rustfmt and standard library sources
# (`just careful`).
toolchains:
    rustup toolchain install
    rustup toolchain install {{ nightly }} --profile minimal --component rustfmt,rust-src

# The gate of every change: format, spelling, unused dependencies, lint, docs, tests.
check: (rustfmt "--check")
    taplo fmt --check
    typos
    cargo shear --locked --deny-warnings
    cargo shear --locked --deny-warnings fuzz
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
    rustfmt="$(rustup which --toolchain {{ nightly }} rustfmt)"
    RUSTFMT="$rustfmt" cargo fmt --all {{ args }}
    RUSTFMT="$rustfmt" cargo fmt --manifest-path fuzz/Cargo.toml {{ args }}

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
    rustup run {{ nightly }} cargo update -Z direct-minimal-versions
    cargo check --workspace --all-targets --all-features

# Advisories, licenses, duplicate crates and sources (cargo-deny, deny.toml), or the checks named: just deny advisories
deny *checks:
    cargo deny check {{ checks }}
    cargo deny --manifest-path fuzz/Cargo.toml check {{ checks }}

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
    src="$out/release-{{ unbound_version }}"
    if [ ! -f "$src/.libs/libunbound.a" ]; then
        rm -rf "$src"
        git clone --quiet --depth 1 --branch "release-{{ unbound_version }}" https://github.com/NLnetLabs/unbound.git "$src"
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
# from the cache, forward or forward-tcp to a second dedensd without one, or two-sockets (the latency of a UDP port
# beside a flooded one): just bench-dnsperf HEAD~1 tcp. `DEDENS_PERF=1` profiles the working tree's server instead
# (D138), under perf: its report lands in target/profile/<mode>.txt; kernel names need `kernel.perf_event_paranoid` 1 and `kernel.kptr_restrict` 0 (run.sh).
bench-dnsperf base="HEAD" mode="udp":
    mkdir -p target/profile
    {{ container }} run --rm --security-opt seccomp=unconfined --security-opt label=disable -e DEDENS_BACK_CPU -e DEDENS_LOAD_CPUS -e DEDENS_ROUNDS -e DEDENS_PERF -v "$(pwd):/src:ro" -v "$(pwd)/target/profile:/profile" -v dedens-dnsperf-cargo:/usr/local/cargo/registry \
        -v dedens-dnsperf-target:/target rust:1 bash /src/crates/dedens-bench/dnsperf/run.sh {{ base }} {{ mode }}

# Where a bench spends its time (D138): the bench target `bench` (`server`, `cache`, ...) built with symbols (the
# bench profile keeps line tables), run under samply with divan's `filter`, a substring of the path (`just profile
# server hit::`), sampled, never instrumented, five seconds a function (`DIVAN_MIN_TIME`). Writes target/profile/<bench>[-<filter>].json.gz and says how to open it. Local, on macOS
# or Linux. dedensd under load on Linux: `DEDENS_PERF=1 just bench-dnsperf`.
profile bench filter="":
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v samply >/dev/null; then
        echo "samply is missing: cargo install --locked samply" >&2
        exit 1
    fi
    exe="$(cargo bench --bench "{{ bench }}" --no-run 2>&1 | tee /dev/stderr | sed -n 's/^ *Executable .* (\(.*\))$/\1/p')"
    if [ -z "$exe" ] || [ "$(printf '%s\n' "$exe" | wc -l)" -ne 1 ]; then
        echo "profile: '{{ bench }}' is not the name of exactly one bench target" >&2
        exit 1
    fi
    filter="{{ filter }}"
    # Divan stops at 100 samples, about a second of samples for a hit: ask for five seconds a function.
    export DIVAN_MIN_TIME="${DIVAN_MIN_TIME:-5}"
    mkdir -p target/profile
    out="target/profile/{{ bench }}${filter:+-${filter//[^[:alnum:]]/-}}.json.gz"
    samply record --save-only --output "$out" -- "$exe" --bench ${filter:+"$filter"}
    echo "profile written: open it with 'samply load $out'"

# Line and region coverage of the tests (cargo-llvm-cov): a summary, not a gate.
cov:
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned stable's own cargo and rustc first: the llvm-tools component belongs to that toolchain.
    rustc="$(rustup which rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    cargo llvm-cov --workspace --all-features --summary-only

# Mutation testing (cargo-mutants, settings in .cargo/mutants.toml, needs cargo-nextest), outside the gate. `args`
# go to cargo-mutants: `just mutants -p dedens-net`; add `--iterate` to test only what the last run did not catch.
# Tests the committed HEAD in its own worktree, target/mutants/tree, one run at a time: `--in-place` edits files,
# and a killed run can leave a mutant applied, so the tree is reset first. Builds in target/mutants/target, results in
# target/mutants/mutants.out.
[positional-arguments]
mutants *args:
    #!/usr/bin/env bash
    set -euo pipefail
    out="$(pwd)/target/mutants"
    tree="$out/tree"
    mkdir -p "$out"
    if ! mkdir "$out/lock" 2>/dev/null; then
        echo "another run holds $out/lock: wait for it, or remove the lock if none runs" >&2
        exit 1
    fi
    trap 'rmdir "$out/lock"' EXIT
    head="$(git rev-parse HEAD)"
    git worktree prune
    if [[ -e "$tree/.git" ]]; then
        git -C "$tree" checkout --quiet --force --detach "$head"
    else
        git worktree add --quiet --detach "$tree" "$head"
    fi
    cd "$tree"
    CARGO_TARGET_DIR="$out/target" cargo mutants --in-place --timeout 240 --output "$out" "$@"

# Mutation testing of the code changed since the branch left `base` (`--in-diff`): minutes, where `just mutants`
# takes hours. `args` as for `just mutants`: just mutants-diff origin/main --iterate
[positional-arguments]
mutants-diff base="origin/main" *args:
    #!/usr/bin/env bash
    set -euo pipefail
    shift
    mkdir -p target/mutants
    git diff "{{ base }}...HEAD" > target/mutants/branch.diff
    {{ just_executable() }} mutants --in-diff "$(pwd)/target/mutants/branch.diff" "$@"

# Loom's model of dedensd's reload wake-up and query flights (D135): lints the code the cfg adds, then tries every
# interleaving up to four preemptions. Its own target dir: the cfg rebuilds the dependencies. Outside `just check`.
loom:
    #!/usr/bin/env bash
    set -euo pipefail
    export RUSTFLAGS="--cfg dedens_loom" CARGO_TARGET_DIR=target/loom
    cargo clippy -p dedensd --bin dedensd --profile test -- -D warnings
    cargo test -p dedensd --profile loom --bin dedensd loom_tests::

# The workspace's tests on a standard library built with its debug assertions and UB checks (cargo-careful, pinned
# nightly, D144), under a sanitizer when given: just careful address (Linux: cargo-careful's sanitized builds fail to
# link on macOS); one package's alone when named: just careful address dedens-net. Own target dir. Outside
# `just check`.
careful sanitizer="" package="":
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned nightly's own cargo and rustc first: cargo-careful builds the standard library with them.
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH" CARGO_TARGET_DIR=target/careful
    # No leak check: a leak is no memory error, and the `LazyLock`s and threads still alive at exit would report.
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
    cargo careful test {{ if sanitizer == "" { "" } else { "-Zcareful-sanitizer=" + sanitizer } }} {{ if package == "" { "--workspace" } else { "-p " + package } }} --all-features

# Fuzz one target with libFuzzer (pinned nightly, cargo-fuzz), starting from the captured responses, for five
# minutes by default, in `fork` processes when given: just fuzz decode_message 60 4
fuzz target="decode_message" seconds="300" fork="0":
    #!/usr/bin/env bash
    set -euo pipefail
    # The pinned nightly's own cargo and rustc first: cargo-fuzz needs `-Z` flags, and rustup proxies would pick
    # the stable of rust-toolchain.toml.
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    # The host's target, named: cargo-fuzz defaults to the one it was built for, musl for a cargo-binstall download,
    # where AddressSanitizer cannot link (D141).
    host="$(rustc -vV | sed -n 's/^host: //p')"
    cd fuzz
    # The first corpus directory is the one libFuzzer writes to; the captured responses and zone files only seed it.
    mkdir -p "corpus/{{ target }}"
    # A target with a token dictionary in dicts/ gets it.
    dict=""
    if [[ -f "dicts/{{ target }}.dict" ]]; then dict="-dict=dicts/{{ target }}.dict"; fi
    cargo fuzz run --target "$host" {{ target }} "corpus/{{ target }}" ../crates/dedens-proto/tests/testdata ../crates/dedens-proto/tests/zones ../crates/dedens-dnssec/tests/testdata ../crates/dedens-dnssec/tests/zones ../crates/dedens-odoh/tests/testdata -- -max_total_time={{ seconds }} -fork={{ fork }} $dict

# Shrink a target's corpus to the inputs that add coverage (libFuzzer's `-merge=1`).
fuzz-cmin target:
    #!/usr/bin/env bash
    set -euo pipefail
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    host="$(rustc -vV | sed -n 's/^host: //p')"
    cd fuzz
    cargo fuzz cmin --target "$host" {{ target }} "corpus/{{ target }}"

# Every fuzz target for `seconds` each, in turn (the scheduled CI job runs them in parallel, D141).
fuzz-all seconds="60":
    #!/usr/bin/env bash
    set -euo pipefail
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    host="$(rustc -vV | sed -n 's/^host: //p')"
    cd fuzz
    for target in $(cargo fuzz list); do
        mkdir -p "corpus/$target"
        dict=""
        if [[ -f "dicts/$target.dict" ]]; then dict="-dict=dicts/$target.dict"; fi
        cargo fuzz run --target "$host" "$target" "corpus/$target" ../crates/dedens-proto/tests/testdata ../crates/dedens-proto/tests/zones ../crates/dedens-dnssec/tests/testdata ../crates/dedens-dnssec/tests/zones ../crates/dedens-odoh/tests/testdata -- -max_total_time={{ seconds }} $dict
    done

# Every simulation scenario under `runs` random seeds (D133); a failure prints its `DEDENS_SIM_SEED=<n>`.
sim runs="100":
    DEDENS_SIM_RUNS={{ runs }} cargo test -p dedens-sim --test '*'

# Replay the captured responses plus truncated and bit-flipped variants on stable (part of `just check`).
fuzz-smoke:
    cargo test --manifest-path fuzz/Cargo.toml --lib

# Capture fresh responses from public servers into the directory `dir`: the queries of its capture.yaml, or
# those with the ids given.
[private]
capture-to dir *ids:
    cargo run -p dedens -- -f {{ dir }}/capture.yaml --save-wire {{ dir }} {{ prepend("--only=", ids) }}

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
    {{ just_executable() }} capture-to "$tmp"
    date +%s > "$tmp/captured_at"
    rm -f "$dir"/*.bin
    cp "$tmp"/*.bin "$tmp/captured_at" "$dir/"

# Ask every public resolver of docs/providers/providers.yaml over the network, IPv4 and IPv6 (D67).
providers:
    cargo test -p dedens --test providers -- --ignored --nocapture

# Oblivious DoH against public targets: a stale key gets the 401, one refetch and an answer (RFC 9230 §4.3, D79).
odoh-live:
    cargo test -p dedens-net --features odoh --test rfc9230 -- --ignored --nocapture

# `dedensd` as an Oblivious DoH target for Cloudflare's odoh-rs over HTTP/3 (aioquic): needs uv and the network.
odoh-interop:
    uv run tests/interop/odoh.py

# Download every list of docs/blocklists/blocklists.yaml and check its format and freshness (D87, D88).
# GITHUB_TOKEN, when set, lifts GitHub's limit of 60 API requests an hour.
blocklists:
    cargo test -p dedensd --test blocklists -- --ignored --nocapture

# Install the pinned RAPx and the nightly's rustc internals. Needs Z3: `brew install z3` or
# `apt-get install libz3-dev`.
rapx-install:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v brew >/dev/null; then
        z3="$(brew --prefix z3)"
        export Z3_SYS_Z3_HEADER="$z3/include/z3.h" LIBRARY_PATH="$z3/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
    fi
    rustup toolchain install {{ nightly }} --profile minimal --component rustc-dev,rust-src,llvm-tools-preview
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    RUSTC="$rustc" rustup run {{ nightly }} cargo install --git https://github.com/safer-rust/RAPx --rev {{ rapx_rev }} rapx --locked

# RAPx static analysis, outside the gate: use-after-free, double free and leaks by default; `just rapx opt` for
# optimization hints. Own target dir: RAPx runs `cargo clean --workspace` before each analysis.
rapx *args="check -f -m":
    #!/usr/bin/env bash
    set -euo pipefail
    # The nightly's own cargo first in PATH: RAPx calls `cargo`, which `rustup run` leaves to a Homebrew cargo
    # ahead in PATH, and the dependencies it builds don't load in RAPx's rustc.
    rustc="$(rustup which --toolchain {{ nightly }} rustc)"
    export PATH="$(dirname "$rustc"):$PATH"
    CARGO_TARGET_DIR=target/rapx RUSTC="$rustc" rustup run {{ nightly }} cargo rapx {{ args }}

# Install the pinned Kani, then its nightly and CBMC into ~/.kani.
kani-install:
    cargo install --locked kani-verifier@{{ kani_version }}
    cargo kani setup

# Kani's proofs of dedens-proto's wire decoders for every small input (D145), outside the gate: all by default, one
# with `just kani --harness name_decoding`. Its own target dir, target/kani.
kani *args:
    cargo kani -p dedens-proto {{ args }}

# Download every RFC linked from docs/rfc/list.md into docs/rfc/archive/, as plain text from rfc-editor.org.
rfc-archive:
    mkdir -p docs/rfc/archive
    grep -oE "datatracker\.ietf\.org/doc/html/rfc[0-9]+" docs/rfc/list.md | grep -oE "[0-9]+$" | sort -un \
        | xargs -P 8 -I{} curl -fsSL --retry 3 -o docs/rfc/archive/rfc{}.txt https://www.rfc-editor.org/rfc/rfc{}.txt

# Refresh IANA's root hints, bundled for `dedens +trace`.
root-hints:
    curl -fsSL --retry 3 -o apps/dedens/src/named.root https://www.internic.net/domain/named.root

# Refresh the bundled root trust anchors (D72): the `KeyDigest` entries of IANA's root-anchors.xml valid now (RFC
# 9718 §2.2: `validFrom` passed, `validUntil` absent or ahead), as DS zone text. No XML parser in Rust: the file is
# flat, and a time with an offset other than UTC stops the recipe.
root-anchors:
    #!/usr/bin/env bash
    set -euo pipefail
    out=crates/dedens-dnssec/src/root.ds
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' EXIT
    today="$(date -u +%Y-%m-%d)"
    {
        echo "; Root zone trust anchors (RFC 9718): the KeyDigest entries of IANA's root-anchors.xml valid on $today."
        echo "; Source: https://data.iana.org/root-anchors/root-anchors.xml. Written by \`just root-anchors\`, never by hand."
        curl -fsSL --retry 3 https://data.iana.org/root-anchors/root-anchors.xml | tr '\n' ' ' \
            | awk -v now="$(date -u +%Y-%m-%dT%H:%M:%S)" -v RS='</KeyDigest>' '
                function text(tag,   s) {
                    if (!match($0, "<" tag ">[^<]*</" tag ">")) return ""
                    s = substr($0, RSTART + length(tag) + 2, RLENGTH - 2 * length(tag) - 5)
                    gsub(/[ \t\r]+/, "", s)
                    return s
                }
                function attr(name,   s) {
                    if (!match($0, name "=\"[^\"]*\"")) return ""
                    return substr($0, RSTART + length(name) + 2, RLENGTH - length(name) - 3)
                }
                function fail(msg) { print "root-anchors: " msg > "/dev/stderr"; failed = 1; exit 1 }
                function utc(t) {
                    if (substr(t, 20) !~ /^(\+00:00|Z)$/) fail("time not in UTC: " t)
                    return substr(t, 1, 19)
                }
                NR == 1 && text("Zone") != "." { fail("not the root zone") }
                index($0, "<KeyDigest") == 0 { next }
                {
                    if (utc(attr("validFrom")) > now) next
                    if (attr("validUntil") != "" && utc(attr("validUntil")) <= now) next
                    printf ". IN DS %s %s %s %s\n", text("KeyTag"), text("Algorithm"), text("DigestType"), text("Digest")
                    n++
                }
                END { if (!failed && n == 0) fail("no key valid now") }'
    } > "$tmp"
    mv "$tmp" "$out"
    chmod 644 "$out"
    cat "$out"
