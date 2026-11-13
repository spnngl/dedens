set shell := ["bash", "-euo", "pipefail", "-c"]

# The one pinned nightly: rustfmt (rustfmt.toml uses unstable options), `-Z` flags and RAPx. RAPx builds on rustc
# internals, so its version and this nightly move together: bump both by hand. Stable is pinned in
# rust-toolchain.toml.
nightly := "nightly-2026-10-26"
rapx_version := "0.7.71"
# Kani brings a nightly and CBMC of its own (`just kani-install`).
# renovate: datasource=crate depName=kani-verifier
kani_version := "0.68.0"
# renovate: datasource=github-tags depName=NLnetLabs/unbound extractVersion=^release-(?<version>.*)$
unbound_version := "1.26.2"
# Verus's release (D180), its own rustc and Z3 in it (`just verus-install`). vstd in Cargo.toml moves with it, by
# hand, to the version `cargo verus toolchain list` gives: `just verus` fails on any other.
# renovate: datasource=github-releases depName=verus-lang/verus extractVersion=^release/(?<version>\d+\.\d+\.\d+\.\d+\.[0-9a-f]+)$
verus_version := "0.2026.11.02.8bf68ee"
# The container engine of `bench-dnsperf`: `DEDENS_CONTAINER=podman just bench-dnsperf`.
# `DEDENS_ROUNDS=5` sets its rounds.
container := env("DEDENS_CONTAINER", "docker")
# The nfpm image of `just packages` (D156).
nfpm := "docker.io/goreleaser/nfpm:v2.49.0@sha256:9ea46a59c4d055ef7071b22f3520b53e8dad98e18043b2f881b53bd7ffec634e"

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
    cargo nextest run --workspace --all-features
    cargo test --workspace --all-features --doc
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

# The exclusions of .cargo/mutants.toml that match no mutant or file (D168), each listed, failing if any. Mutants are
# listed without the configuration, with no build, and without colours, which CI's `CARGO_TERM_COLOR=always` would
# put in the names. Perl matches the names: `--re` keeps every field deletion. The list is taken first, so a failing
# cargo-mutants stops the recipe rather than leaving every pattern unmatched.
mutants-stale:
    #!/usr/bin/env bash
    set -euo pipefail
    patterns="$(taplo get -f .cargo/mutants.toml exclude_re)"
    globs="$(taplo get -f .cargo/mutants.toml exclude_globs)"
    names="$(cargo mutants --list --no-config --colors=never)"
    stale=0
    printf '%s\n' "$names" | perl -e '
        chomp(my @names = <STDIN>);
        my $stale = 0;
        for my $re (split /\n/, shift) {
            next if grep { /$re/ } @names;
            print "exclude_re matches no mutant: \x27$re\x27\n";
            $stale = 1;
        }
        exit $stale;
    ' "$patterns" || stale=1
    while IFS= read -r glob; do
        found="$(cargo mutants --list-files --no-config --colors=never --file="$glob")"
        if [[ -z "$found" ]]; then
            echo "exclude_globs matches no file: '$glob'"
            stale=1
        fi
    done <<< "$globs"
    exit "$stale"

# Loom's model of dedensd's reload wake-up and query flights (D135): lints the code the cfg adds, then tries every
# interleaving up to four preemptions. Its own target dir: the cfg rebuilds the dependencies. Outside `just check`.
loom:
    #!/usr/bin/env bash
    set -euo pipefail
    export RUSTFLAGS="--cfg dedens_loom" CARGO_TARGET_DIR=target/loom
    cargo clippy -p dedensd --lib --profile test -- -D warnings
    cargo test -p dedensd --profile loom --lib loom_tests::

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

# cargo on a musl target (D151), natively in a `rust:alpine` container of the host's architecture, with no cross
# toolchain: `target` is that architecture's `<arch>-unknown-linux-musl`, `cmd` the cargo arguments, the tests by
# default. The root test: just musl x86_64-unknown-linux-musl test -p dedensd --test tests -- --ignored privileges::.
# The image is the one of rust-toolchain.toml (its components stay out: rustup would download them on each run); lld
# is Alpine's own (`lld-cc`), git and procps-ng (BusyBox's `ps` has no `-p`) are for the repository and
# `listeners::tcp_frames` tests.
# Unconfined seccomp, for io_uring, which the host's `kernel.io_uring_disabled` must allow. A linked worktree's `.git`
# points outside the mount, so the repository tests need a clone.
# Volumes, dedens-musl-registry and dedens-musl-<arch>, keep the registry and the build between runs.
musl target *cmd="test --workspace --all-features":
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "{{ target }}" != "{{ arch() }}-unknown-linux-musl" ]]; then
        echo "musl: a container runs the host's architecture: use {{ arch() }}-unknown-linux-musl" >&2
        exit 1
    fi
    channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
    {{ container }} run --rm --security-opt seccomp=unconfined --security-opt label=disable -v "$(pwd):/src:ro" -w /src \
        -v dedens-musl-registry:/usr/local/cargo/registry -v "dedens-musl-{{ arch() }}:/target" \
        -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_TARGET={{ target }} -e "RUSTUP_TOOLCHAIN=$channel" "rust:$channel-alpine" \
        sh -c 'apk add --quiet --no-cache git lld procps-ng && git config --global --add safe.directory /src && exec cargo "$@"' cargo {{ cmd }}

# The release binaries of this machine's architecture, `dedensd` and `dedens` in `dist/` with their notices (D153,
# D158): the Containerfile's `binaries` stage, built twice from scratch and the two compared; a path of the build in a
# binary fails too.
release:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf dist
    mkdir -p dist/1 dist/2
    for n in 1 2; do
        {{ container }} build -f Containerfile --no-cache --target binaries -t "localhost/dedens-binaries:$n" .
        id="$({{ container }} create "localhost/dedens-binaries:$n" /dedensd)"
        for file in dedensd dedens THIRD-PARTY-dedensd.txt THIRD-PARTY-dedens.txt; do
            {{ container }} cp "$id:/$file" "dist/$n/$file"
        done
        {{ container }} rm "$id" >/dev/null
    done
    diff -r dist/1 dist/2
    if grep -aF -e "$(pwd)" -e /src/apps -e /src/crates -e /usr/local/cargo -e /usr/local/rustup dist/1/dedensd dist/1/dedens; then
        echo "release: a path of the build is in a binary" >&2
        exit 1
    fi
    mv dist/1/* dist/
    rm -r dist/1 dist/2
    sha256sum dist/* 2>/dev/null || shasum -a 256 dist/*

# The deb and rpm packages of dedens and dedensd, from the binaries `just release` left in dist/ (D156)
packages:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{ arch() }}" in x86_64) goarch=amd64 ;; aarch64) goarch=arm64 ;; esac
    version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
    # The commit's time, for every file's and the changelog's: the same commit makes the same packages.
    epoch="$(git log -1 --format=%ct)"
    trap 'rm -rf dist/changelog.yaml dist/packages dist/man' EXIT
    mkdir dist/packages dist/man
    # Compressed as Debian's policy asks; `-n`: no name or time in the header.
    for page in deploy/packages/man/*; do gzip -9n < "$page" > "dist/man/${page##*/}.gz"; done
    printf -- '- semver: %s-1\n  date: %s\n  packager: Lola Delannoy <lola.2lannoy@gmail.com>\n  deb:\n    urgency: medium\n    distributions: [unstable]\n  changes:\n    - note: %s\n' \
        "$version" "$(git log -1 --format=%cI)" "https://github.com/spnngl/dedens/releases/tag/v$version" > dist/changelog.yaml
    # The packages owned by the caller: rootless Podman maps only the caller's own id through. nfpm writes to
    # dist/packages only: the binaries and the sources are read-only to it.
    user="--user=$(id -u):$(id -g)"
    if [[ "{{ container }}" == podman ]]; then user=--userns=keep-id; fi
    for package in dedens dedensd; do
        for packager in deb rpm; do
            {{ container }} run --rm "$user" -v "$PWD:/src:ro" -v "$PWD/dist/packages:/out" -w /src -e "ARCH=$goarch" \
                -e "VERSION=$version" -e "SOURCE_DATE_EPOCH=$epoch" {{ nfpm }} \
                package --config "deploy/packages/$package.yaml" --packager "$packager" --target /out/
        done
    done
    mv dist/packages/* dist/

# The man pages in deploy/packages/man/, written again from the command lines (D158).
man:
    DEDENS_WRITE_MAN=1 cargo test -p dedens -p dedensd --lib the_man_page

# The dedensd image, `localhost/dedensd`, for this machine's architecture (D153): just image && docker run --rm -p 5353:53/udp
# localhost/dedensd
image:
    {{ container }} build -f Containerfile -t localhost/dedensd .

# The directories, from fuzz/, every fuzz target starts from: all of testdata/, whatever format the target reads,
# with the seeds `fuzz-seeds` writes out.
fuzz_seeds := "../testdata/proto ../testdata/zones ../testdata/dnssec ../testdata/odoh ../testdata/dnscrypt ../testdata/doh ../testdata/plugins target/seeds/coap target/seeds/command_lines target/seeds/stamps target/seeds/configs"

# The CoAP datagrams of testdata/coap, kept there as hex lines, one to a file in fuzz/target/seeds/coap; the command
# lines of fuzz/seeds/command_lines.txt, NUL between two arguments, in fuzz/target/seeds/command_lines; the stamps
# of fuzz/seeds/stamps.txt, one to a file in fuzz/target/seeds/stamps; dedensd's configurations, the image's, the
# packages', the one of fuzz/seeds/dnscrypt.yaml and the example of its config module, in fuzz/target/seeds/configs (D181).
[private]
fuzz-seeds:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf fuzz/target/seeds/coap fuzz/target/seeds/command_lines fuzz/target/seeds/stamps fuzz/target/seeds/configs
    mkdir -p fuzz/target/seeds/coap fuzz/target/seeds/command_lines fuzz/target/seeds/stamps fuzz/target/seeds/configs
    perl -ne 'next if /^#/; my $hex = (split)[2]; open my $out, ">", "fuzz/target/seeds/coap/$." or die; print $out pack "H*", $hex' testdata/coap/*.txt
    perl -ne 'next if /^#/; chomp; open my $out, ">", "fuzz/target/seeds/command_lines/$." or die; print $out join "\0", split / /, $_, -1' fuzz/seeds/command_lines.txt
    perl -ne 'next if /^#/; chomp; open my $out, ">", "fuzz/target/seeds/stamps/$." or die; print $out $_' fuzz/seeds/stamps.txt
    cp deploy/dedensd.yaml fuzz/target/seeds/configs/dedensd.yaml
    cp deploy/packages/dedensd.conf.yaml fuzz/target/seeds/configs/dedensd.conf.yaml
    cp fuzz/seeds/dnscrypt.yaml fuzz/target/seeds/configs/dnscrypt.yaml
    perl -ne 'last unless s{^//! ?}{}; print if /^```yaml$/ ... /^```$/ and !/^```/' apps/dedensd/src/config/mod.rs > fuzz/target/seeds/configs/example.yaml

# Fuzz one target with libFuzzer (pinned nightly, cargo-fuzz), starting from the captured data, for five
# minutes by default, in `fork` processes when given: just fuzz decode_message 60 4
fuzz target="decode_message" seconds="300" fork="0": fuzz-seeds
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
    # The first corpus directory is the one libFuzzer writes to; the captured data only seeds it.
    mkdir -p "corpus/{{ target }}"
    # A target with a token dictionary in dicts/ gets it.
    dict=""
    if [[ -f "dicts/{{ target }}.dict" ]]; then dict="-dict=dicts/{{ target }}.dict"; fi
    cargo fuzz run --target "$host" {{ target }} "corpus/{{ target }}" {{ fuzz_seeds }} -- -max_total_time={{ seconds }} -fork={{ fork }} $dict

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
fuzz-all seconds="60": fuzz-seeds
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
        cargo fuzz run --target "$host" "$target" "corpus/$target" {{ fuzz_seeds }} -- -max_total_time={{ seconds }} $dict
    done

# Every simulation scenario under `runs` random seeds (D133), or those of one family, a module of
# crates/dedens-sim/tests: just sim 100 dnssec (an unknown family fails, not runs nothing). A failure prints its
# `DEDENS_SIM_SEED=<n>`.
sim runs="100" family="":
    DEDENS_SIM_RUNS={{ runs }} cargo test -p dedens-sim --test tests -- {{ if family == "" { "" } else if path_exists("crates/dedens-sim/tests/" + family + ".rs") == "true" { family + "::" } else { error("no simulation family `" + family + "` in crates/dedens-sim/tests") } }}

# The wall time of each simulation family run alone, then of them all, as `just check` runs them (the workspace's
# debug build with every feature, the fixed seeds): over D133's budgets, 2 s a family and 10 s the crate, it says
# so and fails. Outside the gate, as the time is the machine's (D164). `DEDENS_SIM_TIME_SCALE`, a positive decimal
# (1 when unset), multiplies both budgets for a slower machine (D167; GitHub's runners' scale: D172).
sim-time:
    #!/usr/bin/env bash
    set -euo pipefail
    unset DEDENS_SIM_SEED DEDENS_SIM_RUNS
    scale="${DEDENS_SIM_TIME_SCALE-1}"
    if ! [[ "$scale" =~ ^[0-9]*\.?[0-9]+$ ]] || ! awk -v s="$scale" 'BEGIN { exit !(s > 0) }'; then
        echo "DEDENS_SIM_TIME_SCALE must be a positive decimal, not '$scale'" >&2
        exit 2
    fi
    family_budget="$(awk -v s="$scale" 'BEGIN { print 2 * s }')"
    crate_budget="$(awk -v s="$scale" 'BEGIN { print 10 * s }')"
    # The gate's build, so the artifacts of `just check` serve: features unify over the workspace.
    exe="$(cargo test --workspace --all-features --no-run --test tests --message-format=json \
        | jq -r 'select(.reason == "compiler-artifact" and .target.kind == ["test"]
            and (.manifest_path | endswith("/crates/dedens-sim/Cargo.toml"))) | .executable')"
    [[ -n "$exe" ]] || { echo "no dedens-sim tests binary" >&2; exit 1; }
    # The first run of a new binary pays macOS's check of it, 0.5 s and more, which no family should.
    "$exe" --list > /dev/null
    log="$(mktemp)"
    trap 'rm -f "$log"' EXIT
    TIMEFORMAT=%3R
    over=0
    # Times the tests the filter `$3` selects, all without one, against `$2` seconds; a failure prints their output.
    measure() {
        local name="$1" budget="$2" took
        if ! took=$( { time "$exe" ${3:+"$3"} > "$log" 2>&1; } 2>&1 ); then
            cat "$log"
            exit 1
        fi
        if awk -v took="$took" -v budget="$budget" 'BEGIN { exit !(took > budget) }'; then
            printf '%-10s %7s s  over %s s\n' "$name" "$took" "$budget"
            over=1
        else
            printf '%-10s %7s s\n' "$name" "$took"
        fi
    }
    for family in $(sed -n 's/^mod \([a-z_]*\);$/\1/p' crates/dedens-sim/tests/tests.rs | grep -vx util); do
        measure "$family" "$family_budget" "$family::"
    done
    measure crate "$crate_budget"
    exit "$over"

# Replay the captured responses plus truncated and bit-flipped variants on stable (part of `just check`).
fuzz-smoke:
    cargo test --manifest-path fuzz/Cargo.toml --lib

# Capture fresh responses from public servers into the directory `dir`: the queries of its capture.yaml, or
# those with the ids given.
[private]
capture-to dir *ids:
    cargo run -p dedens -- -f {{ dir }}/capture.yaml --save-wire {{ dir }} {{ prepend("--only=", ids) }}

# Capture fresh responses into testdata/proto/: the queries of its capture.yaml, or those
# with the ids given.
capture *ids: (capture-to "testdata/proto" ids)

# Capture the DNSSEC set of testdata/dnssec/ anew: every query of its capture.yaml, and
# `captured_at`, the Unix time of the run's end (signatures made on demand start at the time of the query). The
# directory is replaced only when every query succeeded: new bytes, same coverage.
capture-dnssec:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=testdata/dnssec
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    cp "$dir/capture.yaml" "$tmp/"
    {{ just_executable() }} capture-to "$tmp"
    date +%s > "$tmp/captured_at"
    rm -f "$dir"/*.bin
    cp "$tmp"/*.bin "$tmp/captured_at" "$dir/"

# Ask every public resolver of docs/providers/providers.yaml over the network, IPv4 and IPv6 (D67).
providers:
    cargo test -p dedens --features dnscrypt --test tests -- --ignored providers:: --nocapture

# Oblivious DoH against public targets: a stale key gets the 401, one refetch and an answer (RFC 9230 §4.3, D79).
odoh-live:
    cargo test -p dedens-net --features odoh --test tests -- --ignored odoh:: --nocapture

# `dedensd` as an Oblivious DoH target for Cloudflare's odoh-rs over HTTP/3 (aioquic): needs uv and the network.
odoh-interop:
    uv run tests/interop/odoh.py

# Download every list of docs/blocklists/blocklists.yaml and check its format and freshness (D87, D88).
# GITHUB_TOKEN, when set, lifts GitHub's limit of 60 API requests an hour.
blocklists:
    cargo test -p dedensd --test tests -- --ignored lists::published --nocapture

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
    RUSTC="$rustc" rustup run {{ nightly }} cargo install rapx@{{ rapx_version }} --locked

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

# Unzip the pinned Verus release into target/verus-<version> and install the rustc it is built on.
verus-install:
    #!/usr/bin/env bash
    set -euo pipefail
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) platform=arm64-macos ;;
        Darwin-x86_64) platform=x86-macos ;;
        Linux-aarch64) platform=arm64-linux ;;
        Linux-x86_64) platform=x86-linux ;;
        *) echo "verus-install: no Verus release for $(uname -sm)" >&2; exit 1 ;;
    esac
    dir=target/verus-{{ verus_version }}
    zip="$(mktemp)"
    trap 'rm -f "$zip"' EXIT
    curl -fsSL -o "$zip" "https://github.com/verus-lang/verus/releases/download/release/{{ verus_version }}/verus-{{ verus_version }}-$platform.zip"
    rm -rf "$dir" && mkdir -p "$dir"
    unzip -q "$zip" -d "$dir"
    mv "$dir/verus-$platform"/* "$dir" && rmdir "$dir/verus-$platform"
    toolchain="$(sed -n 's/.*"toolchain": "\([^ "]*\).*/\1/p' "$dir/version.json")"
    rustup toolchain install --profile minimal "$toolchain"

# Verus's proofs of dedens-proto and dedens-dnssec (D180), outside the gate; its own target dir, target/verus. `--cfg
# verus_keep_ghost` brings in vstd, which no other build has.
verus *args:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="$PWD/target/verus-{{ verus_version }}"
    [[ -x "$dir/cargo-verus" ]] || just verus-install
    export PATH="$dir:$PATH" RUSTFLAGS="--cfg verus_keep_ghost"
    cargo verus verify -p dedens-proto -p dedens-dnssec --target-dir target/verus --check-toolchain {{ args }}

# Kani's proofs of `package` for every small input (D145), outside the gate: all of them by default, one with
# `just kani dedens-proto --harness name_decoding`. Its own target dir, target/kani.
kani package *args:
    cargo kani -p {{ package }} {{ args }}

# The Kani proofs that take under a minute each (D145), as `package:proof`: on each pull request in `deep.yml`,
# informational. A name that matches no proof fails the recipe.
kani-fast:
    #!/usr/bin/env bash
    set -euo pipefail
    fast=(
        dedens-cache:the_cut_is_the_highest_whole_one
        dedens-net:a_nibble_reads_back_what_was_written
        dedens-odoh:a_parsed_message_encodes_back
        dedens-odoh:a_parsed_plaintext_encodes_back
        dedens-proto:a_decoded_subnet_encodes_back
        dedens-proto:edns_appending
        dedens-proto:header_peeking
        dedens-proto:header_round_trip
        dedens-proto:zero_bytes_marks_the_zero_bytes
    )
    for package in $(printf '%s\n' "${fast[@]}" | cut -d: -f1 | sort -u); do
        args=()
        for entry in "${fast[@]}"; do
            [[ "${entry%%:*}" == "$package" ]] || continue
            proof="${entry#*:}"
            if ! grep -rq "fn $proof()" "crates/$package/src"; then
                echo "kani-fast: no proof $proof in crates/$package/src" >&2
                exit 1
            fi
            args+=(--harness "$proof")
        done
        cargo kani -p "$package" "${args[@]}"
    done

# Download every RFC linked from docs/rfc/list.md into docs/rfc/archive/, as plain text from rfc-editor.org; every
# Internet-Draft (at the revision linked) from ietf.org; and every other text linked there by a .txt URL (a draft at
# one revision, a text at one commit), under the lowercased name of the URL's file.
rfc-archive:
    mkdir -p docs/rfc/archive
    grep -oE "datatracker\.ietf\.org/doc/html/rfc[0-9]+" docs/rfc/list.md | grep -oE "[0-9]+$" | sort -un \
        | xargs -P 8 -I{} curl -fsSL --retry 3 -o docs/rfc/archive/rfc{}.txt https://www.rfc-editor.org/rfc/rfc{}.txt
    grep -oE "datatracker\.ietf\.org/doc/html/draft-[a-z0-9-]+-[0-9]+" docs/rfc/list.md | grep -oE "draft-.*$" | sort -u \
        | xargs -P 8 -I{} curl -fsSL --retry 3 -o docs/rfc/archive/{}.txt https://www.ietf.org/archive/id/{}.txt
    grep -oE "https://[^ )]+\.txt" docs/rfc/list.md | sort -u | while read -r url; do \
        curl -fsSL --retry 3 -o "docs/rfc/archive/$(basename "$url" | tr '[:upper:]' '[:lower:]')" "$url"; done

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
