#!/usr/bin/env bash
# Builds every candidate: dedensd (timed, a clean target directory each), then the benches. Usage: build.sh [names]
# Binaries: ~/alloc/bin/<name>/{dedensd,server,cache,message}; logs: ~/alloc/logs/<name>.{build,bench}.log; times: logs/times.
set -uo pipefail
cd ~/alloc
mkdir -p bin logs target
channel=1.99.1
triple=x86_64-unknown-linux-musl
build() { # build <name> <libc: musl|glibc> <feature or -> <cflags or ->
    local name=$1 libc=$2 feat=$3 cflags=$4 image out pre e=()
    if [[ $libc == musl ]]; then
        image=rust:$channel-alpine
        e+=(-e CARGO_BUILD_TARGET=$triple)
        pre="apk add --quiet --no-cache git lld procps-ng make >/dev/null; git config --global --add safe.directory /src;"
        out=/target/$triple/release
    else
        image=rust:1
        pre="true;"
        out=/target/release
    fi
    [[ $feat != - ]] && e+=(-e "FEATS=--features dedensd/$feat" -e "FEATS_BENCH=--features dedens-bench/$feat")
    [[ $cflags != - ]] && e+=(-e "CFLAGS=$cflags")
    [[ -n ${REUSE:-} ]] || rm -rf "target/$name"; mkdir -p "target/$name" "bin/$name"; [[ -n ${REUSE:-} ]] && e+=(-e SKIP_DEDENSD=1)
    echo "== $name $(date +%T)" | tee -a logs/times
    podman run --rm --security-opt seccomp=unconfined --security-opt label=disable \
        -v ~/alloc/src:/src:ro -w /src -v dedens-musl-registry:/usr/local/cargo/registry \
        -v ~/alloc/target/$name:/target -v ~/alloc/bin/$name:/out -v ~/alloc/logs:/logs -v ~/alloc/inner.sh:/inner.sh:ro \
        -e CARGO_TARGET_DIR=/target -e RUSTUP_TOOLCHAIN=$channel -e NAME=$name -e OUT=$out "${e[@]}" "$image" \
        sh -c "$pre exec sh /inner.sh"
    ls -l "bin/$name" | tee -a logs/times
    rm -rf "target/$name"
}
all=(
    "musl-mallocng musl - -"
    "musl-mimalloc musl alloc-mimalloc -"
    "musl-mimalloc-min musl alloc-mimalloc -DMI_SECURE=1"
    "musl-mimalloc-secure musl alloc-mimalloc-secure -"
    "musl-jemalloc musl alloc-jemalloc -"
    "glibc-malloc glibc - -"
    "glibc-mimalloc glibc alloc-mimalloc -"
)
for c in "${all[@]}"; do
    read -r n l f cf <<<"$c"
    if [[ $# -eq 0 || " $* " == *" $n "* ]]; then build "$n" "$l" "$f" "$cf"; fi
done
echo "== done $(date +%T)" | tee -a logs/times
