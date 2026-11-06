#!/usr/bin/env bash
# Build the probe the way dedensd is built for each allocator candidate, and run it.
# One argument, a build name (below), or none for all. The container is `docker` (DEDENS_CONTAINER=podman for Podman).
# The musl builds are `just musl`: rust:<channel>-alpine, the repository's .cargo/config.toml (lld through
# .cargo/lld-cc, found because the probe is inside the repository), the same Cargo.lock versions. The glibc builds
# are references: rust:1.95 (Debian) with the same toolchain installed. Output: `$OUT/<build>.log` (the build, -vv)
# and `$OUT/<build>.md` (the probe). The probe runs in the container it was built in: aarch64 on a Mac.
# `$OUT` must be shared with the container's VM (a Mac: under $HOME).
set -euo pipefail
cd "$(dirname "$0")/../../.."
root="$(pwd)"
channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
container="${DEDENS_CONTAINER:-docker}"
out="${OUT:-$root/../alloc03-out}"
mkdir -p "$out"
arch="$(uname -m)"
[[ "$arch" == arm64 ]] && arch=aarch64

# name|libc|features|CFLAGS
builds=(
  "musl-mallocng|musl||"
  "musl-mimalloc|musl|alloc-mimalloc|"
  "musl-mimalloc-minimal|musl|alloc-mimalloc|-DMI_SECURE=1"
  "musl-mimalloc-secure|musl|alloc-mimalloc-secure|"
  "musl-jemalloc|musl|alloc-jemalloc|"
  "glibc-malloc|gnu||"
  "glibc-mimalloc|gnu|alloc-mimalloc|"
)

for spec in "${builds[@]}"; do
  IFS="|" read -r name libc features cflags <<<"$spec"
  [[ $# -eq 0 || "$1" == "$name" ]] || continue
  target="$arch-unknown-linux-$libc"
  if [[ "$libc" == musl ]]; then
    image="rust:$channel-alpine"
    prep="apk add --quiet --no-cache lld make"
  else
    image="rust:1.95"
    prep="rustup toolchain install $channel --profile minimal --no-self-update >/dev/null 2>&1"
  fi
  echo "== $name ($target, features: ${features:-none}, CFLAGS: ${cflags:-none})" >&2
  "$container" run --rm --security-opt label=disable -v "$root:/src" -w /src/crates/dedens-bench/alloc-probe \
    -v "$out:/out" -v b03-registry:/usr/local/cargo/registry -v b03-target:/target \
    -e "CARGO_TARGET_DIR=/target/$name" -e "CARGO_BUILD_TARGET=$target" -e "RUSTUP_TOOLCHAIN=$channel" \
    -e "CFLAGS=$cflags" -e "FEATURES=$features" -e "NAME=$name" -e "TARGET=$target" "$image" \
    sh -c "$prep && cargo build --release --locked -vv --features \"\$FEATURES\" >/out/\$NAME.log 2>&1 && /target/\$NAME/\$TARGET/release/alloc-probe >/out/\$NAME.md && cat /out/\$NAME.md"
done
