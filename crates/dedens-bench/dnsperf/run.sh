#!/usr/bin/env bash
# Queries per second of dedensd under dnsperf, on Linux (io_uring), the server on one core: the git ref $1
# (default HEAD) against the working tree, two rounds each, in mode $2: udp (the default) or tcp, the cache
# answering every query after the first, which goes to 1.1.1.1 (the network is needed for those); or forward, over
# UDP without a cache, every query going upstream to a second dedensd (the working tree's, on its own core)
# answering from its cache. Runs inside the container `just bench-dnsperf` starts, with the repository at /src
# (read-only), a target directory at /target.
set -euo pipefail
base="${1:-HEAD}"
mode="${2:-udp}"
apt-get update -qq >/dev/null
apt-get install -y -qq dnsperf dnsutils git >/dev/null 2>&1
git config --global --add safe.directory /src
build() { # build <name>: /<name> into /<name>.bin, each in its own target directory (cargo would take one
    # checkout's artifacts for the other's: same relative paths, older modification times)
    (cd "/$1" && CARGO_TARGET_DIR="/target/$1" cargo build -q --release -p dedensd)
    cp "/target/$1/release/dedensd" "/$1.bin"
}
rm -rf /base /tree
git clone -q /src /base && git -C /base checkout -q "$base"
build base
mkdir /tree && tar -C /src --exclude=./target -cf - . | tar -C /tree -xf -
build tree
cat >/perf.yaml <<'EOF'
listen: ['127.0.0.1:5399']
pipeline: [cache, up]
stages:
  cache:
    type: cache
  up:
    type: forward
    servers: ['1.1.1.1']
EOF
cat >/back.yaml <<'EOF'
listen: ['127.0.0.1:5400']
pipeline: [cache, up]
stages:
  cache:
    type: cache
  up:
    type: forward
    servers: ['1.1.1.1']
EOF
cat >/front.yaml <<'EOF'
listen: ['127.0.0.1:5399']
pipeline: [up]
stages:
  up:
    type: forward
    servers: ['127.0.0.1:5400']
EOF
config=/perf.yaml transport="$mode"
if [[ $mode == forward ]]; then
    config=/front.yaml transport=udp
    taskset -c 7 /tree.bin --config /back.yaml 2>/dev/null &
fi
printf 'example.com A\nexample.org A\nwww.example.com AAAA\niana.org MX\n' >/queries.txt
for round in 1 2; do
    for bin in base tree; do
        taskset -c 0 "/$bin.bin" --config "$config" 2>/dev/null &
        pid=$!
        sleep 1
        dig +short @127.0.0.1 -p 5399 example.com A iana.org MX example.org A www.example.com AAAA >/dev/null
        printf '%s, round %s:' "$bin" "$round"
        taskset -c 1-6 dnsperf -m "$transport" -s 127.0.0.1 -p 5399 -d /queries.txt -l 10 -c 8 -T 4 -q 500 |
            grep -E 'per second|lost|Average Latency' | tr -s ' ' | tr '\n' ' '
        echo
        kill "$pid"
        wait "$pid" 2>/dev/null || true
    done
done
