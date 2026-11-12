#!/usr/bin/env bash
# Queries per second of dedensd under dnsperf, on Linux (io_uring), the server on one core: the git ref $1
# (default HEAD) against the working tree, $DEDENS_ROUNDS rounds (2) of each, alternating base and tree so a noisy
# neighbour hits both, in mode $2: udp (the default) or tcp, the cache answering every query after the first, which
# goes to 1.1.1.1 (the network is needed for those); or forward or forward-tcp, over UDP or TCP without a cache,
# every query going upstream over the same transport to a second dedensd (the working tree's, on its own core)
# answering from its cache; or two-sockets, the cache answering on two UDP ports of the one core, the first flooded
# by dnsperf, the second asked at 2000 queries/s: the latency of the second (D107) and the queries the flood lost.
# Runs inside the container `just bench-dnsperf` starts, with the repository at /src (read-only), a target
# directory at /target. Cores: the server on 0, the second dedensd on $DEDENS_BACK_CPU (7), dnsperf on
# $DEDENS_LOAD_CPUS (1-6; two-sockets: its flood, and its 2000 queries/s on $DEDENS_BACK_CPU, which that mode
# leaves free); fewer than eight cores need others.
# DEDENS_PERF=1 profiles instead (D138): only the working tree, one round, built with line tables and symbols, the
# server (the front one when forwarding) under `perf record --call-graph dwarf`; the report goes to /profile (the
# host's target/profile), Rust names demangled. Kernel names need `kernel.perf_event_paranoid` of 1 or less and
# `kernel.kptr_restrict` 0 on the host (perf reads /proc/kallsyms as an unprivileged user). The queries per second
# printed are those of a profiled server, not a measure.
set -euo pipefail
base="${1:-HEAD}"
mode="${2:-udp}"
perf="${DEDENS_PERF:-}"
apt-get update -qq >/dev/null
apt-get install -y -qq dnsperf dnsutils git ${perf:+linux-perf} >/dev/null 2>&1
if [[ -n $perf ]]; then
    command -v perf >/dev/null || { echo "DEDENS_PERF: perf did not install" >&2; exit 1; }
    # perf's demangler does not read Rust's v0 symbols.
    cargo install -q --locked rustfilt
    export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_PROFILE_RELEASE_STRIP=false
fi
git config --global --add safe.directory /src
# No server outlives the script: a leftover one would answer the next run's queries.
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT
build() { # build <name>: /<name> into /<name>.bin, each in its own target directory (cargo would take one
    # checkout's artifacts for the other's: same relative paths, older modification times)
    (cd "/$1" && CARGO_TARGET_DIR="/target/$1" cargo build -q --release -p dedensd)
    cp "/target/$1/release/dedensd" "/$1.bin"
}
rm -rf /base /tree
if [[ -z $perf ]]; then
    git clone -q /src /base && git -C /base checkout -q "$base"
    build base
fi
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
cat >/two.yaml <<'EOF'
listen: ['127.0.0.1:5399', '127.0.0.1:5398']
pipeline: [cache, up]
stages:
  cache:
    type: cache
  up:
    type: forward
    servers: ['1.1.1.1']
EOF
back_cpu="${DEDENS_BACK_CPU:-7}" load_cpus="${DEDENS_LOAD_CPUS:-1-6}" rounds="${DEDENS_ROUNDS:-2}"
bins=(base tree)
[[ -n $perf ]] && bins=(tree) rounds=1
serve() { # serve <bin> <config>: the server on core 0 in the background; $pid is its process (perf's when profiling)
    if [[ -n $perf ]]; then
        perf record -q -o /perf.data -F 999 --call-graph dwarf -- taskset -c 0 "/$1.bin" --config "$2" 2>/dev/null &
    else
        taskset -c 0 "/$1.bin" --config "$2" 2>/dev/null &
    fi
    pid=$!
}
config=/perf.yaml transport="$mode"
[[ $mode == two-sockets ]] && config=/two.yaml transport=udp
if [[ $mode == forward* ]]; then
    config=/front.yaml transport=udp
    [[ $mode == forward-tcp ]] && transport=tcp
    taskset -c "$back_cpu" /tree.bin --config /back.yaml 2>/dev/null &
fi
printf 'example.com A\nexample.org A\nwww.example.com AAAA\niana.org MX\n' >/queries.txt
for round in $(seq "$rounds"); do
    for bin in "${bins[@]}"; do
        serve "$bin" "$config"
        sleep 1
        # Each query of the list once, so the cache holds them: a SERVFAIL here would have dnsperf time failures.
        answered=$(dig @127.0.0.1 -p 5399 +noall +comments example.com A iana.org MX example.org A www.example.com AAAA |
            grep -c 'status: NOERROR' || true)
        [[ $answered == 4 ]] || { echo "$bin: $answered of 4 warm-up queries answered NOERROR" >&2; exit 1; }
        printf '%s, round %s:' "$bin" "$round"
        if [[ $mode == two-sockets ]]; then
            taskset -c "$load_cpus" dnsperf -m udp -s 127.0.0.1 -p 5399 -d /queries.txt -l 12 -c 8 -T 4 -q 500 >/flood.txt &
            flood=$!
            sleep 1
            taskset -c "$back_cpu" dnsperf -m udp -s 127.0.0.1 -p 5398 -d /queries.txt -l 10 -c 1 -T 1 -Q 2000 -q 100 |
                grep -E 'per second|lost|Average Latency|Response codes' | tr -s ' ' | tr '\n' ' '
            wait "$flood"
            grep -E 'lost' /flood.txt | tr -s ' ' | sed 's/^/ flood:/'
        else
            taskset -c "$load_cpus" dnsperf -m "$transport" -s 127.0.0.1 -p 5399 -d /queries.txt -l 10 -c 8 -T 4 -q 500 |
                grep -E 'per second|lost|Average Latency|Response codes' | tr -s ' ' | tr '\n' ' '
        fi
        echo
        kill "$pid"
        wait "$pid" 2>/dev/null || true
        if [[ -n $perf ]]; then
            mkdir -p /profile
            report=(perf report -i /perf.data --stdio --no-inline)
            # Self time, then each function with its callees (--children) and the stacks through the top ones.
            {
                "${report[@]}" --no-children -g none --percent-limit 0.5
                "${report[@]}" --children -g caller,0.5,callee,function,percent --max-stack 12 --percent-limit 5
            } 2>/dev/null | rustfilt | sed 's/ *$//' | cut -c1-200 >"/profile/$mode.txt"
            echo "perf report: target/profile/$mode.txt"
        fi
    done
done
