#!/usr/bin/env bash
# dedensd's allocators under dnsperf (D152, the experiment branch): prebuilt binaries side by side, in the
# container of `run.sh` (dnsperf, dig, taskset; podman needs `--security-opt seccomp=unconfined` for io_uring, and
# the host's `kernel.io_uring_disabled` at 0). The binaries are /bins/<name>/dedensd, `$DEDENS_BINARIES` (all of
# them by default) names the ones compared; results go to /results.
#
#   alloc.sh rounds   $DEDENS_ROUNDS (8) rounds; each runs, in each mode and core count, every binary back to back,
#                     in an order shuffled for the round, $DEDENS_SECS (8) seconds a run: runs.tsv
#   alloc.sh churn S  S seconds of unique names, more than the cache's budget holds, one binary after the other in
#                     a shuffled order: churn-<name>.tsv, a line a second, then 20 s of rest (S=3600: the soak)
#   alloc.sh startup  the resident set of each binary just started, three times: startup.tsv
#   alloc.sh divan    the benches /bins/<name>/{server,cache,message} (cargo build --release --bench ...), which read the
#                     captured responses of /src (the repository, read-only): $DEDENS_ROUNDS rounds, each running every
#                     binary in a shuffled order on core 2 with 100 samples a bench: divan/<round>-<name>-<bench>.txt
#
# Cores (six vCPUs): one serving core: server 0, the back server 1, dnsperf 2-5 (udp, tcp: 2-5 too, the back idle);
# three: server 0-2, back 3, dnsperf 4-5 forwarding, 3-5 otherwise. The back server is always `$DEDENS_BACK`
# (musl-mallocng), whatever is measured. It answers every name locally (a blocklist, `null` action: an A or AAAA of 0.0.0.0
# or ::), so no run needs the network. The front caches (`udp`, `tcp`, `churn`) or forwards every query (`forward`,
# `forward-tcp`: upstream over the client's transport, as in run.sh).
set -euo pipefail
bins=/bins out=/results cfg=/cfg
rounds="${DEDENS_ROUNDS:-8}" secs="${DEDENS_SECS:-8}"
modes="${DEDENS_MODES:-udp tcp forward forward-tcp}" cores="${DEDENS_CORES:-1 3}"
read -r -a names <<<"${DEDENS_BINARIES:-$(ls "$bins" | tr '\n' ' ')}"
back_bin="${DEDENS_BACK:-musl-mallocng}"
mkdir -p "$cfg" "$out/raw" "$out/log"
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

write_configs() { # write_configs <front threads>
    cat >"$cfg/back.yaml" <<'EOF'
listen: ['127.0.0.1:5400']
threads: 1
pipeline: [local]
stages:
  local:
    type: blocklist
    entries: [example.com, example.org, iana.org, churn.test]
    action: 'null'
EOF
    cat >"$cfg/cache.yaml" <<EOF
listen: ['127.0.0.1:5399']
threads: $1
pipeline: [cache, up]
stages:
  cache:
    type: cache
  up:
    type: forward
    servers: ['127.0.0.1:5400']
EOF
    cat >"$cfg/forward.yaml" <<EOF
listen: ['127.0.0.1:5399']
threads: $1
pipeline: [up]
stages:
  up:
    type: forward
    servers: ['127.0.0.1:5400']
EOF
}

printf 'example.com A\nexample.org A\nwww.example.com AAAA\niana.org A\n' >"$cfg/queries.txt"

start() { # start <binary> <cpus> <config> <log>: in the background, $pid its process
    taskset -c "$2" "$bins/$1/dedensd" --config "$3" 2>"$4" &
    pid=$!
}
stop() { kill "$@" 2>/dev/null || true; wait "$@" 2>/dev/null || true; }
status() { awk -v k="$2" '$1 == k ":" { print $2 }' "/proc/$1/status"; } # status <pid> VmRSS|VmHWM: kB
driver() { sed -n 's/.*"driver":"\([a-z_]*\)".*/\1/p' "$1" | head -1; }
# The load average of the last minute.
load() { cut -d' ' -f1 /proc/loadavg; }

# dnsperf's text: `Queries per second`, `Average Latency (s)`, `Queries lost`, then `Latency bucket (s)`: one line a bucket,
# `low - high:  count`, in seconds. p99 is the upper edge of the bucket holding the 99th percentile of the completed
# queries, in milliseconds.
summary() { # summary <dnsperf output>: qps, average latency (ms), p99 (ms), lost, completed
    awk '
        /Queries completed:/ { completed = $3 }
        /Queries lost:/ { lost = $3 }
        /Queries per second:/ { qps = $4 }
        /Average Latency/ { avg = $4 * 1000 }
        /Latency bucket/ { hist = 1; next }
        hist && $2 == "-" { hi[n] = $3 + 0; cnt[n] = $4 + 0; total += $4; n++ }
        END {
            target = total * 0.99; run = 0; p99 = "NA"
            for (i = 0; i < n; i++) { run += cnt[i]; if (run >= target) { p99 = sprintf("%.3f", hi[i] * 1000); break } }
            printf "%s\t%.3f\t%s\t%s\t%s", qps, avg, p99, lost, completed
        }' "$1"
}

run_one() { # run_one <round> <mode> <cores> <binary>
    local round=$1 mode=$2 n=$3 bin=$4 transport=$mode config=$cfg/cache.yaml front back load_cpus
    case "$n:$mode" in
        1:*) front=0 back=1 load_cpus=2-5 ;;
        3:forward*) front=0-2 back=3 load_cpus=4-5 ;;
        *) front=0-2 back=3 load_cpus=3-5 ;;
    esac
    [[ $mode == forward* ]] && config=$cfg/forward.yaml transport=udp
    [[ $mode == forward-tcp ]] && transport=tcp
    write_configs "$n"
    start "$back_bin" "$back" "$cfg/back.yaml" "$out/log/back.log"
    local back_pid=$pid
    start "$bin" "$front" "$config" "$out/log/front-$bin.log"
    local front_pid=$pid
    sleep 1
    dig +short +tries=3 @127.0.0.1 -p 5399 example.com A iana.org A example.org A www.example.com AAAA >/dev/null
    local raw="$out/raw/$round-$mode-$n-$bin.txt"
    taskset -c "$load_cpus" dnsperf -m "$transport" -s 127.0.0.1 -p 5399 -d "$cfg/queries.txt" -l "$secs" \
        -c 8 -T 4 -q 500 -O latency-histogram >"$raw" 2>&1 || true
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$round" "$mode" "$n" "$bin" "$(summary "$raw")" "$(driver "$out/log/front-$bin.log")" \
        "$(status "$front_pid" VmHWM)" | tee -a "$out/runs.tsv"
    stop "$front_pid" "$back_pid"
}

rounds_main() {
    [[ -e $out/runs.tsv ]] || printf 'round\tmode\tcores\tbinary\tqps\tavg_ms\tp99_ms\tlost\tcompleted\tdriver\tvmhwm_kb\n' >"$out/runs.tsv"
    echo "load average at start: $(load)" | tee -a "$out/session.txt"
    for round in $(seq "$rounds"); do
        for n in $cores; do
            for mode in $modes; do
                for bin in $(printf '%s\n' "${names[@]}" | shuf); do
                    run_one "$round" "$mode" "$n" "$bin"
                done
            done
        done
        echo "round $round done, load average $(load)" | tee -a "$out/session.txt"
    done
}

# names.txt: a million unique names under churn.test, about five times what the cache's default 64 MiB holds.
churn_main() { # churn_main <seconds>
    local seconds=$1 rate="${DEDENS_RATE:-30000}"
    seq 0 999999 | awk '{ print "n" $1 ".churn.test A" }' >"$cfg/names.txt"
    write_configs 3
    for bin in $(printf '%s\n' "${names[@]}" | shuf); do
        local csv="$out/churn-$bin.tsv"
        printf 'second\tvmrss_kb\tvmhwm_kb\n' >"$csv"
        start "$back_bin" 3 "$cfg/back.yaml" "$out/log/back.log"
        local back_pid=$pid
        start "$bin" 0-2 "$cfg/cache.yaml" "$out/log/churn-$bin.log"
        local front_pid=$pid
        sleep 1
        dig +short @127.0.0.1 -p 5399 n1.churn.test A >/dev/null
        echo "churn $bin: load average $(load), driver $(driver "$out/log/churn-$bin.log"), start RSS $(status "$front_pid" VmRSS) kB"
        taskset -c 4-5 dnsperf -m udp -s 127.0.0.1 -p 5399 -d "$cfg/names.txt" -l "$seconds" -c 8 -T 4 -q 500 \
            -Q "$rate" -O latency-histogram >"$out/raw/churn-$bin.txt" 2>&1 &
        local load_pid=$!
        local t=0
        while kill -0 "$load_pid" 2>/dev/null; do
            printf '%s\t%s\t%s\n' "$t" "$(status "$front_pid" VmRSS)" "$(status "$front_pid" VmHWM)" >>"$csv"
            t=$((t + 1))
            sleep 1
        done
        for _ in $(seq 20); do
            printf '%s\t%s\t%s\n' "$t" "$(status "$front_pid" VmRSS)" "$(status "$front_pid" VmHWM)" >>"$csv"
            t=$((t + 1))
            sleep 1
        done
        echo "churn $bin: $(summary "$out/raw/churn-$bin.txt")" | tee -a "$out/churn.txt"
        stop "$front_pid" "$back_pid"
    done
}

startup_main() {
    [[ -e $out/startup.tsv ]] || printf 'binary\tthreads\tvmrss_kb\n' >"$out/startup.tsv"
    for n in 1 3; do
        write_configs "$n"
        for _ in 1 2 3; do
            for bin in "${names[@]}"; do
                start "$bin" "$([[ $n == 1 ]] && echo 0 || echo 0-2)" "$cfg/cache.yaml" "$out/log/startup.log"
                local front_pid=$pid
                sleep 2
                printf '%s\t%s\t%s\n' "$bin" "$n" "$(status "$front_pid" VmRSS)" | tee -a "$out/startup.tsv"
                stop "$front_pid"
            done
        done
    done
}

divan_main() {
    mkdir -p "$out/divan"
    for round in $(seq "$rounds"); do
        for bin in $(printf '%s\n' "${names[@]}" | shuf); do
            local run=(taskset -c 2)
            "${run[@]}" "$bins/$bin/server" --bench hit miss --skip guarded --skip dnssec --skip secure --sample-count 100 \
                --color never >"$out/divan/$round-$bin-server.txt"
            "${run[@]}" "$bins/$bin/cache" --bench insert --skip evicting --skip under --sample-count 100 \
                --color never >"$out/divan/$round-$bin-cache.txt"
            "${run[@]}" "$bins/$bin/message" --bench decode_dedens_owned --sample-count 100 --color never \
                >"$out/divan/$round-$bin-message.txt"
        done
        echo "divan round $round done, load average $(load)"
    done
}

case "${1:-rounds}" in
    rounds) rounds_main ;;
    churn) churn_main "${2:-120}" ;;
    startup) startup_main ;;
    divan) divan_main ;;
    *) echo "usage: alloc.sh rounds | churn SECONDS | startup | divan" >&2; exit 2 ;;
esac
