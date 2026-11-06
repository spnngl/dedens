#!/usr/bin/env bash
# One measuring session on the VPS. Usage: session.sh <results dir> <phase>...   phases: startup rounds divan churn soak:<names>
# io_uring is allowed for the session and refused again at the end, whatever happens.
set -uo pipefail
res=$1; shift
mkdir -p "$res"
note() { echo "$*" | tee -a "$res/session.txt"; }
restore() { sudo -n sysctl -q kernel.io_uring_disabled=2; note "kernel.io_uring_disabled restored to $(sysctl -n kernel.io_uring_disabled) at $(date +%T)"; }
trap restore EXIT
sudo -n sysctl -q kernel.io_uring_disabled=0
note "== session $(date -Is) phases: $*"
note "kernel $(uname -r); io_uring_disabled=$(sysctl -n kernel.io_uring_disabled)"
note "THP enabled: $(cat /sys/kernel/mm/transparent_hugepage/enabled); defrag: $(cat /sys/kernel/mm/transparent_hugepage/defrag)"
note "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'none (no cpufreq in the VM)')"
note "cpu: $(lscpu | sed -n 's/^Model name: *//p') x $(nproc)"
note "podman $(podman --version)"
for _ in $(seq 20); do
    l=$(cut -d' ' -f1 /proc/loadavg)
    if awk -v l="$l" 'BEGIN { exit !(l < 1.0) }'; then break; fi
    note "load average $l, waiting"; sleep 30
done
note "load average at start: $(cat /proc/loadavg)"
ct() { # ct <results dir> <alloc.sh args>
    local r=$1; shift
    mkdir -p "$r"
    podman run --rm --security-opt seccomp=unconfined --security-opt label=disable -e DEDENS_ROUNDS -e DEDENS_BINARIES \
        -v ~/alloc/bin:/bins:ro -v ~/alloc/src:/src:ro -v "$r":/results -v ~/alloc/alloc.sh:/alloc.sh:ro \
        dedens-abench bash /alloc.sh "$@"
}
for phase in "$@"; do
    note "-- $phase start $(date +%T), load $(cut -d' ' -f1-3 /proc/loadavg)"
    case $phase in
        startup) ct "$res" startup ;;
        rounds) ct "$res" rounds ;;
        divan) ct "$res" divan ;;
        churn) ct "$res" churn 120 ;;
        soak:*) DEDENS_BINARIES="${phase#soak:}" ct "$res/soak" churn 3600 ;;
    esac
    note "-- $phase done $(date +%T), load $(cut -d' ' -f1-3 /proc/loadavg)"
done
