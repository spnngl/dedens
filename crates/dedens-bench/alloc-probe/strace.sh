#!/bin/bash
# Files opened and threads started by each allocator's prebuilt release `dedensd`: `strace -f` from launch, a few
# queries, then more. Run as the user on the host that serves (the VPS), where `strace` and `dig` exist and
# `sudo -n` works. Env: BINS (default ~/alloc/bin: <BINS>/<name>/dedensd), NAMES, OUT (default ~/alloc03), PORT.
# The traced server caches and forwards to a back server (musl-mallocng, untraced, port 5400).
# Output: <OUT>/<name>.strace (every line stamped), .mark (when the queries began), .log (dedensd's stderr).
# `kernel.io_uring_disabled` is set to 0 so that io_uring is exercised, and restored on exit.
set -u
bins="${BINS:-$HOME/alloc/bin}"
out="${OUT:-$HOME/alloc03}"
port="${PORT:-5361}"
names="${NAMES:-musl-mallocng musl-mimalloc musl-mimalloc-min musl-mimalloc-secure musl-jemalloc glibc-malloc glibc-mimalloc}"
mkdir -p "$out"
cd "$out" || exit 1
old=$(cat /proc/sys/kernel/io_uring_disabled)
back=""
restore() {
    [ -n "$back" ] && kill "$back" 2>/dev/null
    sudo -n sysctl -q kernel.io_uring_disabled="$old"
}
trap restore EXIT
sudo -n sysctl -q kernel.io_uring_disabled=0
cat >back.yaml <<'EOF'
listen: ['127.0.0.1:5400']
threads: 1
pipeline: [local]
stages:
  local:
    type: blocklist
    entries: [example.com, example.org, iana.org, churn.test]
    action: 'null'
EOF
cat >cfg.yaml <<EOF
listen: ['127.0.0.1:$port']
threads: 2
pipeline: [cache, up]
stages:
  cache:
    type: cache
  up:
    type: forward
    servers: ['127.0.0.1:5400']
EOF
"$bins/musl-mallocng/dedensd" --config back.yaml 2>back.log &
back=$!
q() { dig +short +tries=1 +time=2 @127.0.0.1 -p "$port" "$@" >/dev/null; }
for name in $names; do
    rm -f "$name".*
    strace -f -ttt -e trace=%file,clone,clone3 -o "$name.strace" "$bins/$name/dedensd" --config cfg.yaml 2>"$name.log" &
    front=$!
    sleep 3
    date +%s.%N >"$name.mark"
    for i in $(seq 1 300); do
        q "a$i.example.com" A
        q example.org AAAA
        [ $((i % 10)) -eq 0 ] && q +tcp "b$i.example.com" A
    done
    for i in $(seq 301 1500); do q "c$i.example.com" A; done
    kill "$(pgrep -P "$front" -x dedensd)"
    wait "$front"
    echo "$name: $(grep -c -E 'clone3?\(' "$name.strace") clone calls, $(wc -l <"$name.strace") traced calls"
done
