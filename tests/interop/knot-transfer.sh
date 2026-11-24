#!/usr/bin/env bash
# Knot DNS 3.6.2 as a secondary of dedensd (D214): for each test zone, dedensd serves it on the host and knotd, in
# D203's image (`just authoritative-images`), transfers it, unsigned then signed with a TSIG key (HMAC-SHA256) that
# the zone's `transfer` line requires. Knot must hold the zone at dedensd's serial with as many records as `kdig`
# reads in dedensd's AXFR, its log saying AXFR. Then the zone changes and dedensd reloads it: `ISI.EDU.` gains a
# record (serial 20 to 21), the root goes from the capture at 2026111401 to the one at 2026112201; Knot refreshes
# and its log must say IXFR. Needs the image, a container engine (`DEDENS_CONTAINER`, docker by default) whose
# containers reach the host as `host.docker.internal`, `kdig` and `openssl` on the host. Run: `just transfer-interop`.
# Prints one line a transfer and exits 1 at the first failure, the logs of both servers kept in the printed directory.
set -euo pipefail

engine="${DEDENS_CONTAINER:-docker}"
image=dedens-captures-knot:3.6.2
top="$(git rev-parse --show-toplevel)"
cargo build -q -p dedensd
dedensd="$top/target/debug/dedensd"
work="$(mktemp -d)"
chmod 777 "$work"
port=$((20000 + RANDOM % 20000))
secret="$(openssl rand -base64 32)"
container="dedens-knot-transfer-$$"
pid=""

stop() {
    if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; pid=""; fi
    "$engine" rm -f "$container" >/dev/null 2>&1 || true
}
fail() {
    echo "FAILED: $*" >&2
    "$engine" logs "$container" >"$work/knot.log" 2>&1 || true
    stop
    echo "logs in $work" >&2
    exit 1
}
trap stop EXIT

host="$("$engine" run --rm --add-host=host.docker.internal:host-gateway --entrypoint getent "$image" \
    ahostsv4 host.docker.internal | awk '{ print $1; exit }')"
[[ -n $host ]] || fail "host.docker.internal does not resolve in the container"
printf '%s' "$secret" >"$work/secret"
chmod 600 "$work/secret"

# Waits up to 120 s for `$1` to succeed.
wait_for() {
    for _ in $(seq 240); do
        if eval "$1"; then return 0; fi
        sleep 0.5
    done
    return 1
}

# dedensd serving zone `$1` from file `$2`, its transfers signed when `$3` is `signed`.
serve() {
    local keys="" key=""
    if [[ $3 == signed ]]; then
        keys="keys:
  - {name: transfer, algorithm: hmac-sha256, secret_file: '$work/secret'}"
        key=", key: transfer"
    fi
    cat >"$work/dedensd.yaml" <<EOF
$keys
listen: ['0.0.0.0:$port']
pipeline: [zones]
stages:
  zones:
    type: authoritative
    zones:
      - {name: '$1', file: '$2', transfer: [{networks: ['0.0.0.0/0', '::/0']$key}]}
EOF
    : >"$work/dedensd.log"
    "$dedensd" --config "$work/dedensd.yaml" 2>"$work/dedensd.log" &
    pid=$!
    wait_for "grep -q '\"serving\"' '$work/dedensd.log'" || fail "dedensd does not serve $2"
}

# knotd, secondary of dedensd for zone `$1`, signing with the key when `$2` is `signed`.
knot() {
    local key="" ref=""
    if [[ $2 == signed ]]; then
        key="key:
  - id: transfer
    algorithm: hmac-sha256
    secret: $secret"
        ref="key: transfer"
    fi
    rm -rf "$work/knot"
    mkdir -m 777 "$work/knot"
    # The control socket and the databases in the container: a host's mount may not take them.
    cat >"$work/knot/knot.conf" <<EOF
server:
  rundir: /tmp
  listen: 127.0.0.1@5300
log:
  - target: stdout
    any: info
database:
  storage: /tmp
$key
remote:
  - id: dedensd
    address: $host@$port
    $ref
zone:
  - domain: $1
    master: dedensd
    storage: /tmp
    zonefile-load: none
    zonefile-sync: -1
    journal-content: changes
EOF
    "$engine" run -d --name "$container" --add-host=host.docker.internal:host-gateway -v "$work/knot:/knot" \
        --entrypoint knotd "$image" -c /knot/knot.conf >/dev/null
}

knotc() { "$engine" exec "$container" knotc -c /knot/knot.conf "$@"; }

# The serial dedensd serves for `$1`.
serial() { kdig @127.0.0.1 -p "$port" +short SOA "$1" | awk '{ print $3 }'; }

# Knot holds zone `$1` at dedensd's serial, as many records as dedensd's AXFR read by kdig, its log naming `$2`.
check() {
    local apex="$1" kind="$2" mode="$3" want tsig=()
    want="$(serial "$apex")"
    [[ -n $want ]] || fail "dedensd does not answer the SOA of $apex"
    wait_for "knotc zone-status '$apex' 2>/dev/null | grep -q 'serial: $want '" \
        || fail "$kind of $apex ($mode): Knot is not at serial $want"
    "$engine" logs "$container" 2>&1 | grep -qi "\[$apex\] $kind, incoming, remote .*, finished" \
        || fail "$kind of $apex ($mode): Knot's log has no $kind"
    [[ $mode == signed ]] && tsig=(-y "hmac-sha256:transfer:$secret")
    local sent held
    sent="$(kdig @127.0.0.1 -p "$port" "${tsig[@]}" +noall +answer AXFR "$apex" | grep -cv '^;')"
    held="$(knotc zone-read "$apex" | grep -c .)"
    [[ $((sent - 1)) -eq $held ]] || fail "$kind of $apex ($mode): Knot holds $held records, dedensd sent $((sent - 1))"
    echo "ok $kind $apex serial $want, $held records ($mode)"
}

testdata="$top/testdata"
cp "$testdata/zones/rfc1035_isi_mailboxes.zone" "$work/mailboxes.zone"
sed 's/<SUBSYS>ISI-MAILBOXES.TXT/mailboxes.zone/' "$testdata/zones/rfc1035_isi.zone" >"$work/isi.zone"
zones=(
    ". $testdata/zones/rfc1034_root.zone"
    "ISI.EDU. $work/isi.zone"
    "example. $testdata/zones/rfc4035_appendix_a.zone"
    "example. $testdata/zones/rfc5155_appendix_a.zone"
    "example. $testdata/zones/nsec3_source.zone"
    "example. $testdata/authoritative/zones/nsec3_signed.zone"
    "zonetransfer.me. $testdata/authoritative/zones/zonetransfer.me.zone"
    ". $testdata/authoritative/zones/root.zone"
)
for mode in unsigned signed; do
    for zone in "${zones[@]}"; do
        read -r apex file <<<"$zone"
        serve "$apex" "$file" "$mode"
        knot "$apex" "$mode"
        check "$apex" AXFR "$mode"
        stop
    done

    # IXFR: the next version of ISI.EDU., then of the root.
    cp "$work/isi.zone" "$work/isi-now.zone"
    cp "$work/mailboxes.zone" "$work/mailboxes-before.zone"
    serve ISI.EDU. "$work/isi-now.zone" "$mode"
    knot ISI.EDU. "$mode"
    check ISI.EDU. AXFR "$mode"
    sed -i.bak 's/20     ; SERIAL/21     ; SERIAL/' "$work/isi-now.zone"
    echo "MOE MB B.ISI.EDU." >>"$work/mailboxes.zone"
    kill -HUP "$pid"
    wait_for "grep -q '\"reloaded\"' '$work/dedensd.log'" || fail "dedensd does not reload ISI.EDU."
    knotc zone-refresh ISI.EDU. >/dev/null
    check ISI.EDU. IXFR "$mode"
    stop
    cp "$work/mailboxes-before.zone" "$work/mailboxes.zone"

    cp "$testdata/authoritative/zones/root-previous.zone" "$work/root.zone"
    serve . "$work/root.zone" "$mode"
    knot . "$mode"
    check . AXFR "$mode"
    cp "$testdata/authoritative/zones/root.zone" "$work/root.zone"
    kill -HUP "$pid"
    wait_for "grep -q '\"reloaded\"' '$work/dedensd.log'" || fail "dedensd does not reload the root"
    knotc zone-refresh . >/dev/null
    check . IXFR "$mode"
    stop
done
rm -rf "$work"
