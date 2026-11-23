#!/usr/bin/env bash
# dedensd against TelltaleDNS, Unbound and CoreDNS under dnsperf, on Linux, each server in its own container on
# its own cores, all forwarding to one neutral Knot DNS: `just bench-compare <mode> [cores]`. Builds what it runs
# (the working tree's dedensd, the others at the versions below), then compare/compare.py measures and prints a
# table per configuration (shipped, lean), and writes target/compare/results/<time>-<mode>.json. On a Mac, the
# engine's Linux VM (`podman machine`) is the Linux: the numbers are indicative, the VPS's are the record (D213).
# authoritative, authoritative-dnssec: dedensd, Knot and NSD each serving the root zone capture and a generated
# 100k-record zone from files, no upstream, answers compared with Knot's (D213); they build no TelltaleDNS, Unbound
# or CoreDNS. DEDENS_ZONES ("root big"): `root`, `big` or both.
# Modes: udp, tcp, dot (from the cache); forward, forward-tcp (the cache-hot names from a cold cache); miss (unique
# names, each upstream); dnssec (miss, validated); blocked (the 1M-name list); recurse, recurse-dnssec (unique
# names resolved from the root hints of a mini Internet of three Knot authorities on 127.0.0.2-4:53, which needs
# `net.ipv4.ip_unprivileged_port_start` at 53 or less; dedensd and Unbound only, D201); crosscheck (TelltaleDNS's
# own `bench/run.sh smoke --target` against dedensd, once). `cores` (1): the server's cores, 0 to cores-1; Knot on
# the last core, dnsperf on those between, unless DEDENS_SERVER_CPUS, DEDENS_KNOT_CPUS or DEDENS_LOAD_CPUS say.
# DEDENS_CONTAINER: the engine (docker; podman). DEDENS_ROUNDS (2), DEDENS_DURATION (10, seconds a run),
# DEDENS_SERVERS ("dedensd telltale unbound coredns"; a name twice for an A/A run, `dedensd-8mib` for dedensd on an
# 8 MiB cache, `broken` for the CoreDNS that answers SERVFAIL, which the answer check must fail), DEDENS_CONFIGS ("lean shipped").
# Each server starts afresh before it is measured, and fails the run unless it answers the check file's 1000
# questions with the mode's rcode, none lost, and `dedens` gets Knot's answers to 20 of them. A run is void, out of
# the medians, when Knot or, at saturation, dnsperf is busier than 90% of its cores, when dnsperf held to a rate
# sends 1% less, or when 1% of its queries are lost or get another rcode; a saturation run losing 1% is run again
# 10% under what it answered, twice at most. Rounds alternate the servers' order.
set -euo pipefail
mode="${1:?usage: compare.sh <mode> [cores]}"
cores="${2:-1}"
case $mode in
    udp | tcp | dot | forward | forward-tcp | miss | dnssec | blocked | recurse | recurse-dnssec | crosscheck) ;;
    authoritative | authoritative-dnssec) ;;
    *) echo "unknown mode $mode: udp, tcp, dot, forward, forward-tcp, miss, dnssec, blocked, recurse, recurse-dnssec, crosscheck, authoritative or authoritative-dnssec" >&2; exit 2 ;;
esac
[[ $(uname) == Linux || $(uname) == Darwin ]] ||
    { echo "compare.sh measures Linux servers (io_uring, cgroups): run it on Linux, or on a Mac with a podman machine" >&2; exit 2; }

# Each version raised by hand to the last tag before a run, never between runs.
telltale_version=0.6.0
telltale_commit=940f136b65943f482b53ee000f93164c72f9b125 # the tag's, which a moved tag would not match
unbound_version=1.26.2
unbound_sha256=d8ee7aa6bbb3ff1be7d9e57637d0d0ec2f18273a8efff1a0afe2c665858b96f7
coredns_version=1.15.0
coredns_go=1.27.3 # CoreDNS's .go-version at its tag
knot_version=3.6.2
knot_image=docker.io/cznic/knot:v$knot_version@sha256:174b0fcb24c6c3bc5065c9d1ce46b588eec607a5f32bc40ff0cda60150f00bd9
nsd_version=4.15.4
nsd_sha256=74a095fdb774a157c8aec9009e440fc3d2ba94c4372ae9ed86588c1719d1df2f
# The 1M names of `blocked`: the first million of HaGeZi's Threat Intelligence Feeds, at a commit. GPL-3.0, so
# fetched, not kept here.
blocklist_url=https://raw.githubusercontent.com/hagezi/dns-blocklists/8fa17506631ad3db94df1530264194c35c0a91d7/wildcard/tif-onlydomains.txt
blocklist_sha256=495c10af0ecda4ac9ff98d5b562ef4e9c0402297b5f5d9c35b6e5b66573b9b9c

engine="${DEDENS_CONTAINER:-docker}"
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
work="$repo/target/compare"
telltale_src="$work/src/telltaledns-$telltale_version"
mkdir -p "$work/bin" "$work/src"

copy_out() { # copy_out <image> <path in it> <destination>
    local id
    id="$("$engine" create "$1" /none)"
    "$engine" cp "$id:$2" "$3"
    "$engine" rm "$id" >/dev/null
}

nsd_args=(--build-arg "NSD_VERSION=$nsd_version" --build-arg "NSD_SHA256=$nsd_sha256")
if [[ $mode == authoritative* ]]; then
    echo "building the images (NSD $nsd_version)" >&2
    image="localhost/dedens-compare:nsd-$nsd_version"
    "$engine" build -q -t "$image" --target authoritative "${nsd_args[@]}" -f "$here/compare/Containerfile" \
        "$here/compare" >/dev/null
else
    echo "building the images (Unbound $unbound_version, CoreDNS $coredns_version, TelltaleDNS $telltale_version)" >&2
    image="localhost/dedens-compare:unbound-$unbound_version-coredns-$coredns_version"
    "$engine" build -q -t "$image" --build-arg "UNBOUND_VERSION=$unbound_version" \
        --build-arg "UNBOUND_SHA256=$unbound_sha256" --build-arg "COREDNS_VERSION=$coredns_version" \
        --build-arg "COREDNS_GO=$coredns_go" "${nsd_args[@]}" -f "$here/compare/Containerfile" "$here/compare" >/dev/null
fi
"$engine" build -q -t localhost/dedens-compare-dedensd --target binaries -f "$repo/Containerfile" "$repo" >/dev/null
copy_out localhost/dedens-compare-dedensd /dedensd "$work/bin/dedensd"
copy_out localhost/dedens-compare-dedensd /dedens "$work/bin/dedens"
if [[ $mode != authoritative* ]]; then
    [[ -d $telltale_src ]] ||
        git clone -q --depth 1 --branch "v$telltale_version" https://github.com/paimonsoror/telltaledns "$telltale_src"
    [[ $(git -C "$telltale_src" rev-parse HEAD) == "$telltale_commit" ]] ||
        { echo "$telltale_src is not TelltaleDNS's commit $telltale_commit" >&2; exit 1; }
    "$engine" build -q -t "localhost/dedens-compare-telltale:$telltale_version" --target bin \
        --build-arg "TELLTALE_BUILD_VERSION=$telltale_version" "$telltale_src" >/dev/null
    copy_out "localhost/dedens-compare-telltale:$telltale_version" /telltale "$work/bin/telltale"
fi
"$engine" pull -q "$knot_image" >/dev/null

if [[ $mode == blocked ]]; then
    list="$work/src/blocklist-$blocklist_sha256.txt"
    if [[ ! -f $list ]]; then
        curl -fsSL -o "$list.part" "$blocklist_url"
        echo "$blocklist_sha256  $list.part" | sha256sum -c --quiet -
        mv "$list.part" "$list"
    fi
    export DEDENS_BLOCKLIST="$list"
fi

export DEDENS_CONTAINER="$engine" DEDENS_IMAGE="$image" DEDENS_KNOT_IMAGE="$knot_image" DEDENS_TELLTALE_SRC="$telltale_src"
export DEDENS_VERSIONS="telltale=$telltale_version unbound=$unbound_version coredns=$coredns_version knot=$knot_version nsd=$nsd_version"
exec python3 "$here/compare/compare.py" "$mode" "$cores" "$work"
