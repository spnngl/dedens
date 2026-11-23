"""The zones and queries of the `authoritative` modes (D213): the root zone of the capture (`testdata/authoritative`),
a generated zone of exactly BIG_RECORDS records, and the query files built from their names.

Everything here is deterministic: the zone text and the queries come from the capture and from `random.Random`'s
`random()` alone (the one method whose stream no Python release has changed), so that `corpora.sha256` can pin the
query files. The generated zone is signed by `kzonesign` in the pinned Knot image (compare.py), whose signatures
and keys differ at each run.
"""

import collections
import random

BIG_APEX = "big.example."
BIG_RECORDS = 100_000
CORPUS_LINES = 1_000_000
CHECK_LINES = 1000  # the first lines of the query file, which the check pass asks: compare.py's CHECK_QUERIES
SEED = 213
DELEGATIONS = 2000  # `d0000`...: two NS each, out of the zone
CNAMES = 3000  # `c0000`...: to a host
WILDCARDS = 100  # `*.w000`...
DNAMES = 10  # `dn0`...: to `pool`, which has a wildcard
LABELS = ("www", "mail", "ns1", "api", "ftp", "smtp", "vpn", "cdn")
ROOT_TYPES = ("SOA", "NS", "DNSKEY", "AAAA")  # the apex's: AAAA is NODATA

# The share of each kind of query, in percent, and its rcode: the mix of D213.
ROOT_MIX = (("referral", 50, "NOERROR"), ("ds", 15, "NOERROR"), ("nxdomain", 25, "NXDOMAIN"), ("apex", 10, "NOERROR"))
BIG_MIX = (("a", 40, "NOERROR"), ("aaaa", 10, "NOERROR"), ("txt", 5, "NOERROR"), ("nodata", 5, "NOERROR"),
           ("nxdomain", 15, "NXDOMAIN"), ("referral", 10, "NOERROR"), ("cname", 5, "NOERROR"),
           ("wildcard", 5, "NOERROR"), ("dname", 5, "NOERROR"))


def big_zone():
    """The text of the unsigned zone, BIG_RECORDS records, and the number of its hosts (`h00000`...: A, AAAA and
    TXT each)."""
    records = ["@ IN SOA ns1 hostmaster 1 3600 900 604800 300", "@ IN NS ns1", "@ IN NS ns2",
               "ns1 IN A 198.51.100.1", "ns2 IN A 198.51.100.2", "@ IN MX 10 mail", "mail IN A 198.51.100.3",
               '@ IN TXT "v=spf1 -all"']
    for i in range(DELEGATIONS):
        records += [f"d{i:04d} IN NS ns1.delegee.example.org.", f"d{i:04d} IN NS ns2.delegee.example.org."]
    records += [f"*.w{i:03d} IN A 198.51.100.4" for i in range(WILDCARDS)]
    records += [f"dn{i} IN DNAME pool" for i in range(DNAMES)]
    records += ["*.pool IN A 198.51.100.5"]
    records += [f"c{i:04d} IN CNAME h{i:05d}" for i in range(CNAMES)]
    hosts = (BIG_RECORDS - len(records)) // 3
    for i in range(hosts):
        records += [f"h{i:05d} IN A 198.18.{i >> 8 & 255}.{i & 255}", f"h{i:05d} IN AAAA 2001:db8::{i:x}",
                    f'h{i:05d} IN TXT "bench {i}"']
    # The one or two records the division leaves out: A records of further hosts.
    records += [f"x{i:03d} IN A 198.51.100.6" for i in range(BIG_RECORDS - len(records))]
    return "\n".join([f"$ORIGIN {BIG_APEX}", "$TTL 3600", *records]) + "\n", hosts


def generic_dnames(zone_text):
    """The zone with each DNAME in its generic form (RFC 3597 §5): the loader has no text form of the type (it is
    opaque to it, `crates/dedens-bench/benches/zone.rs` writes it so too), while Knot writes the signed zone's in
    the mnemonic form. A target is an absolute name, which is all kzonesign writes."""
    out = []
    for line in zone_text.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] == "DNAME":
            wire = b"".join(bytes([len(label)]) + label.encode() for label in fields[3].rstrip(".").split(".")) + b"\0"
            line = f"{fields[0]}\t{fields[1]}\tDNAME\t\\# {len(wire)} {wire.hex()}"
        out.append(line)
    return "\n".join(out) + "\n"


def root_names(zone_text):
    """The delegated names of the root zone, and those with a DS: the owners of its NS and DS records."""
    delegated, signed = set(), set()
    for line in zone_text.splitlines():
        fields = line.split("\t")
        if len(fields) >= 4 and fields[0] != "." and fields[2] == "IN":
            if fields[3] == "NS":
                delegated.add(fields[0].rstrip("."))
            elif fields[3] == "DS":
                signed.add(fields[0].rstrip("."))
    return sorted(delegated), sorted(signed)


def pick(rng, items):
    return items[int(rng.random() * len(items))]


def hexname(rng, digits=8):
    return f"{int(rng.random() * 16 ** digits):0{digits}x}"


def root_query(rng, kind, delegated, signed):
    if kind == "referral":
        return f"{pick(rng, LABELS)}{hexname(rng, 3)}.{pick(rng, delegated)}. A"
    if kind == "ds":
        return f"{pick(rng, signed)}. DS"
    if kind == "nxdomain":
        name = f"{hexname(rng)}."
        return (f"www.{name}" if rng.random() < 0.5 else name) + " A"
    return f". {pick(rng, ROOT_TYPES)}"


def big_query(rng, kind, hosts):
    i = int(rng.random() * hosts)
    apex = BIG_APEX
    return {
        "a": f"h{i:05d}.{apex} A",
        "aaaa": f"h{i:05d}.{apex} AAAA",
        "txt": f"h{i:05d}.{apex} TXT",
        "nodata": f"h{i:05d}.{apex} MX",
        "nxdomain": f"{hexname(rng)}.{apex} A",
        "referral": f"www.d{int(rng.random() * DELEGATIONS):04d}.{apex} A",
        "cname": f"c{int(rng.random() * CNAMES):04d}.{apex} A",
        "wildcard": f"{hexname(rng, 4)}.w{int(rng.random() * WILDCARDS):03d}.{apex} A",
        "dname": f"{hexname(rng, 4)}.dn{int(rng.random() * DNAMES)}.{apex} A",
    }[kind]


def weighted(rng, mix):
    """The kind of `mix` a draw falls in: its share is in percent."""
    x = rng.random() * 100
    for kind, share, rcode in mix:
        x -= share
        if x < 0:
            return kind, rcode
    return mix[-1][0], mix[-1][2]


def corpus(zones, root_zone_text, hosts):
    """The query file for `zones` (`root`, `big`): CORPUS_LINES `name type` lines, each zone's mix in turn at random,
    and the rcodes the first CHECK_LINES must be answered with (a Counter)."""
    rng = random.Random(SEED)
    delegated, signed = root_names(root_zone_text)
    lines, expected = [], collections.Counter()
    for n in range(CORPUS_LINES):
        zone = pick(rng, zones)
        if zone == "root":
            kind, rcode = weighted(rng, ROOT_MIX)
            lines.append(root_query(rng, kind, delegated, signed))
        else:
            kind, rcode = weighted(rng, BIG_MIX)
            lines.append(big_query(rng, kind, hosts))
        if n < CHECK_LINES:
            expected[rcode] += 1
    return lines, expected
