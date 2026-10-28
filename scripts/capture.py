#!/usr/bin/env python3
"""Capture real DNS responses into crates/dedens-proto/tests/testdata/<case>.bin.

Standard library only. Each case sends one query over UDP and, like a resolver, retries over TCP when the
answer is truncated, unless the case wants the truncated answer itself. The files are the raw messages; the
tests in tests/captured.rs decode them, and the fuzz smoke test uses them as seeds.

    python3 scripts/capture.py            # all cases
    python3 scripts/capture.py a nsid     # the named ones
"""

import pathlib
import secrets
import socket
import struct
import sys
from dataclasses import dataclass

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates/dedens-proto/tests/testdata"

A, NS, SOA, MX, TXT, AAAA, SRV, HTTPS, ANY, CAA = 1, 2, 6, 15, 16, 28, 33, 65, 255, 257

CLOUDFLARE = "1.1.1.1"
GOOGLE = "8.8.8.8"
CLOUDFLARE_NS = "ns3.cloudflare.com"  # authoritative, answers ANY as RFC 8482 asks

NSID = struct.pack("!HH", 3, 0)
COOKIE = struct.pack("!HH8s", 10, 8, bytes(range(1, 9)))


@dataclass
class Case:
    name: str
    qname: str
    qtype: int
    server: str = CLOUDFLARE
    # None: no EDNS; else the UDP payload size to advertise.
    payload: int | None = 1232
    dnssec: bool = False
    options: bytes = b""
    rd: bool = True
    # Keep the truncated UDP answer instead of retrying over TCP.
    keep_truncated: bool = False


CASES = [
    Case("a", "example.com", A),
    Case("aaaa", "cloudflare.com", AAAA),
    Case("ns", "example.com", NS),
    Case("soa", "example.com", SOA),
    Case("mx", "gmail.com", MX),
    Case("txt_large", "google.com", TXT, GOOGLE),
    Case("srv", "_sip._tls.microsoft.com", SRV, GOOGLE),
    Case("caa", "google.com", CAA, GOOGLE),
    Case("https", "cloudflare.com", HTTPS),
    Case("cname_chain", "www.github.com", A),
    Case("nxdomain_soa", "nonexistent.invalid", A),
    Case("any_rfc8482", "cloudflare.com", ANY, CLOUDFLARE_NS),
    Case("truncated", "google.com", TXT, GOOGLE, payload=None, keep_truncated=True),
    Case("ede", "dnssec-failed.org", A, dnssec=True),
    Case("nsid", "example.com", A, options=NSID),
    Case("cookie", "isc.org", SOA, "ns1.isc.org", options=COOKIE, rd=False),
]


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\0"


class BadReply(Exception):
    """A reply that does not answer the query sent."""


def question(case: Case) -> bytes:
    return encode_name(case.qname) + struct.pack("!HH", case.qtype, 1)


def build_query(case: Case) -> bytes:
    flags = 0x0100 if case.rd else 0  # RD
    additional = 0 if case.payload is None else 1
    msg = struct.pack("!HHHHHH", secrets.randbits(16), flags, 1, 0, 0, additional)
    msg += question(case)
    if case.payload is not None:
        ttl = 0x8000 if case.dnssec else 0
        msg += b"\0" + struct.pack("!HHIH", 41, case.payload, ttl, len(case.options)) + case.options
    return msg


def check_reply(case: Case, query: bytes, answer: bytes) -> None:
    """The reply carries the query's ID, the QR bit and the one question sent (RFC 5452 §9.1)."""
    q = question(case)
    if len(answer) < 12 + len(q):
        raise BadReply(f"reply of {len(answer)} bytes")
    if answer[:2] != query[:2]:
        raise BadReply("reply ID differs from the query's")
    if not answer[2] & 0x80:
        raise BadReply("QR bit clear")
    if answer[4:6] != b"\0\1" or answer[12 : 12 + len(q)] != q:
        raise BadReply("question differs from the query's")


def udp(server: str, query: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        # Connected: the OS drops datagrams from any other address.
        s.connect((server, 53))
        s.send(query)
        return s.recv(65535)


def tcp(server: str, query: bytes) -> bytes:
    with socket.create_connection((server, 53), timeout=5) as s:
        s.sendall(struct.pack("!H", len(query)) + query)
        (length,) = struct.unpack("!H", read_exactly(s, 2))
        return read_exactly(s, length)


def read_exactly(s: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def capture(case: Case) -> bytes:
    query = build_query(case)
    answer = udp(case.server, query)
    check_reply(case, query, answer)
    truncated = answer[2] & 0x02
    if truncated and not case.keep_truncated:
        answer = tcp(case.server, query)
        check_reply(case, query, answer)
    return answer


def main() -> int:
    wanted = set(sys.argv[1:])
    unknown = wanted - {c.name for c in CASES}
    if unknown:
        print(f"unknown cases: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    failed = 0
    for case in CASES:
        if wanted and case.name not in wanted:
            continue
        try:
            data = capture(case)
        except (OSError, BadReply) as e:
            print(f"{case.name}: {e}", file=sys.stderr)
            failed += 1
            continue
        (OUT / f"{case.name}.bin").write_bytes(data)
        print(f"{case.name}: {len(data)} bytes")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
