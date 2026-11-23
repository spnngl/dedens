#!/usr/bin/env python3
"""The first answer of a server, asked from inside the loader container (compare.py copies this file to /w).

`probe.py <port> <rcode> <qtype> <name>...` asks 127.0.0.1:<port> every 2 ms, rotating through the names, until one
is answered with the rcode, and prints that moment in Unix nanoseconds. It runs in the loader container, not on the
host, so that the moment and the `/w/start` stamp of the server's container come from one clock, and the host may
be a Mac whose loopback is not the containers' (the engine's Linux VM). A list still loading answers NOERROR for a
while, not forever: answers with other rcodes only, WRONG_FOR seconds after the first, exit 1 with the rcode seen;
no right answer in START_TIMEOUT seconds exits 1 too. The standard library only.
"""

import socket
import struct
import sys
import time

START_TIMEOUT = 120
WRONG_FOR = 10
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def query(qid, name, qtype=1):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack(">HH", qtype, 1)


def first_answer(port, rcode, qtype, names):
    """The time (ns) of the first answer to one of the names with the rcode. An answer later than 2 ms counts as
    well: the IDs are those of the questions asked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.002)
    want = next(n for n, name in RCODES.items() if name == rcode)
    deadline = time.monotonic() + START_TIMEOUT
    first_wrong = None
    i = 0
    while time.monotonic() < deadline:
        try:
            sock.sendto(query(i & 0xFFFF, names[i % len(names)], qtype), ("127.0.0.1", port))
            data = sock.recv(4096)
            if len(data) >= 4 and struct.unpack(">H", data[:2])[0] <= min(i, 0xFFFF):
                if data[3] & 0xF == want:
                    return time.time_ns()
                first_wrong = first_wrong or time.monotonic()
                if time.monotonic() - first_wrong > WRONG_FOR:
                    sys.exit(f"rcode {RCODES.get(data[3] & 0xF, data[3] & 0xF)} for {WRONG_FOR} s, not {rcode}")
        except OSError:
            pass
        i += 1
    sys.exit(f"no {rcode} answer in {START_TIMEOUT} s")


if __name__ == "__main__":
    print(first_answer(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4:]))
