"""Real CoAP datagrams of libcoap, as `capture.nu` runs it: `coap-server` and `coap-client` of libcoap 4.3.5b.

The same logging UDP proxy and file format as `capture.py` (imported from it), between a `coap-client` and a
`coap-server` of libcoap on the loopback address. The server's `/example_data` resource keeps what a PUT gives it and
answers a GET or a FETCH with it, in blocks (Block2) as soon as it is longer than 1024 bytes; `/async` answers after
an empty ACK; `/time` is a small observable resource. A scenario first stores its body with a PUT straight to the
server (not captured), then runs the captured request through the proxy. Never edit the files by hand.

`python capture_libcoap.py [id ...]`, no id for all. Needs `coap-client` and `coap-server` on the PATH.
"""

import asyncio
import pathlib
import subprocess
import sys

import capture
from capture import Back, Proxy

HERE = pathlib.Path(__file__).resolve().parent
QUERY = HERE.parent / "doh" / "quad9_mx.query"
# Real responses to queries with ID 0, over DoH (`dedens @https://dns.google/dns-query . DNSKEY +dnssec
# --save-wire`, and cloudflare.com TXT): 1280 and 2808 bytes, so longer than the 1024 of a libcoap block.
DNSKEY = HERE / "dns_dnskey.body"
TXT = HERE / "dns_txt.body"
SMALL = HERE.parent / "doh" / "quad9_mx.body"
FRONT = capture.FRONT
SERVER = capture.SERVER
DOC = ["-t", "553", "-A", "553"]


def client(*args, uri="example_data"):
    return ["coap-client", *args, f"coap://{FRONT[0]}:{FRONT[1]}/{uri}"]


# id: (the file the server stores first or None, the coap-client arguments, the datagrams to lose).
SCENARIOS = {
    "libcoap_get_block2": (TXT, client("-m", "get"), ()),
    "libcoap_get_block2_64": (TXT, client("-m", "get", "-b", "64"), ()),
    "libcoap_fetch_doc": (SMALL, client("-m", "fetch", *DOC, "-f", str(QUERY)), ()),
    "libcoap_fetch_doc_block2": (TXT, client("-m", "fetch", *DOC, "-f", str(QUERY)), ()),
    "libcoap_fetch_doc_block2_64": (DNSKEY, client("-m", "fetch", *DOC, "-b", "64", "-f", str(QUERY)), ()),
    "libcoap_put_block1_64": (None, client("-m", "put", "-t", "553", "-b", "64", "-f", str(DNSKEY)), ()),
    "libcoap_get_async": (None, client("-m", "get", uri="async"), ()),
    "libcoap_get_non": (None, client("-m", "get", "-N", uri="time"), ()),
    "libcoap_get_lost_request": (SMALL, client("-m", "get"), (("c2s", 0),)),
    "libcoap_get_lost_ack": (SMALL, client("-m", "get"), (("s2c", 0),)),
}


async def run(*argv):
    process = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await process.communicate()
    return process.returncode, out, err


async def capture_one(id_):
    stored, argv, lose = SCENARIOS[id_]
    log = []
    loop = asyncio.get_running_loop()
    server = await asyncio.create_subprocess_exec(
        "coap-server", "-p", str(SERVER[1]), "-A", SERVER[0],
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        await asyncio.sleep(0.5)
        if stored is not None:
            code, _, err = await run(
                "coap-client", "-m", "put", "-t", "553", "-f", str(stored),
                f"coap://{SERVER[0]}:{SERVER[1]}/example_data",
            )
            assert code == 0, err
        proxy = Proxy(lose, log)
        proxy.front, _ = await loop.create_datagram_endpoint(lambda: proxy, local_addr=FRONT)
        proxy.back, _ = await loop.create_datagram_endpoint(lambda: Back(proxy), local_addr=("127.0.0.1", 0))
        code, out, err = await run(*argv, "-B", "20", "-o", "-")
        print(id_, code, len(out), err.decode().strip(), file=sys.stderr)
        assert code == 0
        await asyncio.sleep(0.3)
        proxy.front.close()
        proxy.back.close()
    finally:
        server.terminate()
        await server.wait()
    # Paths relative to testdata.
    command = " ".join(argv).replace(f"{HERE.parent}/", "")
    header = f"# {command} (coap-server -p {SERVER[1]}), libcoap 4.3.5b"
    (HERE / f"{id_}.txt").write_text("\n".join([header, *log, ""]))


def main():
    for id_ in sys.argv[1:] or list(SCENARIOS):
        asyncio.run(capture_one(id_))


if __name__ == "__main__":
    main()
