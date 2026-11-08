"""Real CoAP datagrams of aiocoap talking to aiocoap over the loopback address, as `capture.nu` runs it.

A server and a client of aiocoap, a logging UDP proxy between them. The proxy writes each datagram it sees to
`<id>.txt`: a `#` line with the command, then one line a datagram: milliseconds since the first, a direction
(`c2s` client to server, `s2c` server to client; a `-lost` suffix means the proxy dropped it), the datagram in
hex. Never edit the files by hand.

`python capture.py [id ...]`, no id for all.
"""

import asyncio
import pathlib
import sys
import time

import aiocoap
import aiocoap.resource as resource
from aiocoap import CHANGED, CONTENT, FETCH, GET, NON, POST, Message
from aiocoap.optiontypes import BlockOption

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DNS_MESSAGE = 553
SERVER = ("127.0.0.1", 56830)
FRONT = ("127.0.0.1", 56831)

# The DoC payloads: a real query and its real response, from the DoH captures (RFC 9953 §4.2.2, ID 0).
QUERY = (HERE.parent / "doh" / "quad9_mx.query").read_bytes()
ANSWER = (HERE.parent / "doh" / "quad9_mx.body").read_bytes()
# A body of 2500 bytes that is not made up: the start of RFC 9953.
RFC = (ROOT / "docs" / "rfc" / "archive" / "rfc9953.txt").read_bytes()[:2500]


class Temperature(resource.Resource):
    async def render_get(self, request):
        return Message(code=CONTENT, payload=b"22.3 C")


class Slow(resource.Resource):
    """Answers after the delay that makes aiocoap send an empty ACK first (a separate response)."""

    async def render_get(self, request):
        await asyncio.sleep(0.6)
        return Message(code=CONTENT, payload=b"22.3 C")


class Rfc(resource.Resource):
    async def render_get(self, request):
        return Message(code=CONTENT, payload=RFC)


class Dns(resource.Resource):
    async def render_fetch(self, request):
        assert request.opt.content_format == DNS_MESSAGE and request.payload == QUERY
        return Message(code=CONTENT, payload=ANSWER, content_format=DNS_MESSAGE)


class Echo(resource.Resource):
    async def render_post(self, request):
        return Message(code=CHANGED, payload=request.payload)


class Upload(resource.Resource):
    async def render_post(self, request):
        assert request.payload == RFC
        return Message(code=CHANGED)


def site():
    s = resource.Site()
    for path, res in [
        ("temperature", Temperature()),
        ("slow", Slow()),
        ("rfc", Rfc()),
        ("dns", Dns()),
        ("echo", Echo()),
        ("upload", Upload()),
    ]:
        s.add_resource([path], res)
    return s


class Proxy(asyncio.DatagramProtocol):
    """Between the client (which talks to `FRONT`) and the server, logging every datagram. `lose` is the set of
    (direction, n) to drop: the n-th datagram of that direction, from 0."""

    def __init__(self, lose, log):
        self.lose, self.log = set(lose), log
        self.client = None
        self.seen = {"c2s": 0, "s2c": 0}
        self.start = None
        self.front = None
        self.back = None

    def note(self, direction, data):
        now = time.monotonic()
        self.start = self.start or now
        lost = (direction, self.seen[direction]) in self.lose
        self.seen[direction] += 1
        self.log.append(f"{round((now - self.start) * 1000)} {direction}{'-lost' if lost else ''} {data.hex()}")
        return not lost

    # The front socket receives from the client.
    def datagram_received(self, data, addr):
        self.client = addr
        if self.note("c2s", data):
            self.back.sendto(data, SERVER)


class Back(asyncio.DatagramProtocol):
    """The proxy's side towards the server."""

    def __init__(self, proxy):
        self.proxy = proxy

    def datagram_received(self, data, addr):
        if self.proxy.note("s2c", data):
            self.proxy.front.sendto(data, self.proxy.client)


def uri(path):
    return f"coap://{FRONT[0]}:{FRONT[1]}/{path}"


async def get(client, path, **kw):
    return await client.request(Message(code=GET, uri=uri(path), **kw)).response


async def get_non(client):
    return await get(client, "temperature", mtype=NON)


async def get_block2_64(client):
    request = Message(code=GET, uri=uri("rfc"))
    request.opt.block2 = BlockOption.BlockwiseTuple(0, False, 2)
    return await client.request(request).response


async def fetch_doc(client, block2=False):
    request = Message(code=FETCH, uri=uri("dns"), payload=QUERY, content_format=DNS_MESSAGE)
    request.opt.accept = DNS_MESSAGE
    if block2:
        request.opt.block2 = BlockOption.BlockwiseTuple(0, False, 2)
    response = await client.request(request).response
    assert response.payload == ANSWER
    return response


async def post(client, path, size_exp=None):
    request = Message(code=POST, uri=uri(path), payload=RFC)
    if size_exp is not None:
        request.opt.block1 = BlockOption.BlockwiseTuple(0, False, size_exp)
    return await client.request(request).response


# id: (the request, the datagrams to lose). The ids are the file names.
SCENARIOS = {
    "get_piggybacked": (lambda c: get(c, "temperature"), ()),
    "get_separate": (lambda c: get(c, "slow"), ()),
    "get_non": (get_non, ()),
    "get_block2": (lambda c: get(c, "rfc"), ()),
    "get_block2_64": (get_block2_64, ()),
    "fetch_doc": (fetch_doc, ()),
    "fetch_doc_block2_64": (lambda c: fetch_doc(c, block2=True), ()),
    "post_block1": (lambda c: post(c, "upload"), ()),
    "post_block1_64": (lambda c: post(c, "upload", size_exp=2), ()),
    "post_block1_block2": (lambda c: post(c, "echo", size_exp=2), ()),
    "get_lost_request": (lambda c: get(c, "temperature"), (("c2s", 0),)),
    "get_lost_ack": (lambda c: get(c, "temperature"), (("s2c", 0),)),
}


async def capture(id_):
    run, lose = SCENARIOS[id_]
    log = []
    loop = asyncio.get_running_loop()
    proxy = Proxy(lose, log)
    proxy.front, _ = await loop.create_datagram_endpoint(lambda: proxy, local_addr=FRONT)
    proxy.back, _ = await loop.create_datagram_endpoint(lambda: Back(proxy), local_addr=("127.0.0.1", 0))
    server = await aiocoap.Context.create_server_context(site(), bind=SERVER)
    client = await aiocoap.Context.create_client_context()
    try:
        response = await run(client)
        print(id_, response.code, len(response.payload), file=sys.stderr)
        await asyncio.sleep(0.3)
    finally:
        await client.shutdown()
        await server.shutdown()
        proxy.front.close()
        proxy.back.close()
    header = f"# uv run --with aiocoap==0.4.17 python capture.py {id_}"
    (HERE / f"{id_}.txt").write_text("\n".join([header, *log, ""]))


def main():
    ids = sys.argv[1:] or list(SCENARIOS)
    for id_ in ids:
        asyncio.run(capture(id_))


if __name__ == "__main__":
    main()
