# /// script
# requires-python = ">=3.10"
# dependencies = ["aioquic"]
# ///
"""`dedensd` as an Oblivious DoH target (RFC 9230 §4, §5) for a client that is not ours.

The client is Cloudflare's `odoh-rs` (`odoh-rs/`, from crates.io: it seals a query to the target's configurations and
opens the response) and `aioquic` (the HTTP/3 POSTs and GET: the system's curl has no HTTP/3). The queries are the
captured ones of `crates/dedens-net/tests/testdata/doh/`; the answers come from 8.8.8.8, so the network is needed.

Run from the repository root, with `uv` and a Rust toolchain:

    uv run tests/interop/odoh.py

It builds `dedensd` with the `odoh` feature (`DEDENSD=path` uses that binary instead), makes a CA and a certificate for
`localhost` in a temporary directory, starts `dedensd` on a free UDP port with an `odoh` section and a forward stage,
and checks: the configurations are served for an hour and `odoh-rs` takes them; each query, at three paddings, gets an
`application/oblivious-dns-message` response that `odoh-rs` opens to the answer of the question (ID 0, QR, the rcode
of the name); a key the target does not hold gets 401, a damaged ciphertext 400. Exit status 0 when all hold.
"""

import asyncio
import datetime
import ipaddress
import os
import pathlib
import socket
import subprocess
import sys
import tempfile

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DOH = ROOT / "crates/dedens-net/tests/testdata/doh"
MEDIA_TYPE = "application/oblivious-dns-message"
NAME = "localhost"
UPSTREAM = "8.8.8.8"

# Captured query and the rcode of its answer: names that exist (an A and an MX), and one that does not (RFC 1035
# §4.1.1).
QUERIES = [("cloudflare_a", 0), ("quad9_mx", 0), ("cloudflare_nxdomain", 3)]
PADDINGS = [0, 17, 400]


def certificate(subject, key, issuer=None, issuer_key=None, leaf=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer or name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=not leaf, path_length=None), critical=True)
    )
    if leaf:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(NAME), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def write_certificates(directory):
    """A CA (`ca.pem`) and its certificate for `localhost` (`cert.pem`, `key.pem`)."""
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = certificate("dedens interop CA", ca_key)
    leaf = certificate(NAME, key, ca.subject, ca_key, leaf=True)
    pem = serialization.Encoding.PEM
    (directory / "ca.pem").write_bytes(ca.public_bytes(pem))
    (directory / "cert.pem").write_bytes(leaf.public_bytes(pem))
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_dedensd(directory):
    """Builds and starts `dedensd`, and returns the process and its port once it logs that it serves."""
    binary = os.environ.get("DEDENSD")
    if binary is None:
        subprocess.run(
            ["cargo", "build", "--quiet", "-p", "dedensd", "--features", "odoh"],
            cwd=ROOT,
            check=True,
        )
        binary = ROOT / "target/debug/dedensd"
    port = free_udp_port()
    config = directory / "dedensd.yaml"
    config.write_text(
        f"""listen: ['https://127.0.0.1:{port}']
tls:
  certificate: '{directory / "cert.pem"}'
  key: '{directory / "key.pem"}'
odoh: {{}}
pipeline: [up]
stages:
  up:
    type: forward
    servers: ['{UPSTREAM}']
    timeout_ms: 3000
    tries: 2
"""
    )
    process = subprocess.Popen(
        [binary, "--config", config], stderr=subprocess.PIPE, text=True
    )
    for line in process.stderr:
        if '"serving"' in line:
            return process, port
    raise SystemExit("dedensd exited before it served")


class Http3(QuicConnectionProtocol):
    """One HTTP/3 connection, a request at a time."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.pending = {}

    def quic_event_received(self, event):
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, (HeadersReceived, DataReceived)):
                done, got = self.pending[h3_event.stream_id]
                if isinstance(h3_event, HeadersReceived):
                    got["headers"] = {
                        k.decode(): v.decode() for k, v in h3_event.headers
                    }
                else:
                    got["body"] += h3_event.data
                if h3_event.stream_ended:
                    done.set_result(got)

    async def request(self, method, port, path, content_type=None, body=b""):
        stream = self._quic.get_next_available_stream_id()
        headers = [
            (b":method", method.encode()),
            (b":scheme", b"https"),
            (b":authority", f"{NAME}:{port}".encode()),
            (b":path", path.encode()),
        ]
        if content_type:
            headers += [(b"content-type", content_type.encode()), (b"accept", content_type.encode())]
        done = asyncio.get_running_loop().create_future()
        self.pending[stream] = (done, {"headers": {}, "body": b""})
        self.h3.send_headers(stream, headers, end_stream=not body)
        if body:
            self.h3.send_data(stream, body, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(done, 30)


def odoh_rs(binary, *args):
    subprocess.run([binary, *map(str, args)], check=True)


def question_end(wire):
    """The offset after the one question of `wire` (RFC 1035 §4.1.2: labels, 0, type, class)."""
    offset = 12
    while wire[offset]:
        offset += wire[offset] + 1
    return offset + 5


def check(condition, what):
    print(("ok   " if condition else "FAIL ") + what)
    return condition


async def run(directory, port, tool):
    results = []
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, cafile=str(directory / "ca.pem"), server_name=NAME)
    async with connect("127.0.0.1", port, configuration=configuration, create_protocol=Http3) as http:
        got = await http.request("GET", port, "/.well-known/odohconfigs")
        results.append(check(got["headers"][":status"] == "200", "configurations: 200"))
        results.append(
            check("max-age=3600" in got["headers"].get("cache-control", ""), f"configurations: cache-control {got['headers'].get('cache-control')!r}")
        )
        configs = directory / "configs.bin"
        configs.write_bytes(got["body"])

        # A key the target does not hold: the last byte of the one configuration is the last byte of its public key.
        wrong = directory / "wrong.bin"
        wrong.write_bytes(got["body"][:-1] + bytes([got["body"][-1] ^ 1]))

        async def post(body):
            return await http.request("POST", port, "/dns-query", MEDIA_TYPE, body)

        for name, rcode in QUERIES:
            query = DOH / f"{name}.query"
            for padding in PADDINGS:
                label = f"{name}, padding {padding}"
                message, secret = directory / "message.bin", directory / "secret.bin"
                odoh_rs(tool, "seal", configs, query, padding, message, secret)
                got = await post(message.read_bytes())
                headers = got["headers"]
                results.append(check(headers[":status"] == "200", f"{label}: 200"))
                results.append(check(headers.get("content-type") == MEDIA_TYPE, f"{label}: content-type {headers.get('content-type')!r}"))
                results.append(check("no-store" in headers.get("cache-control", ""), f"{label}: cache-control {headers.get('cache-control')!r}"))
                response, answer = directory / "response.bin", directory / "answer.bin"
                response.write_bytes(got["body"])
                odoh_rs(tool, "open", query, padding, secret, response, answer)
                wire, asked = answer.read_bytes(), query.read_bytes()
                results.append(
                    check(
                        wire[:2] == b"\0\0" and wire[2] & 0x80 and wire[3] & 0x0F == rcode,
                        f"{label}: odoh-rs opens an answer, ID 0, QR, rcode {wire[3] & 0x0F}",
                    )
                )
                results.append(check(wire[12:question_end(wire)] == asked[12:question_end(asked)], f"{label}: the question is echoed"))
                if rcode == 0:
                    results.append(check(int.from_bytes(wire[6:8], "big") > 0, f"{label}: {int.from_bytes(wire[6:8], 'big')} answer records"))

        query = DOH / "cloudflare_a.query"
        message, secret = directory / "message.bin", directory / "secret.bin"
        odoh_rs(tool, "seal", wrong, query, 0, message, secret)
        got = await post(message.read_bytes())
        results.append(check(got["headers"][":status"] == "401", f"a key it does not hold: {got['headers'][':status']}"))

        odoh_rs(tool, "seal", configs, query, 0, message, secret)
        sealed = bytearray(message.read_bytes())
        sealed[-1] ^= 1
        got = await post(bytes(sealed))
        results.append(check(got["headers"][":status"] == "400", f"a damaged ciphertext: {got['headers'][':status']}"))
    return all(results)


def main():
    subprocess.run(["cargo", "build", "--quiet"], cwd=HERE / "odoh-rs", check=True)
    tool = HERE / "odoh-rs/target/debug/odoh-rs-interop"
    with tempfile.TemporaryDirectory() as name:
        directory = pathlib.Path(name)
        write_certificates(directory)
        process, port = start_dedensd(directory)
        try:
            ok = asyncio.run(run(directory, port, tool))
        finally:
            process.terminate()
            process.wait()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
