#!/usr/bin/env python3
"""The measuring half of compare.sh, which builds what this runs and passes its versions in the environment.

`compare.py <mode> <cores> <work>`: renders the configurations beside it into <work> (mounted as /w in every
container), generates the corpora with TelltaleDNS's own bench/corpus.py, starts Knot, then each server in turn in
its own container on its own cores, as many times as rounds and run kinds need, and drives it with dnsperf from a
loader container on other cores. The standard library only: it runs on the host, which may be a Mac whose engine
runs the containers in a Linux VM: everything that touches a server (its first answer, its cgroup, its cores) is
asked from inside the containers.

The `authoritative` modes (D213) differ: the servers compared are the authorities (dedensd, Knot, NSD), serving the
zones of authzones.py, so there is no upstream Knot, and Knot's answers to the sample are the reference.

A server is measured only after it answers right: every query of a check pass with the mode's rcode, nothing lost,
and a sample of answers, asked by `dedens`, equal to Knot's (DNSSEC: with AD set). A server failing it fails the
run, which writes its JSON and exits 1. A saturation run losing 1% or more is run again 10% under the rate it
answered, twice at most. A measured run is void, kept out of the medians, when Knot or, at
saturation, dnsperf was over 90% busy (the upstream or the loader, not the server, was the limit), when dnsperf
held to a rate sent 1% less, when 1% of queries or more were lost, or when over 1% of the answers had
another rcode.
"""

import hashlib
import importlib.util
import json
import math
import os
import pathlib
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

import authzones

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
PORT, TLS_PORT = 5301, 8531
KNOT = ("127.0.0.1", 5300)
# The mini Internet of the `recurse` modes (D201): one Knot authority per zone, each on its own loopback address and
# port 53, leaf first so that a zone's DS is known when its parent is written; the root server is the root hints'.
AUTHORITIES = [("sld", "recurse.bench.", "127.0.0.4"), ("tld", "bench.", "127.0.0.3"), ("root", ".", "127.0.0.2")]
UNIQUE_NAMES = 1_000_000  # the `recurse` corpus: each name once, `u{i:06x}.recurse.bench A`
BLOCKLIST_NAMES = 1_000_000
CHECK_QUERIES = 1000  # the check pass: the corpus's first lines, at CHECK_RATE
CHECK_RATE = 2000
SAMPLE = 20  # the answers compared with Knot's
VOID_BUSY = 0.90
# The wait for the last answers, in the seconds of a run that sent its whole corpus (0.01-0.22 s on the VPS, D183).
DRAIN_S = 0.25
VOID_SHARE = 0.01
SAT_RETRIES = 2
SIGN_THREADS = 4  # kzonesign's, for the generated zone

# corpus: TelltaleDNS's; transport: dnsperf's -m; cached: primed by a pass, the server kept between runs, else
# started anew before each run, which then makes a single pass (-n 1) over the corpus; tags: the template lines kept.
MODES = {
    "udp": {"corpus": "cache-hot", "transport": "udp", "cached": True},
    "tcp": {"corpus": "cache-hot", "transport": "tcp", "cached": True},
    "dot": {"corpus": "cache-hot", "transport": "dot", "cached": True},
    "forward": {"corpus": "cache-hot", "transport": "udp", "cached": False},
    "forward-tcp": {"corpus": "cache-hot", "transport": "tcp", "cached": False, "upstream": "tcp"},
    "miss": {"corpus": "miss-heavy", "transport": "udp", "cached": False},
    "dnssec": {"corpus": "miss-heavy", "transport": "udp", "cached": False, "tags": {"dnssec"}},
    "blocked": {"corpus": "blocked", "transport": "udp", "cached": True, "tags": {"blocked"}, "rcode": "NXDOMAIN"},
    # recursive: the servers resolve from the root hints of the mini Internet (D201), not forward to one upstream.
    "recurse": {"corpus": "recurse-unique", "transport": "udp", "cached": False, "recursive": True},
    "recurse-dnssec": {"corpus": "recurse-unique", "transport": "udp", "cached": False, "recursive": True,
                       "tags": {"dnssec"}},
    "crosscheck": {"corpus": None, "transport": "udp", "cached": False},
    # authoritative: the servers serve the zones of authzones.py (`DEDENS_ZONES`: root, big or both, default both);
    # the corpus is theirs, every name asked of the server itself. dnssec asks with DO set.
    "authoritative": {"corpus": "authoritative", "transport": "udp", "cached": True, "authoritative": True},
    "authoritative-dnssec": {"corpus": "authoritative", "transport": "udp", "cached": True, "authoritative": True,
                             "tags": {"dnssec"}},
}
AUTHORITATIVE_SERVERS = "knot nsd dedensd"

# A server's configuration template per configuration (`recursion`: those of the recursive modes, which a server
# without them does not serve), its command line in the container, and the modes it has no way to serve: its row
# stays empty (the plan's choice: not emulated).
SERVERS = {
    "dedensd": {
        "configs": {"lean": "dedensd.yaml", "shipped": "dedensd.yaml"},
        "recursion": {"lean": "dedensd-recurse.yaml", "shipped": "dedensd-recurse.yaml"},
        "authoritative": {"lean": "dedensd-authoritative.yaml", "shipped": "dedensd-authoritative.yaml"},
        "command": ["/w/bin/dedensd", "--config", "{conf}"],
    },
    # The authorities dedensd is compared with (D213). Knot runs in its own image, whose entrypoint is `sh` to stamp
    # the start; NSD is in the compare image.
    "knot": {
        "authoritative": {"lean": "knot-authoritative.conf", "shipped": "knot-authoritative.conf"},
        "command": ["-c", "date +%s%N >/w/start; exec knotd -c {conf}"],
        "image": "DEDENS_KNOT_IMAGE", "entrypoint": "sh",
    },
    "nsd": {
        "authoritative": {"lean": "nsd-authoritative.conf", "shipped": "nsd-authoritative.conf"},
        "command": ["nsd", "-d", "-c", "{conf}"],
    },
    # dedensd with an 8 MiB cache, Unbound's order of size (4 MiB of messages, 4 of RRsets) against its default
    # 64 MiB (D116): what the memory columns owe to the cache. `file+tag`: the file rendered with that tag too.
    "dedensd-8mib": {
        "configs": {"lean": "dedensd.yaml+cache8mib", "shipped": "dedensd.yaml+cache8mib"},
        "recursion": {"lean": "dedensd-recurse.yaml+cache8mib", "shipped": "dedensd-recurse.yaml+cache8mib"},
        "command": ["/w/bin/dedensd", "--config", "{conf}"],
    },
    "telltale": {
        "configs": {"lean": "telltale-lean.toml", "shipped": "telltale-shipped.toml"},
        "command": ["/w/bin/telltale", "run", "-c", "{conf}"],
    },
    "unbound": {
        "configs": {"lean": "unbound.conf", "shipped": "unbound.conf"},
        "recursion": {"lean": "unbound-recurse.conf", "shipped": "unbound-recurse.conf"},
        "command": ["unbound", "-d", "-c", "{conf}"],
    },
    "coredns": {
        "configs": {"lean": "coredns-lean.Corefile", "shipped": "coredns-shipped.Corefile"},
        "command": ["coredns", "-conf", "{conf}"],
        "lacks": {"dnssec", "blocked"},
    },
    "broken": {
        "configs": {"lean": "broken.Corefile", "shipped": "broken.Corefile"},
        "recursion": {"lean": "broken.Corefile", "shipped": "broken.Corefile"},
        "command": ["coredns", "-conf", "{conf}"],
    },
}


def log(*args):
    print(*args, file=sys.stderr, flush=True)


class Fail(Exception):
    """A server answering wrong, or not at all: the run fails."""


class Engine:
    """The container engine, and the containers of the run: names, mounts, users and cores."""

    def __init__(self, name, work, image, cpus):
        self.name, self.work, self.image, self.cpus = name, work, image, cpus
        podman = pathlib.Path(name).name == "podman"
        self.user = ["--userns=keep-id"] if podman else ["--user", f"{os.getuid()}:{os.getgid()}"]
        self.rm = ["rm", "-f", "-t", "0"] if podman else ["rm", "-f"]
        # Rootless podman has no cpuset controller unless delegated: taskset in the container instead.
        probe = subprocess.run([name, "run", "--rm", "--cpuset-cpus", cpus["server"], image, "true"],
                               check=False, capture_output=True)
        self.pinning = "cpuset" if probe.returncode == 0 else "taskset"

    def __call__(self, *args, check=True):
        p = subprocess.run([self.name, *args], check=False, capture_output=True, text=True)
        if check and p.returncode:
            raise RuntimeError(f"{self.name} {' '.join(args)}: {p.stderr.strip()}")
        return p.stdout

    def logs(self, name):
        """What container `name` wrote, both streams: the engine gives each back on its own."""
        p = subprocess.run([self.name, "logs", name], check=False, capture_output=True, text=True)
        return p.stdout + p.stderr

    def start(self, role, command, image=None, entrypoint=None):
        """Starts container dedens-compare-<role> on the cores of its role, writing /w/start as it execs."""
        name = f"dedens-compare-{role}"
        self(*self.rm, name, check=False)
        cpus = self.cpus[role]
        # The engines' default seccomp filters refuse io_uring, so dedensd would serve on its poll fallback (D107):
        # off for every container alike.
        args = ["run", "-d", "--name", name, "--network", "host", "--security-opt", "label=disable",
                "--security-opt", "seccomp=unconfined", "-v", f"{self.work}:/w", *self.user]
        stamp = ["sh", "-c", 'date +%s%N >/w/start; exec "$@"', "sh"]
        if self.pinning == "cpuset":
            args += ["--cpuset-cpus", cpus]
            prefix = []
        else:
            prefix = ["taskset", "-c", cpus]
        if entrypoint:  # images without sh: no stamp
            args += ["--entrypoint", prefix[0] if prefix else entrypoint]
            command = (prefix[1:] + [entrypoint] if prefix else []) + command
        else:
            command = prefix + stamp + command
        self(*args, image or self.image, *command)
        return name

    def stop(self, name):
        self(*self.rm, name, check=False)

    def cgroup(self, name):
        """The container's CPU time (µs) and memory (bytes): anonymous now, and the peak of everything."""
        out = self("exec", name, "cat", "/sys/fs/cgroup/cpu.stat", "/sys/fs/cgroup/memory.stat",
                   "/sys/fs/cgroup/memory.peak")
        lines = out.split("\n")
        field = {k: int(v) for k, v in (ln.split() for ln in lines if len(ln.split()) == 2)}
        peak = next((int(ln) for ln in reversed(lines) if ln.strip().isdigit()), 0)
        return {"cpu_us": field["usage_usec"], "user_us": field["user_usec"], "system_us": field["system_usec"],
                "anon": field["anon"], "peak": peak}


def render(template, values, tags):
    """`@NAME@` replaced by its value; a `#@tag rest` line kept as `rest` when the run has tag (`!tag`: has not).
    Comment lines are kept as they are."""
    out = []
    for line in (HERE / template).read_text().splitlines():
        if m := re.match(r"#@(!?)(\w+) (.*)", line):
            if (m[2] in tags) == (m[1] == ""):
                out.append(re.sub(r"@(\w+)@", lambda v: values[v[1]], m[3]))
            continue
        out.append(line if line.lstrip().startswith("#") else re.sub(r"@(\w+)@", lambda v: values[v[1]], line))
    return "\n".join(out) + "\n"


def corpora(work, mode, telltale_src):
    """Writes the mode's corpus (and the 1M-name list) into <work>, checked against corpora.sha256."""
    expected = dict(ln.split()[::-1] for ln in (HERE / "corpora.sha256").read_text().splitlines()
                    if ln.strip() and not ln.startswith("#"))
    if MODES[mode].get("recursive"):  # ours: the names of the mini Internet's zone, no TelltaleDNS's corpus fits it
        (work / "corpora").mkdir(exist_ok=True)
        path = work / "corpora/recurse-unique.txt"
        data = "".join(f"u{i:06x}.recurse.bench A\n" for i in range(UNIQUE_NAMES)).encode()
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        if expected.get(path.name) != digest:
            raise SystemExit(f"{path.name}: sha256 {digest}, corpora.sha256 says {expected.get(path.name)}")
        lines = data.decode().splitlines()
        (work / "corpora/check.txt").write_text("\n".join(lines[:CHECK_QUERIES]) + "\n")
        return path, {path.name: digest}
    spec = importlib.util.spec_from_file_location("corpus", pathlib.Path(telltale_src) / "bench/corpus.py")
    corpus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(corpus)
    lists = work / "lists"
    hashes = {}
    if mode == "blocked":
        source = pathlib.Path(os.environ["DEDENS_BLOCKLIST"])
        lists.mkdir(exist_ok=True)
        tmp = work / "list-source"
        tmp.mkdir(exist_ok=True)
        (tmp / "list.txt").write_bytes(source.read_bytes())
        names = list(dict.fromkeys(corpus.blocked_names(tmp)))[:BLOCKLIST_NAMES]
        data = ("\n".join(names) + "\n").encode()
        (lists / "blocklist.txt").write_bytes(data)
        (work / "blocklist.conf").write_text("".join(f'local-zone: "{n}." always_nxdomain\n' for n in names))
        hashes["blocklist.txt"] = hashlib.sha256(data).hexdigest()
    name = MODES[mode]["corpus"]
    path, digest = corpus.generate(name, work / "corpora", lists if mode == "blocked" else None)
    hashes[path.name] = digest
    for file, digest in hashes.items():
        if expected.get(file) != digest:
            raise SystemExit(f"{file}: sha256 {digest}, corpora.sha256 says {expected.get(file)}")
    lines = path.read_text().splitlines()
    (work / "corpora/check.txt").write_text("\n".join(lines[:CHECK_QUERIES]) + "\n")
    return path, hashes


def parse_dnsperf(out):
    """dnsperf's statistics, as TelltaleDNS's bench.py reads them; percentiles at a histogram bucket's upper edge."""
    def num(pattern):
        m = re.search(pattern, out)
        return float(m[1]) if m else 0.0

    r = {
        "sent": int(num(r"Queries sent:\s+(\d+)")),
        "completed": int(num(r"Queries completed:\s+(\d+)")),
        "lost": int(num(r"Queries lost:\s+(\d+)")),
        "qps": num(r"Queries per second:\s+([\d.]+)"),
        "seconds": num(r"Run time \(s\):\s+([\d.]+)"),
        "avg_ms": num(r"Average Latency \(s\):\s+([\d.]+)") * 1000,
    }
    m = re.search(r"Response codes:\s+(.*)", out)
    r["rcodes"] = {k: int(v) for k, v in re.findall(r"(\w+) (\d+) \(", m[1])} if m else {}
    buckets = [(float(hi), int(n)) for _, hi, n in
               re.findall(r"^\s+([\d.]+) - ([\d.]+):\s+(\d+)\s*$", out.split("Connection Statistics")[0], re.MULTILINE)]
    total = sum(n for _, n in buckets)
    for q in (99, 99.9):
        acc, edge = 0, 0.0
        for hi, n in buckets:
            acc += n
            if acc >= total * q / 100:
                edge = hi
                break
        r[f"p{q}_ms"] = edge * 1000
    v = re.search(r"Version ([\d.]+)", out)
    r["version"] = v[1] if v else ""
    return r


class Bench:
    def __init__(self, mode, cores, work):
        self.mode, self.spec, self.work = mode, MODES[mode], work
        self.rounds = int(os.environ.get("DEDENS_ROUNDS", "2"))
        self.duration = int(os.environ.get("DEDENS_DURATION", "10"))
        self.outstanding = int(os.environ.get("DEDENS_OUTSTANDING", "500"))
        # The authorities compared are the servers, and Knot is one of them: no neutral upstream, no Knot core.
        self.authoritative = bool(self.spec.get("authoritative"))
        self.servers = os.environ.get("DEDENS_SERVERS", AUTHORITATIVE_SERVERS if self.authoritative
                                      else "dedensd telltale unbound coredns").split()
        self.configs = os.environ.get("DEDENS_CONFIGS", "shipped" if self.authoritative
                                      else "lean shipped").split()
        for s in self.servers:
            if s not in SERVERS:
                raise SystemExit(f"unknown server {s}: {', '.join(SERVERS)}")
        # The cores the containers see: the engine's Linux VM's on a Mac, not the host's.
        n = int(subprocess.run([os.environ.get("DEDENS_CONTAINER", "docker"), "run", "--rm", os.environ["DEDENS_IMAGE"],
                                "nproc"], check=True, capture_output=True, text=True).stdout)
        needed = cores + 1 if self.authoritative else cores + 2
        cpus = {
            "server": os.environ.get("DEDENS_SERVER_CPUS", f"0-{cores - 1}"),
            "loader": os.environ.get("DEDENS_LOAD_CPUS", f"{cores}-{n - 1 if self.authoritative else n - 2}"),
        }
        if not self.authoritative:
            cpus["knot"] = os.environ.get("DEDENS_KNOT_CPUS", str(n - 1))
        self.count = {role: count_cpus(c) for role, c in cpus.items()}
        if min(self.count.values()) < 1 or n < needed:
            raise SystemExit(f"{n} cores: not enough for {cores} server cores, a loader core"
                             + ("" if self.authoritative else " and a Knot core"))
        low = pathlib.Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        if self.spec.get("recursive") and int(low.read_text()) > 53:
            raise SystemExit("the authorities listen on port 53: `sudo sysctl net.ipv4.ip_unprivileged_port_start=53`, "
                             "back to its value after the run")
        self.engine = Engine(os.environ.get("DEDENS_CONTAINER", "docker"), work, os.environ["DEDENS_IMAGE"], cpus)
        self.rcode = self.spec.get("rcode", "NOERROR")
        self.tags = set(self.spec.get("tags", set()))
        self.knot = None
        self.result = {
            "mode": mode, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "versions": dict(kv.split("=") for kv in os.environ["DEDENS_VERSIONS"].split()),
            "host": host(self.engine) | {"container_cores": n}, "engine": self.engine("--version").strip(), "pinning": self.engine.pinning,
            "servers": self.servers, "config_names": self.configs, "cpus": cpus, "rounds": self.rounds, "duration_s": self.duration, "outstanding": self.outstanding,
            "configs": {}, "corpora": {}, "starts": [], "checks": [], "runs": [],
        }

    # Setup: certificate, Knot, anchors, configurations.

    def setup(self):
        w = self.work
        for d in ("conf", "knot", "data", "results"):
            (w / d).mkdir(exist_ok=True)
        subprocess.run(["rm", "-rf", str(w / "knot")], check=True)
        (w / "knot").mkdir()
        shutil.copy(HERE / "probe.py", w / "probe.py")
        if self.authoritative:
            return self.setup_authoritative()
        if self.spec["corpus"]:
            self.corpus, self.result["corpora"] = corpora(w, self.mode, os.environ["DEDENS_TELLTALE_SRC"])
            self.corpus_lines = len(self.corpus.read_text().splitlines())
        if not (w / "key.pem").exists():
            self.engine("run", "--rm", "-v", f"{w}:/w", *self.engine.user, self.engine.image, "openssl", "req",
                        "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "3650",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", "/w/key.pem", "-out", "/w/cert.pem")
        (w / "key.pem").chmod(0o600)
        if self.spec.get("recursive"):
            self.mini_internet()
            self.auth, root = ("127.0.0.4", 53), ("127.0.0.2", 53)
            shutil.copy(HERE / "recurse-root.hints", w / "root.hints")
        else:
            (w / "root.zone").write_text((HERE / "root.zone").read_text())
            knot = render("knot.conf", {"KNOT_THREADS": str(self.count["knot"])}, self.tags)
            (w / "conf/knot.conf").write_text(knot)
            self.knot = self.engine.start("knot", ["-c", "/w/conf/knot.conf"], os.environ["DEDENS_KNOT_IMAGE"],
                                          "knotd")
            self.auth = root = KNOT
        self.loader = self.engine.start("loader", ["sleep", "infinity"])

        def dig(at, *question):
            return self.engine("exec", self.loader, "dig", f"@{at[0]}", "-p", str(at[1]), "+noall", "+answer",
                               "+dnssec", *question, check=False)

        # Knot answers: the wildcard for the one upstream; each zone, signed for `dnssec`, for the mini Internet.
        probes = ([(at, zone, "SOA", "RRSIG" if "dnssec" in self.tags else "SOA")
                   for _, zone, host in AUTHORITIES for at in [(host, 53)]] if self.spec.get("recursive")
                  else [(KNOT, "x.", "A", "198.18.0.1")])
        for at, zone, rtype, expected in probes:
            for _ in range(100):
                if expected in dig(at, zone, rtype):
                    break
                time.sleep(0.1)
            else:
                raise SystemExit(f"Knot does not answer {zone} at {at[0]}: " + self.engine.logs(self.knot))
        # The key-signing key of the signed root: the trust anchor of every validator.
        anchors = [ln for ln in dig(root, ".", "DNSKEY").splitlines() if re.search(r"\sDNSKEY\s+257 3 ", ln)]
        if "dnssec" in self.tags and not anchors:
            raise SystemExit("Knot serves no key-signing key: " + self.engine.logs(self.knot))
        (w / "anchors.zone").write_text("".join(ln + "\n" for ln in anchors))
        upstream = self.spec.get("upstream", "udp")
        values = {"DNSSEC": "validate" if "dnssec" in self.tags else "off", "CORES": str(self.count["server"]),
                  "TCP_UPSTREAM": "yes" if upstream == "tcp" else "no", "UPSTREAM_PROTO": upstream}
        for server in {s for s in self.servers if serves(s, self.mode)}:
            for template in {config_of(server, c, self.mode) for c in self.configs}:
                source, *extra = template.split("+")
                text = render(source, values, self.tags | set(extra))
                (w / "conf" / template).write_text(text)
                self.result["configs"][template] = hashlib.sha256(text.encode()).hexdigest()

    def setup_authoritative(self):
        """The zones (D213) in <work>/zones: the root zone of the capture and the generated zone, signed by
        `kzonesign`; their query file, its pinned hash and the expected rcodes of its check pass; the loader;
        the configurations of the servers, serving the zones of `DEDENS_ZONES`."""
        w = self.work
        zones = self.zones = os.environ.get("DEDENS_ZONES", "root big").replace(",", " ").split()
        if not zones or any(z not in ("root", "big") for z in zones):
            raise SystemExit(f"DEDENS_ZONES is `root`, `big` or both, not {zones}")
        self.loader = self.engine.start("loader", ["sleep", "infinity"])
        for d in ("zones", "gen", "corpora"):
            subprocess.run(["rm", "-rf", str(w / d)], check=True)
            (w / d).mkdir()
        root_text = (REPO / "testdata/authoritative/zones/root.zone").read_text()
        (w / "zones/root.zone").write_text(root_text)
        big_text, hosts = authzones.big_zone()
        (w / "gen/big.example.zone").write_text(big_text)
        sign = render("knot-sign.conf", {"THREADS": str(SIGN_THREADS)}, set())
        (w / "conf/knot-sign.conf").write_text(sign)
        self.engine("run", "--rm", "-v", f"{w}:/w", *self.engine.user, "--entrypoint", "sh",
                    os.environ["DEDENS_KNOT_IMAGE"], "-c",
                    "mkdir -p /tmp/sign && kzonesign -c /w/conf/knot-sign.conf -o /w/zones big.example.")
        signed = w / "zones/big.example.zone"
        signed.write_text(authzones.generic_dnames(signed.read_text()))
        self.result["zones"] = {
            name: {"bytes": (w / f"zones/{file}").stat().st_size,
                   "records": sum(1 for ln in (w / f"zones/{file}").read_text().splitlines()
                                  if ln.strip() and not ln.startswith((";", "$")))}
            for name, file in (("root", "root.zone"), ("big", "big.example.zone"))}
        self.result["zones"]["big"] |= {"unsigned_records": authzones.BIG_RECORDS, "hosts": hosts}
        lines, self.expected_rcodes = authzones.corpus(zones, root_text, hosts)
        name = f"authoritative-{'-'.join(zones)}.txt"
        data = "".join(f"{ln}\n" for ln in lines).encode()
        self.corpus = w / "corpora" / name
        self.corpus.write_bytes(data)
        self.corpus_lines = len(lines)
        (w / "corpora/check.txt").write_text("".join(f"{ln}\n" for ln in lines[:CHECK_QUERIES]))
        digest = hashlib.sha256(data).hexdigest()
        self.result["corpora"] = {name: digest}
        pinned = dict(ln.split()[::-1] for ln in (HERE / "corpora.sha256").read_text().splitlines()
                      if ln.strip() and not ln.startswith("#"))
        if pinned.get(name) != digest:
            raise SystemExit(f"{name}: sha256 {digest}, corpora.sha256 says {pinned.get(name)}")
        values = {"CORES": str(self.count["server"])}
        for server in self.servers:
            for template in {config_of(server, c, self.mode) for c in self.configs}:
                text = render(template, values, set(zones))
                (w / "conf" / template).write_text(text)
                self.result["configs"][template] = hashlib.sha256(text.encode()).hexdigest()

    def mini_internet(self):
        """The root, the TLD and the zone of the corpus (D201), each served by its own Knot process on its own address
        in one container; for `dnssec` signed, each zone's DS in its parent, from keys made before the parent is
        written (the zone files are written leaf first for it)."""
        w, image, ds = self.work, os.environ["DEDENS_KNOT_IMAGE"], None
        for name, zone, addr in AUTHORITIES:
            (w / "knot" / name).mkdir()
            values = {"NAME": name, "ZONE": zone, "ADDR": addr, "KNOT_THREADS": str(self.count["knot"])}
            (w / f"conf/knot-{name}.conf").write_text(render("recurse-knot.conf", values, self.tags))
            (w / "knot" / name / "zone").write_text(render(f"recurse-{name}.zone", {"DS": ds}, self.tags))
            if "dnssec" in self.tags:
                keymgr = f"keymgr -c /w/conf/knot-{name}.conf {zone}"
                out = self.engine("run", "--rm", "-v", f"{w}:/w", *self.engine.user, "--entrypoint", "sh", image,
                                  "-c", f"{keymgr} generate ksk=yes >&2 && {keymgr} generate >&2 && {keymgr} ds")
                found = re.search(r"\sDS (\d+ 13 2 [0-9a-f]+)", out)
                if not found:
                    raise SystemExit(f"keymgr gives no SHA-256 DS for {zone}: {out}")
                ds = found[1]
        command = " & ".join(f"knotd -c /w/conf/knot-{name}.conf" for name, *_ in AUTHORITIES) + " & wait"
        self.knot = self.engine.start("knot", ["-c", command], image, "sh")

    # One server: start, check, measure.

    def start(self, session):
        """Starts the server, cold: its time to a first right answer and its memory once idle."""
        label, server, template = session
        subprocess.run(["rm", "-rf", str(self.work / "data")], check=True)
        (self.work / "data").mkdir()
        command = [a.format(conf=f"/w/conf/{template}") for a in SERVERS[server]["command"]]
        image = os.environ[SERVERS[server]["image"]] if "image" in SERVERS[server] else None
        name = self.engine.start("server", command, image, SERVERS[server].get("entrypoint"))
        if self.mode == "blocked":
            probes = [((self.work / "lists/blocklist.txt").read_text().split("\n", 1000)[:1000], 1)]
        elif self.authoritative:  # every zone served answers, at its SOA: the load is over when the last does
            probes = [(["."] if z == "root" else [authzones.BIG_APEX], 6) for z in self.zones]
        else:
            probes = [([f"c{i}.cold-start.{'recurse.bench' if self.spec.get('recursive') else 'net'}"
                        for i in range(1000)], 1)]
        try:
            answered = max(self.first_answer(names, qtype) for names, qtype in probes)
        except Fail as e:
            raise Fail(f"{label} {template}: {e}\n" + self.engine.logs(name)[-3000:]) from e
        started = int((self.work / "start").read_text())
        time.sleep(1)
        mem = self.engine.cgroup(name)
        start = {"label": label, "server": server, "template": template, "start_ms": (answered - started) / 1e6,
                 "idle_mib": mem["anon"] / 2**20}
        if server.startswith("dedensd"):  # measured as it ships on Linux: on io_uring, never its poll fallback (D107)
            found = re.search(r'"driver":"(\w+)"', self.engine.logs(name))
            start["driver"] = found[1] if found else None
            if start["driver"] != "io_uring":
                raise Fail(f"{label}: serves on {start['driver']}, not io_uring: kernel.io_uring_disabled?")
        self.result["starts"].append(start)
        if self.spec["cached"]:
            self.dnsperf(self.corpus, once=True)  # primes the cache
        return name

    def first_answer(self, names, qtype):
        """The time (ns) of the server's first answer to one of the names with the mode's rcode, asked by probe.py in
        the loader: its clock is that of the `/w/start` stamp."""
        try:
            return int(self.engine("exec", self.loader, "python3", "/w/probe.py", str(PORT), self.rcode, str(qtype),
                                   *names))
        except RuntimeError as e:
            raise Fail(str(e)) from e

    def dnsperf(self, path, rate=None, once=False, transport=None):
        transport = transport or self.spec["transport"]
        port = TLS_PORT if transport == "dot" else PORT
        threads = self.count["loader"]
        cmd = ["dnsperf", "-s", "127.0.0.1", "-p", str(port), "-d", f"/w/{path.relative_to(self.work)}",
               "-l", str(self.duration), "-T", str(threads), "-c", str(max(8, threads)),
               "-q", str(self.outstanding), "-t", "2", "-O", "latency-histogram",
               "-O", "suppress=timeout,unexpected"]
        if transport != "udp":
            cmd += ["-m", transport]
        if self.authoritative and "dnssec" in self.tags:
            cmd += ["-D"]  # DO set, which turns EDNS on
        if rate:
            cmd += ["-Q", str(int(rate))]
        if once:
            cmd += ["-n", "1"]
        if self.engine.pinning == "taskset":
            cmd = ["taskset", "-c", self.engine.cpus["loader"], *cmd]
        return parse_dnsperf(self.engine("exec", self.loader, *cmd))

    def check(self, session, name):
        """Every query of the check pass answered with the mode's rcode; the sample equal to Knot's answers."""
        label, server, template = session
        asked = self.authority_questions()
        r = self.dnsperf(self.work / "corpora/check.txt", rate=CHECK_RATE, once=True)
        asked = {a: {t: n - asked[a].get(t, 0) for t, n in types.items()}
                 for a, types in self.authority_questions().items()}
        expected = dict(self.expected_rcodes) if self.authoritative else {self.rcode: CHECK_QUERIES}
        ok = r["lost"] == 0 and r["rcodes"] == expected and r["sent"] == CHECK_QUERIES
        sample = self.sample(PORT if self.spec["transport"] != "dot" else TLS_PORT, self.spec["transport"])
        wrong = {q: a for q, a in sample.items() if a != self.reference[q]}
        self.result["checks"].append({"label": label, "server": server, "template": template, "rcodes": r["rcodes"],
                                      "lost": r["lost"], "sample_wrong": {q: str(a) for q, a in wrong.items()},
                                      "authority_questions_per_query": {
                                          a: {t: n / r["sent"] for t, n in types.items() if n}
                                          for a, types in asked.items()}})
        if not ok or wrong:
            logs = self.engine.logs(name)[-2000:]
            raise Fail(f"{label} {template} answers wrong: rcodes {r['rcodes']}, {r['lost']} lost of "
                       f"{r['sent']}, expected {expected}; sample differs from {'Knot' if not self.authoritative else 'Knot (the reference)'}'s on "
                       f"{sorted(wrong)[:5]}\n{logs}")

    def authority_questions(self):
        """The questions each authority of the mini Internet has answered so far, by type (Knot's `mod-stats`); none
        for the modes with one upstream."""
        out = {}
        for name, zone, _ in AUTHORITIES if self.spec.get("recursive") else []:
            text = self.engine("exec", self.knot, "knotc", "-c", f"/w/conf/knot-{name}.conf", "zone-stats", zone,
                               check=False)
            out[name] = {m[1]: int(m[2]) for m in re.finditer(r"mod-stats\.query-type\[(\w+)\]: (\d+)", text)}
        return out

    def sample(self, port, transport, upstream=False, host="127.0.0.1"):
        """`dedens` asking the first SAMPLE questions of the check file: question -> (rcode, answers, AD). With
        DNSSEC, asked with DO and AD set (TelltaleDNS sets AD for DO only), signatures left out of the answers.
        An authority's (`authoritative` modes): (rcode, AA, answer, authority, additional), the signatures kept: the
        servers serve the same signed zones, so equal sets are the right answer, DO set or not; the last two are
        left out of a positive answer."""
        questions = list(dict.fromkeys((self.work / "corpora/check.txt").read_text().splitlines()))[:SAMPLE]
        cmd = ["/w/bin/dedens", f"@{host}", "-p", str(port), "--json"]
        cmd += {"udp": [], "tcp": ["--tcp"], "dot": ["--tls", "--tls-insecure"]}[transport]
        if self.authoritative:
            cmd += ["--dnssec"] if "dnssec" in self.tags else []
        elif "dnssec" in self.tags and not upstream:
            cmd += ["--dnssec", "--adflag"]
        out = self.engine("exec", self.loader, *cmd, *(w for q in questions for w in q.split()), check=False)
        got = {}
        for line in out.splitlines():
            m = json.loads(line)
            q = m.get("question", [{}])[0]
            if self.authoritative:
                def section(name):
                    return frozenset((a["name"].lower(), a["type"], a["data"]) for a in m.get(name, [])
                                     if a["type"] != "OPT")

                answer = section("answer")
                # NSD adds the apex NS set and its addresses to a positive answer, Knot does not (RFC 2181
                # section 9 lets either): the authority and additional sections count when the answer is empty.
                got[f"{q.get('name', '').rstrip('.')} {q.get('type')}"] = (
                    m["header"]["rcode"], "aa" in m["header"]["flags"], answer,
                    frozenset() if answer else section("authority"),
                    frozenset() if answer else section("additional"))
                continue
            answers = frozenset((a["name"].lower(), a["type"], a["data"]) for a in m.get("answer", [])
                                if a["type"] != "RRSIG")
            got[f"{q.get('name', '').rstrip('.')} {q.get('type')}"] = (
                m["header"]["rcode"], answers, "ad" in m["header"]["flags"])
        # The check file of an authority's zones writes its names absolute, the answers' keys do not.
        return {q: got.get(q.replace(". ", " ", 1), ("no answer",)) for q in questions}

    def measure(self, session, name, kind, rate=None):
        """One run: dnsperf's numbers, and the CPU of the server, the loader and Knot over it."""
        label, server, template = session
        if not self.spec["cached"]:
            self.engine.stop(name)
            name = self.start(session)
        roles = {"server": name, "loader": self.loader, **({"knot": self.knot} if self.knot else {})}
        before = {k: self.engine.cgroup(c) for k, c in roles.items()}
        t0 = time.monotonic()
        r = self.dnsperf(self.corpus, rate=rate, once=not self.spec["cached"])
        wall = time.monotonic() - t0
        after = {k: self.engine.cgroup(c) for k, c in roles.items()}
        cpu = {k: after[k]["cpu_us"] - before[k]["cpu_us"] for k in roles}
        user = after["server"]["user_us"] - before["server"]["user_us"]
        system = after["server"]["system_us"] - before["server"]["system_us"]
        r |= {"label": label, "server": server, "template": template, "kind": kind, "rate": rate,
              "server_cpu_us_per_query": cpu["server"] / max(r["completed"], 1),
              "server_user_us_per_query": user / max(r["completed"], 1),
              "server_system_us_per_query": system / max(r["completed"], 1),
              "server_busy": cpu["server"] / (wall * 1e6 * self.count["server"]),
              "loader_busy": cpu["loader"] / (wall * 1e6 * self.count["loader"]),
              "knot_busy": cpu["knot"] / (wall * 1e6 * self.count["knot"]) if self.knot else 0.0,
              "loaded_mib": after["server"]["anon"] / 2**20, "peak_mib": after["server"]["peak"] / 2**20}
        # An authority answers NXDOMAIN to the names the corpus holds that are not in a zone: right, not another rcode.
        right = r["rcodes"].get(self.rcode, 0) + (r["rcodes"].get("NXDOMAIN", 0) if self.authoritative else 0)
        others = r["completed"] - right
        # dnsperf held to a rate spins between sends, so its CPU tells nothing: a rate it fell short of does. A run
        # that sent the whole corpus before its time was up counts the wait for its last answers in its seconds.
        whole = not self.spec["cached"] and r["sent"] >= self.corpus_lines
        sending = r["seconds"] - (DRAIN_S if whole else 0)
        reasons = [why for why, bad in [
            ("dnsperf busy", rate is None and r["loader_busy"] > VOID_BUSY),
            ("rate missed", rate is not None and r["sent"] < (1 - VOID_SHARE) * rate * sending),
            ("Knot busy", r["knot_busy"] > VOID_BUSY),
            ("loss", r["lost"] >= VOID_SHARE * max(r["sent"], 1)),
            ("rcodes", others > VOID_SHARE * max(r["completed"], 1))] if bad]
        r["void"] = reasons
        self.result["runs"].append(r)
        knot = "" if self.authoritative else f"  Knot {r['knot_busy']:4.0%}"
        log(f"  {label:10} {template:24} {kind:6} {r['qps']:10.0f} q/s  lost {r['lost']:6}  "
            f"dnsperf {r['loader_busy']:4.0%}{knot}  {' '.join(reasons)}")
        return name, r

    def run(self):
        self.setup()
        if self.mode == "crosscheck":
            return self.crosscheck()
        sessions = sessions_of(self.servers, self.configs, self.mode)
        if self.authoritative:  # Knot's own answers, sampled once, are the reference the others must give
            knot = next((s for s in sessions if s[1] == "knot"), None)
            if not knot:
                raise SystemExit("the reference is Knot's answers: `knot` is in DEDENS_SERVERS")
            name = self.start(knot)
            try:
                self.reference = self.sample(PORT, "udp")
            finally:
                self.engine.stop(name)
            if missing := [q for q, a in self.reference.items() if a == ("no answer",)]:
                raise Fail(f"Knot gave no answer to {missing[:5]} of the sample")
        else:
            ref = self.sample(self.auth[1], "udp", upstream=True, host=self.auth[0])
            if self.mode == "blocked":
                ref = {q: ("NXDOMAIN", frozenset(), False) for q in ref}
            elif "dnssec" in self.tags:
                ref = {q: (rcode, answers, True) for q, (rcode, answers, _) in ref.items()}
            self.reference = ref
        for rnd in range(self.rounds):  # the order reversed every other round
            log(f"round {rnd + 1}/{self.rounds}")
            for session in sessions if rnd % 2 == 0 else sessions[::-1]:
                name = self.start(session)
                try:
                    self.check(session, name)
                    name, r = self.measure(session, name, "sat")
                    # A server dropping queries at full load saturates lower: 10% under what it answered, twice.
                    # Loss comes with other reasons (dnsperf busy, a rate missed while lost queries time out).
                    for _ in range(SAT_RETRIES):
                        if "loss" not in r["void"]:
                            break
                        name, r = self.measure(session, name, "sat", rate=r["qps"] * 0.9)
                    if not r["void"]:
                        name, _ = self.measure(session, name, "half", rate=r["qps"] / 2)
                finally:
                    self.engine.stop(name)
        sat = {}
        for r in self.result["runs"]:
            if r["kind"] == "sat" and not r["void"]:
                sat.setdefault((r["label"], r["template"]), []).append(r["qps"])
        if not sat:
            return
        # The latency and CPU of every server at one rate: half the lowest saturation.
        common = min(statistics.median(q) for q in sat.values()) / 2
        self.result["common_rate"] = common
        log(f"common rate {common:.0f} q/s")
        for session in sessions:
            name = self.start(session)
            try:
                self.measure(session, name, "common", rate=common)
            finally:
                self.engine.stop(name)

    def crosscheck(self):
        """TelltaleDNS's own smoke bench (`bench/run.sh smoke --target`) against dedensd, as its gate runs it."""
        name = self.start(("dedensd", "dedensd", "dedensd.yaml"))
        src = "/w/" + str(pathlib.Path(os.environ["DEDENS_TELLTALE_SRC"]).relative_to(self.work))
        p = subprocess.run([self.engine.name, "exec", "-w", src, self.loader, "bash", "bench/run.sh", "smoke",
                            "--target", f"127.0.0.1:{PORT}"], check=False, text=True, capture_output=True)
        print(p.stdout + p.stderr)
        self.result["crosscheck"] = {"exit": p.returncode, "output": p.stdout[-5000:]}
        self.engine.stop(name)
        if p.returncode:
            raise Fail(f"TelltaleDNS's smoke bench failed against dedensd ({p.returncode})")


def labels(servers):
    """A name per server of the list, a repeated one numbered (`dedensd`, `dedensd#2`: an A/A run)."""
    return [s if not servers[:i].count(s) else f"{s}#{servers[:i].count(s) + 1}" for i, s in enumerate(servers)]


def sessions_of(servers, configs, mode):
    """(label, server, template) to measure: a configuration file shared by two configurations measured once."""
    out = []
    for label, server in zip(labels(servers), servers):
        if not serves(server, mode):
            continue
        for config in configs:
            session = (label, server, config_of(server, config, mode))
            if session not in out:
                out.append(session)
    return out


def templates_of(mode):
    """The key of SERVERS holding a mode's templates: a recursive mode and an authoritative one have their own."""
    return "authoritative" if MODES[mode].get("authoritative") else "recursion" if MODES[mode].get("recursive") \
        else "configs"


def serves(server, mode):
    """Whether the server has a way to serve the mode: it has templates for it, and does not lack it."""
    return templates_of(mode) in SERVERS[server] and mode not in SERVERS[server].get("lacks", ())


def config_of(server, config, mode):
    """The template of the server's `config` (lean, shipped) for the mode."""
    return SERVERS[server][templates_of(mode)][config]


def count_cpus(spec):
    n = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        n += int(hi or lo) - int(lo) + 1 if lo else 0
    return n


def host(engine):
    """The machine and the kernel the containers run on: on a Mac the host's CPU, and the kernel of the engine's VM.
    The load average is the host's at the start: a run shares the machine with whatever else runs on it."""
    if platform.system() == "Darwin":
        cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], check=True, capture_output=True,
                             text=True).stdout.strip()
    else:
        cpu = next((ln.split(":", 1)[1].strip() for ln in pathlib.Path("/proc/cpuinfo").read_text().splitlines()
                    if ln.startswith("model name")), "")
    return {"system": platform.system(), "kernel": engine("run", "--rm", engine.image, "uname", "-r").strip(),
            "cpu": cpu, "cores": os.cpu_count(), "load_avg_start": os.getloadavg()}


def fmt(x, spec=".2f"):
    """A number for the table, a dash for none (every run void)."""
    return "–" if math.isnan(x) else format(x, spec)


def table(result):
    """A table per configuration: the medians of the valid runs of each server, the void runs counted."""
    runs, starts, servers = result["runs"], result["starts"], result["servers"]
    lines = []
    for config in result["config_names"]:
        lines.append(f"\n{result['mode']}, {config} configurations; common rate "
                     f"{result.get('common_rate', 0):.0f} q/s; medians of the valid runs")
        lines.append("| server | q/s (range) | void | at common rate: avg / p99 / p99.9 ms, CPU µs/query | "
                     "at half its own: avg / p99 / p99.9 ms | MiB idle / loaded | start ms |")
        lines.append("|---|---|---|---|---|---|---|")
        for label, server in zip(labels(servers), servers):
            if not serves(server, result["mode"]):
                lines.append(f"| {label} | | | | | | |")
                continue
            template = config_of(server, config, result["mode"])
            mine = [r for r in runs if r["label"] == label and r["template"] == template]
            st = [s for s in starts if s["label"] == label and s["template"] == template]
            if not mine:
                lines.append(f"| {label} | | | | | | |")
                continue

            def med(kind, key, rs=mine):
                vals = [r[key] for r in rs if (kind is None or r["kind"] == kind) and not r["void"]]
                return statistics.median(vals) if vals else float("nan")

            def lat(kind):
                return " / ".join(fmt(med(kind, k)) for k in ("avg_ms", "p99_ms", "p99.9_ms"))

            sat = [r["qps"] for r in mine if r["kind"] == "sat" and not r["void"]]
            span = f" ({min(sat):.0f}–{max(sat):.0f})" if sat else ""
            lines.append(
                f"| {label} | {fmt(med('sat', 'qps'), '.0f')}{span} | {sum(1 for r in mine if r['void'])}/{len(mine)}"
                f" | {lat('common')}, {fmt(med('common', 'server_cpu_us_per_query'), '.1f')} | {lat('half')} | "
                f"{statistics.median(s['idle_mib'] for s in st):.0f} / {fmt(med(None, 'loaded_mib'), '.0f')} | "
                f"{statistics.median(s['start_ms'] for s in st):.0f} |")
    busy = [(r["loader_busy"], r["knot_busy"]) for r in runs]
    if busy:
        knot = "" if result["mode"].startswith("authoritative") else f", busiest Knot {max(b[1] for b in busy):.0%}"
        lines.append(f"\nbusiest dnsperf {max(b[0] for b in busy):.0%}{knot};"
                     f" void runs: {sum(1 for r in runs if r['void'])} of {len(runs)}")
    return "\n".join(lines)


def main():
    mode, cores, work = sys.argv[1], int(sys.argv[2]), pathlib.Path(sys.argv[3])
    bench = Bench(mode, cores, work)
    status = 0
    try:
        bench.run()
    except Fail as e:
        log(f"FAILED: {e}")
        bench.result["failed"] = str(e)
        status = 1
    finally:
        for role in ("server", "loader", "knot"):
            bench.engine.stop(f"dedens-compare-{role}")
        bench.result["host"]["load_avg_end"] = os.getloadavg()
        out = work / "results" / f"{bench.result['time'].replace(':', '')}-{mode}.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(bench.result, indent=1, default=str))
        log(f"wrote {out}")
    if mode != "crosscheck" and not status:
        print(table(bench.result))
    sys.exit(status)


if __name__ == "__main__":
    main()
