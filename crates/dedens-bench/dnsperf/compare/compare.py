#!/usr/bin/env python3
"""The measuring half of compare.sh, which builds what this runs and passes its versions in the environment.

`compare.py <mode> <cores> <work>`: renders the configurations beside it into <work> (mounted as /w in every
container), generates the corpora with TelltaleDNS's own bench/corpus.py, starts Knot, then each server in turn in
its own container on its own cores, as many times as rounds and run kinds need, and drives it with dnsperf from a
loader container on other cores. The standard library only: it runs on the host.

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
import socket
import statistics
import struct
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
PORT, TLS_PORT = 5301, 8531
KNOT = ("127.0.0.1", 5300)
BLOCKLIST_NAMES = 1_000_000
CHECK_QUERIES = 1000  # the check pass: the corpus's first lines, at CHECK_RATE
CHECK_RATE = 2000
SAMPLE = 20  # the answers compared with Knot's
VOID_BUSY = 0.90
# The wait for the last answers, in the seconds of a run that sent its whole corpus (0.01-0.22 s on the VPS, D183).
DRAIN_S = 0.25
VOID_SHARE = 0.01
START_TIMEOUT = 120
WRONG_FOR = 10
SAT_RETRIES = 2
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

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
    "crosscheck": {"corpus": None, "transport": "udp", "cached": False},
}

# A server's configuration template per configuration, its command line in the container, and the modes it has
# no way to serve: its row stays empty (the plan's choice: not emulated).
SERVERS = {
    "dedensd": {
        "configs": {"lean": "dedensd.yaml", "shipped": "dedensd.yaml"},
        "command": ["/w/bin/dedensd", "--config", "{conf}"],
    },
    "telltale": {
        "configs": {"lean": "telltale-lean.toml", "shipped": "telltale-shipped.toml"},
        "command": ["/w/bin/telltale", "run", "-c", "{conf}"],
    },
    "unbound": {
        "configs": {"lean": "unbound.conf", "shipped": "unbound.conf"},
        "command": ["unbound", "-d", "-c", "{conf}"],
    },
    "coredns": {
        "configs": {"lean": "coredns-lean.Corefile", "shipped": "coredns-shipped.Corefile"},
        "command": ["coredns", "-conf", "{conf}"],
        "lacks": {"dnssec", "blocked"},
    },
    "broken": {
        "configs": {"lean": "broken.Corefile", "shipped": "broken.Corefile"},
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

    def start(self, role, command, image=None, entrypoint=None):
        """Starts container dedens-compare-<role> on the cores of its role, writing /w/start as it execs."""
        name = f"dedens-compare-{role}"
        self(*self.rm, name, check=False)
        cpus = self.cpus[role]
        args = ["run", "-d", "--name", name, "--network", "host", "--security-opt", "label=disable",
                "-v", f"{self.work}:/w", *self.user]
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
        return {"cpu_us": field["usage_usec"], "anon": field["anon"], "peak": peak}


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
    spec = importlib.util.spec_from_file_location("corpus", pathlib.Path(telltale_src) / "bench/corpus.py")
    corpus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(corpus)
    expected = dict(ln.split()[::-1] for ln in (HERE / "corpora.sha256").read_text().splitlines()
                    if ln.strip() and not ln.startswith("#"))
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


def query(qid, name, qtype=1):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack(">HH", qtype, 1)


def first_answer(names, rcode):
    """Asks the server, every 2 ms, until it answers one of the names with the rcode; the time of that answer.
    An answer later than 2 ms counts as well: the IDs are those of the questions asked. Answers with another rcode
    only, WRONG_FOR seconds after the first, fail: a list still loading answers NOERROR for a while, not forever."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.002)
    want = next(n for n, name in RCODES.items() if name == rcode)
    deadline = time.monotonic() + START_TIMEOUT
    first_wrong = None
    i = 0
    while time.monotonic() < deadline:
        try:
            sock.sendto(query(i & 0xFFFF, names[i % len(names)]), ("127.0.0.1", PORT))
            data = sock.recv(4096)
            if len(data) >= 4 and struct.unpack(">H", data[:2])[0] <= min(i, 0xFFFF):
                if data[3] & 0xF == want:
                    return time.time_ns()
                first_wrong = first_wrong or time.monotonic()
                if time.monotonic() - first_wrong > WRONG_FOR:
                    raise Fail(f"rcode {RCODES.get(data[3] & 0xF, data[3] & 0xF)} for {WRONG_FOR} s, not {rcode}")
        except OSError:
            pass
        i += 1
    raise Fail(f"no {rcode} answer in {START_TIMEOUT} s")


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
        self.servers = os.environ.get("DEDENS_SERVERS", "dedensd telltale unbound coredns").split()
        self.configs = os.environ.get("DEDENS_CONFIGS", "lean shipped").split()
        for s in self.servers:
            if s not in SERVERS:
                raise SystemExit(f"unknown server {s}: {', '.join(SERVERS)}")
        n = os.cpu_count() or 1
        cpus = {
            "server": os.environ.get("DEDENS_SERVER_CPUS", f"0-{cores - 1}"),
            "knot": os.environ.get("DEDENS_KNOT_CPUS", str(n - 1)),
            "loader": os.environ.get("DEDENS_LOAD_CPUS", f"{cores}-{n - 2}"),
        }
        self.count = {role: count_cpus(c) for role, c in cpus.items()}
        if min(self.count.values()) < 1 or n < cores + 2:
            raise SystemExit(f"{n} cores: not enough for {cores} server cores, a loader core and a Knot core")
        self.engine = Engine(os.environ.get("DEDENS_CONTAINER", "docker"), work, os.environ["DEDENS_IMAGE"], cpus)
        self.rcode = self.spec.get("rcode", "NOERROR")
        self.tags = set(self.spec.get("tags", set()))
        self.result = {
            "mode": mode, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "versions": dict(kv.split("=") for kv in os.environ["DEDENS_VERSIONS"].split()),
            "host": host(), "engine": self.engine("--version").strip(), "pinning": self.engine.pinning,
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
        if self.spec["corpus"]:
            self.corpus, self.result["corpora"] = corpora(w, self.mode, os.environ["DEDENS_TELLTALE_SRC"])
            self.corpus_lines = len(self.corpus.read_text().splitlines())
        if not (w / "key.pem").exists():
            self.engine("run", "--rm", "-v", f"{w}:/w", *self.engine.user, self.engine.image, "openssl", "req",
                        "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "3650",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", "/w/key.pem", "-out", "/w/cert.pem")
        (w / "key.pem").chmod(0o600)
        (w / "root.zone").write_text((HERE / "root.zone").read_text())
        knot = render("knot.conf", {"KNOT_THREADS": str(self.count["knot"])}, self.tags)
        (w / "conf/knot.conf").write_text(knot)
        self.knot = self.engine.start("knot", ["-c", "/w/conf/knot.conf"], os.environ["DEDENS_KNOT_IMAGE"], "knotd")
        self.loader = self.engine.start("loader", ["sleep", "infinity"])
        dig = ["exec", self.loader, "dig", "@127.0.0.1", "-p", str(KNOT[1]), "+noall", "+answer"]
        for _ in range(100):
            if "198.18.0.1" in self.engine(*dig, "x.", check=False):
                break
            time.sleep(0.1)
        else:
            raise SystemExit("Knot does not answer: " + self.engine("logs", self.knot, check=False))
        # The key-signing key of the signed root: the trust anchor of every validator.
        anchors = [ln for ln in self.engine(*dig, ".", "DNSKEY").splitlines() if re.search(r"\sDNSKEY\s+257 3 ", ln)]
        if "dnssec" in self.tags and not anchors:
            raise SystemExit("Knot serves no key-signing key: " + self.engine("logs", self.knot, check=False))
        (w / "anchors.zone").write_text("".join(ln + "\n" for ln in anchors))
        upstream = self.spec.get("upstream", "udp")
        values = {"DNSSEC": "validate" if "dnssec" in self.tags else "off", "CORES": str(self.count["server"]),
                  "TCP_UPSTREAM": "yes" if upstream == "tcp" else "no", "UPSTREAM_PROTO": upstream}
        for server in set(self.servers):
            for template in set(SERVERS[server]["configs"].values()):
                text = render(template, values, self.tags)
                (w / "conf" / template).write_text(text)
                self.result["configs"][template] = hashlib.sha256(text.encode()).hexdigest()

    # One server: start, check, measure.

    def start(self, session):
        """Starts the server, cold: its time to a first right answer and its memory once idle."""
        label, server, template = session
        subprocess.run(["rm", "-rf", str(self.work / "data")], check=True)
        (self.work / "data").mkdir()
        command = [a.format(conf=f"/w/conf/{template}") for a in SERVERS[server]["command"]]
        name = self.engine.start("server", command)
        if self.mode == "blocked":
            names = (self.work / "lists/blocklist.txt").read_text().split("\n", 1000)[:1000]
        else:
            names = [f"c{i}.cold-start.net" for i in range(1000)]
        try:
            answered = first_answer(names, self.rcode)
        except Fail as e:
            raise Fail(f"{label} {template}: {e}\n" + self.engine("logs", name, check=False)[-3000:]) from e
        started = int((self.work / "start").read_text())
        time.sleep(1)
        mem = self.engine.cgroup(name)
        start = {"label": label, "server": server, "template": template, "start_ms": (answered - started) / 1e6,
                 "idle_mib": mem["anon"] / 2**20}
        self.result["starts"].append(start)
        if self.spec["cached"]:
            self.dnsperf(self.corpus, once=True)  # primes the cache
        return name

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
        r = self.dnsperf(self.work / "corpora/check.txt", rate=CHECK_RATE, once=True)
        ok = r["lost"] == 0 and r["rcodes"] == {self.rcode: r["sent"]} and r["sent"] == CHECK_QUERIES
        sample = self.sample(PORT if self.spec["transport"] != "dot" else TLS_PORT, self.spec["transport"])
        wrong = {q: a for q, a in sample.items() if a != self.reference[q]}
        self.result["checks"].append({"label": label, "server": server, "template": template, "rcodes": r["rcodes"],
                                      "lost": r["lost"], "sample_wrong": {q: str(a) for q, a in wrong.items()}})
        if not ok or wrong:
            logs = self.engine("logs", name, check=False)[-2000:]
            raise Fail(f"{label} {template} answers wrong: rcodes {r['rcodes']}, {r['lost']} lost of "
                       f"{r['sent']}, expected {self.rcode} for all {CHECK_QUERIES}; sample differs from Knot's on "
                       f"{sorted(wrong)[:5]}\n{logs}")

    def sample(self, port, transport, upstream=False):
        """`dedens` asking the first SAMPLE questions of the check file: question -> (rcode, answers, AD). With
        DNSSEC, asked with DO and AD set (TelltaleDNS sets AD for DO only), signatures left out of the answers."""
        questions = list(dict.fromkeys((self.work / "corpora/check.txt").read_text().splitlines()))[:SAMPLE]
        cmd = ["/w/bin/dedens", "@127.0.0.1", "-p", str(port), "--json"]
        cmd += {"udp": [], "tcp": ["--tcp"], "dot": ["--tls", "--tls-insecure"]}[transport]
        if "dnssec" in self.tags and not upstream:
            cmd += ["--dnssec", "--adflag"]
        out = self.engine("exec", self.loader, *cmd, *(w for q in questions for w in q.split()), check=False)
        got = {}
        for line in out.splitlines():
            m = json.loads(line)
            q = m.get("question", [{}])[0]
            answers = frozenset((a["name"].lower(), a["type"], a["data"]) for a in m.get("answer", [])
                                if a["type"] != "RRSIG")
            got[f"{q.get('name', '').rstrip('.')} {q.get('type')}"] = (
                m["header"]["rcode"], answers, "ad" in m["header"]["flags"])
        return {q: got.get(q, ("no answer", frozenset(), False)) for q in questions}

    def measure(self, session, name, kind, rate=None):
        """One run: dnsperf's numbers, and the CPU of the server, the loader and Knot over it."""
        label, server, template = session
        if not self.spec["cached"]:
            self.engine.stop(name)
            name = self.start(session)
        roles = {"server": name, "loader": self.loader, "knot": self.knot}
        before = {k: self.engine.cgroup(c) for k, c in roles.items()}
        t0 = time.monotonic()
        r = self.dnsperf(self.corpus, rate=rate, once=not self.spec["cached"])
        wall = time.monotonic() - t0
        after = {k: self.engine.cgroup(c) for k, c in roles.items()}
        cpu = {k: after[k]["cpu_us"] - before[k]["cpu_us"] for k in roles}
        r |= {"label": label, "server": server, "template": template, "kind": kind, "rate": rate,
              "server_cpu_us_per_query": cpu["server"] / max(r["completed"], 1),
              "loader_busy": cpu["loader"] / (wall * 1e6 * self.count["loader"]),
              "knot_busy": cpu["knot"] / (wall * 1e6 * self.count["knot"]),
              "loaded_mib": after["server"]["anon"] / 2**20, "peak_mib": after["server"]["peak"] / 2**20}
        others = r["completed"] - r["rcodes"].get(self.rcode, 0)
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
        log(f"  {label:10} {template:24} {kind:6} {r['qps']:10.0f} q/s  lost {r['lost']:6}  "
            f"dnsperf {r['loader_busy']:4.0%}  Knot {r['knot_busy']:4.0%}  {' '.join(reasons)}")
        return name, r

    def run(self):
        self.setup()
        if self.mode == "crosscheck":
            return self.crosscheck()
        ref = self.sample(KNOT[1], "udp", upstream=True)
        if self.mode == "blocked":
            ref = {q: ("NXDOMAIN", frozenset(), False) for q in ref}
        elif "dnssec" in self.tags:
            ref = {q: (rcode, answers, True) for q, (rcode, answers, _) in ref.items()}
        self.reference = ref
        sessions = sessions_of(self.servers, self.configs, self.mode)
        for rnd in range(self.rounds):  # the order reversed every other round
            log(f"round {rnd + 1}/{self.rounds}")
            for session in sessions if rnd % 2 == 0 else sessions[::-1]:
                name = self.start(session)
                try:
                    self.check(session, name)
                    name, r = self.measure(session, name, "sat")
                    # A server dropping queries at full load saturates lower: 10% under what it answered, twice.
                    for _ in range(SAT_RETRIES):
                        if r["void"] != ["loss"]:
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
        if mode in SERVERS[server].get("lacks", ()):
            continue
        for config in configs:
            session = (label, server, SERVERS[server]["configs"][config])
            if session not in out:
                out.append(session)
    return out


def count_cpus(spec):
    n = 0
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        n += int(hi or lo) - int(lo) + 1 if lo else 0
    return n


def host():
    cpu = next((ln.split(":", 1)[1].strip() for ln in pathlib.Path("/proc/cpuinfo").read_text().splitlines()
                if ln.startswith("model name")), "") if pathlib.Path("/proc/cpuinfo").exists() else ""
    return {"kernel": platform.release(), "cpu": cpu, "cores": os.cpu_count()}


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
            template = SERVERS[server]["configs"][config]
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
        lines.append(f"\nbusiest dnsperf {max(b[0] for b in busy):.0%}, busiest Knot {max(b[1] for b in busy):.0%};"
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
        out = work / "results" / f"{bench.result['time'].replace(':', '')}-{mode}.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(bench.result, indent=1, default=str))
        log(f"wrote {out}")
    if mode != "crosscheck" and not status:
        print(table(bench.result))
    sys.exit(status)


if __name__ == "__main__":
    main()
