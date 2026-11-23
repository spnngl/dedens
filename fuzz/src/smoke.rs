//! Stable-toolchain stand-in for a short fuzz run: replays the seeds of the justfile's `fuzz_seeds` and `fuzz-seeds`
//! (but the `CoAP` captures, of which the first datagram each way), plus truncated and bit-flipped variants, through
//! each target. Any panic fails the test and the offending input is written under `target/fuzz-smoke-crash/` (turn it
//! into a test).

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Instant;

use dedens_testkit::recursion::Resolution;

use crate::{Entry, TARGETS};

/// Single-bit flips tried per seed.
const FLIPS: usize = 512;
/// Truncation points tried per seed.
const CUTS: usize = 200;
/// Targets that run a whole resolution on an input (30 s for all the variants), which try every
/// n-th variant only, so that the test stays under ten seconds: the fuzz run does the rest.
const THINNED: &[(&str, usize)] = &[("resolve_replay", 4)];

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Captured responses, example zone files, DNS-over-HTTPS exchanges, blocklists and RDAP answers, the directories of the
/// justfile's `fuzz_seeds`: every target gets every seed, whatever format it parses.
fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds = Vec::new();
    for dir in [
        "proto", "zones", "dnssec", "odoh", "dnscrypt", "doh", "plugins", "rdap",
    ] {
        let dir = root().join("../testdata").join(dir);
        for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            seeds.push((name, fs::read(&path).expect("read seed")));
        }
    }
    seeds.extend(coap_seeds());
    seeds.extend(recursion());
    seeds.extend(command_lines());
    seeds.extend(stamps());
    seeds.extend(configs());
    // Trust anchors: the root's DS records as IANA publishes them (RFC 9718 §2.2).
    seeds.push((
        "root.ds".into(),
        include_bytes!("../../crates/dedens-dnssec/src/root.ds").to_vec(),
    ));
    // IANA's root hints and a few entries of its TLD list, as `just roots` captured them (D126).
    seeds.push((
        "named.root".into(),
        include_bytes!("../../crates/dedens-roots/src/named.root").to_vec(),
    ));
    seeds.push((
        "tlds.json".into(),
        include_bytes!("../../crates/dedens-roots/tests/data/tlds.json").to_vec(),
    ));
    // ICANN's CA bundle, which checks the signature of `root-anchors.xml` (D127).
    seeds.push((
        "icannbundle.pem".into(),
        include_bytes!("../../crates/dedens-dnssec/src/icannbundle.pem").to_vec(),
    ));
    // The state of a root key rollover followed by RFC 5011, as `Rollover` writes it (D200).
    seeds.push((
        "root-5011.state".into(),
        include_bytes!("../seeds/root-5011.state").to_vec(),
    ));
    // A journal of three versions of the RFC 4035 appendix A zone, as `Journal` writes it (D207).
    seeds.push((
        "example.journal".into(),
        include_bytes!("../seeds/example.journal").to_vec(),
    ));
    seeds.sort();
    seeds
}

/// The first datagram each way of every CoAP capture of `testdata/coap/` (hex lines).
fn coap_seeds() -> Vec<(String, Vec<u8>)> {
    let dir = root().join("../testdata/coap");
    let mut seeds = Vec::new();
    for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.extension().is_none_or(|ext| ext != "txt") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read capture");
        let name = path
            .file_stem()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        for direction in ["c2s", "s2c"] {
            let hex = text
                .lines()
                .filter(|line| !line.starts_with('#'))
                .find_map(|line| line.split(' ').nth(2).filter(|_| line.contains(direction)))
                .expect("a datagram each way");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect();
            seeds.push((format!("coap {name} {direction}"), bytes));
        }
    }
    seeds
}

/// The responses of the captured resolutions of `testdata/recursion/` and `testdata/recursion/minimised/` (D188).
fn recursion() -> Vec<(String, Vec<u8>)> {
    let mut seeds = Vec::new();
    for id in ["recursion", "recursion/minimised"] {
        let dir = root().join("../testdata").join(id);
        for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("dir entry").path();
            if path.extension().is_none_or(|ext| ext != "yaml") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("read resolution");
            let resolution =
                Resolution::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let name = format!(
                "{id}/{}",
                path.file_stem().expect("file name").to_string_lossy()
            );
            seeds.extend(
                (resolution.exchanges.into_iter().enumerate())
                    .map(|(i, exchange)| (format!("{name} {i}"), exchange.response)),
            );
        }
    }
    seeds
}

/// The command lines of `seeds/command_lines.txt`, NUL between two arguments, as `just fuzz` writes them.
fn command_lines() -> Vec<(String, Vec<u8>)> {
    include_str!("../seeds/command_lines.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            (
                format!("dedens {line}"),
                line.replace(' ', "\0").into_bytes(),
            )
        })
        .collect()
}

/// The stamps of `seeds/stamps.txt`, one to a line, as `just fuzz` writes them.
fn stamps() -> Vec<(String, Vec<u8>)> {
    include_str!("../seeds/stamps.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| (format!("stamp {line}"), line.as_bytes().to_vec()))
        .collect()
}

/// The configurations of `dedensd` the justfile's `fuzz-seeds` copies: the image's, the packages', `seeds/dnscrypt.yaml`,
/// `seeds/odoh.yaml` and the examples of `apps/dedensd/src/config/mod.rs` (`example.yaml`, `example2.yaml`,
/// `example3.yaml`).
fn configs() -> Vec<(String, Vec<u8>)> {
    let mut examples: Vec<String> = Vec::new();
    let mut open: Option<Vec<&str>> = None;
    let docs = include_str!("../../apps/dedensd/src/config/mod.rs")
        .lines()
        .map_while(|line| line.strip_prefix("//!"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line));
    for line in docs {
        match (line, open.as_mut()) {
            ("```yaml", None) => open = Some(Vec::new()),
            ("```", Some(example)) => {
                examples.push(example.join("\n") + "\n");
                open = None;
            }
            (line, Some(example)) => example.push(line),
            (_, None) => {}
        }
    }
    let [forwarder, resolver, authoritative] =
        <[String; 3]>::try_from(examples).expect("the three example configurations");
    vec![
        (
            "dedensd.yaml".into(),
            include_bytes!("../../deploy/dedensd.yaml").to_vec(),
        ),
        (
            "dedensd.conf.yaml".into(),
            include_bytes!("../../deploy/packages/dedensd.conf.yaml").to_vec(),
        ),
        (
            "dnscrypt.yaml".into(),
            include_bytes!("../seeds/dnscrypt.yaml").to_vec(),
        ),
        (
            "odoh.yaml".into(),
            include_bytes!("../seeds/odoh.yaml").to_vec(),
        ),
        ("example.yaml".into(), forwarder.into_bytes()),
        ("example2.yaml".into(), resolver.into_bytes()),
        ("example3.yaml".into(), authoritative.into_bytes()),
    ]
}

/// Deterministic xorshift64: reproducible variants without a `rand` dependency.
struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(bound).expect("small bound")).expect("below bound")
    }
}

/// `messages` each behind its length in two octets, the input of `resolve_replay`.
fn framed(messages: &[&[u8]]) -> Vec<u8> {
    messages
        .iter()
        .flat_map(|message| {
            let length = u16::try_from(message.len()).expect("a datagram");
            [&length.to_be_bytes()[..], message].concat()
        })
        .collect()
}

/// Inputs that are not derived from a seed: empty, binary, huge counts and pointer loops.
fn edge_cases() -> Vec<(String, Vec<u8>)> {
    let header = |counts: [u8; 8]| [&[0, 1, 0, 0][..], &counts].concat();
    vec![
        ("empty".into(), Vec::new()),
        ("0xff".into(), vec![0xFF; 64]),
        ("nul".into(), vec![0; 64]),
        ("huge counts".into(), header([0xFF; 8])),
        (
            "pointer to itself".into(),
            [header([0, 1, 0, 0, 0, 0, 0, 0]), vec![0xC0, 12, 0, 1, 0, 1]].concat(),
        ),
        (
            "pointer loop".into(),
            [
                header([0, 1, 0, 0, 0, 0, 0, 0]),
                vec![1, b'a', 0xC0, 12, 0, 1, 0, 1],
            ]
            .concat(),
        ),
        (
            "long name".into(),
            [header([0, 1, 0, 0, 0, 0, 0, 0]), vec![63; 300]].concat(),
        ),
        // `resolve_replay`: responses each behind its length, the n-th for the n-th query, the middle one cut short.
        ("framed responses".into(), framed(&[
            include_bytes!("../../testdata/proto/cname_chain.bin"),
            &include_bytes!("../../testdata/proto/nodata.bin")[..20],
            include_bytes!("../../testdata/proto/a.bin"),
        ])),
        // Blocklists: names that are parents of each other, the blocked first, the allowed second, in mixed case.
        (
            "blocklist names".into(),
            b"example.com ok.example.com a.B.c.example.COM *.x.ok.example.com e.f.g.h.example.com 127.0.0.1 a.b.c.d.example.com"
                .to_vec(),
        ),
        (
            "blocklist deep allowlist".into(),
            b"example.com a.b.c.d.e.example.com b.example.net x.y.example.com Z.B.EXAMPLE.net 127.0.0.1"
                .to_vec(),
        ),
        // A chain of names, the even ones listed (D118), and one of more names than are checked.
        (
            "blocklist chain".into(),
            b"ads.example a.b.example t.example c.d.example".to_vec(),
        ),
        (
            "blocklist long chain".into(),
            b"a.example b.example c.example d.example e.example f.example g.example h.example i.example j.example k.example l.example m.example n.example o.example p.example q.example r.example"
                .to_vec(),
        ),
        // CoAP discovery: the listing of RFC 6690 §5.5, and the paths a `DoC` server may hold (D95).
        (
            "link format".into(),
            b"</sensors>;ct=40;title=\"Sensor Index\",\n</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\n</sensors/light>;rt=\"light-lux\";if=\"sensor\",\n<http://www.example.com/sensors/t123>;anchor=\"/sensors/temp\"\n;rel=\"describedby\",\n</t>;anchor=\"/sensors/temp\";rel=\"alternate\""
                .to_vec(),
        ),
        // Encoded delimiters a segment holds once decoded (RFC 7252 §6.4): the nightly run's crash of 2026-11-19.
        (
            "link with encoded delimiters".into(),
            b"</;ii<%25>,</a%2Fb%3Fc%23d/e>".to_vec(),
        ),
        ("link path".into(), b"dns/query".to_vec()),
        ("link path with empty segments".into(), b"/a//b/".to_vec()),
        // DoH: a template, a GET (RFC 8484 §4.1.1) and an aged response around a captured message.
        (
            "doh template".into(),
            b"https://dnsserver.example.net/dns-query{?dns}".to_vec(),
        ),
        (
            "doh get".into(),
            b"\0dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB".to_vec(),
        ),
        (
            "doh response".into(),
            [
                &b"\x80\x00100\x00Sun, 06 Nov 1994 08:49:37 GMT\x00"[..],
                include_bytes!("../../testdata/proto/aaaa.bin"),
            ]
            .concat(),
        ),
        // Oblivious DoH: the headers of Cloudflare's configurations (captured) and a message around its body.
        (
            "odoh http".into(),
            [
                &b"\x11\x01\x3b\x9a\xca\x01\x00no-cache, no-store\x000\x00Sun, 06 Nov 1994 08:49:37 GMT\x00"[..],
                include_bytes!("../../testdata/odoh/odoh-go-query.bin"),
            ]
            .concat(),
        ),
    ]
}

fn variants(name: &str, seed: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![(name.to_owned(), seed.to_vec())];
    let step = (seed.len() / CUTS).max(1);
    out.extend(
        (0..seed.len())
            .step_by(step)
            .map(|n| (format!("{name} cut at {n}"), seed[..n].to_vec())),
    );
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    if !seed.is_empty() {
        for _ in 0..FLIPS {
            let (byte, bit) = (rng.below(seed.len()), rng.below(8));
            let mut flipped = seed.to_vec();
            flipped[byte] ^= 1 << bit;
            out.push((format!("{name} flip byte {byte} bit {bit}"), flipped));
        }
    }
    out
}

fn run(target: &str, entry: Entry, label: &str, input: &[u8]) {
    if catch_unwind(AssertUnwindSafe(|| entry(input))).is_ok() {
        return;
    }
    let dir: PathBuf = root().join("target/fuzz-smoke-crash");
    let saved = fs::create_dir_all(&dir)
        .and_then(|()| {
            let hash = input.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
                (h ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3)
            });
            let file = dir.join(format!("{target}-{hash:016x}"));
            fs::write(&file, input).map(|()| file)
        })
        .map_or_else(
            |e| format!("not saved: {e}"),
            |f| format!("saved to {}", f.display()),
        );
    panic!(
        "{target} panicked on `{label}` ({} bytes), {saved}",
        input.len()
    );
}

/// Every seed, its variants and the edge cases through `entry`: the test `survives::<target>` of each target.
pub(crate) fn survives(target: &str, entry: Entry) {
    static SEEDS: LazyLock<Vec<(String, Vec<u8>)>> = LazyLock::new(seeds);
    assert!(!SEEDS.is_empty(), "no seeds, run just capture");
    let started = Instant::now();
    let every = THINNED
        .iter()
        .find_map(|(thinned, every)| (*thinned == target).then_some(*every))
        .unwrap_or(1);
    for (name, seed) in SEEDS.iter() {
        for (label, input) in variants(name, seed).iter().step_by(every) {
            run(target, entry, label, input);
        }
    }
    for (label, input) in edge_cases() {
        run(target, entry, &label, &input);
    }
    // Seen with `--nocapture`: a target whose time grows is a cost to look at before a fuzz run is.
    println!("{target}: {:?}", started.elapsed());
}

#[test]
fn targets_and_shims_agree() {
    let mut listed: Vec<_> = TARGETS.iter().map(|(name, _)| (*name).to_owned()).collect();
    listed.sort();
    let mut shims: Vec<_> = fs::read_dir(root().join("fuzz_targets"))
        .expect("fuzz_targets directory")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".rs")
                .to_owned()
        })
        .collect();
    shims.sort();
    assert_eq!(listed, shims, "fuzz_targets/");
    let mut bins = bin_names(&fs::read_to_string(root().join("Cargo.toml")).expect("Cargo.toml"));
    bins.sort();
    assert_eq!(listed, bins, "[[bin]] in Cargo.toml");
}

/// The `name` of every `[[bin]]` table of a manifest.
fn bin_names(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if in_bin && let Some(value) = line.strip_prefix("name") {
            let value = value.trim_start().trim_start_matches('=').trim();
            names.push(value.trim_matches('"').to_owned());
        }
    }
    names
}
