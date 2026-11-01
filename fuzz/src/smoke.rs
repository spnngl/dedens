//! Stable-toolchain stand-in for a short fuzz run: replays every captured response in
//! `crates/dedens-proto/tests/testdata/`, `crates/dedens-dnssec/tests/testdata/` and
//! `crates/dedens-odoh/tests/testdata/`, and the zone files of `crates/dedens-proto/tests/zones/` and
//! `crates/dedens-dnssec/tests/zones/`, plus truncated and bit-flipped variants through each target. Any panic
//! fails the test and the offending input is written under `target/fuzz-smoke-crash/` (turn it into a test).

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use crate::{Entry, TARGETS};

/// Single-bit flips tried per seed.
const FLIPS: usize = 512;
/// Truncation points tried per seed.
const CUTS: usize = 200;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Captured responses and example zone files: every target gets every seed, whatever format it parses.
fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds = Vec::new();
    for dir in [
        "dedens-proto/tests/testdata",
        "dedens-proto/tests/zones",
        "dedens-dnssec/tests/testdata",
        "dedens-dnssec/tests/zones",
        "dedens-odoh/tests/testdata",
    ] {
        let dir = root().join("../crates").join(dir);
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
    seeds.sort();
    seeds
}

/// The first datagram each way of every CoAP capture of `crates/dedens-net/tests/testdata/coap/` (hex lines).
fn coap_seeds() -> Vec<(String, Vec<u8>)> {
    let dir = root().join("../crates/dedens-net/tests/testdata/coap");
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
                include_bytes!("../../crates/dedens-proto/tests/testdata/aaaa.bin"),
            ]
            .concat(),
        ),
        // Oblivious DoH: the headers of Cloudflare's configurations (captured) and a message around its body.
        (
            "odoh http".into(),
            [
                &b"\x69\x00no-cache, no-store\x000\x00"[..],
                include_bytes!("../../crates/dedens-odoh/tests/testdata/odoh-go-query.bin"),
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

#[test]
fn every_target_survives_seeds_and_mutations() {
    let seeds = seeds();
    assert!(!seeds.is_empty(), "no seeds, run just capture");
    for (target, entry) in TARGETS {
        for (name, seed) in &seeds {
            for (label, input) in variants(name, seed) {
                run(target, *entry, &label, &input);
            }
        }
        for (label, input) in edge_cases() {
            run(target, *entry, &label, &input);
        }
    }
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
