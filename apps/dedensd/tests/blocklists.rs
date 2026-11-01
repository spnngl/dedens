//! The published blocklists of `docs/blocklists/blocklists.yaml` (D87): the file is read and checked offline, and
//! the ignored test, `just blocklists`, downloads every list and checks its format.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Duration;

use dedens_plugins::Lists;
use serde::Deserialize;
use ureq::tls::{RootCerts, TlsConfig};

/// The file, read at build time.
const CATALOG: &str = include_str!("../../../docs/blocklists/blocklists.yaml");

/// The largest list taken, as `dedensd` (D57).
const MAX_LIST_LEN: u64 = 256 << 20;

/// The time a download may take: more than `dedensd`'s 30 s, the largest lists being tens of MB.
const TIMEOUT: Duration = Duration::from_secs(120);

/// Downloads running at once.
const DOWNLOADS_AT_ONCE: usize = 8;

/// Tries of a download, which public servers sometimes fail (oisd answers 503 now and then), and the wait
/// before the first retry, doubled for each next one.
const TRIES: u32 = 3;
const RETRY_AFTER: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    sources: Vec<Source>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    id: String,
    name: String,
    maintainer: String,
    site: String,
    /// An SPDX id, else the terms.
    license: String,
    description: String,
    lists: Vec<List>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    id: String,
    description: Option<String>,
    url: String,
    format: Format,
    categories: Vec<Category>,
    /// How often, as announced, else as measured.
    updated: String,
}

/// What a line of a list holds, after comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Format {
    /// A name.
    Domains,
    /// `*.name`.
    Wildcard,
    /// `/etc/hosts`: `0.0.0.0 name`.
    Hosts,
    /// `||name^` rules.
    Adblock,
    /// An address or a CIDR network first, other columns after it.
    Ips,
    /// A URL.
    Urls,
}

impl Format {
    /// Whether `dedensd` reads it as a blocklist (D56).
    const fn is_read(self) -> bool {
        matches!(self, Self::Domains | Self::Wildcard | Self::Hosts)
    }

    /// The format of `line`, none for a comment or a blank line. A line no other format takes is a name:
    /// [`Lists::check`] tells whether it reads as one.
    fn of(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';', '!']) {
            return None;
        }
        let mut fields = line.split_whitespace();
        let first = fields.next()?;
        if first.starts_with("||") {
            return Some(Self::Adblock);
        }
        if first.contains("://") {
            return Some(Self::Urls);
        }
        if first.starts_with("*.") {
            return Some(Self::Wildcard);
        }
        if let Ok(address) = first.parse::<IpAddr>() {
            // A hosts line sinks a name; an address list may follow its addresses with a count or a comment.
            let sinks = address.is_unspecified() || address.is_loopback();
            let named = fields.next().is_some_and(|field| {
                !field.starts_with(['#', ';'])
                    && field.parse::<IpAddr>().is_err()
                    && !field.bytes().all(|b| b.is_ascii_digit())
            });
            return Some(if sinks && named {
                Self::Hosts
            } else {
                Self::Ips
            });
        }
        if is_network(first) {
            return Some(Self::Ips);
        }
        Some(Self::Domains)
    }
}

/// What a list holds, as the maintainer says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Category {
    /// And trackers.
    Ads,
    Malware,
    Phishing,
    Scam,
    Cryptojacking,
    Adult,
    Gambling,
    Spam,
    /// Command and control servers.
    Botnet,
    /// Addresses scanning, brute-forcing or exploiting.
    Attacks,
}

fn catalog() -> Catalog {
    serde_saphyr::from_str(CATALOG).expect("docs/blocklists/blocklists.yaml reads")
}

/// Whether `field` is a CIDR network: an address, `/`, a prefix length its family holds.
fn is_network(field: &str) -> bool {
    field.split_once('/').is_some_and(|(address, length)| {
        let bits = match address.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => 32,
            Ok(IpAddr::V6(_)) => 128,
            Err(_) => return false,
        };
        length.parse::<u8>().is_ok_and(|length| length <= bits)
    })
}

/// Whether `id` is lowercase letters, digits and inner hyphens.
fn is_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether `items` holds no item twice.
fn unique<T: Eq + std::hash::Hash>(items: impl IntoIterator<Item = T>) -> bool {
    let mut seen = HashSet::new();
    items.into_iter().all(|item| seen.insert(item))
}

#[test]
fn catalog_is_well_formed() {
    let catalog = catalog();
    assert!(!catalog.sources.is_empty());
    assert!(
        unique(catalog.sources.iter().map(|s| &s.id)),
        "source ids repeat"
    );
    assert!(
        unique(
            catalog
                .sources
                .iter()
                .flat_map(|s| &s.lists)
                .map(|l| &l.url)
        ),
        "list URLs repeat"
    );
    for s in &catalog.sources {
        let at = &s.id;
        assert!(is_id(at), "{at}: id");
        for (field, text) in [
            ("name", &s.name),
            ("maintainer", &s.maintainer),
            ("license", &s.license),
            ("description", &s.description),
        ] {
            assert!(!text.trim().is_empty(), "{at}: empty {field}");
        }
        assert!(s.site.starts_with("https://"), "{at}: site {}", s.site);
        assert!(
            unique(s.lists.iter().map(|l| &l.id)),
            "{at}: list ids repeat"
        );
        for l in &s.lists {
            let at = format!("{at}.{}", l.id);
            assert!(is_id(&l.id), "{at}: id");
            assert!(
                l.description.as_ref().is_none_or(|d| !d.trim().is_empty()),
                "{at}: empty description"
            );
            // `dedensd` takes `http://` lists from a server of one's own only (D57).
            assert!(l.url.starts_with("https://"), "{at}: url {}", l.url);
            assert!(
                !l.categories.is_empty() && unique(&l.categories),
                "{at}: categories {:?}",
                l.categories
            );
            assert!(!l.updated.trim().is_empty(), "{at}: empty updated");
        }
    }
}

#[test]
fn formats_of_lines() {
    for (line, format) in [
        ("# comment", None),
        ("! adblock comment", None),
        ("; Spamhaus DROP List", None),
        ("   ", None),
        ("ads.example", Some(Format::Domains)),
        ("*.ads.example", Some(Format::Wildcard)),
        ("0.0.0.0 ads.example", Some(Format::Hosts)),
        ("127.0.0.1\tads.example # tracker", Some(Format::Hosts)),
        (":: ads.example", Some(Format::Hosts)),
        ("0.0.0.0 0.0.0.0", Some(Format::Ips)),
        ("||ads.example^", Some(Format::Adblock)),
        ("192.0.2.1", Some(Format::Ips)),
        ("192.0.2.1\t12", Some(Format::Ips)),
        ("192.0.2.1      # TH  AS23969   TOT", Some(Format::Ips)),
        ("198.51.100.0/24 ; SBL123", Some(Format::Ips)),
        ("2001:db8::/32", Some(Format::Ips)),
        ("192.0.2.0/33", Some(Format::Domains)),
        ("https://phish.example/login", Some(Format::Urls)),
    ] {
        assert_eq!(Format::of(line), format, "{line:?}");
    }
}

/// The text at `url`, or why not.
fn download(agent: &ureq::Agent, url: &str) -> Result<String, String> {
    let mut error = String::new();
    for tried in 0..TRIES {
        if tried > 0 {
            std::thread::sleep(RETRY_AFTER * 2_u32.pow(tried - 1));
        }
        match agent.get(url).call().and_then(|mut response| {
            response
                .body_mut()
                .with_config()
                .limit(MAX_LIST_LEN)
                .read_to_string()
        }) {
            Ok(text) => return Ok(text),
            Err(e) => error = e.to_string(),
        }
    }
    Err(error)
}

/// What the lines of `text` hold, when most are of `format`; when `dedensd` reads `format`, `text` must read as a
/// downloaded list (D56).
fn judge(text: &str, format: Format) -> Result<String, String> {
    let mut formats = BTreeMap::<Format, usize>::new();
    for line in text.lines().filter_map(Format::of) {
        *formats.entry(line).or_default() += 1;
    }
    let lines: usize = formats.values().sum();
    let held = formats.get(&format).copied().unwrap_or_default();
    if lines == 0 || held * 2 < lines {
        return Err(format!("{held} of {lines} lines {format:?}: {formats:?}"));
    }
    if format.is_read() {
        let read = Lists::check(text).map_err(|e| e.to_string())?;
        return Ok(format!(
            "{} names, {} lines skipped",
            read.names, read.skipped
        ));
    }
    Ok(format!("{held} of {lines} lines {format:?}"))
}

#[test]
#[ignore = "downloads every published list: `just blocklists`"]
fn every_list_has_its_format() {
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .https_only(true)
        .tls_config(tls)
        .build()
        .new_agent();
    let catalog = catalog();
    let lists: Vec<(String, &List)> = catalog
        .sources
        .iter()
        .flat_map(|s| s.lists.iter().map(|l| (format!("{}.{}", s.id, l.id), l)))
        .collect();
    let outcomes: Vec<Result<String, String>> = lists
        .chunks(DOWNLOADS_AT_ONCE)
        .flat_map(|chunk| {
            std::thread::scope(|scope| {
                let runs: Vec<_> = chunk
                    .iter()
                    .map(|(_, list)| {
                        let agent = &agent;
                        scope.spawn(move || {
                            download(agent, &list.url).and_then(|text| judge(&text, list.format))
                        })
                    })
                    .collect();
                runs.into_iter()
                    .map(|run| run.join().expect("a download runs"))
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    let mut table = String::new();
    let mut failures = 0;
    for ((id, list), outcome) in lists.iter().zip(&outcomes) {
        let (status, detail) = match outcome {
            Ok(detail) => ("ok", detail),
            Err(error) => ("FAILED", error),
        };
        failures += usize::from(outcome.is_err());
        writeln!(table, "{status:8} {id} {detail} ({})", list.url).expect("a String takes text");
    }
    println!("{table}");
    assert_eq!(
        failures,
        0,
        "{failures} of {} lists failed:\n{table}",
        lists.len()
    );
}
