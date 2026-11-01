//! The public resolvers of `docs/providers/providers.yaml` (D67): the file is read and checked offline, and the
//! ignored test, `just providers`, asks every endpoint over the network.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use dedens_net::doh::Template;
use serde::Deserialize;
use serde_json::{Value, json};

/// The file, read at build time.
const CATALOG: &str = include_str!("../../../docs/providers/providers.yaml");

/// A domain whose DNSSEC signatures do not validate: a validating resolver answers SERVFAIL.
const BROKEN_DNSSEC: &str = "dnssec-failed.org";

/// The EDE code of a resolver refusing by law (RFC 8914 §4.17): it answered, so it is up.
const EDE_CENSORED: u64 = 16;

/// The EDE codes of a blocked name: Blocked, Censored, Filtered (RFC 8914 §4.16 to §4.18).
const EDE_BLOCKING: [u64; 3] = [15, 16, 17];

/// Global addresses (a.root-servers.net) whose route tells whether this host reaches each address family.
const ROUTE_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53);
const ROUTE_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30)),
    53,
);

/// Retries running at once, each its own `dedens` process.
const RETRIES_AT_ONCE: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    canaries: Canaries,
    providers: Vec<Provider>,
}

/// Per category, names a resolver blocking it blocks at least one of and the others answer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Canaries {
    ads: Vec<String>,
    malware: Vec<String>,
    adult: Vec<String>,
    gambling: Vec<String>,
    social: Vec<String>,
}

impl Canaries {
    fn of(&self, block: Block) -> &[String] {
        match block {
            Block::Ads => &self.ads,
            Block::Malware => &self.malware,
            Block::Adult => &self.adult,
            Block::Gambling => &self.gambling,
            Block::Social => &self.social,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    id: String,
    name: String,
    operator: String,
    /// ISO 3166-1 alpha-2.
    country: String,
    site: String,
    description: String,
    privacy: String,
    resolvers: Vec<Resolver>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolver {
    id: String,
    description: Option<String>,
    blocks: Vec<Block>,
    /// Addresses answered for a blocked name, beside `0.0.0.0` and `127.0.0.0/8`.
    #[serde(default)]
    block_pages: Vec<Ipv4Addr>,
    dnssec: Dnssec,
    /// Whether a packet cache answers with the cookie of an earlier client, which `dedens` drops as forged
    /// (RFC 7873 §5.3): it is then asked without one.
    #[serde(default)]
    stale_cookies: bool,
    /// Addresses answering over UDP and TCP, port 53.
    #[serde(default)]
    plain: Vec<IpAddr>,
    tls: Option<Encrypted>,
    quic: Option<Encrypted>,
    /// `DoH` URLs (RFC 8484 §3), asked over HTTP/3 (D83).
    #[serde(default)]
    https: Vec<String>,
    /// `DoH` URLs of servers where HTTP/3 does not answer: parsed, not asked until HTTP/2 (D83).
    #[serde(default)]
    https_h2: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Encrypted {
    /// The name the certificate holds.
    name: String,
    addresses: Vec<IpAddr>,
}

/// What a resolver does with a broken signature, as measured.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Dnssec {
    /// Answers SERVFAIL.
    Validates,
    /// Answers the data.
    Ignores,
    /// Its servers disagree: not checked.
    Inconsistent,
}

impl Dnssec {
    /// The rcode a query of [`BROKEN_DNSSEC`] gets, when one is sure.
    fn rcode(self) -> Option<&'static str> {
        match self {
            Self::Validates => Some("SERVFAIL"),
            Self::Ignores => Some("NOERROR"),
            Self::Inconsistent => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Block {
    Ads,
    Malware,
    Adult,
    Gambling,
    Social,
}

impl Block {
    const ALL: [Self; 5] = [
        Self::Ads,
        Self::Malware,
        Self::Adult,
        Self::Gambling,
        Self::Social,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Ads => "ads",
            Self::Malware => "malware",
            Self::Adult => "adult",
            Self::Gambling => "gambling",
            Self::Social => "social",
        }
    }
}

/// One query of the run: its id, its server's address (none for a `DoH` URL, whose host name the system resolves)
/// and the server as `dedens` reads it, whether over TCP and with a cookie.
struct Probe {
    id: String,
    address: Option<IpAddr>,
    server: String,
    tcp: bool,
    cookie: bool,
}

impl Resolver {
    /// One probe per address and transport, plain addresses over UDP then TCP, then one per `DoH` URL.
    fn probes(&self, provider: &str) -> Vec<Probe> {
        let prefix = format!("{provider}.{}", self.id);
        let mut probes = Vec::new();
        for &address in &self.plain {
            for (transport, tcp) in [("udp", false), ("tcp", true)] {
                probes.push(Probe {
                    id: format!("{prefix}.{transport}.{address}"),
                    address: Some(address),
                    server: address.to_string(),
                    tcp,
                    cookie: !self.stale_cookies,
                });
            }
        }
        for (scheme, encrypted) in [("tls", &self.tls), ("quic", &self.quic)] {
            if let Some(encrypted) = encrypted {
                for &address in &encrypted.addresses {
                    probes.push(Probe {
                        id: format!("{prefix}.{scheme}.{address}"),
                        address: Some(address),
                        server: format!(
                            "{scheme}://{}#{}",
                            SocketAddr::new(address, 853),
                            encrypted.name
                        ),
                        tcp: false,
                        cookie: !self.stale_cookies,
                    });
                }
            }
        }
        for (number, url) in (1..).zip(&self.https) {
            probes.push(Probe {
                id: format!("{prefix}.https.{number}"),
                address: None,
                server: url.clone(),
                tcp: false,
                cookie: !self.stale_cookies,
            });
        }
        probes
    }
}

fn catalog() -> Catalog {
    serde_saphyr::from_str(CATALOG).expect("docs/providers/providers.yaml reads")
}

/// Whether this host has a route to `to`: connecting a UDP socket sends nothing, but needs one.
fn routed(to: SocketAddr) -> bool {
    let any = match to {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    UdpSocket::bind(any)
        .and_then(|socket| socket.connect(to))
        .is_ok()
}

/// Whether `id` is lowercase letters, digits and inner hyphens: a query id as is.
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
    for block in Block::ALL {
        let names = catalog.canaries.of(block);
        assert!(
            !names.is_empty()
                && unique(names)
                && names.iter().all(|n| !n.is_empty() && !n.ends_with('.')),
            "canaries of {}: {names:?}",
            block.name()
        );
    }
    assert!(!catalog.providers.is_empty());
    assert!(
        unique(catalog.providers.iter().map(|p| &p.id)),
        "provider ids repeat"
    );
    for p in &catalog.providers {
        let at = &p.id;
        assert!(is_id(at), "{at}: id");
        for (field, text) in [
            ("name", &p.name),
            ("operator", &p.operator),
            ("description", &p.description),
            ("privacy", &p.privacy),
        ] {
            assert!(!text.trim().is_empty(), "{at}: empty {field}");
        }
        assert!(
            p.country.len() == 2 && p.country.bytes().all(|b| b.is_ascii_uppercase()),
            "{at}: country {}",
            p.country
        );
        assert!(p.site.starts_with("https://"), "{at}: site {}", p.site);
        assert!(!p.resolvers.is_empty(), "{at}: no resolver");
        assert!(
            unique(p.resolvers.iter().map(|r| &r.id)),
            "{at}: resolver ids repeat"
        );
        for r in &p.resolvers {
            let at = format!("{at}.{}", r.id);
            assert!(is_id(&r.id), "{at}: id");
            assert!(
                r.description.as_ref().is_none_or(|d| !d.trim().is_empty()),
                "{at}: empty description"
            );
            assert!(unique(&r.blocks), "{at}: blocks repeat");
            assert!(unique(&r.block_pages), "{at}: block pages repeat");
            assert!(
                r.block_pages.is_empty() || !r.blocks.is_empty(),
                "{at}: block pages without blocks"
            );
            assert!(unique(&r.plain), "{at}: plain addresses repeat");
            for encrypted in [&r.tls, &r.quic].into_iter().flatten() {
                assert!(!encrypted.name.is_empty(), "{at}: empty name");
                assert!(
                    !encrypted.addresses.is_empty(),
                    "{at}: {} without addresses",
                    encrypted.name
                );
                assert!(
                    unique(&encrypted.addresses),
                    "{at}: {} addresses repeat",
                    encrypted.name
                );
            }
            for url in r.https.iter().chain(&r.https_h2) {
                assert!(
                    Template::parse(url).is_ok(),
                    "{at}: {url} is no DoH URI template"
                );
            }
            assert!(unique(&r.https), "{at}: https URLs repeat");
            assert!(unique(&r.https_h2), "{at}: https_h2 URLs repeat");
            assert!(
                r.https.iter().all(|url| !r.https_h2.contains(url)),
                "{at}: a URL in https and https_h2"
            );
            assert!(
                !r.probes(&p.id).is_empty() || !r.https_h2.is_empty(),
                "{at}: no endpoint"
            );
        }
    }
}

/// What came back for one query.
enum Outcome {
    /// Its check held.
    Passed,
    /// Refused by law where the test runs (EDE 16): the resolver is up.
    Censored,
    Failed(String),
}

/// What a query checks.
enum Check {
    /// Its `expect`: the rcode.
    Expect,
    /// Whether the resolver blocks the name (`blocked`) or answers it; `pages` are its block pages. `category`
    /// is the id of the resolver's category: one of its canaries blocked is enough.
    Blocks {
        blocked: bool,
        pages: Vec<Ipv4Addr>,
        category: String,
    },
}

/// A query of the run and what it checks.
struct Ask {
    query: Value,
    check: Check,
}

impl Ask {
    fn id(&self) -> &str {
        self.query["id"].as_str().expect("an id")
    }
}

/// The query of `name` at `probe`, expecting `rcode` when there is one.
fn query(id: &str, probe: &Probe, name: &str, rcode: Option<&str>) -> Value {
    let mut query = json!({
        "id": id,
        "name": name,
        "type": "A",
        "server": probe.server,
        "options": {"tcp": probe.tcp, "cookie": probe.cookie},
    });
    if let Some(rcode) = rcode {
        query["expect"] = json!({"rcode": rcode});
    }
    query
}

/// Judges the report of a query by its check.
fn judge(report: &Value, check: &Check) -> Outcome {
    let ede: Vec<u64> = report["edns"]["options"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|option| option["option"] == "ede")
        .filter_map(|option| option["code"].as_u64())
        .collect();
    let censored = ede.contains(&EDE_CENSORED);
    match check {
        Check::Expect => {
            let failures: Vec<&str> = report["failures"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            match (failures.is_empty(), censored) {
                (true, _) => Outcome::Passed,
                (false, true) => Outcome::Censored,
                (false, false) => Outcome::Failed(failures.join("; ")),
            }
        }
        Check::Blocks { blocked, pages, .. } => {
            let addresses: Vec<Ipv4Addr> = report["answer"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|record| record["type"] == "A")
                .filter_map(|record| record["data"].as_str()?.parse().ok())
                .collect();
            let is_blocked = match report["header"]["rcode"].as_str() {
                Some("REFUSED") if censored => return Outcome::Censored,
                Some("NXDOMAIN") => true,
                Some("NOERROR") => {
                    ede.iter().any(|code| EDE_BLOCKING.contains(code))
                        || addresses.is_empty()
                        || addresses.iter().any(|address| {
                            address.is_unspecified()
                                || address.is_loopback()
                                || pages.contains(address)
                        })
                }
                rcode => return Outcome::Failed(format!("rcode {rcode:?}")),
            };
            match (is_blocked, blocked) {
                (true, true) | (false, false) => Outcome::Passed,
                (true, false) => Outcome::Failed("blocked, not in `blocks`".to_owned()),
                (false, true) => Outcome::Failed(format!("answered {addresses:?}")),
            }
        }
    }
}

/// Asks `asks` in one `dedens` run, each `tries` times at most, keyed by query id; a query without output
/// is missing.
fn ask(asks: &[&Ask], tries: u8) -> BTreeMap<String, Outcome> {
    let queries: Vec<&Value> = asks.iter().map(|ask| &ask.query).collect();
    let file = json!({"options": {"time": 3, "tries": tries}, "queries": queries});
    let output = assert_cmd::cargo_bin_cmd!("dedens")
        .args(["-f", "-", "--json"])
        .write_stdin(file.to_string())
        .output()
        .expect("dedens runs");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8");
    assert_ne!(output.status.code(), Some(2), "usage error: {stderr}");

    let checks: BTreeMap<&str, &Check> = asks.iter().map(|ask| (ask.id(), &ask.check)).collect();
    let mut outcomes = BTreeMap::new();
    for line in stdout.lines() {
        let report: Value = serde_json::from_str(line).expect("a JSON report");
        let id = report["id"].as_str().expect("an id");
        let check = checks.get(id).expect("a query of the run");
        outcomes.insert(id.to_owned(), judge(&report, check));
    }
    for line in stderr.lines() {
        if let Some((id, error)) = line
            .strip_prefix("dedens: ")
            .and_then(|line| line.split_once(": "))
        {
            outcomes.insert(id.to_owned(), Outcome::Failed(error.to_owned()));
        }
    }
    outcomes
}

#[test]
#[ignore = "asks public resolvers over the network, IPv4 and IPv6: `just providers`"]
fn every_endpoint_answers() {
    // An address family without a route (IPv6 on many CI runners) is skipped, not failed.
    let (v4, v6) = (routed(ROUTE_V4), routed(ROUTE_V6));
    assert!(v4 || v6, "no route to the internet");
    let catalog = catalog();
    let mut asks = Vec::new();
    let mut skipped = 0;
    for p in &catalog.providers {
        for r in &p.resolvers {
            let (probes, unrouted): (Vec<_>, Vec<_>) =
                r.probes(&p.id)
                    .into_iter()
                    .partition(|probe| match probe.address {
                        Some(address) if address.is_ipv4() => v4,
                        Some(_) => v6,
                        None => true,
                    });
            skipped += unrouted.len();
            for probe in &probes {
                asks.push(Ask {
                    query: query(&probe.id, probe, "example.com", Some("NOERROR")),
                    check: Check::Expect,
                });
            }
            // DNSSEC validation and blocking, at the first endpoint.
            let Some(probe) = probes.first() else {
                continue;
            };
            if let Some(rcode) = r.dnssec.rcode() {
                let id = format!("{}.{}.dnssec", p.id, r.id);
                asks.push(Ask {
                    query: query(&id, probe, BROKEN_DNSSEC, Some(rcode)),
                    check: Check::Expect,
                });
            }
            for block in Block::ALL {
                let category = format!("{}.{}.blocks.{}", p.id, r.id, block.name());
                for name in catalog.canaries.of(block) {
                    asks.push(Ask {
                        query: query(&format!("{category}.{name}"), probe, name, None),
                        check: Check::Blocks {
                            blocked: r.blocks.contains(&block),
                            pages: r.block_pages.clone(),
                            category: category.clone(),
                        },
                    });
                }
            }
        }
    }
    if skipped > 0 {
        let family = if v4 { "IPv6" } else { "IPv4" };
        println!("no {family} route: {skipped} endpoints skipped");
    }
    let outcomes = ask(&asks.iter().collect::<Vec<_>>(), 2);

    // A failure is asked again alone, in its own run, with more tries: some public servers drop many queries
    // (Comodo half of them), and QUIC connections sharing one UDP socket time out at some (docs/TODECIDE.md).
    // A dead endpoint costs 8 tries of 3 s. Most queries failing is the network, not the servers.
    let failed: Vec<&Ask> = asks
        .iter()
        .filter(|ask| {
            !matches!(
                outcomes.get(ask.id()),
                Some(Outcome::Passed | Outcome::Censored)
            )
        })
        .collect();
    assert!(
        failed.len() * 2 <= asks.len(),
        "{} of {} queries failed: is the network down?",
        failed.len(),
        asks.len()
    );
    let retried: BTreeMap<String, Outcome> = failed
        .chunks(RETRIES_AT_ONCE)
        .flat_map(|chunk| {
            std::thread::scope(|scope| {
                let runs: Vec<_> = chunk
                    .iter()
                    .map(|one| scope.spawn(move || ask(std::slice::from_ref(one), 8)))
                    .collect();
                runs.into_iter()
                    .flat_map(|run| run.join().expect("a retry runs"))
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    let (table, failures) = report(&asks, &outcomes, &retried);
    println!("{table}");
    assert_eq!(
        failures,
        0,
        "{failures} of {} queries failed:\n{table}",
        asks.len()
    );
}

/// The table of `asks`, a line per query with its status, after the first run (`outcomes`) and the retries
/// (`retried`), and how many failed.
fn report(
    asks: &[Ask],
    outcomes: &BTreeMap<String, Outcome>,
    retried: &BTreeMap<String, Outcome>,
) -> (String, usize) {
    let rows: Vec<(&Ask, &str, &str)> = asks
        .iter()
        .map(|ask| {
            let (status, detail) = match (outcomes.get(ask.id()), retried.get(ask.id())) {
                (Some(Outcome::Passed), _) => ("ok", ""),
                (Some(Outcome::Censored), _) | (_, Some(Outcome::Censored)) => {
                    ("censored", "EDE 16, refused here by law")
                }
                (Some(Outcome::Failed(error)), Some(Outcome::Passed)) => {
                    ("retried", error.as_str())
                }
                (None, Some(Outcome::Passed)) => ("retried", "no output"),
                (_, Some(Outcome::Failed(error))) => ("FAILED", error.as_str()),
                (_, None) => ("FAILED", "no output"),
            };
            (ask, status, detail)
        })
        .collect();
    // The categories blocked as claimed: one canary blocked is enough.
    let blocking: HashSet<&str> = rows
        .iter()
        .filter_map(|(ask, status, _)| match &ask.check {
            Check::Blocks {
                blocked: true,
                category,
                ..
            } if *status != "FAILED" => Some(category.as_str()),
            _ => None,
        })
        .collect();

    let mut table = String::new();
    let mut failures = 0;
    for (ask, mut status, mut detail) in rows {
        if let Check::Blocks { category, .. } = &ask.check
            && status == "FAILED"
            && blocking.contains(category.as_str())
        {
            (status, detail) = ("ok", "answered, another canary blocked");
        }
        failures += usize::from(status == "FAILED");
        writeln!(table, "{status:8} {} {detail}", ask.id()).expect("a String takes text");
    }
    (table, failures)
}
