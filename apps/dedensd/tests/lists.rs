//! Blocklists: `dedensd` downloading a stage's lists, and the published lists.

#[cfg(unix)]
mod downloads {
    //! `dedensd` downloading the lists of a blocklist stage (D57) from a loopback HTTP server: a list blocks once
    //! fetched, and after a restart from its saved copy; a SIGHUP fetches again, an unchanged list is not downloaded
    //! again, and a failed download or an error page keeps the saved copy.

    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread;

    use dedens_proto::{Message, Question, Rcode, RecordType};

    use crate::util::{Server, ask_udp};

    /// What the HTTP server answers, and the version tags its requests carried.
    #[derive(Debug, Default)]
    struct Page {
        status: u16,
        body: String,
        etag: String,
        asked_with: Vec<Option<String>>,
    }

    /// A loopback HTTP/1.1 server of one page, answering 304 to a request carrying its version tag.
    struct Http {
        addr: SocketAddr,
        page: Arc<Mutex<Page>>,
    }

    impl Http {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("a TCP port");
            let addr = listener.local_addr().expect("its address");
            let page = Arc::new(Mutex::new(Page::default()));
            let shared = Arc::clone(&page);
            thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    let mut tag = None;
                    for line in BufReader::new(&stream).lines().map_while(Result::ok) {
                        if line.is_empty() {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("if-none-match")
                        {
                            tag = Some(value.trim().to_owned());
                        }
                    }
                    let mut page = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    let (status, body) = if tag.as_deref() == Some(page.etag.as_str()) {
                        (304, "")
                    } else {
                        (page.status, page.body.as_str())
                    };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\nETag: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        page.etag,
                        body.len()
                    );
                    page.asked_with.push(tag);
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Self { addr, page }
        }

        /// Serves `body` with `status`, as version `etag`.
        fn serve(&self, status: u16, body: &str, etag: &str) {
            let mut page = self.page.lock().unwrap_or_else(PoisonError::into_inner);
            page.status = status;
            body.clone_into(&mut page.body);
            page.etag = format!("\"{etag}\"");
        }

        /// The version tag the last request carried.
        fn last_tag(&self) -> Option<String> {
            let page = self.page.lock().unwrap_or_else(PoisonError::into_inner);
            page.asked_with.last().cloned().flatten()
        }
    }

    /// A server blocking the names of the list at `url`, its copy kept in `dir`, and answering both names of the test
    /// from a hosts stage otherwise.
    fn blocking(listen: &str, url: &str, dir: &Path) -> String {
        format!(
            "listen: ['{listen}']\ndownloads:\n  dir: '{}'\npipeline: [block, hosts]\nstages:\n  block:\n    type: blocklist\n    urls: ['{url}']\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 ads.example tracker.example']\n",
            dir.display()
        )
    }

    /// Whether `server` blocks `name`.
    fn blocks(server: &Server, name: &str) -> bool {
        let name = name.parse().expect("a name");
        let query = Message::query(1, Question::new(name, RecordType::A))
            .to_vec()
            .expect("a query fits");
        ask_udp(server.addr, &query).rcode() == Rcode::NXDOMAIN
    }

    /// A directory of its own in the temporary directory.
    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dedensd-lists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn downloaded_lists_block_and_outlive_failures_and_restarts() {
        let http = Http::start();
        http.serve(200, "ads.example\n", "v1");
        let url = format!("http://{}/list", http.addr);
        let dir = temp_dir();
        let mut server = Server::configured(|listen| blocking(listen, &url, &dir));
        assert!(server.event("list downloaded").is_some());
        assert!(server.event("reloaded").is_some());
        assert!(blocks(&server, "ads.example."));
        assert!(!blocks(&server, "tracker.example."));

        // A SIGHUP fetches the lists again: a new version replaces the list.
        http.serve(200, "tracker.example\n", "v2");
        server.hang_up();
        assert!(server.event("list downloaded").is_some());
        assert!(server.event("reloaded").is_some());
        assert!(blocks(&server, "tracker.example."));
        assert!(!blocks(&server, "ads.example."));

        // The same version is not downloaded again.
        server.hang_up();
        assert!(server.event("list unchanged").is_some());
        assert_eq!(http.last_tag().as_deref(), Some("\"v2\""));

        // An error page served with status 200 is not a list: the saved copy stays.
        http.serve(200, "404: Not Found", "v3");
        server.hang_up();
        assert!(
            server
                .event("list download failed, keeping the saved copy")
                .is_some()
        );
        assert!(blocks(&server, "tracker.example."));
        drop(server);

        // A start serves the saved copy at once, whatever the download does.
        http.serve(500, "", "v4");
        let mut server = Server::configured(|listen| blocking(listen, &url, &dir));
        assert!(blocks(&server, "tracker.example."));
        assert!(
            server
                .event("list download failed, keeping the saved copy")
                .is_some()
        );
        assert!(blocks(&server, "tracker.example."));
        std::fs::remove_dir_all(&dir).expect("removed");
    }

    /// S15.c: a list is logged by its scheme, host and path, never by the credentials or the query of its URL, and no
    /// line the server writes holds them, whether its list downloads, is unchanged or fails.
    #[test]
    fn logged_urls_carry_no_credentials_or_query() {
        let http = Http::start();
        http.serve(200, "ads.example\n", "v1");
        let url = format!("http://user:secret@{}/list?token=t", http.addr);
        let dir = tempfile::tempdir().expect("a directory");
        let mut server = Server::configured(|listen| blocking(listen, &url, dir.path()));
        let event = server.event("list downloaded").expect("the list downloads");
        assert_eq!(event["fields"]["url"], format!("http://{}/list", http.addr));
        server.hang_up();
        assert!(server.event("list unchanged").is_some());
        http.serve(200, "404: Not Found", "v2");
        server.hang_up();
        assert!(
            server
                .event("list download failed, keeping the saved copy")
                .is_some()
        );
        let lines = server.stderr();
        assert!(lines.len() > 3, "{lines:?}");
        for line in lines {
            assert!(
                !line.contains("secret") && !line.contains("token"),
                "{line}"
            );
        }
    }

    /// How many lists `server` has read from a saved copy so far.
    fn copies_read(server: &Server) -> usize {
        server
            .stderr()
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| {
                event["fields"]["message"] == "list parsed"
                    && event["fields"]["kind"] == "saved copy"
            })
            .count()
    }

    /// D120: a list is read once, when it downloads; the reload that follows, a SIGHUP, and a download that finds it
    /// unchanged read no copy again. A start reads the copy it finds.
    #[test]
    fn a_downloaded_list_is_read_once() {
        let http = Http::start();
        http.serve(200, "ads.example\n", "v1");
        let url = format!("http://{}/list", http.addr);
        let dir = tempfile::tempdir().expect("a directory");
        let mut server = Server::configured(|listen| blocking(listen, &url, dir.path()));
        assert!(server.event("list downloaded").is_some());
        assert!(server.event("reloaded").is_some());
        assert!(blocks(&server, "ads.example."));
        // A SIGHUP reloads, then fetches; a list that changed reloads once more.
        server.hang_up();
        assert!(server.event("reloaded").is_some());
        assert!(server.event("list unchanged").is_some());
        http.serve(200, "tracker.example\n", "v2");
        server.hang_up();
        assert!(server.event("reloaded").is_some());
        assert!(server.event("list downloaded").is_some());
        assert!(server.event("reloaded").is_some());
        assert!(blocks(&server, "tracker.example."));
        assert_eq!(copies_read(&server), 0);
        drop(server);

        http.serve(304, "", "v2");
        let server = Server::configured(|listen| blocking(listen, &url, dir.path()));
        assert!(blocks(&server, "tracker.example."));
        assert_eq!(copies_read(&server), 1);
    }
}

mod published {
    //! The published blocklists of `docs/blocklists/blocklists.yaml` (D87): the file is read and checked offline, and
    //! the ignored test, `just blocklists`, downloads every list and checks its format and its freshness.

    use std::collections::{BTreeMap, HashSet};
    use std::fmt::Write as _;
    use std::io::Read as _;
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use dedens_plugins::{Names, Tlds};
    use serde::Deserialize;
    use ureq::tls::{RootCerts, TlsConfig};

    /// The file, read at build time.
    const CATALOG: &str = include_str!("../../../docs/blocklists/blocklists.yaml");

    /// The largest list taken, as `dedensd` (D57).
    const MAX_LIST_LEN: u64 = 256 << 20;

    /// The bytes read of a list `dedensd` does not read, whose format its first lines tell.
    const PREFIX_LEN: u64 = 1 << 20;

    /// The time a download may take: more than `dedensd`'s 30 s, the largest lists being tens of MB.
    const TIMEOUT: Duration = Duration::from_secs(120);

    /// Downloads running at once.
    const DOWNLOADS_AT_ONCE: usize = 8;

    /// Tries of a request, which public servers sometimes fail (oisd answers 503 now and then), and the wait
    /// before the first retry, doubled for each next one.
    const TRIES: u32 = 3;
    const RETRY_AFTER: Duration = Duration::from_secs(5);

    /// A list may miss this many updates, plus [`GRACE`], before it counts as stale: the lists of `stevenblack`, announced
    /// daily, come every 1 to 3 days.
    const MISSED_UPDATES: u32 = 3;
    const GRACE: Duration = Duration::from_hours(24);

    /// The SPDX ids the file uses; one is added when a source takes it.
    const SPDX: [&str; 5] = [
        "BSD-3-Clause",
        "GPL-3.0-only",
        "MIT",
        "MPL-2.0",
        "Unlicense",
    ];

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
        status: Status,
        license: License,
        #[serde(rename = "use")]
        usage: Use,
        /// For a [`License::Custom`] or [`License::None`] only.
        terms: Option<String>,
        description: String,
        lists: Vec<List>,
    }

    /// Whether a source still publishes.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Status {
        Active,
        /// Its lists unchanged since that day.
        Frozen(Day),
        /// No list left to download.
        Retired,
    }

    /// A day, `2026-11-01`: its midnight UTC.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(try_from = "String")]
    struct Day(SystemTime);

    impl TryFrom<String> for Day {
        type Error = String;

        fn try_from(text: String) -> Result<Self, String> {
            parse_date(&text)
                .map(Self)
                .ok_or_else(|| format!("{text:?} is no YYYY-MM-DD date"))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(try_from = "String")]
    enum License {
        /// One of [`SPDX`].
        Spdx,
        /// The source's own terms.
        Custom,
        /// None given.
        None,
    }

    impl TryFrom<String> for License {
        type Error = String;

        fn try_from(text: String) -> Result<Self, String> {
            match text.as_str() {
                "custom" => Ok(Self::Custom),
                "none" => Ok(Self::None),
                id if SPDX.contains(&id) => Ok(Self::Spdx),
                id => Err(format!(
                    "{id:?} is neither `custom`, `none` nor an SPDX id of {SPDX:?}"
                )),
            }
        }
    }

    /// What the terms allow with the data, as read.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    enum Use {
        /// Any use, commercial included.
        Free,
        /// Any use but selling it.
        NoResale,
        NonCommercial,
        /// In a product or a service for others, only with permission.
        Ask,
        /// No terms given.
        Unknown,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct List {
        id: String,
        description: Option<String>,
        url: String,
        format: Format,
        categories: Vec<Category>,
        updated: Updated,
    }

    /// How often a list changes, as announced, else as measured.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(try_from = "String")]
    enum Updated {
        Every(Duration),
        Irregular,
    }

    impl TryFrom<String> for Updated {
        type Error = String;

        fn try_from(text: String) -> Result<Self, String> {
            if text == "irregular" {
                return Ok(Self::Irregular);
            }
            parse_duration(&text).map(Self::Every).ok_or_else(|| {
                format!(
                    "{text:?} is neither an ISO 8601 duration of weeks to seconds nor `irregular`"
                )
            })
        }
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
        /// [`Names::check`] tells whether it reads as one.
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

    /// Decimal digits only, as `str::parse` also takes `+1`.
    fn number(text: &str) -> Option<u64> {
        if text.bytes().all(|b| b.is_ascii_digit()) {
            text.parse().ok()
        } else {
            None
        }
    }

    /// `N` numbers between `separator`s.
    fn numbers<const N: usize>(text: &str, separator: char) -> Option<[u64; N]> {
        let mut parts = text.split(separator);
        let mut numbers = [0; N];
        for slot in &mut numbers {
            *slot = number(parts.next()?)?;
        }
        parts.next().is_none().then_some(numbers)
    }

    /// An ISO 8601 duration of weeks to seconds, `P1D` or `PT1H30M`, not zero: years and months have no fixed length.
    fn parse_duration(text: &str) -> Option<Duration> {
        let text = text.strip_prefix('P')?;
        let (date, time) = match text.split_once('T') {
            Some((_, "")) => return None,
            Some((date, time)) => (date, time),
            None => (text, ""),
        };
        let date_units: &[(char, u64)] = &[('W', 604_800), ('D', 86_400)];
        let time_units: &[(char, u64)] = &[('H', 3_600), ('M', 60), ('S', 1)];
        let mut seconds = 0_u64;
        for (mut part, units) in [(date, date_units), (time, time_units)] {
            for &(unit, scale) in units {
                if let Some((count, rest)) = part.split_once(unit) {
                    seconds = seconds.checked_add(number(count)?.checked_mul(scale)?)?;
                    part = rest;
                }
            }
            if !part.is_empty() {
                return None;
            }
        }
        (seconds > 0).then(|| Duration::from_secs(seconds))
    }

    /// The midnight UTC opening a day of 1970 or later (Howard Hinnant's `days_from_civil`).
    fn civil(year: u64, month: u64, day: u64) -> Option<SystemTime> {
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        let year = if month <= 2 {
            year.checked_sub(1)?
        } else {
            year
        };
        let (era, year_of_era) = (year / 400, year % 400);
        let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
        Some(UNIX_EPOCH + Duration::from_secs(days * 86_400))
    }

    /// `2026-11-01`.
    fn parse_date(text: &str) -> Option<SystemTime> {
        let [year, month, day] = numbers(text, '-')?;
        civil(year, month, day)
    }

    /// `date` at `10:08:50`.
    fn at(date: SystemTime, clock: &str) -> Option<SystemTime> {
        let [hours, minutes, seconds] = numbers(clock, ':')?;
        (hours < 24 && minutes < 60 && seconds < 61)
            .then(|| date + Duration::from_secs(hours * 3_600 + minutes * 60 + seconds))
    }

    /// `2026-11-01T10:08:50Z`, as GitHub's API writes a time.
    fn parse_iso_time(text: &str) -> Option<SystemTime> {
        let (date, clock) = text.strip_suffix('Z')?.split_once('T')?;
        at(parse_date(date)?, clock)
    }

    /// `Sun, 01 Nov 2026 10:08:50 GMT`, an HTTP date (RFC 9110 §5.6.7).
    fn parse_http_date(text: &str) -> Option<SystemTime> {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let fields: Vec<&str> = text.split_whitespace().collect();
        let [_, day, month, year, clock, "GMT"] = fields.as_slice() else {
            return None;
        };
        let month = MONTHS.iter().position(|name| name == month)? + 1;
        let date = civil(number(year)?, u64::try_from(month).ok()?, number(day)?)?;
        at(date, clock)
    }

    /// `duration` in hours, or days past two.
    fn shown(duration: Duration) -> String {
        let hours = duration.as_secs() / 3_600;
        if hours < 48 {
            format!("{hours} h")
        } else {
            format!("{} days", hours / 24)
        }
    }

    /// Whether a list last `changed` agrees with its source's `status` and its `updated`.
    fn judge_freshness(
        status: Status,
        updated: Updated,
        changed: SystemTime,
        now: SystemTime,
    ) -> Result<String, String> {
        let age = now.duration_since(changed).unwrap_or_default();
        let changed_ago = format!("changed {} ago", shown(age));
        match (status, updated) {
            (Status::Frozen(Day(since)), _) if changed > since + GRACE => Err(format!(
                "{changed_ago}, after the day it froze: set `status: active`"
            )),
            (Status::Active, Updated::Every(every)) if age > every * MISSED_UPDATES + GRACE => Err(
                format!("{changed_ago}, announced every {}: frozen?", shown(every)),
            ),
            _ => Ok(changed_ago),
        }
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
                ("description", &s.description),
            ] {
                assert!(!text.trim().is_empty(), "{at}: empty {field}");
            }
            assert!(s.site.starts_with("https://"), "{at}: site {}", s.site);
            let explained = matches!(s.license, License::Custom | License::None);
            assert_eq!(
                s.terms.as_ref().is_some_and(|t| !t.trim().is_empty()),
                explained,
                "{at}: terms go with a `custom` or `none` licence, and only there"
            );
            assert!(
                s.license != License::Spdx || s.usage == Use::Free,
                "{at}: an SPDX licence allows any use"
            );
            assert_eq!(
                s.lists.is_empty(),
                matches!(s.status, Status::Retired),
                "{at}: a retired source has no list, and only it"
            );
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

    #[test]
    fn durations() {
        for (text, seconds) in [
            ("P1D", Some(86_400)),
            ("P1W", Some(604_800)),
            ("PT30M", Some(1_800)),
            ("PT1H30M", Some(5_400)),
            ("P1DT12H", Some(129_600)),
            ("P", None),
            ("PT", None),
            ("P1DT", None),
            ("PT0S", None),
            ("P1M", None),
            ("P1Y", None),
            ("P1H", None),
            ("PT1D", None),
            ("PT30M1H", None),
            ("P+1D", None),
            ("1D", None),
            ("daily", None),
        ] {
            assert_eq!(
                parse_duration(text),
                seconds.map(Duration::from_secs),
                "{text:?}"
            );
        }
    }

    #[test]
    fn dates() {
        // 2026-11-01 is day 20,758 of the Unix epoch.
        let day = UNIX_EPOCH + Duration::from_hours(20_758 * 24);
        let time = day + Duration::from_secs(10 * 3_600 + 8 * 60 + 50);
        assert_eq!(parse_date("1970-01-01"), Some(UNIX_EPOCH));
        assert_eq!(parse_date("2026-11-01"), Some(day));
        assert_eq!(parse_iso_time("2026-11-01T10:08:50Z"), Some(time));
        assert_eq!(parse_http_date("Sun, 01 Nov 2026 10:08:50 GMT"), Some(time));
        for text in [
            "2026-13-01",
            "2026-11-32",
            "1969-12-31",
            "2026-11",
            "2026-11-01-02",
        ] {
            assert_eq!(parse_date(text), None, "{text:?}");
        }
        assert_eq!(parse_iso_time("2026-11-01T24:00:00Z"), None);
        assert_eq!(parse_http_date("Sun, 01 Nov 2026 10:08:50 CET"), None);
    }

    #[test]
    fn freshness() {
        let now = UNIX_EPOCH + Duration::from_hours(20_758 * 24);
        let hours = |n: u64| now - Duration::from_hours(n);
        let daily = Updated::Every(Duration::from_hours(24));
        let frozen = Status::Frozen(Day(hours(30 * 24)));
        for (status, updated, changed, fresh) in [
            (Status::Active, daily, hours(1), true),
            (Status::Active, daily, hours(4 * 24), true),
            (Status::Active, daily, hours(4 * 24 + 1), false),
            (Status::Active, Updated::Irregular, hours(365 * 24), true),
            (frozen, daily, hours(30 * 24), true),
            (frozen, daily, hours(40 * 24), true),
            (frozen, daily, hours(28 * 24), false),
        ] {
            assert_eq!(
                judge_freshness(status, updated, changed, now).is_ok(),
                fresh,
                "{status:?} {updated:?} {changed:?}"
            );
        }
    }

    /// `request` tried [`TRIES`] times.
    fn retried<T>(mut request: impl FnMut() -> Result<T, String>) -> Result<T, String> {
        let mut error = String::new();
        for tried in 0..TRIES {
            if tried > 0 {
                std::thread::sleep(RETRY_AFTER * 2_u32.pow(tried - 1));
            }
            match request() {
                Ok(value) => return Ok(value),
                Err(e) => error = e,
            }
        }
        Err(error)
    }

    /// A downloaded list: its text, whole when `dedensd` reads its format, else its first lines; and when it last
    /// changed, when its server tells (`Last-Modified`).
    struct Fetched {
        text: String,
        /// Whether `text` is the first lines only.
        cut: bool,
        changed: Option<SystemTime>,
    }

    fn download(agent: &ureq::Agent, list: &List) -> Result<Fetched, String> {
        let mut response = agent.get(&list.url).call().map_err(|e| e.to_string())?;
        let changed = response
            .headers()
            .get("last-modified")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_http_date);
        let body = response.body_mut();
        let mut cut = false;
        let text = if list.format.is_read() {
            body.with_config()
                .limit(MAX_LIST_LEN)
                .read_to_string()
                .map_err(|e| e.to_string())?
        } else {
            let mut bytes = Vec::new();
            body.as_reader()
                .take(PREFIX_LEN)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            cut = u64::try_from(bytes.len()) == Ok(PREFIX_LEN);
            if cut && let Some(end) = bytes.iter().rposition(|&b| b == b'\n') {
                bytes.truncate(end + 1);
            }
            String::from_utf8(bytes).map_err(|e| e.to_string())?
        };
        Ok(Fetched { text, cut, changed })
    }

    #[derive(Deserialize)]
    struct Commit {
        commit: CommitData,
    }

    #[derive(Deserialize)]
    struct CommitData {
        committer: Signature,
    }

    #[derive(Deserialize)]
    struct Signature {
        date: String,
    }

    /// When a list last changed, as far as one can tell.
    enum Changed {
        At(SystemTime),
        /// Why not.
        Unknown(&'static str),
    }

    /// When the file at a `raw.githubusercontent.com` URL last changed, its last commit as GitHub's API tells. With
    /// `GITHUB_TOKEN` when set: GitHub answers 60 requests an hour without one, and past them a date is unknown, not
    /// wrong.
    fn github_changed(agent: &ureq::Agent, url: &str) -> Result<Changed, String> {
        let Some(path) = url.strip_prefix("https://raw.githubusercontent.com/") else {
            return Ok(Changed::Unknown("no Last-Modified"));
        };
        let parts: Vec<&str> = path.split('/').collect();
        let ([owner, repo, "refs", "heads", branch, file @ ..] | [owner, repo, branch, file @ ..]) =
            parts.as_slice()
        else {
            return Err(format!("{url}: no GitHub file"));
        };
        let mut request = agent
            .get(format!(
                "https://api.github.com/repos/{owner}/{repo}/commits"
            ))
            .query("path", file.join("/"))
            .query("sha", *branch)
            .query("per_page", "1")
            .header("Accept", "application/vnd.github+json");
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let text = match request
            .call()
            .and_then(|mut response| response.body_mut().read_to_string())
        {
            Ok(text) => text,
            Err(ureq::Error::StatusCode(403 | 429)) => {
                return Ok(Changed::Unknown(
                    "GitHub's API limit reached, set GITHUB_TOKEN",
                ));
            }
            Err(e) => return Err(format!("GitHub API: {e}")),
        };
        let commits: Vec<Commit> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let date = &commits
            .first()
            .ok_or_else(|| format!("{url}: no commit"))?
            .commit
            .committer
            .date;
        parse_iso_time(date)
            .map(Changed::At)
            .ok_or_else(|| format!("GitHub API: {date:?} is no time"))
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
            let read = Names::downloaded(text)
                .check(Tlds::Allow)
                .map_err(|e| e.to_string())?;
            return Ok(format!(
                "{} names, {} lines skipped",
                read.names + read.duplicates,
                read.skipped
            ));
        }
        Ok(format!("{held} of {lines} lines {format:?}"))
    }

    /// A list downloaded and judged: its format, then its freshness when its date is known.
    fn check(
        agent: &ureq::Agent,
        status: Status,
        list: &List,
        now: SystemTime,
    ) -> Result<String, String> {
        let fetched = retried(|| download(agent, list))?;
        let lines = judge(&fetched.text, list.format)?;
        let changed = match fetched.changed {
            Some(changed) => Changed::At(changed),
            None => retried(|| github_changed(agent, &list.url))?,
        };
        let freshness = match changed {
            Changed::At(changed) => judge_freshness(status, list.updated, changed, now)?,
            Changed::Unknown(why) => format!("date unknown: {why}"),
        };
        let cut = if fetched.cut { " in its first MiB" } else { "" };
        Ok(format!("{lines}{cut}, {freshness}"))
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
        let now = SystemTime::now();
        let catalog = catalog();
        let lists: Vec<(String, Status, &List)> = catalog
            .sources
            .iter()
            .flat_map(|s| {
                s.lists
                    .iter()
                    .map(|l| (format!("{}.{}", s.id, l.id), s.status, l))
            })
            .collect();
        let outcomes: Vec<Result<String, String>> = lists
            .chunks(DOWNLOADS_AT_ONCE)
            .flat_map(|chunk| {
                std::thread::scope(|scope| {
                    let runs: Vec<_> = chunk
                        .iter()
                        .map(|&(_, status, list)| {
                            let agent = &agent;
                            scope.spawn(move || check(agent, status, list, now))
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
        for ((id, _, list), outcome) in lists.iter().zip(&outcomes) {
            let (status, detail) = match outcome {
                Ok(detail) => ("ok", detail),
                Err(error) => ("FAILED", error),
            };
            failures += usize::from(outcome.is_err());
            writeln!(table, "{status:8} {id} {detail} ({})", list.url)
                .expect("a String takes text");
        }
        println!("{table}");
        assert_eq!(
            failures,
            0,
            "{failures} of {} lists failed:\n{table}",
            lists.len()
        );
    }
}
