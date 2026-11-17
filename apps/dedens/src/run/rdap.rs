//! `+rdap NAME` (D130): a domain's registration from the RDAP server of its TLD, found in IANA's bootstrap file (RFC
//! 9224 §4), asked over HTTPS (RFC 7480) for the name, then each parent until one is registered (RFC 9082 §3.1.3,
//! RFC 9083 §5.3); and the RDAP client and printer `+tld` (D129) shares.

use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use dedens_net::tls::Trust;
use dedens_proto::Name;
use dedens_roots::Tlds;
use ureq::ResponseExt;
use ureq::tls::{Certificate, RootCerts, TlsConfig};

use super::Usage;
use crate::args::Cli;
use crate::output::{BAD, Format, GOOD, STRONG, millis};
use crate::rdap::{Bootstrap, Card, Domain, Failure};

/// IANA's bootstrap file for domains (RFC 9224 §4, §12.4).
const BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";

/// The media type of RDAP (RFC 7480 §4.2).
pub(super) const RDAP_JSON: &str = "application/rdap+json";

/// The largest answer read: IANA's bootstrap file is 71 kB, a domain a few.
const MAX_LEN: u64 = 1 << 20;

/// The redirects followed from one URL (RFC 7480 §5.2): a registry that moved, or one server sending to another.
const MAX_REDIRECTS: u32 = 5;

/// What the server said of the domain.
#[derive(Debug)]
pub(crate) enum Answer {
    /// The domain, HTTP 200.
    Found(Box<Domain>),
    /// HTTP 404: the server knows no such domain.
    NotFound,
}

/// How the answer came: from where, after any redirect, how fast, with which HTTP status.
#[derive(Debug)]
pub(crate) struct Exchange {
    pub(crate) url: String,
    pub(crate) rtt: Duration,
    pub(crate) status: u16,
}

/// What a GET brought: an answer of any HTTP status, or the server's silence, refusal or reset (exit 9, D33).
pub(super) enum Got {
    Reply(Exchange, Vec<u8>),
    Silence(ureq::Error),
}

/// Asks the RDAP server of `text`'s TLD about it and its parents and prints the first registered, or the last asked
/// when none is, in `cli`'s format. Exit 0 on an answer, a domain's or a 404 (D33), 9 when a server does not
/// answer, connection refused or reset included.
pub(crate) fn run(cli: &Cli, text: &str) -> anyhow::Result<ExitCode> {
    let name = name(text).map_err(Usage)?;
    let trust = cli.trust().map_err(Usage)?;
    let origin = std::env::var("DEDENS_RDAP").ok();
    let agent = agent(&trust, cli.options.exchange().timeout);
    let url = relocate(BOOTSTRAP, origin.as_deref());
    let (exchange, body) = match get(&agent, &url, "application/json")? {
        Got::Reply(exchange, body) => (exchange, body),
        Got::Silence(error) => return Ok(silence(&name, &url, &error)),
    };
    if exchange.status != 200 {
        bail!("{url}: HTTP {}", exchange.status);
    }
    let bootstrap: Bootstrap = serde_json::from_slice(&body)
        .with_context(|| format!("{url}: not an RDAP bootstrap file"))?;
    let base = base(&bootstrap, &name)?;
    let labels = name.split('.').count();
    // RFC 9224 §4 names the TLD's server, which holds the names a label under its entry: the TLD itself is `+tld`'s.
    let floor = bootstrap
        .servers(&name)
        .map_or(0, |(matched, _)| matched)
        .saturating_add(1)
        .max(2)
        .min(labels);
    let mut suffix = name.as_str();
    let mut parents = labels - floor;
    loop {
        // RFC 9082 §3.1.3, RFC 9224 §3: the base URL ends in `/`.
        let url = relocate(&format!("{base}domain/{suffix}"), origin.as_deref());
        let (exchange, body) = match get(&agent, &url, RDAP_JSON)? {
            Got::Reply(exchange, body) => (exchange, body),
            Got::Silence(error) => return Ok(silence(&name, &url, &error)),
        };
        // A 404, or the 400 of a registry asked for a name it holds none under (Public Interest Registry's), sends
        // the walk a label up; no public suffix list tells where registrations are (D130).
        if parents > 0 && matches!(exchange.status, 400 | 404) {
            tracing::debug!(
                url,
                status = exchange.status,
                "not registered here, one label up"
            );
            parents -= 1;
            suffix = suffix.split_once('.').map_or(suffix, |(_, parent)| parent);
            continue;
        }
        let answer = read(exchange.status, &body).with_context(|| exchange.url.clone())?;
        let mut out = anstream::AutoStream::new(io::stdout().lock(), cli.output.color());
        match cli.output.format() {
            Format::Json | Format::Yaml => raw(&mut out, cli.output.format(), &body)?,
            // `--short` is refused with `+rdap`.
            Format::Human | Format::Short => human(&mut out, suffix, "domain", &answer, &exchange)?,
        }
        out.flush()?;
        return Ok(ExitCode::SUCCESS);
    }
}

/// The domain `text` names, as `+rdap` asks it: in A-labels, lowercase, without its trailing dot, two LDH labels at
/// least, 253 octets at most (RFC 1035 §2.3.1, §2.3.4, RFC 9082 §3.1.3).
fn name(text: &str) -> anyhow::Result<String> {
    let name = ascii(text)?;
    if name.len() > 253 || !name.contains('.') || !name.split('.').all(is_ldh) {
        bail!(
            "{text}: not a domain under a TLD: +rdap takes two labels or more of letters, digits and hyphens, 253 octets at most, as `example.fr`; +tld asks about a TLD"
        );
    }
    Ok(name)
}

/// `text` in A-labels (RFC 9082 §3.1.3), lowercase, without its trailing dot.
pub(super) fn ascii(text: &str) -> anyhow::Result<String> {
    let (ascii, warnings) =
        crate::idn::to_ascii(text).map_err(|e| anyhow!("{text}: not a domain name: {e}"))?;
    for warning in warnings {
        eprintln!("dedens: warning: {warning}");
    }
    Ok(ascii
        .strip_suffix('.')
        .unwrap_or(&ascii)
        .to_ascii_lowercase())
}

/// Whether `label` is 1 to 63 letters, digits and hyphens (RFC 1035 §2.3.1, §2.3.4).
pub(super) fn is_ldh(label: &str) -> bool {
    let ldh = |c: char| c.is_ascii_alphanumeric() || c == '-';
    (1..=63).contains(&label.len()) && label.chars().all(ldh)
}

/// The HTTPS base URL of `name`'s RDAP server in `bootstrap` (RFC 9224 §3: HTTPS first).
///
/// # Errors
///
/// No entry matches (RFC 9224 §7), or the server matched has no HTTPS URL: `+rdap` asks over HTTPS only (D130).
fn base<'a>(bootstrap: &'a Bootstrap, name: &str) -> anyhow::Result<&'a str> {
    let tld = name.rsplit('.').next().unwrap_or(name);
    let Some((_, urls)) = bootstrap.servers(name) else {
        let known = tld
            .parse::<Name<'static>>()
            .ok()
            .and_then(|tld| Tlds::bundled().get(&tld))
            .is_some();
        let what = if known {
            "a TLD without RDAP"
        } else {
            "not a TLD"
        };
        bail!("{name}: no RDAP server for {tld} in IANA's bootstrap file (RFC 9224 §7): {what}");
    };
    let https = |url: &&String| {
        url.get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
    };
    match urls.iter().find(https) {
        Some(url) => Ok(url),
        None => bail!(
            "{name}: the RDAP server of {tld} is not on HTTPS ({}); +rdap asks over HTTPS only",
            urls.join(", ")
        ),
    }
}

/// `url` with its scheme, host and port replaced by `origin`, the `DEDENS_RDAP` of tests.
pub(super) fn relocate(url: &str, origin: Option<&str>) -> String {
    let Some(origin) = origin else {
        return url.to_owned();
    };
    let after_scheme = url.find("://").map_or(0, |at| at + 3);
    let path = url[after_scheme..]
        .find('/')
        .map_or("", |at| &url[after_scheme + at..]);
    format!("{origin}{path}")
}

/// Prints that the server at `url` did not answer about `name`: exit 9 (D33).
pub(super) fn silence(name: &str, url: &str, error: &ureq::Error) -> ExitCode {
    eprintln!("dedens: {name}: {url}: {error}");
    ExitCode::from(9)
}

/// A GET of `url` accepting `accept`, its redirects followed (RFC 7480 §5.2).
///
/// # Errors
///
/// Anything but the server's silence: TLS, too many redirects, a body over [`MAX_LEN`].
pub(super) fn get(agent: &ureq::Agent, url: &str, accept: &str) -> anyhow::Result<Got> {
    let start = Instant::now();
    let mut response = match agent.get(url).header("accept", accept).call() {
        Ok(response) => response,
        Err(error) if no_reply(&error) => return Ok(Got::Silence(error)),
        Err(error) => return Err(anyhow!(error).context(url.to_owned())),
    };
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_LEN)
        .read_to_vec()
        .with_context(|| url.to_owned())?;
    let exchange = Exchange {
        url: response.get_uri().to_string(),
        rtt: start.elapsed(),
        status: response.status().as_u16(),
    };
    Ok(Got::Reply(exchange, body))
}

/// An agent trusting what `trust` does, waiting `timeout` for each exchange, over HTTPS only.
pub(super) fn agent(trust: &Trust, timeout: Duration) -> ureq::Agent {
    let tls = TlsConfig::builder();
    let tls = match trust {
        Trust::Anyone => tls.disable_verification(true),
        Trust::Roots(roots) => tls.root_certs(RootCerts::Specific(Arc::new(
            roots
                .iter()
                .map(|root| Certificate::from_der(root).to_owned())
                .collect(),
        ))),
        // The system's store, and any trust to come until it is mapped here.
        _ => tls.root_certs(RootCerts::PlatformVerifier),
    };
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .https_only(true)
        .max_redirects(MAX_REDIRECTS)
        // A 404 is an answer (RFC 7480 §5.3), read here with the rest.
        .http_status_as_error(false)
        // Without the `gzip` feature ureq sends none, which RFC 9110 §12.5.3 reads as no preference.
        .accept_encoding("identity")
        .tls_config(tls.build())
        .build()
        .new_agent()
}

/// Whether `error` is the server's silence, refusal or reset: dig's exit code 9, as for DNS.
fn no_reply(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Timeout(_) | ureq::Error::ConnectionFailed => true,
        ureq::Error::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::TimedOut
        ),
        _ => false,
    }
}

/// The answer of HTTP status `status` and body `body`: a domain (RFC 9083 §5.3) for 200, none for 404 (RFC 7480
/// §5.3).
///
/// # Errors
///
/// A 200 whose body is not a domain, or another status, with the error the body explains (RFC 9083 §6).
pub(crate) fn read(status: u16, body: &[u8]) -> anyhow::Result<Answer> {
    match status {
        200 => Ok(Answer::Found(
            serde_json::from_slice(body).context("not an RDAP domain")?,
        )),
        404 => Ok(Answer::NotFound),
        _ => {
            let mut message = format!("HTTP {status}");
            if let Ok(failure) = serde_json::from_slice::<Failure>(body) {
                for line in std::iter::once(&failure.title).chain(&failure.description) {
                    if !line.is_empty() {
                        message.push_str(": ");
                        message.push_str(line);
                    }
                }
            }
            bail!(message)
        }
    }
}

/// Prints `body` as received for JSON, as the same tree for YAML (D129); an empty body, as Verisign's 404, as nothing.
pub(super) fn raw(out: &mut impl Write, format: Format, body: &[u8]) -> anyhow::Result<()> {
    if body.is_empty() {
        return Ok(());
    }
    if format == Format::Yaml {
        let json: serde_json::Value = serde_json::from_slice(body).context("not JSON")?;
        let yaml = serde_saphyr::to_string(&json).map_err(io::Error::other)?;
        write!(out, "---\n{yaml}")?;
        return Ok(());
    }
    out.write_all(body)?;
    if body.last() != Some(&b'\n') {
        writeln!(out)?;
    }
    Ok(())
}

/// Prints `answer` for humans: a status line headed `name` and its `kind`, then a section for each part of the
/// domain it holds.
pub(crate) fn human(
    out: &mut impl Write,
    name: &str,
    kind: &str,
    answer: &Answer,
    exchange: &Exchange,
) -> io::Result<()> {
    write!(out, "{STRONG}{name}. {kind}{STRONG:#}  ")?;
    match answer {
        Answer::Found(domain) if domain.status.is_empty() => write!(out, "{GOOD}found{GOOD:#}")?,
        Answer::Found(domain) => write!(
            out,
            "{GOOD}{}{GOOD:#}",
            printable(&domain.status.join(", "))
        )?,
        Answer::NotFound => write!(out, "{BAD}not found{BAD:#}")?,
    }
    let micros = u64::try_from(exchange.rtt.as_micros()).unwrap_or(u64::MAX);
    writeln!(
        out,
        "  {} ms from {} (HTTP {})",
        millis(micros),
        exchange.url,
        exchange.status
    )?;
    match answer {
        Answer::Found(domain) => found(out, name, domain),
        Answer::NotFound => Ok(()),
    }
}

/// The sections of `domain`, named `name`: registrar, contacts, name servers, DS records, dates, redacted fields,
/// RDAP servers.
fn found(out: &mut impl Write, name: &str, domain: &Domain) -> io::Result<()> {
    let (registrars, others): (Vec<_>, Vec<_>) = domain
        .entities
        .iter()
        .partition(|entity| entity.roles.iter().any(|role| role == "registrar"));
    let registrars: Vec<_> = registrars
        .iter()
        .map(|entity| {
            let mut lines = contact(&entity.vcard_array);
            let title = lines.remove(0);
            let ids = entity
                .public_ids
                .iter()
                .map(|id| format!("{} {}", id.kind, id.identifier));
            lines.splice(0..0, ids);
            (title, lines)
        })
        .collect();
    section(out, "registrar", &registrars)?;
    let contacts: Vec<_> = others
        .iter()
        .map(|entity| (entity.roles.join(", "), contact(&entity.vcard_array)))
        .collect();
    section(out, "contacts", &contacts)?;
    let servers: Vec<_> = domain
        .nameservers
        .iter()
        .map(|server| {
            let v4 = server.ip_addresses.v4.iter().map(ToString::to_string);
            let v6 = server.ip_addresses.v6.iter().map(ToString::to_string);
            let addresses = v4.chain(v6).collect::<Vec<_>>().join("  ");
            // Nominet's names end in a dot, others' do not.
            let name = server
                .ldh_name
                .strip_suffix('.')
                .unwrap_or(&server.ldh_name);
            (format!("{name}."), vec![addresses])
        })
        .collect();
    section(out, "name servers", &servers)?;
    let ds: Vec<_> = domain
        .secure_dns
        .ds_data
        .iter()
        .map(|ds| {
            let digest = ds.digest.to_ascii_uppercase();
            let data = format!(
                "{} {} {} {digest}",
                ds.key_tag, ds.algorithm, ds.digest_type
            );
            (format!("{name}.  DS"), vec![data])
        })
        .collect();
    section(out, "ds", &ds)?;
    let dates: Vec<_> = domain
        .events
        .iter()
        .map(|event| (event.event_action.clone(), vec![event.event_date.clone()]))
        .collect();
    section(out, "dates", &dates)?;
    let redacted: Vec<_> = domain
        .redacted
        .iter()
        .map(|field| {
            let how = match field.reason.text() {
                "" => field.method.clone(),
                reason => format!("{}: {reason}", field.method),
            };
            (field.name.text().to_owned(), vec![how])
        })
        .collect();
    section(out, "redacted", &redacted)?;
    // A TLD's own server (`alternate`, D129), the registrar's for a domain (`related`, D130).
    let servers: Vec<_> = domain
        .links
        .iter()
        .filter(|link| {
            matches!(link.rel.as_str(), "alternate" | "related") && link.media_type == RDAP_JSON
        })
        .map(|link| (link.href.clone(), Vec::new()))
        .collect();
    section(out, "rdap server", &servers)
}

/// The lines of a contact card: names, `redacted` for an empty one (RFC 9537 §3.2), address, phones with their
/// kind, emails.
fn contact(card: &Card) -> Vec<String> {
    let mut names: Vec<String> = card
        .texts("fn")
        .chain(card.texts("org"))
        .filter(|name| !name.is_empty())
        .collect();
    names.dedup();
    if names.is_empty() && card.all("fn").next().is_some() {
        names.push("redacted".to_owned());
    }
    let mut lines = vec![names.join(", ")];
    lines.extend(card.all("adr").map(|adr| match &adr.label {
        Some(label) => label.lines().collect::<Vec<_>>().join(", "),
        None => adr.text(),
    }));
    lines.extend(card.all("tel").map(|tel| {
        let kinds: Vec<_> = tel
            .types
            .iter()
            .filter(|kind| *kind != "work")
            .map(String::as_str)
            .collect();
        if kinds.is_empty() {
            tel.text()
        } else {
            format!("{} ({})", tel.text(), kinds.join(", "))
        }
    }));
    lines.extend(card.texts("email"));
    lines
}

/// A section, `heading` then each row: its key, aligned, then its lines one under the other, all printable. None
/// without rows.
pub(super) fn section(
    out: &mut impl Write,
    heading: &str,
    rows: &[(String, Vec<String>)],
) -> io::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    writeln!(out, "{STRONG}{heading}{STRONG:#}")?;
    let keys: Vec<_> = rows.iter().map(|(key, _)| printable(key)).collect();
    let width = keys
        .iter()
        .map(|key| key.chars().count())
        .max()
        .unwrap_or(0);
    for (key, (_, lines)) in keys.iter().zip(rows) {
        let mut lines = lines
            .iter()
            .filter(|line| !line.is_empty())
            .map(|line| printable(line));
        match lines.next() {
            Some(first) => writeln!(out, "  {key:width$}  {first}")?,
            None => writeln!(out, "  {key}")?,
        }
        for line in lines {
            writeln!(out, "  {:width$}  {line}", "")?;
        }
    }
    Ok(())
}

/// `text` with its control characters escaped, as `\u{1b}`: a server's text must not drive the terminal.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Exchange, human, printable, read, relocate};

    /// RFC 9083 §4.6: `status` is optional; a domain without it is found all the same.
    #[test]
    fn a_domain_without_status_is_found() {
        let mut fr: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../../testdata/rdap/fr.json"))
                .expect("JSON");
        fr.as_object_mut().expect("an object").remove("status");
        let answer = read(200, fr.to_string().as_bytes()).expect("a domain");
        let exchange = Exchange {
            url: "https://rdap.iana.org/domain/fr".to_owned(),
            rtt: Duration::ZERO,
            status: 200,
        };
        let mut out = Vec::new();
        human(&mut out, "fr", "TLD", &answer, &exchange).expect("printed");
        let out = String::from_utf8(out).expect("UTF-8");
        let out = anstream::adapter::strip_str(&out).to_string();
        assert!(out.starts_with("fr. TLD  found  0.0 ms from "), "{out}");
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(printable("é\u{1b}[31m\tx\n"), "é\\u{1b}[31m\\tx\\n");
    }

    #[test]
    fn relocate_keeps_the_path() {
        let origin = Some("https://127.0.0.1:9");
        assert_eq!(
            relocate("https://rdap.nominet.uk/uk/", origin),
            "https://127.0.0.1:9/uk/"
        );
        assert_eq!(
            relocate("https://rdap.nic.fr", origin),
            "https://127.0.0.1:9"
        );
        assert_eq!(
            relocate("https://a.b/c/d", origin),
            "https://127.0.0.1:9/c/d"
        );
        assert_eq!(
            relocate("https://rdap.nic.fr/", None),
            "https://rdap.nic.fr/"
        );
    }
}
