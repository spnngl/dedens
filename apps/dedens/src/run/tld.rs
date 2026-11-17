//! `+tld NAME` (D129): what IANA's RDAP server says of a top-level domain (RFC 7480, RFC 9082 §3.1.3, RFC 9083
//! §5.3), printed as a response is (D37); of a name it does not know, what the TLD list bundled says (D126).

use std::fmt::Write as _;
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use dedens_net::tls::Trust;
use dedens_proto::Name;
use dedens_roots::{Kind, Tlds};
use ureq::tls::{Certificate, RootCerts, TlsConfig};

use super::Usage;
use crate::args::Cli;
use crate::output::{BAD, Format, GOOD, QUIET, STRONG, millis};
use crate::rdap::{Domain, Failure};

/// IANA's RDAP server, which answers for every TLD; `DEDENS_RDAP` replaces it for tests.
const IANA: &str = "https://rdap.iana.org";

/// The media type of RDAP (RFC 7480 §4.2).
const RDAP_JSON: &str = "application/rdap+json";

/// The largest answer read: IANA's are a few kilobytes.
const MAX_LEN: u64 = 1 << 20;

/// What the server said of the TLD.
#[derive(Debug)]
pub(crate) enum Answer {
    /// The TLD, HTTP 200.
    Found(Box<Domain>),
    /// HTTP 404: the server knows no such TLD.
    NotFound,
}

/// How the answer came: from where, how fast, with which HTTP status.
#[derive(Debug)]
pub(crate) struct Exchange<'a> {
    pub(crate) url: &'a str,
    pub(crate) rtt: Duration,
    pub(crate) status: u16,
}

/// Asks IANA's RDAP server about the TLD `text` and prints the answer in `cli`'s format. Exit 0 on an answer, a
/// TLD's or a 404 (D33), 9 when the server does not answer, connection refused or reset included.
pub(crate) fn run(cli: &Cli, text: &str) -> anyhow::Result<ExitCode> {
    let label = label(text).map_err(Usage)?;
    let trust = cli.trust().map_err(Usage)?;
    let base = std::env::var("DEDENS_RDAP").unwrap_or_else(|_| IANA.to_owned());
    // RFC 9082 §3.1.3: a domain by its name in A-labels.
    let url = format!("{base}/domain/{label}");
    let agent = agent(&trust, cli.options.exchange().timeout);
    let start = Instant::now();
    let mut response = match agent.get(&url).header("accept", RDAP_JSON).call() {
        Ok(response) => response,
        Err(error) if no_reply(&error) => {
            eprintln!("dedens: {label}: {url}: {error}");
            return Ok(ExitCode::from(9));
        }
        Err(error) => return Err(anyhow!(error).context(url)),
    };
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_LEN)
        .read_to_vec()
        .with_context(|| url.clone())?;
    let exchange = Exchange {
        url: &url,
        rtt: start.elapsed(),
        status: response.status().as_u16(),
    };
    let answer = read(exchange.status, &body).with_context(|| url.clone())?;
    let mut out = anstream::AutoStream::new(io::stdout().lock(), cli.output.color());
    match cli.output.format() {
        Format::Json => {
            out.write_all(&body)?;
            if body.last() != Some(&b'\n') {
                writeln!(out)?;
            }
        }
        Format::Yaml => {
            let json: serde_json::Value = serde_json::from_slice(&body).context("not JSON")?;
            let yaml = serde_saphyr::to_string(&json).map_err(io::Error::other)?;
            write!(out, "---\n{yaml}")?;
        }
        // `--short` is refused with `+tld`.
        Format::Human | Format::Short => human(&mut out, &label, &answer, &exchange)?,
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// The TLD `text` names, as one LDH label in A-labels, lowercase: a name in Unicode is converted (RFC 9082 §3.1.3),
/// a trailing dot dropped.
fn label(text: &str) -> anyhow::Result<String> {
    let (ascii, warnings) =
        crate::idn::to_ascii(text).map_err(|e| anyhow!("{text}: not a domain name: {e}"))?;
    for warning in warnings {
        eprintln!("dedens: warning: {warning}");
    }
    let label = ascii.strip_suffix('.').unwrap_or(&ascii);
    let ldh = |c: char| c.is_ascii_alphanumeric() || c == '-';
    if label.is_empty() || label.len() > 63 || !label.chars().all(ldh) {
        bail!("{text}: not a TLD: +tld takes one label of letters, digits and hyphens, as `fr`");
    }
    Ok(label.to_ascii_lowercase())
}

/// An agent trusting what `trust` does, waiting `timeout` for the whole exchange, over HTTPS only.
fn agent(trust: &Trust, timeout: Duration) -> ureq::Agent {
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
                        let _ = write!(message, ": {line}");
                    }
                }
            }
            bail!(message)
        }
    }
}

/// Prints `answer` for humans: a status line, then a section for each part of the domain it holds.
pub(crate) fn human(
    out: &mut impl Write,
    label: &str,
    answer: &Answer,
    exchange: &Exchange<'_>,
) -> io::Result<()> {
    write!(out, "{STRONG}{label}. TLD{STRONG:#}  ")?;
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
        Answer::Found(domain) => found(out, label, domain),
        Answer::NotFound => not_found(out, label),
    }
}

/// The sections of `domain`: contacts, name servers, DS records, dates, the TLD's own RDAP server.
fn found(out: &mut impl Write, label: &str, domain: &Domain) -> io::Result<()> {
    let contacts: Vec<_> = domain
        .entities
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
            (format!("{}.", server.ldh_name), vec![addresses])
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
            (format!("{label}.  DS"), vec![data])
        })
        .collect();
    section(out, "ds", &ds)?;
    let dates: Vec<_> = domain
        .events
        .iter()
        .map(|event| (event.event_action.clone(), vec![event.event_date.clone()]))
        .collect();
    section(out, "dates", &dates)?;
    let servers: Vec<_> = domain
        .links
        .iter()
        .filter(|link| link.rel == "alternate" && link.media_type == RDAP_JSON)
        .map(|link| (link.href.clone(), Vec::new()))
        .collect();
    section(out, "rdap server", &servers)
}

/// What the TLD list bundled says of `label`, not in IANA's RDAP: a special-use name's purpose, or that it is no TLD.
fn not_found(out: &mut impl Write, label: &str) -> io::Result<()> {
    let tld = label
        .parse::<Name<'static>>()
        .ok()
        .and_then(|name| Tlds::bundled().get(&name));
    let Some(tld) = tld else {
        return writeln!(out, "{QUIET}not a TLD{QUIET:#}");
    };
    let mut rows = vec![
        ("kind".to_owned(), vec![tld.kind().to_string()]),
        ("status".to_owned(), vec![tld.status().to_string()]),
    ];
    if let Kind::SpecialUse {
        purpose: Some(purpose),
    } = tld.kind()
    {
        rows.push(("purpose".to_owned(), vec![purpose.to_string()]));
    }
    section(out, "tld list", &rows)
}

/// The lines of a contact card: names, address, phones with their kind, emails.
fn contact(card: &crate::rdap::Card) -> Vec<String> {
    let mut names: Vec<String> = card.texts("fn").chain(card.texts("org")).collect();
    names.dedup();
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
fn section(out: &mut impl Write, heading: &str, rows: &[(String, Vec<String>)]) -> io::Result<()> {
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

    use super::{Exchange, human, printable, read};

    /// RFC 9083 §4.6: `status` is optional; a domain without it is found all the same.
    #[test]
    fn a_domain_without_status_is_found() {
        let mut fr: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../../testdata/rdap/fr.json"))
                .expect("JSON");
        fr.as_object_mut().expect("an object").remove("status");
        let answer = read(200, fr.to_string().as_bytes()).expect("a domain");
        let exchange = Exchange {
            url: "https://rdap.iana.org/domain/fr",
            rtt: Duration::ZERO,
            status: 200,
        };
        let mut out = Vec::new();
        human(&mut out, "fr", &answer, &exchange).expect("printed");
        let out = String::from_utf8(out).expect("UTF-8");
        let out = anstream::adapter::strip_str(&out).to_string();
        assert!(out.starts_with("fr. TLD  found  0.0 ms from "), "{out}");
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(printable("é\u{1b}[31m\tx\n"), "é\\u{1b}[31m\\tx\\n");
    }
}
