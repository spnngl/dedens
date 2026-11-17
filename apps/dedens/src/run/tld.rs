//! `+tld NAME` (D129): what IANA's RDAP server says of a top-level domain (RFC 7480, RFC 9082 §3.1.3, RFC 9083
//! §5.3), printed as a response is (D37) by `+rdap`'s printer (D130); of a name it does not know, what the TLD list
//! bundled says (D126).

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::{Context, bail};
use dedens_proto::Name;
use dedens_roots::{Kind, Tlds};

use super::Usage;
use super::rdap::{self, Answer, Got};
use crate::args::Cli;
use crate::output::{Format, QUIET};

/// IANA's RDAP server, which answers for every TLD.
const IANA: &str = "https://rdap.iana.org";

/// Asks IANA's RDAP server about the TLD `text` and prints the answer in `cli`'s format. Exit 0 on an answer, a
/// TLD's or a 404 (D33), 9 when the server does not answer, connection refused or reset included.
pub(crate) fn run(cli: &Cli, text: &str) -> anyhow::Result<ExitCode> {
    let label = label(text).map_err(Usage)?;
    let trust = cli.trust().map_err(Usage)?;
    let origin = std::env::var("DEDENS_RDAP").ok();
    // RFC 9082 §3.1.3: a domain by its name in A-labels.
    let url = rdap::relocate(&format!("{IANA}/domain/{label}"), origin.as_deref());
    let agent = rdap::agent(&trust, cli.options.exchange().timeout);
    let (exchange, body) = match rdap::get(&agent, &url, rdap::RDAP_JSON)? {
        Got::Reply(exchange, body) => (exchange, body),
        Got::Silence(error) => return Ok(rdap::silence(&label, &url, &error)),
    };
    let answer = rdap::read(exchange.status, &body).with_context(|| exchange.url.clone())?;
    let mut out = anstream::AutoStream::new(io::stdout().lock(), cli.output.color());
    match cli.output.format() {
        Format::Json | Format::Yaml => rdap::raw(&mut out, cli.output.format(), &body)?,
        // `--short` is refused with `+tld`.
        Format::Human | Format::Short => {
            rdap::human(&mut out, &label, "TLD", &answer, &exchange)?;
            if let Answer::NotFound = answer {
                not_found(&mut out, &label)?;
            }
        }
    }
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

/// The TLD `text` names, as one LDH label in A-labels, lowercase: a name in Unicode is converted (RFC 9082 §3.1.3),
/// a trailing dot dropped.
fn label(text: &str) -> anyhow::Result<String> {
    let label = rdap::ascii(text)?;
    if !rdap::is_ldh(&label) {
        bail!("{text}: not a TLD: +tld takes one label of letters, digits and hyphens, as `fr`");
    }
    Ok(label)
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
    rdap::section(out, "tld list", &rows)
}
