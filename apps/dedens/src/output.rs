//! The formats of a response: for humans by default, `short`, and JSON lines or YAML documents (D37),
//! all from its [`Report`].

use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::SocketAddr;

use anstyle::{AnsiColor, Style};
use dedens_proto::{Message, Name};
use dedens_scenario::{EdnsReport, OptionReport, RecordReport, Report, Transport, server_text};

/// How responses are printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Format {
    /// A status line, the records under their section, the rest in words.
    Human,
    /// The data of the answer records.
    Short,
    /// One JSON object per line.
    Json,
    /// One YAML document per response.
    Yaml,
}

const STRONG: Style = Style::new().bold();
const QUIET: Style = Style::new().dimmed();
const GOOD: Style = AnsiColor::Green.on_default().bold();
const BAD: Style = AnsiColor::Red.on_default().bold();

/// How to print a response.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Printing {
    pub(crate) format: Format,
    /// A hop of `+trace`: the human format counts the additional records of a referral, its glue, instead of
    /// listing them.
    pub(crate) trace: bool,
}

/// Prints `report`, of response `wire`, as `printing` says.
pub(crate) fn print(
    out: &mut impl Write,
    printing: Printing,
    report: &Report,
    wire: &[u8],
) -> io::Result<()> {
    match printing.format {
        Format::Human => {
            let decoded = Message::decode(wire).map_err(io::Error::other)?;
            human(out, report, decoded.message.referral(), printing.trace)
        }
        Format::Short => report
            .answer
            .iter()
            .try_for_each(|record| writeln!(out, "{}", record.data)),
        Format::Json => {
            serde_json::to_writer(&mut *out, report)?;
            writeln!(out)
        }
        Format::Yaml => {
            let yaml = serde_saphyr::to_string(report).map_err(io::Error::other)?;
            write!(out, "---\n{yaml}")
        }
    }
}

fn human(
    out: &mut impl Write,
    report: &Report,
    referral: Option<&Name<'_>>,
    trace: bool,
) -> io::Result<()> {
    status(out, report)?;
    let brief = trace && referral.is_some();
    let none = Vec::new();
    let sections = [
        ("answer", &report.answer),
        ("authority", &report.authority),
        ("additional", if brief { &none } else { &report.additional }),
    ];
    if report.answer.is_empty() && report.header.rcode == "NOERROR" {
        match referral {
            Some(zone) => writeln!(out, "{QUIET}referral to{QUIET:#} {zone}")?,
            None => writeln!(out, "{QUIET}no records{QUIET:#}")?,
        }
    }
    let records = || sections.iter().flat_map(|(_, records)| records.iter());
    let width = |field: fn(&RecordReport) -> usize| records().map(field).max().unwrap_or(0);
    let name_width = width(|r| r.name.len());
    let ttl_width = width(|r| duration(r.ttl).len());
    let type_width = width(|r| rtype(r).len());
    for (heading, records) in sections.iter().filter(|(_, records)| !records.is_empty()) {
        writeln!(out, "{STRONG}{heading}{STRONG:#}")?;
        let mut previous: Option<&RecordReport> = None;
        for r in *records {
            // A run of records of one owner shows it once, and its TTL once while the same.
            let same_name = previous.is_some_and(|p| p.name == r.name);
            let name = if same_name { "" } else { &r.name };
            let ttl = if same_name && previous.is_some_and(|p| p.ttl == r.ttl) {
                String::new()
            } else {
                duration(r.ttl)
            };
            writeln!(
                out,
                "  {name:name_width$}  {ttl:>ttl_width$}  {:type_width$}  {}",
                rtype(r),
                r.data
            )?;
            previous = Some(r);
        }
    }
    if brief && !report.additional.is_empty() {
        writeln!(
            out,
            "{QUIET}{} additional records{QUIET:#}",
            report.additional.len()
        )?;
    }
    footer(out, report)?;
    if let Some(latency) = &report.latency {
        let spread = [
            ("min", latency.min_us),
            ("p50", latency.p50_us),
            ("p90", latency.p90_us),
            ("p99", latency.p99_us),
            ("max", latency.max_us),
        ]
        .map(|(rank, us)| format!("{rank} {}", millis(us)));
        write!(out, "{} queries: {} ms", latency.sent, spread.join(" · "))?;
        if latency.errors > 0 {
            write!(out, " · {BAD}{} unanswered{BAD:#}", latency.errors)?;
        }
        writeln!(out)?;
    }
    for violation in &report.violations {
        writeln!(out, "{BAD}violation{BAD:#} {violation}")?;
    }
    for failure in &report.failures {
        writeln!(out, "{BAD}failed{BAD:#} {failure}")?;
    }
    Ok(())
}

/// The question, the rcode in color, and how the response came.
fn status(out: &mut impl Write, report: &Report) -> io::Result<()> {
    for question in &report.question {
        write!(out, "{STRONG}{}", question.name)?;
        if question.class != "IN" {
            write!(out, " {}", question.class)?;
        }
        write!(out, " {}{STRONG:#}  ", question.qtype)?;
    }
    let rcode = &report.header.rcode;
    let color = if rcode == "NOERROR" { GOOD } else { BAD };
    write!(out, "{color}{rcode}{color:#}")?;
    if let Some(meaning) = meaning(rcode) {
        write!(out, " ({meaning})")?;
    }
    if let Some(exchange) = &report.exchange {
        let transport = match exchange.transport {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
            Transport::Tls => "TLS",
            Transport::Quic => "QUIC",
            Transport::Https => "DoH",
            Transport::Odoh => "ODoH",
            Transport::Coap => "CoAP",
        };
        write!(out, "  {} ms from ", millis(exchange.rtt_us))?;
        write!(out, "{} over {transport}", server_text(exchange.server))?;
        if let Some(http) = exchange.http {
            write!(out, " ({} {})", http.version, http.status)?;
        }
        if exchange.sends > 1 {
            write!(out, " after {} queries", exchange.sends)?;
        }
    }
    writeln!(out)
}

/// The flags worth a word, EDNS, and the sizes, on one quiet line; then each Extended DNS Error on its own.
fn footer(out: &mut impl Write, report: &Report) -> io::Result<()> {
    let flags = &report.header.flags;
    let set = |flag: &str| flags.iter().any(|f| f == flag);
    let mut words: Vec<String> = [
        (set("aa"), "authoritative"),
        (set("tc"), "truncated"),
        (set("rd") && !set("ra"), "recursion unavailable"),
        (set("ad"), "DNSSEC-validated"),
        (set("cd"), "checking disabled"),
        (set("z"), "Z bit set"),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, word)| word.to_owned())
    .collect();
    if let Some(edns) = &report.edns {
        edns_words(edns, &mut words);
    }
    words.push(match &report.exchange {
        Some(exchange) => format!("{}/{} bytes", exchange.query_size, report.size),
        None => format!("{} bytes", report.size),
    });
    writeln!(out, "{QUIET}{}{QUIET:#}", words.join(" · "))?;
    for option in report.edns.iter().flat_map(|e| &e.options) {
        if let OptionReport::Ede {
            code,
            purpose,
            text,
        } = option
        {
            write!(out, "{BAD}EDE {code}{BAD:#}")?;
            if let Some(purpose) = purpose {
                write!(out, " {purpose}")?;
            }
            if !text.is_empty() {
                write!(out, ": {text}")?;
            }
            writeln!(out)?;
        }
    }
    Ok(())
}

fn edns_words(edns: &EdnsReport, words: &mut Vec<String>) {
    let mut edns_word = format!("EDNS {} bytes", edns.payload);
    if edns.version > 0 {
        let _ = write!(edns_word, ", version {}", edns.version);
    }
    words.push(edns_word);
    words.extend(edns.flags.iter().map(|flag| match flag.as_str() {
        "do" => "DNSSEC OK".to_owned(),
        other => format!("EDNS flags {other}"),
    }));
    for option in &edns.options {
        match option {
            OptionReport::Nsid { text, .. } => words.push(format!("NSID {text}")),
            OptionReport::Cookie { server, .. } => words.push(
                if server.is_some() {
                    "server cookie"
                } else {
                    "no server cookie"
                }
                .to_owned(),
            ),
            OptionReport::Ede { .. } => {}
            OptionReport::Other { name, data } => {
                words.push(format!("{name} {data}").trim_end().to_owned());
            }
        }
    }
}

/// What servers asked the same question are compared on: the rcode and the answer records, without TTL or order.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Answers {
    rcode: String,
    records: Vec<String>,
}

impl Answers {
    pub(crate) fn of(report: &Report) -> Self {
        let mut records: Vec<String> = report
            .answer
            .iter()
            .map(|r| {
                // Names compare whatever their case (RFC 4343): the owner, and the data of the types holding only
                // names and numbers.
                let data = match r.rtype.as_str() {
                    "NS" | "CNAME" | "DNAME" | "PTR" | "MX" | "SRV" | "SOA" => {
                        r.data.to_ascii_lowercase()
                    }
                    _ => r.data.clone(),
                };
                let name = r.name.to_ascii_lowercase();
                format!("{name} {} {} {data}", r.class, r.rtype)
            })
            .collect();
        records.sort_unstable();
        Self {
            rcode: report.header.rcode.clone(),
            records,
        }
    }
}

/// Prints which servers answered alike, when not all did: `servers disagree: 1.1.1.1, 8.8.8.8 vs 9.9.9.9`.
pub(crate) fn disagreement(
    out: &mut impl Write,
    answers: &[(SocketAddr, Answers)],
) -> io::Result<()> {
    let mut alike: Vec<(&Answers, Vec<String>)> = Vec::new();
    for (address, answer) in answers {
        match alike.iter_mut().find(|(other, _)| *other == answer) {
            Some((_, servers)) => servers.push(server_text(*address)),
            None => alike.push((answer, vec![server_text(*address)])),
        }
    }
    if alike.len() < 2 {
        return Ok(());
    }
    let groups: Vec<String> = alike
        .iter()
        .map(|(_, servers)| servers.join(", "))
        .collect();
    writeln!(out, "{BAD}servers disagree{BAD:#}: {}", groups.join(" vs "))
}

/// `us` microseconds in milliseconds, to a tenth: `25.7`.
fn millis(us: u64) -> String {
    format!("{}.{}", us / 1000, us % 1000 / 100)
}

/// The type of `r`, after its class unless IN.
fn rtype(r: &RecordReport) -> String {
    if r.class == "IN" {
        r.rtype.clone()
    } else {
        format!("{} {}", r.class, r.rtype)
    }
}

/// `secs` in weeks, days, hours, minutes and seconds, each unit only when not zero: `1h1s`, `0s`.
fn duration(secs: u32) -> String {
    if secs == 0 {
        return "0s".to_owned();
    }
    let mut text = String::new();
    let mut left = secs;
    for (unit, len) in [
        ("w", 604_800),
        ("d", 86_400),
        ("h", 3_600),
        ("m", 60),
        ("s", 1),
    ] {
        if left >= len {
            let _ = write!(text, "{}{unit}", left / len);
            left %= len;
        }
    }
    text
}

/// What an rcode other than NOERROR means, when its mnemonic says it poorly (RFC 1035 §4.1.1, RFC 6891 §9).
fn meaning(rcode: &str) -> Option<&'static str> {
    Some(match rcode {
        "FORMERR" => "format error",
        "SERVFAIL" => "server failure",
        "NXDOMAIN" => "no such name",
        "NOTIMP" => "not implemented",
        "YXDOMAIN" => "name exists",
        "YXRRSET" => "RRset exists",
        "NXRRSET" => "no such RRset",
        "NOTAUTH" => "not authoritative",
        "NOTZONE" => "name not in zone",
        "BADVERS" => "bad EDNS version",
        "BADCOOKIE" => "bad cookie",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_name_each_unit_not_zero() {
        for (secs, text) in [
            (0, "0s"),
            (59, "59s"),
            (60, "1m"),
            (2_741, "45m41s"),
            (3_601, "1h1s"),
            (86_400, "1d"),
            (694_861, "1w1d1h1m1s"),
            (u32::MAX, "7101w3d6h28m15s"),
        ] {
            assert_eq!(duration(secs), text);
        }
    }

    #[test]
    fn round_trips_are_milliseconds_to_a_tenth() {
        for (us, text) in [
            (0, "0.0"),
            (99, "0.0"),
            (25_749, "25.7"),
            (1_000_000, "1000.0"),
        ] {
            assert_eq!(millis(us), text);
        }
    }

    #[test]
    fn rcodes_other_than_noerror_are_spelled_out() {
        let rcodes = [
            "FORMERR",
            "SERVFAIL",
            "NXDOMAIN",
            "NOTIMP",
            "YXDOMAIN",
            "YXRRSET",
            "NXRRSET",
            "NOTAUTH",
            "NOTZONE",
            "BADVERS",
            "BADCOOKIE",
        ];
        for rcode in rcodes {
            assert!(meaning(rcode).is_some(), "{rcode}");
        }
        // REFUSED says it well enough.
        assert_eq!(meaning("NOERROR").or(meaning("REFUSED")), None);
    }
}
