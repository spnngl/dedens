//! The outputs of a response (D32): compact, dig's layout, `+short`, and JSON (D35), all from its [`Report`].

use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use dedens_scenario::{EdnsReport, OptionReport, RecordReport, Report, Transport};

/// How responses are printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layout {
    /// One line per record under each section's heading, then a footer in words.
    Compact,
    /// dig 9.20's layout, as with `+nocmd`, without its `WHEN` line.
    Dig,
    /// The data of the answer records.
    Short,
    /// One JSON object per line (D35).
    Json,
}

const HEADING: Style = Style::new().bold();
const FOOTER: Style = Style::new().dimmed();
const GOOD: Style = AnsiColor::Green.on_default().bold();
const BAD: Style = AnsiColor::Red.on_default().bold();

/// Prints `report` in `layout`.
pub(crate) fn print(out: &mut impl Write, layout: Layout, report: &Report) -> io::Result<()> {
    match layout {
        Layout::Compact => compact(out, report),
        Layout::Dig => dig(out, report),
        Layout::Short => report
            .answer
            .iter()
            .try_for_each(|record| writeln!(out, "{}", record.data)),
        Layout::Json => {
            serde_json::to_writer(&mut *out, report)?;
            writeln!(out)
        }
    }
}

fn compact(out: &mut impl Write, report: &Report) -> io::Result<()> {
    for question in &report.question {
        let class = if question.class == "IN" {
            ""
        } else {
            &question.class
        };
        let words: Vec<&str> = [question.name.as_str(), class, &question.qtype]
            .into_iter()
            .filter(|w| !w.is_empty())
            .collect();
        writeln!(out, "{HEADING}{}{HEADING:#}", words.join(" "))?;
    }
    let sections = [
        ("ANSWER", &report.answer),
        ("AUTHORITY", &report.authority),
        ("ADDITIONAL", &report.additional),
    ];
    let records = || sections.iter().flat_map(|(_, records)| records.iter());
    let width = |field: fn(&RecordReport) -> usize| records().map(field).max().unwrap_or(0);
    let name = width(|r| r.name.len());
    let ttl = width(|r| r.ttl.to_string().len());
    let rtype_width = width(|r| {
        r.rtype.len()
            + if r.class == "IN" {
                0
            } else {
                r.class.len() + 1
            }
    });
    for (heading, records) in sections.iter().filter(|(_, records)| !records.is_empty()) {
        writeln!(out, "{HEADING}{heading}{HEADING:#}")?;
        for r in *records {
            let rtype = if r.class == "IN" {
                r.rtype.clone()
            } else {
                format!("{} {}", r.class, r.rtype)
            };
            writeln!(
                out,
                "{:name$}  {:>ttl$}  {rtype:rtype_width$}  {}",
                r.name, r.ttl, r.data
            )?;
        }
    }
    let status = if report.header.rcode == "NOERROR" {
        GOOD
    } else {
        BAD
    };
    write!(
        out,
        "{status}{}{status:#}{FOOTER} {}",
        report.header.rcode,
        report.header.flags.join(" ")
    )?;
    if let Some(exchange) = &report.exchange {
        let transport = match exchange.transport {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
        };
        write!(
            out,
            " from {} over {transport} in {}.{} ms",
            exchange.server,
            exchange.rtt_us / 1000,
            exchange.rtt_us % 1000 / 100
        )?;
        if exchange.sends > 1 {
            write!(out, " after {} queries", exchange.sends)?;
        }
        write!(out, ", query {} bytes", exchange.query_size)?;
    }
    writeln!(out, ", response {} bytes{FOOTER:#}", report.size)?;
    if let Some(edns) = &report.edns {
        compact_edns(out, edns)?;
    }
    for failure in &report.failures {
        writeln!(out, "{BAD}failed{BAD:#} {failure}")?;
    }
    Ok(())
}

fn compact_edns(out: &mut impl Write, edns: &EdnsReport) -> io::Result<()> {
    let mut words = vec![format!("EDNS{} payload {}", edns.version, edns.payload)];
    words.extend(edns.flags.iter().cloned());
    let mut cookie = "no cookie";
    for option in &edns.options {
        match option {
            OptionReport::Nsid { text, .. } => words.push(format!("NSID {text}")),
            OptionReport::Cookie { server, .. } => {
                cookie = if server.is_some() {
                    "server cookie returned"
                } else {
                    "no server cookie"
                };
            }
            OptionReport::Ede { .. } => {}
            OptionReport::Other { name, data } => {
                words.push(format!("{name} {data}").trim_end().to_owned());
            }
        }
    }
    words.push(cookie.to_owned());
    writeln!(out, "{FOOTER}{}{FOOTER:#}", words.join(", "))?;
    for option in &edns.options {
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

fn dig(out: &mut impl Write, report: &Report) -> io::Result<()> {
    let header = &report.header;
    writeln!(out, ";; Got answer:")?;
    writeln!(
        out,
        ";; ->>HEADER<<- opcode: {}, status: {}, id: {}",
        header.opcode, header.rcode, header.id
    )?;
    writeln!(
        out,
        ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
        header.flags.join(" "),
        report.question.len(),
        report.answer.len(),
        report.authority.len(),
        report.additional.len() + usize::from(report.edns.is_some())
    )?;
    let flag = |name: &str| header.flags.iter().any(|f| f == name);
    if flag("rd") && !flag("ra") {
        writeln!(out, ";; WARNING: recursion requested but not available")?;
    }
    writeln!(out)?;
    if let Some(edns) = &report.edns {
        dig_edns(out, edns)?;
    }
    writeln!(out, ";; QUESTION SECTION:")?;
    for question in &report.question {
        let mut line = Columns::default();
        line.push(&format!(";{}", question.name), 32);
        line.push(&question.class, 40);
        line.text.push_str(&question.qtype);
        writeln!(out, "{}", line.text)?;
    }
    writeln!(out)?;
    for (heading, records) in [
        ("ANSWER", &report.answer),
        ("AUTHORITY", &report.authority),
        ("ADDITIONAL", &report.additional),
    ] {
        if records.is_empty() {
            continue;
        }
        writeln!(out, ";; {heading} SECTION:")?;
        for r in records {
            let mut line = Columns::default();
            line.push(&r.name, 24);
            line.push(&r.ttl.to_string(), 32);
            line.push(&r.class, 40);
            line.push(&r.rtype, 48);
            line.text.push_str(&r.data);
            writeln!(out, "{}", line.text)?;
        }
        writeln!(out)?;
    }
    if let Some(exchange) = &report.exchange {
        let transport = match exchange.transport {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
        };
        writeln!(out, ";; Query time: {} msec", exchange.rtt_us / 1000)?;
        let ip = exchange.server.ip();
        writeln!(
            out,
            ";; SERVER: {ip}#{}({ip}) ({transport})",
            exchange.server.port()
        )?;
    }
    writeln!(out, ";; MSG SIZE  rcvd: {}", report.size)?;
    writeln!(out)
}

fn dig_edns(out: &mut impl Write, edns: &EdnsReport) -> io::Result<()> {
    writeln!(out, ";; OPT PSEUDOSECTION:")?;
    write!(out, "; EDNS: version: {}, flags:", edns.version)?;
    for flag in &edns.flags {
        write!(out, " {flag}")?;
    }
    writeln!(out, "; udp: {}", edns.payload)?;
    for option in &edns.options {
        match option {
            OptionReport::Nsid { hex, text } => {
                let bytes: Vec<&str> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|at| hex.get(at..at + 2))
                    .collect();
                writeln!(out, "; NSID: {} (\"{text}\")", bytes.join(" "))?;
            }
            OptionReport::Cookie { client, server } => match server {
                Some(server) => writeln!(out, "; COOKIE: {client}{server} (good)")?,
                None => writeln!(out, "; COOKIE: {client}")?,
            },
            OptionReport::Ede {
                code,
                purpose,
                text,
            } => {
                write!(out, "; EDE: {code}")?;
                if let Some(purpose) = purpose {
                    write!(out, " ({purpose})")?;
                }
                if !text.is_empty() {
                    write!(out, ": ({text})")?;
                }
                writeln!(out)?;
            }
            OptionReport::Other { name, data } => writeln!(out, "; {name}: {data}")?,
        }
    }
    Ok(())
}

/// A line of dig's columns: tab stops every 8 characters, one space when a field reaches past its column.
#[derive(Default)]
struct Columns {
    text: String,
    /// The column the next character goes to, a tab counting up to the next stop.
    at: usize,
}

impl Columns {
    /// Writes `field`, then moves to `column`, a multiple of 8.
    fn push(&mut self, field: &str, column: usize) {
        self.text.push_str(field);
        self.at += field.len();
        if self.at >= column {
            self.text.push(' ');
            self.at += 1;
        } else {
            for _ in 0..(column / 8 - self.at / 8) {
                self.text.push('\t');
            }
            self.at = column;
        }
    }
}
