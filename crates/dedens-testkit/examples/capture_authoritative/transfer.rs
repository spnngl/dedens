//! The `sources` stage: AXFR (RFC 5936) of zones from public servers, kept as the zone text and the raw messages.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use dedens_proto::rdata::RData;
use dedens_proto::{
    Flags, Message, Name, Question, Rcode, Record, RecordType, ZoneEntry, ZoneReader,
};
use dedens_testkit::authoritative::{Packet, Peer, Recording, Transport};

use crate::{Result, now, write, zones};

/// A zone and the public servers that transfer it to anyone, in the order tried: its file in `zones/`, its
/// recording's id and where the sources are published.
struct Source {
    zone: &'static str,
    file: &'static str,
    id: &'static str,
    /// RFC 8806 Appendix A for the root: ICANN's two transfer servers, then three root servers that allow AXFR.
    servers: &'static [&'static str],
}

const SOURCES: &[Source] = &[
    Source {
        zone: ".",
        file: "root.zone",
        id: "axfr-root",
        servers: &[
            "lax.xfr.dns.icann.org",
            "iad.xfr.dns.icann.org",
            "b.root-servers.net",
            "f.root-servers.net",
        ],
    },
    Source {
        zone: "zonetransfer.me.",
        file: "zonetransfer.me.zone",
        id: "axfr-zonetransfer.me",
        servers: &["nsztm1.digi.ninja"],
    },
];

/// How long a transfer waits for the next bytes.
const IO_TIMEOUT: Duration = Duration::from_secs(60);
/// The messages of a transfer before the client gives up: the root zone is a few hundred.
const MAX_MESSAGES: usize = 100_000;

/// One transfer: what the server sent and what it held.
pub(crate) struct Transfer {
    pub(crate) server: SocketAddr,
    pub(crate) messages: Vec<Packet>,
    /// The records, the SOA first, without the SOA that ends the transfer.
    pub(crate) records: Vec<Record<'static>>,
    pub(crate) serial: u32,
}

/// Transfers `zone` from `server` by AXFR over TCP, without TSIG or EDNS.
pub(crate) fn axfr(server: SocketAddr, zone: &Name<'static>) -> Result<Transfer> {
    let mut stream = TcpStream::connect_timeout(&server, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let started = Instant::now();
    let packet = |from, message: &[u8]| Packet {
        at_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        transport: Transport::Tcp,
        connection: 1,
        from,
        message: message.to_vec(),
    };
    let id = 0xA5F0;
    let mut query = Message::query(id, Question::new(zone.clone(), RecordType::AXFR));
    query.header.flags = Flags::NONE;
    query.edns = None;
    let query = query.to_vec()?;
    stream.write_all(&u16::try_from(query.len())?.to_be_bytes())?;
    stream.write_all(&query)?;
    let mut messages = vec![packet(Peer::Client, &query)];
    let mut records: Vec<Record<'static>> = Vec::new();
    let mut soas = 0;
    while soas < 2 {
        if messages.len() > MAX_MESSAGES {
            return Err("transfer without end".into());
        }
        let mut length = [0u8; 2];
        stream.read_exact(&mut length)?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut body)?;
        messages.push(packet(Peer::Server, &body));
        let decoded = Message::decode(&body)?;
        if !decoded.violations.is_empty() {
            return Err(format!("a message breaks a rule: {:?}", decoded.violations).into());
        }
        let message = decoded.message.into_owned();
        if message.header.id != id || message.rcode() != Rcode::NOERROR {
            return Err(format!("{zone}: refused: {}", message.rcode()).into());
        }
        for record in message.answer {
            soas += usize::from(record.rtype() == RecordType::SOA);
            records.push(record);
        }
        if records
            .first()
            .is_none_or(|first| first.rtype() != RecordType::SOA)
        {
            return Err("the transfer does not start with the SOA".into());
        }
    }
    let Some(RData::Soa(soa)) = records.first().map(Record::data) else {
        return Err("no SOA".into());
    };
    let serial = soa.serial;
    // The SOA that ends the transfer repeats the first.
    records.pop();
    Ok(Transfer {
        server,
        messages,
        records,
        serial,
    })
}

/// Transfers `zone` from the first of `servers` that does, over IPv4 as the containers have no IPv6.
pub(crate) fn from_any(servers: &[&str], zone: &Name<'static>) -> Result<Transfer> {
    let mut last = String::from("no server");
    for host in servers {
        let Some(address) = (*host, 53)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.find(SocketAddr::is_ipv4))
        else {
            last = format!("{host}: no IPv4 address");
            continue;
        };
        match axfr(address, zone) {
            Ok(transfer) => return Ok(transfer),
            Err(error) => last = format!("{host} ({address}): {error}"),
        }
        eprintln!("{last}");
    }
    Err(format!("{zone}: no server transferred it: {last}").into())
}

/// The recording of `transfer`.
fn recording(source: &Source, transfer: Transfer, captured_at: u64) -> Result<Recording> {
    Ok(Recording {
        description: format!(
            "AXFR of {} over TCP, without TSIG or EDNS, as a client of a public server",
            source.zone
        ),
        server: transfer.server.to_string(),
        captured_at,
        zone: source.zone.parse()?,
        serial: Some(transfer.serial),
        key: None,
        messages: transfer.messages,
    })
}

/// The Wayback Machine's latest capture of `internic.net/domain/root.zone` before the zone transferred. A second
/// serial of the root takes half a day to wait for: it is published twice a day.
const PREVIOUS_ROOT_AT: &str = "20261114221805";

/// `text` with the ZONEMD type (RFC 8976) as `TYPE63` and its data in the generic form of RFC 3597 §5:
/// `dedens-proto` has no ZONEMD yet, and the AXFR's text has the type so too.
fn generic_zonemd(text: &str) -> Result<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        out.push(match fields.as_slice() {
            [
                owner,
                ttl,
                class,
                "ZONEMD",
                serial,
                scheme,
                hash,
                digest @ ..,
            ] => {
                let digest = digest.concat();
                let serial: u32 = serial.parse()?;
                let (scheme, hash): (u8, u8) = (scheme.parse()?, hash.parse()?);
                let length = 6 + digest.len() / 2;
                format!(
                    "{owner}\t{ttl}\t{class}\tTYPE63\t\\# {length} {serial:08X}{scheme:02X}{hash:02X}{digest}"
                )
            }
            [owner, ttl, class, "RRSIG", "ZONEMD", rest @ ..] => {
                format!("{owner}\t{ttl}\t{class}\tRRSIG\tTYPE63 {}", rest.join(" "))
            }
            [owner, ttl, class, "NSEC", rest @ ..] => {
                let rest: Vec<&str> = rest
                    .iter()
                    .map(|word| if *word == "ZONEMD" { "TYPE63" } else { word })
                    .collect();
                format!("{owner}\t{ttl}\t{class}\tNSEC\t{}", rest.join(" "))
            }
            _ => line.to_owned(),
        });
    }
    Ok(out.join("\n") + "\n")
}

/// The root zone the Wayback Machine archived at [`PREVIOUS_ROOT_AT`], into `zones/root-previous.zone`: the zone
/// the IXFR of `root-ixfr` starts from.
fn previous_root(dir: &Path) -> Result<()> {
    let url = format!(
        "https://web.archive.org/web/{PREVIOUS_ROOT_AT}id_/https://www.internic.net/domain/root.zone"
    );
    let output = Command::new("curl")
        .args(["-sS", "-f", "-L", "--compressed", "--max-time", "300", &url])
        .output()?;
    if !output.status.success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    let text = generic_zonemd(&String::from_utf8(output.stdout)?)?;
    let mut records = Vec::new();
    for entry in ZoneReader::new(text.as_bytes(), Some(Name::root())) {
        if let ZoneEntry::Record(decoded) = entry? {
            records.push(decoded.record);
        }
    }
    let serial = match records.first().map(Record::data) {
        Some(RData::Soa(soa)) => soa.serial,
        _ => return Err("the archived root zone does not start with its SOA".into()),
    };
    eprintln!(
        ".: {} records archived at {PREVIOUS_ROOT_AT}, serial {serial}",
        records.len()
    );
    let text = zones::render(
        &records,
        &format!(
            "The root zone, serial {serial}, as the Wayback Machine archived {url}; written by `just capture-authoritative`."
        ),
    );
    write(&dir.join("zones/root-previous.zone"), text.as_bytes())
}

/// The `sources` stage: each of [`SOURCES`] into `dir`'s `zones/` and `recordings/`, and the previous root zone.
pub(crate) fn sources(dir: &Path) -> Result<()> {
    previous_root(dir)?;
    for source in SOURCES {
        let captured_at = now()?;
        let transfer = from_any(source.servers, &source.zone.parse()?)?;
        eprintln!(
            "{}: {} records from {}, serial {}",
            source.zone,
            transfer.records.len(),
            transfer.server,
            transfer.serial
        );
        let text = zones::render(
            &transfer.records,
            &format!(
                "AXFR of {} from {}, serial {}, Unix time {captured_at}; written by `just capture-authoritative`.",
                source.zone, transfer.server, transfer.serial
            ),
        );
        let file = dir.join("zones").join(source.file);
        write(&file, text.as_bytes())?;
        let recording = recording(source, transfer, captured_at)?;
        write(
            &dir.join("recordings").join(format!("{}.yaml", source.id)),
            recording.to_yaml()?.as_bytes(),
        )?;
    }
    Ok(())
}
