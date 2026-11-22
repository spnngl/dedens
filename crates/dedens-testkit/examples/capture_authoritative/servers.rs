//! The `answers` stage: Knot and NSD serve a zone each, side by side, and answer the same questions.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use dedens_proto::{Message, Name, RecordType};
use dedens_testkit::authoritative::{Answers, Reference, Server, Transport};

use crate::engine::{self, Container, Mount};
use crate::proxy;
use crate::zones::{self, ZONES};
use crate::{Result, now, queries, write};

/// How long a server has to answer a datagram, or a stream to deliver.
const ANSWER_WAIT: Duration = Duration::from_secs(5);
/// Tries, half a second apart, at the zone's SOA before a server is taken for refusing the zone.
const READY_TRIES: u32 = 40;
/// An answer of this size with DNSSEC is asked again in the other transports and sizes: it may need
/// truncation (RFC 6891 §6.2.5).
const LARGE: usize = 300;

/// How one question is put.
#[derive(Clone, Copy)]
struct Variant {
    edns_size: Option<u16>,
    dnssec_ok: bool,
    transport: Transport,
}

/// Every question, over UDP with a 1232-byte EDNS (the DNS flag day 2020 size) without and with DO.
const BASE: [Variant; 2] = [
    Variant {
        edns_size: Some(1232),
        dnssec_ok: false,
        transport: Transport::Udp,
    },
    Variant {
        edns_size: Some(1232),
        dnssec_ok: true,
        transport: Transport::Udp,
    },
];

/// The questions with a large answer, and the apex's: without EDNS (the 512 bytes of RFC 1035 §4.2.1), with a
/// 512-byte EDNS, and over TCP.
const EXTRA: [Variant; 3] = [
    Variant {
        edns_size: None,
        dnssec_ok: false,
        transport: Transport::Udp,
    },
    Variant {
        edns_size: Some(512),
        dnssec_ok: true,
        transport: Transport::Udp,
    },
    Variant {
        edns_size: Some(1232),
        dnssec_ok: true,
        transport: Transport::Tcp,
    },
];

/// A temporary directory of the files one run mounts, removed when dropped.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new(name: &str) -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("dedens-capture-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn put(&self, name: &str, text: &str) -> Result<()> {
        std::fs::write(self.0.join(name), text)?;
        Ok(())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sends `query` to `port` on the loopback, and returns the response, or `None` when none comes.
pub(crate) fn exchange(port: u16, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
    let address = proxy::local(port);
    match transport {
        Transport::Udp => udp(address, query),
        Transport::Tcp => tcp(address, query),
    }
}

fn udp(address: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket.set_read_timeout(Some(ANSWER_WAIT)).ok()?;
    socket.send_to(query, address).ok()?;
    let mut buf = vec![0u8; 65535];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    buf.truncate(len);
    Some(buf)
}

fn tcp(address: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&address, ANSWER_WAIT).ok()?;
    stream.set_read_timeout(Some(ANSWER_WAIT)).ok()?;
    stream
        .write_all(&u16::try_from(query.len()).ok()?.to_be_bytes())
        .ok()?;
    stream.write_all(query).ok()?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut body).ok()?;
    Some(body)
}

/// The first line of the output of `entrypoint --version` in `image`.
fn version(image: &str, entrypoint: &str, flag: &str) -> Result<String> {
    let output = engine::tool(image, entrypoint, &[flag], &[], None)?;
    engine::text(&output)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("{entrypoint} {flag}: no output").into())
}

/// The versions of both servers, as their binaries say.
pub(crate) fn versions() -> Result<BTreeMap<Server, String>> {
    Ok(BTreeMap::from([
        (
            Server::Knot,
            version(engine::KNOT_IMAGE, "knotd", "--version")?,
        ),
        (Server::Nsd, version(engine::NSD_IMAGE, "nsd", "-v")?),
    ]))
}

/// The configuration of `server` serving `apex` from `/zones/zone.zone`.
fn config(server: Server, apex: &Name<'_>) -> (&'static str, String) {
    match server {
        Server::Knot => (
            "knot.conf",
            format!(
                "server:\n  listen: 0.0.0.0@53\n  rundir: /tmp\nlog:\n  - target: stderr\n    any: info\n\
                 template:\n  - id: default\n    storage: /zones\n    semantic-checks: off\n\
                 zone:\n  - domain: {apex}\n    file: zone.zone\n"
            ),
        ),
        Server::Nsd => (
            "nsd.conf",
            format!(
                "server:\n  ip-address: 0.0.0.0@53\n  username: root\n  zonesdir: /zones\n  database: \"\"\n  \
                 pidfile: /tmp/nsd.pid\n  xfrdfile: /tmp/xfrd.state\n  zonelistfile: /tmp/zone.list\n  \
                 logfile: /dev/stderr\n  verbosity: 2\n\
                 zone:\n  name: {apex}\n  zonefile: zone.zone\n"
            ),
        ),
    }
}

/// Whether a response is an answer with an SOA at the apex: the zone is loaded and served.
fn serves(response: &[u8], apex: &Name<'_>) -> bool {
    Message::decode(response).is_ok_and(|decoded| {
        decoded
            .message
            .answer
            .iter()
            .any(|record| record.rtype() == RecordType::SOA && record.name == *apex)
    })
}

/// The lines of a server's log that say why it does not serve the zone.
fn reason(log: &str) -> String {
    let lines: Vec<&str> = log
        .lines()
        .filter(|line| {
            let line = line.to_ascii_lowercase();
            ["error", "fail", "refus", "invalid", "cannot", "unknown"]
                .iter()
                .any(|word| line.contains(word))
        })
        .take(3)
        .collect();
    let reason = if lines.is_empty() {
        log.lines().last().unwrap_or("no log").to_owned()
    } else {
        lines.join(" | ")
    };
    reason.chars().take(400).collect()
}

/// Starts `server` on the zone in `scratch`, and waits until it serves it. The reason, when it does not.
fn serve(
    server: Server,
    scratch: &Scratch,
    apex: &Name<'_>,
) -> Result<std::result::Result<Container, String>> {
    let (file, text) = config(server, apex);
    scratch.put(file, &text)?;
    let mounts = [Mount {
        host: scratch.path(),
        container: "/zones",
        writable: true,
    }];
    let container = match server {
        Server::Knot => Container::start(
            engine::KNOT_IMAGE,
            "knotd",
            &["-c", "/zones/knot.conf"],
            &mounts,
        )?,
        Server::Nsd => Container::start(
            engine::NSD_IMAGE,
            "nsd",
            &["-d", "-c", "/zones/nsd.conf"],
            &mounts,
        )?,
    };
    let soa = Reference {
        name: apex.clone().into_owned(),
        rtype: RecordType::SOA,
        dnssec_ok: false,
        edns_size: Some(1232),
        transport: Transport::Udp,
        responses: BTreeMap::new(),
    }
    .query()
    .to_vec()?;
    for _ in 0..READY_TRIES {
        if exchange(container.port, &soa, Transport::Udp)
            .is_some_and(|response| serves(&response, apex))
        {
            return Ok(Ok(container));
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(Err(reason(&container.logs()?)))
}

/// The `answers` stage: for each of [`ZONES`], both servers answer every question of [`queries::list`].
pub(crate) fn answers(dir: &Path) -> Result<()> {
    let testdata = dir.parent().ok_or("no testdata directory")?;
    let versions = versions()?;
    for zone in ZONES {
        let captured_at = now()?;
        let apex = zone.apex()?;
        let records = zone.load(testdata)?;
        let questions = queries::list(&apex, &records)?;
        let scratch = Scratch::new(zone.id)?;
        scratch.put(
            "zone.zone",
            &zones::render(&records, &format!("{}, as the servers read it.", zone.file)),
        )?;
        let mut running = BTreeMap::new();
        let mut refused = BTreeMap::new();
        for server in [Server::Knot, Server::Nsd] {
            match serve(server, &scratch, &apex)? {
                Ok(container) => {
                    running.insert(server, container);
                }
                Err(reason) => {
                    eprintln!("{}: {server} refuses the zone: {reason}", zone.id);
                    refused.insert(server, reason);
                }
            }
        }
        let mut references = Vec::new();
        if !running.is_empty() {
            for (name, rtype) in &questions {
                let mut ask = |variant: Variant| -> Result<usize> {
                    let mut reference = Reference {
                        name: name.clone(),
                        rtype: *rtype,
                        dnssec_ok: variant.dnssec_ok,
                        edns_size: variant.edns_size,
                        transport: variant.transport,
                        responses: BTreeMap::new(),
                    };
                    let query = reference.query().to_vec()?;
                    for (server, container) in &running {
                        match exchange(container.port, &query, variant.transport) {
                            Some(response) => {
                                reference.responses.insert(*server, response);
                            }
                            None => {
                                eprintln!("{}: {server} did not answer {name} {rtype}", zone.id);
                            }
                        }
                    }
                    let largest = reference
                        .responses
                        .values()
                        .map(Vec::len)
                        .max()
                        .unwrap_or(0);
                    references.push(reference);
                    Ok(largest)
                };
                let mut largest = 0;
                for variant in BASE {
                    largest = largest.max(ask(variant)?);
                }
                if largest > LARGE || name == &apex {
                    for variant in EXTRA {
                        ask(variant)?;
                    }
                }
            }
        }
        let file = Answers {
            zone: apex,
            file: zone.file.to_owned(),
            captured_at,
            versions: versions.clone(),
            refused,
            answers: references,
        };
        write(
            &dir.join("answers").join(format!("{}.yaml", zone.id)),
            file.to_yaml()?.as_bytes(),
        )?;
    }
    Ok(())
}
