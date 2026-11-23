//! The `exchanges` and `root-ixfr` stages: Knot's own tools (`kdig`, `knsupdate`, `knotc`) talk to a Knot in a
//! container through a recording proxy, one fresh Knot a scenario.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use dedens_proto::rdata::RData;
use dedens_proto::{Message, Name, Record, RecordType};
use dedens_testkit::authoritative::{
    Packet, Peer, Recording, Reference, Server, TSIG_KEY, Transport,
};

use crate::engine::{self, Container, Mount};
use crate::proxy::{self, Proxy};
use crate::servers::{self, Scratch};
use crate::zones::{self, PREVIOUS_ROOT, ZONES};
use crate::{Result, now, write};

/// The zone of RFC 4035 Appendix A, open to transfers and updates without a key.
const OPEN: &str = "example.";
/// The zone transferred from a public server, served to the key's holder only.
const SIGNED: &str = "zonetransfer.me.";
/// A secret that is not [`TSIG_KEY`]'s.
const WRONG_SECRET: &str = "d3Jvbmcgc2VjcmV0Cg==";
/// How long a NOTIFY, sent after a change, has to reach its receiver.
const NOTIFY_WAIT: Duration = Duration::from_secs(4);
/// The seconds `faketime` turns the client's clock back: TSIG's fudge is 300 seconds (RFC 8945 §5.2.3).
const CLOCK_OFFSET: &str = "-600";

/// A TSIG key as a client holds it.
#[derive(Clone, Copy)]
struct Key {
    name: &'static str,
    secret: &'static str,
}

/// The key the server knows.
const GOOD: Key = Key {
    name: TSIG_KEY.name,
    secret: TSIG_KEY.secret,
};
/// The key's name with another secret: the MAC is wrong (RFC 8945 §5.3.3).
const BAD_SECRET: Key = Key {
    name: TSIG_KEY.name,
    secret: WRONG_SECRET,
};
/// A key the server does not know (RFC 8945 §5.3.1).
const UNKNOWN: Key = Key {
    name: "dedens-unknown-key",
    secret: TSIG_KEY.secret,
};

/// One action of a scenario.
enum Step {
    /// `kdig`, with the key and the seconds the clock is set back.
    Kdig {
        args: Vec<String>,
        key: Option<Key>,
        back: bool,
    },
    /// `knsupdate`, the script on its standard input.
    Update { script: String, key: Option<Key> },
    /// `knotc` in the server's container.
    Knotc(&'static [&'static str]),
    /// A pause, for the server to act.
    Wait,
}

/// Whose messages a recording holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// The tools' with Knot.
    Tools,
    /// Knot's NOTIFYs to the receiver that answers them.
    Notifies,
}

/// A scenario: one file of `recordings/`.
struct Scenario {
    id: String,
    description: String,
    zone: &'static str,
    seen: Seen,
    /// The key the first requests are signed with, for the recording's notes.
    key: Option<Key>,
    steps: Vec<Step>,
}

fn kdig(zone: &str, query: &str) -> Step {
    Step::Kdig {
        args: vec![zone.to_owned(), query.to_owned()],
        key: None,
        back: false,
    }
}

fn signed(zone: &str, query: &str, key: Key) -> Step {
    Step::Kdig {
        args: vec![zone.to_owned(), query.to_owned()],
        key: Some(key),
        back: false,
    }
}

/// An UPDATE of `OPEN` that does `lines`, and the AXFR that shows what is left.
fn update(id: &str, description: &str, lines: &[&str]) -> Scenario {
    let mut script = format!("zone {OPEN}\n");
    for line in lines {
        script.push_str(line);
        script.push('\n');
    }
    script.push_str("send\n");
    Scenario {
        id: format!("update-{id}"),
        description: format!("UPDATE of {OPEN} without TSIG: {description}; then AXFR"),
        zone: OPEN,
        seen: Seen::Tools,
        key: None,
        steps: vec![Step::Update { script, key: None }, kdig(OPEN, "AXFR")],
    }
}

/// The scenarios, in the order of `recordings/`. `serial` is the one of [`SIGNED`], `open_serial` of [`OPEN`].
#[allow(
    clippy::too_many_lines,
    reason = "a table of scenarios, one entry each"
)]
fn scenarios(serial: u32, open_serial: u32) -> Vec<Scenario> {
    let tool = |id: &str, description: &str, zone, key, steps| Scenario {
        id: id.to_owned(),
        description: description.to_owned(),
        zone,
        seen: Seen::Tools,
        key,
        steps,
    };
    let add = "update add dedens-new.example. 300 A 192.0.2.1";
    let mut all = vec![
        tool(
            "axfr-tsig",
            "AXFR signed with hmac-sha256 (RFC 8945, RFC 5936 §2.2)",
            SIGNED,
            Some(GOOD),
            vec![signed(SIGNED, "AXFR", GOOD)],
        ),
        tool(
            "axfr-tsig-bad-secret",
            "AXFR signed with the right key name and a wrong secret: BADSIG (RFC 8945 §5.3.3)",
            SIGNED,
            Some(BAD_SECRET),
            vec![signed(SIGNED, "AXFR", BAD_SECRET)],
        ),
        tool(
            "axfr-tsig-unknown-key",
            "AXFR signed with a key the server does not know: BADKEY (RFC 8945 §5.3.1)",
            SIGNED,
            Some(UNKNOWN),
            vec![signed(SIGNED, "AXFR", UNKNOWN)],
        ),
        tool(
            "axfr-tsig-bad-time",
            "AXFR signed by a client whose clock is 600 seconds behind: BADTIME (RFC 8945 §5.2.3)",
            SIGNED,
            Some(GOOD),
            vec![Step::Kdig {
                args: vec![SIGNED.to_owned(), "AXFR".to_owned()],
                key: Some(GOOD),
                back: true,
            }],
        ),
        tool(
            "axfr-unsigned-refused",
            "AXFR without TSIG of a zone that is for the key's holder: NOTAUTH, unsigned",
            SIGNED,
            None,
            vec![kdig(SIGNED, "AXFR")],
        ),
        tool(
            "ixfr-tsig-uptodate",
            "IXFR signed, from the serial the server has: one SOA (RFC 1995 §4)",
            SIGNED,
            Some(GOOD),
            vec![signed(SIGNED, &format!("IXFR={serial}"), GOOD)],
        ),
        tool(
            "axfr-open",
            "AXFR without TSIG of a zone open to all (RFC 5936 §2.2)",
            OPEN,
            None,
            vec![kdig(OPEN, "AXFR")],
        ),
        tool(
            "ixfr-uptodate",
            "IXFR over UDP from the serial the server has: one SOA (RFC 1995 §4)",
            OPEN,
            None,
            vec![kdig(OPEN, &format!("IXFR={open_serial}"))],
        ),
        tool(
            "ixfr-unknown-serial",
            "IXFR from a serial the server never had: a full transfer in the form of an AXFR (RFC 1995 §4)",
            OPEN,
            None,
            vec![Step::Kdig {
                args: vec![OPEN.to_owned(), "IXFR=1".to_owned(), "+tcp".to_owned()],
                key: None,
                back: false,
            }],
        ),
        tool(
            "ixfr-difference-tcp",
            "UPDATE adding a name, then IXFR over TCP from the serial before it: the difference (RFC 1995 §4)",
            OPEN,
            None,
            vec![
                Step::Update {
                    script: format!("zone {OPEN}\n{add}\nsend\n"),
                    key: None,
                },
                Step::Kdig {
                    args: vec![
                        OPEN.to_owned(),
                        format!("IXFR={open_serial}"),
                        "+tcp".to_owned(),
                    ],
                    key: None,
                    back: false,
                },
            ],
        ),
        tool(
            "ixfr-difference-udp",
            "UPDATE adding a name, then IXFR over UDP from the serial before it (RFC 1995 §3)",
            OPEN,
            None,
            vec![
                Step::Update {
                    script: format!("zone {OPEN}\n{add}\nsend\n"),
                    key: None,
                },
                kdig(OPEN, &format!("IXFR={open_serial}")),
            ],
        ),
        tool(
            "update-signed-key-not-allowed",
            "UPDATE of a zone whose ACL has no key, signed: refused (RFC 2136 §3.3, RFC 8945)",
            OPEN,
            Some(GOOD),
            vec![Step::Update {
                script: format!("zone {OPEN}\n{add}\nsend\n"),
                key: Some(GOOD),
            }],
        ),
        tool(
            "update-signed",
            "UPDATE signed with hmac-sha256 adding a name to the zone for the key's holder; then AXFR (RFC 2136 §3.3)",
            SIGNED,
            Some(GOOD),
            vec![
                Step::Update {
                    script: format!(
                        "zone {SIGNED}\nupdate add dedens-new.{SIGNED} 300 A 192.0.2.1\nsend\n"
                    ),
                    key: Some(GOOD),
                },
                signed(SIGNED, "AXFR", GOOD),
            ],
        ),
        tool(
            "update-unsigned-refused",
            "UPDATE without TSIG of a zone that is for the key's holder: REFUSED (RFC 2136 §3.3)",
            SIGNED,
            None,
            vec![Step::Update {
                script: format!(
                    "zone {SIGNED}\nupdate add dedens-new.{SIGNED} 300 A 192.0.2.1\nsend\n"
                ),
                key: None,
            }],
        ),
        tool(
            "update-bad-secret",
            "UPDATE signed with a wrong secret: NOTAUTH with BADSIG (RFC 2136 §3.3, RFC 8945 §5.3.3)",
            SIGNED,
            Some(BAD_SECRET),
            vec![Step::Update {
                script: format!(
                    "zone {SIGNED}\nupdate add dedens-new.{SIGNED} 300 A 192.0.2.1\nsend\n"
                ),
                key: Some(BAD_SECRET),
            }],
        ),
        update(
            "add-name",
            "add a record at a new name (RFC 2136 §2.5.1)",
            &[add],
        ),
        update(
            "add-to-rrset",
            "add a record to an existing RRset (§2.5.1)",
            &["update add xx.example. 3600 A 192.0.2.2"],
        ),
        update(
            "add-duplicate",
            "add a record the RRset holds (§3.4.2.2)",
            &["update add ns1.example. 3600 A 192.0.2.1"],
        ),
        update(
            "add-cname-conflict",
            "add a CNAME where other records are: ignored (§3.4.2.2)",
            &["update add xx.example. 300 CNAME ai.example."],
        ),
        update(
            "add-outside-zone",
            "add a record at a name outside the zone: NOTZONE (§3.4.1.3)",
            &["update add dedens.example.com. 300 A 192.0.2.1"],
        ),
        update(
            "delete-rrset",
            "delete an RRset (§2.5.2)",
            &["update delete xx.example. A"],
        ),
        update(
            "delete-name",
            "delete all the RRsets of a name (§2.5.3)",
            &["update delete xx.example."],
        ),
        update(
            "delete-record",
            "delete one record of an RRset (§2.5.4)",
            &["update delete example. NS ns2.example."],
        ),
        update(
            "delete-soa",
            "delete the SOA: ignored (§3.4.2.3)",
            &["update delete example. SOA"],
        ),
        update(
            "delete-apex-ns",
            "delete the apex NS RRset: the last NS stays (§3.4.2.4)",
            &["update delete example. NS"],
        ),
        update(
            "delete-absent",
            "delete an RRset that is not there: nothing (§3.4.2.3)",
            &["update delete nothere.example. A"],
        ),
        update(
            "prereq-yxdomain",
            "prerequisite: the name is in use (§2.4.4), met",
            &["prereq yxdomain xx.example.", add],
        ),
        update(
            "prereq-yxdomain-fails",
            "prerequisite: the name is in use (§2.4.4), not met: NXDOMAIN",
            &["prereq yxdomain nothere.example.", add],
        ),
        update(
            "prereq-nxdomain",
            "prerequisite: the name is not in use (§2.4.5), met",
            &["prereq nxdomain nothere.example.", add],
        ),
        update(
            "prereq-nxdomain-fails",
            "prerequisite: the name is not in use (§2.4.5), not met: YXDOMAIN",
            &["prereq nxdomain xx.example.", add],
        ),
        update(
            "prereq-yxrrset",
            "prerequisite: the RRset exists, whatever its data (§2.4.1), met",
            &["prereq yxrrset xx.example. A", add],
        ),
        update(
            "prereq-yxrrset-fails",
            "prerequisite: the RRset exists (§2.4.1), not met: NXRRSET",
            &["prereq yxrrset xx.example. MX", add],
        ),
        update(
            "prereq-yxrrset-value",
            "prerequisite: the RRset exists with exactly this data (§2.4.2), met",
            &[
                "prereq yxrrset example. NS ns1.example.",
                "prereq yxrrset example. NS ns2.example.",
                add,
            ],
        ),
        update(
            "prereq-yxrrset-value-fails",
            "prerequisite: the RRset exists with exactly this data (§2.4.2), not met: NXRRSET",
            &["prereq yxrrset example. NS ns1.example.", add],
        ),
        update(
            "prereq-nxrrset",
            "prerequisite: the RRset does not exist (§2.4.3), met",
            &["prereq nxrrset xx.example. MX", add],
        ),
        update(
            "prereq-nxrrset-fails",
            "prerequisite: the RRset does not exist (§2.4.3), not met: YXRRSET",
            &["prereq nxrrset xx.example. A", add],
        ),
    ];
    all.push(Scenario {
        id: "notify-load".to_owned(),
        description: "the NOTIFY Knot sends when it loads a zone (RFC 1996 §3.11)".to_owned(),
        zone: OPEN,
        seen: Seen::Notifies,
        key: None,
        steps: vec![Step::Wait],
    });
    all.push(Scenario {
        id: "notify-command".to_owned(),
        description: "the NOTIFY Knot sends when told to by `knotc zone-notify` (RFC 1996 §3.11)"
            .to_owned(),
        zone: OPEN,
        seen: Seen::Notifies,
        key: None,
        steps: vec![Step::Wait, Step::Knotc(&["zone-notify", OPEN]), Step::Wait],
    });
    all.push(Scenario {
        id: "notify-after-update".to_owned(),
        description: "the NOTIFY Knot sends after an UPDATE changed the zone (RFC 1996 §3.11)"
            .to_owned(),
        zone: OPEN,
        seen: Seen::Notifies,
        key: None,
        steps: vec![
            Step::Update {
                script: format!("zone {OPEN}\n{add}\nsend\n"),
                key: None,
            },
            Step::Wait,
        ],
    });
    all
}

/// A receiver of NOTIFYs: an NSD, behind a proxy.
struct Sink {
    _scratch: Scratch,
    _container: Container,
    proxy: Proxy,
}

/// A Knot serving zones, behind a proxy, with the files it reads.
struct Lab {
    scratch: Scratch,
    knot: Container,
    proxy: Proxy,
    host: Ipv4Addr,
    sink: Option<Sink>,
}

/// A zone a Knot serves.
struct Served {
    apex: String,
    /// The zone's text, written to `<apex>.zone`.
    text: String,
    /// The ACL: [`OPEN`]'s or [`SIGNED`]'s.
    acl: &'static str,
}

impl Served {
    /// The name of the zone's file: the apex without its root dot, `root` for the root zone.
    fn file(&self) -> String {
        match self.apex.trim_end_matches('.') {
            "" => "root.zone".to_owned(),
            name => format!("{name}.zone"),
        }
    }
}

/// The configuration of a Knot serving `zones`.
fn knot_config(zones: &[Served], sink: Option<SocketAddr>, diff: bool) -> String {
    let remote = sink.map_or_else(String::new, |sink| {
        format!(
            "remote:\n  - id: sink\n    address: {}@{}\n",
            sink.ip(),
            sink.port()
        )
    });
    let load = if diff { "difference" } else { "whole" };
    let notify = if sink.is_some() {
        "    notify: sink\n"
    } else {
        ""
    };
    let zones = zones
        .iter()
        .map(|zone| {
            format!(
                "  - domain: {}\n    file: {}\n    acl: {}\n{notify}",
                zone.apex,
                zone.file(),
                zone.acl
            )
        })
        .collect::<Vec<String>>()
        .concat();
    format!(
        "server:\n  listen: 0.0.0.0@53\n  rundir: /tmp\n\
         log:\n  - target: stderr\n    any: info\n\
         key:\n  - id: {key}\n    algorithm: {algorithm}\n    secret: {secret}\n\
         {remote}\
         acl:\n  - id: signed\n    key: {key}\n    action: [transfer, update]\n\
         \x20 - id: open\n    address: [0.0.0.0/0, \"::/0\"]\n    action: [transfer, update]\n\
         template:\n  - id: default\n    storage: /zones\n    semantic-checks: off\n    zonefile-sync: -1\n\
         \x20   journal-content: changes\n    zonefile-load: {load}\n\
         zone:\n{zones}",
        key = TSIG_KEY.name,
        algorithm = TSIG_KEY.algorithm,
        secret = TSIG_KEY.secret,
    )
}

/// The configuration of the NOTIFY receiver, secondary of `apex`.
fn sink_config(apex: &str) -> String {
    format!(
        "server:\n  ip-address: 0.0.0.0@53\n  username: root\n  zonesdir: /zones\n  database: \"\"\n  \
         pidfile: /tmp/nsd.pid\n  xfrdfile: /tmp/xfrd.state\n  zonelistfile: /tmp/zone.list\n  \
         logfile: /dev/stderr\n  verbosity: 2\n\
         zone:\n  name: {apex}\n  zonefile: sink.zone\n  allow-notify: 0.0.0.0/0 NOKEY\n  \
         request-xfr: AXFR 127.0.0.1@9 NOKEY\n"
    )
}

impl Lab {
    /// Starts a Knot on `zones`, and a receiver of its NOTIFYs when `notify`.
    fn start(zones: &[Served], notify: bool, diff: bool) -> Result<Self> {
        let host = engine::host_address()?;
        let scratch = Scratch::new("lab")?;
        for zone in zones {
            scratch.put(&zone.file(), &zone.text)?;
        }
        let sink = if notify {
            let sink_scratch = Scratch::new("sink")?;
            sink_scratch.put("nsd.conf", &sink_config(OPEN))?;
            let held = zones
                .iter()
                .find(|zone| zone.apex == OPEN)
                .ok_or("no zone for the receiver")?;
            sink_scratch.put("sink.zone", &held.text)?;
            let mounts = [Mount {
                host: sink_scratch.path(),
                container: "/zones",
                writable: true,
            }];
            let container = Container::start(
                engine::NSD_IMAGE,
                "nsd",
                &["-d", "-c", "/zones/nsd.conf"],
                &mounts,
            )?;
            thread::sleep(Duration::from_secs(2));
            let proxy = Proxy::start(proxy::local(container.port))?;
            Some(Sink {
                _scratch: sink_scratch,
                _container: container,
                proxy,
            })
        } else {
            None
        };
        let sink_address = sink
            .as_ref()
            .map(|sink| SocketAddr::from((host, sink.proxy.port)));
        scratch.put("knot.conf", &knot_config(zones, sink_address, diff))?;
        let mounts = [Mount {
            host: scratch.path(),
            container: "/zones",
            writable: true,
        }];
        let knot = Container::start(
            engine::KNOT_IMAGE,
            "knotd",
            &["-c", "/zones/knot.conf"],
            &mounts,
        )?;
        let proxy = Proxy::start(proxy::local(knot.port))?;
        let lab = Self {
            scratch,
            knot,
            proxy,
            host,
            sink,
        };
        for zone in zones {
            lab.await_serial(&zone.apex.parse()?, None)?;
        }
        Ok(lab)
    }

    /// Waits until Knot answers an SOA for `apex`, with `serial` when given.
    fn await_serial(&self, apex: &Name<'static>, serial: Option<u32>) -> Result<u32> {
        let query = Reference {
            name: apex.clone(),
            rtype: RecordType::SOA,
            dnssec_ok: false,
            edns_size: Some(1232),
            transport: Transport::Udp,
            responses: BTreeMap::new(),
        }
        .query()
        .to_vec()?;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            let found = servers::exchange(self.knot.port, &query, Transport::Udp)
                .and_then(|response| soa_serial(&response, apex));
            if let Some(found) = found.filter(|found| serial.is_none_or(|wanted| *found == wanted))
            {
                return Ok(found);
            }
            thread::sleep(Duration::from_millis(500));
        }
        Err(format!("Knot does not serve {apex}: {}", self.knot.logs()?).into())
    }

    /// The address the tools use: the proxy, through the host.
    fn target(&self) -> (String, String) {
        (format!("@{}", self.host), self.proxy.port.to_string())
    }

    /// Runs `step`; the tool's output is shown, for the person running the capture.
    fn run(&self, step: &Step) -> Result<()> {
        let (server, port) = self.target();
        let output = match step {
            Step::Kdig { args, key, back } => {
                let mut kdig: Vec<String> = vec!["-p".into(), port, server];
                if let Some(key) = key {
                    kdig.push("-y".into());
                    kdig.push(format!(
                        "{}:{}:{}",
                        TSIG_KEY.algorithm, key.name, key.secret
                    ));
                }
                kdig.extend(args.iter().cloned());
                let (entrypoint, args): (&str, Vec<String>) = if *back {
                    let mut all = vec!["-f".into(), CLOCK_OFFSET.into(), "kdig".into()];
                    all.extend(kdig);
                    ("faketime", all)
                } else {
                    ("kdig", kdig)
                };
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                engine::tool(engine::KNOT_IMAGE, entrypoint, &args, &[], None)?
            }
            Step::Update { script, key } => {
                let mut args: Vec<String> = vec!["-p".into(), port];
                if let Some(key) = key {
                    args.push("-y".into());
                    args.push(format!(
                        "{}:{}:{}",
                        TSIG_KEY.algorithm, key.name, key.secret
                    ));
                }
                let script = format!("server {} {}\n{script}", self.host, self.proxy.port);
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                engine::tool(engine::KNOT_IMAGE, "knsupdate", &args, &[], Some(&script))?
            }
            Step::Knotc(words) => {
                let mut args = vec!["knotc", "-c", "/zones/knot.conf"];
                args.extend(words.iter().copied());
                self.knot.exec(&args)?
            }
            Step::Wait => {
                thread::sleep(NOTIFY_WAIT);
                return Ok(());
            }
        };
        let text = engine::text(&output);
        eprintln!(
            "    {}",
            text.lines().take(3).collect::<Vec<_>>().join(" | ")
        );
        Ok(())
    }
}

/// The serial of the SOA `response` answers with, for `apex`.
fn soa_serial(response: &[u8], apex: &Name<'_>) -> Option<u32> {
    let decoded = Message::decode(response).ok()?;
    decoded
        .message
        .answer
        .iter()
        .find_map(|record: &Record<'_>| match record.data() {
            RData::Soa(soa) if record.name == *apex => Some(soa.serial),
            _ => None,
        })
}

/// The rcode of the first response of `messages`, for the person running the capture.
fn summary(messages: &[Packet]) -> String {
    let codes: Vec<String> = messages
        .iter()
        .filter(|packet| packet.from == Peer::Server)
        .take(3)
        .map(|packet| {
            Message::decode(&packet.message).map_or_else(
                |_| "undecodable".to_owned(),
                |decoded| decoded.message.rcode().to_string(),
            )
        })
        .collect();
    format!(
        "{} messages, first responses {}",
        messages.len(),
        codes.join(", ")
    )
}

/// The zone `apex`'s SOA serial in `records`.
fn serial_of(records: &[Record<'static>]) -> Result<u32> {
    records
        .iter()
        .find_map(|record| match record.data() {
            RData::Soa(soa) => Some(soa.serial),
            _ => None,
        })
        .ok_or_else(|| "a zone without an SOA".into())
}

/// The `exchanges` stage.
pub(crate) fn exchanges(dir: &Path) -> Result<()> {
    let testdata = dir.parent().ok_or("no testdata directory")?;
    let knot_version = servers::versions()?
        .remove(&Server::Knot)
        .ok_or("no Knot version")?;
    let nsd_version = servers::versions()?
        .remove(&Server::Nsd)
        .ok_or("no NSD version")?;
    let load = |id: &str| -> Result<(Vec<Record<'static>>, &'static zones::Zone)> {
        let zone = ZONES
            .iter()
            .find(|zone| zone.id == id)
            .ok_or_else(|| format!("no zone {id}"))?;
        Ok((zone.load(testdata)?, zone))
    };
    let (open_records, open_zone) = load("rfc4035_appendix_a")?;
    let (signed_records, signed_zone) = load("zonetransfer.me")?;
    let serve = |records: &[Record<'static>], zone: &zones::Zone, acl| -> Result<Served> {
        Ok(Served {
            apex: zone.origin.to_owned(),
            text: zones::render(records, &format!("{}, as Knot reads it.", zone.file)),
            acl,
        })
    };
    let all = [
        serve(&open_records, open_zone, "open")?,
        serve(&signed_records, signed_zone, "signed")?,
    ];
    let scenarios = scenarios(serial_of(&signed_records)?, serial_of(&open_records)?);
    for scenario in scenarios {
        eprintln!("{}", scenario.id);
        let captured_at = now()?;
        let lab = Lab::start(&all, scenario.seen == Seen::Notifies, false)?;
        // The startup NOTIFYs belong to `notify-load` only.
        if let (Some(sink), true) = (&lab.sink, scenario.id != "notify-load") {
            thread::sleep(NOTIFY_WAIT);
            let _ = sink.proxy.take();
        }
        let _ = lab.proxy.take();
        for step in &scenario.steps {
            lab.run(step)?;
        }
        let (messages, server) = match (&lab.sink, scenario.seen) {
            (Some(sink), Seen::Notifies) => (sink.proxy.take(), nsd_version.clone()),
            _ => (lab.proxy.take(), knot_version.clone()),
        };
        if messages.len() < 2 {
            return Err(format!("{}: {} messages", scenario.id, messages.len()).into());
        }
        eprintln!("  {}", summary(&messages));
        let recording = Recording {
            description: scenario.description,
            server,
            captured_at,
            zone: scenario.zone.parse()?,
            serial: None,
            key: scenario.key.map(|key| key.name.to_owned()),
            messages,
        };
        write(
            &dir.join("recordings").join(format!("{}.yaml", scenario.id)),
            recording.to_yaml()?.as_bytes(),
        )?;
    }
    Ok(())
}

/// How many records of the root zone the `signed-stream` stage serves: its transfer takes five messages or more.
const STREAM_RECORDS: usize = 1200;

/// The `signed-stream` stage: Knot serves the first [`STREAM_RECORDS`] records of the root zone to the key's holder,
/// and `kdig` signs the AXFR: the response is several messages, each signed over the one before (RFC 8945 §5.3.1).
pub(crate) fn signed_stream(dir: &Path) -> Result<()> {
    let testdata = dir.parent().ok_or("no testdata directory")?;
    let root = ZONES
        .iter()
        .find(|zone| zone.id == "root")
        .ok_or("no root zone")?
        .load(testdata)?;
    let records = root
        .get(..STREAM_RECORDS)
        .ok_or("the root zone is shorter")?;
    let serial = serial_of(records)?;
    let captured_at = now()?;
    let served = [Served {
        apex: ".".to_owned(),
        text: zones::render(
            records,
            &format!("the first {STREAM_RECORDS} records of the root zone."),
        ),
        acl: "signed",
    }];
    let lab = Lab::start(&served, false, false)?;
    let _ = lab.proxy.take();
    lab.run(&signed(".", "AXFR", GOOD))?;
    let messages = lab.proxy.take();
    eprintln!("{}", summary(&messages));
    let recording = Recording {
        description: format!(
            "AXFR of the first {STREAM_RECORDS} records of the root zone signed with hmac-sha256: a stream of TSIG-signed messages (RFC 8945 §5.3.1)"
        ),
        server: servers::versions()?
            .remove(&Server::Knot)
            .ok_or("no Knot version")?,
        captured_at,
        zone: Name::root(),
        serial: Some(serial),
        key: Some(GOOD.name.to_owned()),
        messages,
    };
    write(
        &dir.join("recordings/axfr-tsig-stream.yaml"),
        recording.to_yaml()?.as_bytes(),
    )
}

/// The `root-ixfr` stage: Knot loads the previous root zone, then the current one as a difference, and IXFRs the
/// difference (RFC 1995 §4).
pub(crate) fn root_ixfr(dir: &Path) -> Result<()> {
    let testdata = dir.parent().ok_or("no testdata directory")?;
    let current = ZONES
        .iter()
        .find(|zone| zone.id == "root")
        .ok_or("no root zone")?
        .load(testdata)?;
    let previous = PREVIOUS_ROOT.load(testdata)?;
    let (old_serial, new_serial) = (serial_of(&previous)?, serial_of(&current)?);
    if new_serial <= old_serial {
        return Err(
            format!("the root zone's serial {new_serial} does not follow {old_serial}").into(),
        );
    }
    eprintln!("root: {old_serial} to {new_serial}");
    let captured_at = now()?;
    let served = [Served {
        apex: ".".to_owned(),
        text: zones::render(&previous, "the previous root zone."),
        acl: "open",
    }];
    let lab = Lab::start(&served, false, true)?;
    let _ = lab.proxy.take();
    lab.scratch.put(
        "root.zone",
        &zones::render(&current, "the current root zone."),
    )?;
    let output = lab
        .knot
        .exec(&["knotc", "-c", "/zones/knot.conf", "zone-reload", "."])?;
    eprintln!("{}", engine::text(&output));
    lab.await_serial(&Name::root(), Some(new_serial))?;
    lab.run(&Step::Kdig {
        args: vec![
            ".".to_owned(),
            format!("IXFR={old_serial}"),
            "+tcp".to_owned(),
        ],
        key: None,
        back: false,
    })?;
    let messages = lab.proxy.take();
    eprintln!("{}", summary(&messages));
    let recording = Recording {
        description: format!(
            "IXFR of the root zone over TCP from serial {old_serial} to {new_serial}: Knot loaded the first zone, then the second as a difference (zonefile-load: difference)"
        ),
        server: servers::versions()?
            .remove(&Server::Knot)
            .ok_or("no Knot version")?,
        captured_at,
        zone: Name::root(),
        serial: Some(new_serial),
        key: None,
        messages,
    };
    write(
        &dir.join("recordings/root-ixfr.yaml"),
        recording.to_yaml()?.as_bytes(),
    )
}
