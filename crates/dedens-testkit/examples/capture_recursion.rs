//! Captures the resolutions of `testdata/recursion/` (D188), run by `just capture-recursion`: resolves each name
//! from a root server as an iterator does (RFC 1034 §5.3.3), and writes every exchange to `<dir>/<id>.yaml`.
//!
//! Usage: `capture_recursion <dir> [id]...`, every case of [`CASES`] when no id is given.
//!
//! Each resolution starts with priming (RFC 8109 §3) and asks the DS of each zone it enters at the parent and its
//! DNSKEY at the zone, the root's included. Each question goes to one server of each family, the first in address
//! order that answers, so a recapture asks the same servers while they stay; the iterator goes on with the IPv4
//! response. Queries set DO alone, with no cookie and no 0x20, and advertise 1232 bytes (RFC 9715 §3.2); a
//! truncated response is asked again over TCP, both recorded (RFC 9471 §2.1). A referral's glue is taken for the
//! names within the parent zone (RFC 9471 §2.1, §2.2), the other server names resolved from the root. A CNAME
//! chain, a DNAME's included, is followed from the closest zone known.

use std::collections::BTreeSet;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_net::client::Client;
use dedens_net::exchange::Options;
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Name, Rcode, Record, RecordType};
use dedens_roots::RootHints;
use dedens_testkit::recursion::{self, Exchange, QueryFlag, Resolution, Transport};

/// Each case: its id, the name of its file, and the name and type resolved.
const CASES: &[(&str, &str, &str)] = &[
    ("priming", ".", "NS"),
    // A signed name under com, whose denials are NSEC3.
    ("signed-com", "example.com", "A"),
    // A signed name under nl.
    ("signed-nl", "sidn.nl", "A"),
    // An unsigned name: com's NSEC3 denies its DS.
    ("unsigned", "google.com", "A"),
    // A CNAME chain across three zones.
    ("cname", "www.microsoft.com", "A"),
    // A DNAME (RFC 6672) in a signed zone, its target in a child zone.
    ("dname", "www.dname.dns.netmeister.org", "A"),
    // A glueless delegation: the servers of netmeister.org are under gandi.net.
    ("glueless", "netmeister.org", "A"),
    ("nxdomain-signed", "dedens-nxdomain.sidn.nl", "A"),
    // NXDOMAIN from a TLD, denied by NSEC3.
    ("nxdomain-nsec3", "dedens-nxdomain.nl", "A"),
    ("nxdomain-unsigned", "dedens-nxdomain.google.com", "A"),
    ("nodata-signed", "sidn.nl", "SRV"),
    ("nodata-unsigned", "google.com", "SRV"),
    // An answer over 1232 bytes: truncated over UDP, asked again over TCP.
    ("truncated", "microsoft.com", "TXT"),
    // An RRSIG question: the answer is signatures, no RRset of their own (D176).
    ("rrsig", "sidn.nl", "RRSIG"),
];

/// The servers of a family a question goes to before the iterator gives the family up.
const TRIED: usize = 3;
/// The referrals one resolution follows.
const MAX_REFERRALS: usize = 16;
/// The resolutions nested in one: server names of glueless delegations and CNAME targets.
const MAX_DEPTH: usize = 6;
/// The flags of every query.
const FLAGS: &[QueryFlag] = &[QueryFlag::Do];

/// A zone the iterator knows: its name and its servers' addresses, sorted.
struct Zone {
    name: Name<'static>,
    servers: Vec<IpAddr>,
}

/// One resolution in progress.
struct Iterator {
    client: Client,
    options: Options,
    zones: Vec<Zone>,
    exchanges: Vec<Exchange>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .ok_or("usage: capture_recursion <dir> [id]...")?;
    let ids: Vec<String> = args.collect();
    let cases: Vec<_> = CASES
        .iter()
        .filter(|(id, ..)| ids.is_empty() || ids.iter().any(|wanted| wanted == id))
        .collect();
    if let Some(unknown) = ids
        .iter()
        .find(|id| !CASES.iter().any(|(case, ..)| case == id))
    {
        return Err(format!("no case {unknown}").into());
    }
    compio::runtime::Runtime::new()?.block_on(async {
        for (id, name, rtype) in cases {
            let resolution = capture(name.parse()?, rtype.parse()?).await?;
            let path = format!("{dir}/{id}.yaml");
            std::fs::write(&path, resolution.to_yaml()?)?;
            eprintln!("{path}: {} exchanges", resolution.exchanges.len());
        }
        Ok(())
    })
}

/// The resolution of `name` and `rtype` from the root.
async fn capture(name: Name<'static>, rtype: RecordType) -> Result<Resolution, Box<dyn Error>> {
    let mut hints: Vec<IpAddr> = RootHints::bundled()
        .servers()
        .iter()
        .flat_map(dedens_roots::Server::addresses)
        .collect();
    hints.sort_unstable();
    let mut options = Options::default();
    options.tcp_fallback = false;
    options.cookies = false;
    let mut iterator = Iterator {
        client: Client::new(),
        options,
        zones: vec![Zone {
            name: Name::root(),
            servers: hints,
        }],
        exchanges: Vec::new(),
    };
    iterator.prime().await?;
    iterator
        .resolve(&name, rtype, 0)
        .await
        .ok_or_else(|| format!("{name} {rtype}: the resolution failed"))?;
    // Signatures made on demand start at the time of the query: the end of the run is within them all.
    let captured_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(Resolution {
        captured_at,
        name,
        rtype,
        exchanges: iterator.exchanges,
    })
}

impl Iterator {
    /// Primes the root's servers from the hints (RFC 8109 §3, §4), then asks the root's DNSKEY.
    async fn prime(&mut self) -> Result<(), Box<dyn Error>> {
        let root = Name::root();
        let response = self
            .ask(0, &root, RecordType::NS)
            .await
            .ok_or("no root server answered the priming query")?;
        let names = servers(&response, &root);
        let primed = glue(&response, &names, &root);
        if !primed.is_empty() {
            self.zones[0].servers = primed;
        }
        self.ask(0, &root, RecordType::DNSKEY).await;
        Ok(())
    }

    /// The answer records for `name` and `rtype`, none for NXDOMAIN or NODATA; `None` when no server answers,
    /// with an error, or the resolution goes past [`MAX_REFERRALS`] or [`MAX_DEPTH`].
    async fn resolve(
        &mut self,
        name: &Name<'static>,
        rtype: RecordType,
        depth: usize,
    ) -> Option<Vec<Record<'static>>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let mut zone = self.closest(name);
        for _ in 0..MAX_REFERRALS {
            let response = self.ask(zone, name, rtype).await?;
            if ![Rcode::NOERROR, Rcode::NXDOMAIN].contains(&response.rcode()) {
                return None;
            }
            let parent = self.zones[zone].name.clone();
            let cut = response
                .referral()
                .filter(|cut| name.is_within(cut) && cut.label_count() > parent.label_count())
                .map(|cut| cut.clone().into_owned());
            let Some(cut) = cut else {
                return Box::pin(self.follow(name, rtype, response.answer, depth)).await;
            };
            let names = servers(&response, &cut);
            let mut addresses = glue(&response, &names, &parent);
            for server in &names {
                if !addresses.is_empty() {
                    break;
                }
                addresses = Box::pin(self.addresses(server, depth + 1)).await;
            }
            if addresses.is_empty() {
                return None;
            }
            self.ask(zone, &cut, RecordType::DS).await;
            self.zones.push(Zone {
                name: cut.clone(),
                servers: addresses,
            });
            zone = self.zones.len() - 1;
            self.ask(zone, &cut, RecordType::DNSKEY).await;
        }
        None
    }

    /// The `answer` to `name` and `rtype`, with the records of its CNAME chain's target when the answer stops at
    /// a name holding none.
    async fn follow(
        &mut self,
        name: &Name<'static>,
        rtype: RecordType,
        mut answer: Vec<Record<'static>>,
        depth: usize,
    ) -> Option<Vec<Record<'static>>> {
        let mut target = name.clone();
        // Each step takes a record of the answer: as many steps end a loop.
        for _ in 0..answer.len() {
            let Some(next) = answer.iter().find_map(|r| match r.data() {
                RData::Cname(next) if r.name == target => Some(next.into_owned()),
                _ => None,
            }) else {
                break;
            };
            target = next;
        }
        let held = answer
            .iter()
            .any(|r| r.name == target && r.rdata.rtype() == rtype);
        if target != *name && rtype != RecordType::CNAME && !held {
            answer.extend(self.resolve(&target, rtype, depth + 1).await?);
        }
        Some(answer)
    }

    /// The IPv4 and IPv6 addresses of the server `name`.
    async fn addresses(&mut self, name: &Name<'static>, depth: usize) -> Vec<IpAddr> {
        let mut addresses = Vec::new();
        for rtype in [RecordType::A, RecordType::AAAA] {
            for record in self.resolve(name, rtype, depth).await.unwrap_or_default() {
                match record.data() {
                    RData::A(ip) => addresses.push(IpAddr::from(ip)),
                    RData::Aaaa(ip) => addresses.push(IpAddr::from(ip)),
                    _ => {}
                }
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

    /// The index of the closest known zone enclosing `name`.
    fn closest(&self, name: &Name<'_>) -> usize {
        self.zones
            .iter()
            .enumerate()
            .filter(|(_, zone)| name.is_within(&zone.name))
            .max_by_key(|(_, zone)| zone.name.label_count())
            .map_or(0, |(index, _)| index)
    }

    /// The response of the zone `zone` to `name` and `rtype`: asked of one server of each family, the IPv4 one
    /// returned when both answer.
    async fn ask(
        &mut self,
        zone: usize,
        name: &Name<'static>,
        rtype: RecordType,
    ) -> Option<Message<'static>> {
        let mut response = None;
        let servers = self.zones[zone].servers.clone();
        for v4 in [true, false] {
            let family = servers.iter().filter(|ip| ip.is_ipv4() == v4).take(TRIED);
            for &server in family {
                if let Some(answered) = self.exchange(zone, server, name, rtype).await {
                    response.get_or_insert(answered);
                    break;
                }
            }
        }
        response
    }

    /// The response of `server` to `name` and `rtype`, recorded: over UDP, again over TCP when truncated. An
    /// exchange already recorded is not asked again. Nothing is recorded unless the last try answers: a truncated
    /// response kept without its TCP retry would be replayed as the server's answer.
    async fn exchange(
        &mut self,
        zone: usize,
        server: IpAddr,
        name: &Name<'static>,
        rtype: RecordType,
    ) -> Option<Message<'static>> {
        if let Some(done) = self
            .exchanges
            .iter()
            .rev()
            .find(|e| e.server == server && e.name == *name && e.rtype == rtype)
        {
            return Some(dedens_testkit::message(&done.response));
        }
        let mut tried = Vec::new();
        let mut response = None;
        for transport in [Transport::Udp, Transport::Tcp] {
            let mut options = self.options;
            options.transport = match transport {
                Transport::Udp => dedens_proto::Transport::Udp,
                Transport::Tcp => dedens_proto::Transport::Tcp,
            };
            let query = recursion::query(0, name, rtype, FLAGS);
            let wire = match self
                .client
                .exchange(query, SocketAddr::new(server, 53), &options)
                .await
            {
                Ok(exchanged) => exchanged.wire,
                Err(error) => {
                    eprintln!("{server} {name} {rtype} over {transport:?}: {error}");
                    return None;
                }
            };
            let decoded = dedens_testkit::message(&wire);
            let truncated = decoded.header.flags.contains(Flags::TC);
            tried.push(Exchange {
                server,
                zone: self.zones[zone].name.clone(),
                name: name.clone(),
                rtype,
                flags: FLAGS.to_vec(),
                transport,
                response: wire,
            });
            response = Some(decoded);
            if !truncated {
                break;
            }
        }
        self.exchanges.append(&mut tried);
        response
    }
}

/// The names of the servers `response` gives for `zone`, sorted.
fn servers(response: &Message<'_>, zone: &Name<'_>) -> Vec<Name<'static>> {
    let names: BTreeSet<String> = response
        .answer
        .iter()
        .chain(&response.authority)
        .filter(|r| r.name == *zone)
        .filter_map(|r| match r.data() {
            RData::Ns(name) => Some(name.to_string().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    names.iter().filter_map(|name| name.parse().ok()).collect()
}

/// The addresses `response` gives for the server `names` within `parent` (RFC 9471 §2.1, §2.2), sorted.
fn glue(response: &Message<'_>, names: &[Name<'static>], parent: &Name<'_>) -> Vec<IpAddr> {
    let mut addresses: Vec<IpAddr> = response
        .additional
        .iter()
        .filter(|r| r.name.is_within(parent) && names.contains(&r.name))
        .filter_map(|r| match r.data() {
            RData::A(ip) => Some(ip.into()),
            RData::Aaaa(ip) => Some(ip.into()),
            _ => None,
        })
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}
