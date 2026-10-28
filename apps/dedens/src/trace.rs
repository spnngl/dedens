//! `+trace`: a question followed from the root servers down the referrals (RFC 1034 §4.3.2, §5.3.3), as dig's
//! `+trace`, without recursion or DNSSEC validation (D40).

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use anyhow::{anyhow, bail};
use dedens_net::client::Client;
use dedens_net::exchange::Response;
use dedens_proto::text::{Entry, ZoneReader};
use dedens_proto::{Flags, Message, Name, Question, RData, Rcode, Record, RecordType};
use dedens_scenario::{Id, Options, Report};

/// IANA's root hints, <https://www.internic.net/domain/named.root>; `just root-hints` refreshes them.
const ROOT_HINTS: &str = include_str!("named.root");

/// Referrals followed at most: the deepest names have 127 labels, real chains a handful.
const MAX_HOPS: usize = 32;

/// Name servers without glue whose address is looked up, one inside the other, at most.
const MAX_DEPTH: u8 = 4;

/// Addresses of a server set tried, in order, before the hop fails.
const TRIED: usize = 3;

/// A response and its wire form.
type Hop = (Report, Vec<u8>);

/// The responses of each hop, and the error that ended the trace early, if any.
pub(crate) type Trail = (Vec<Hop>, Option<anyhow::Error>);

/// Where [`walk`] puts the responses: the id of the trace, and the hops so far.
type Hops<'a> = Option<(&'a Id, &'a mut Vec<Hop>)>;

/// Follows `question` from the root servers, or from `roots` when given (tests), until an answer, an error rcode
/// or an authoritative response.
pub(crate) async fn trace(
    client: &Client,
    options: Options,
    question: Question<'static>,
    id: &Id,
    roots: Option<Vec<SocketAddr>>,
) -> Trail {
    let options = Options {
        recurse: Some(false),
        ..options
    };
    let roots = roots.unwrap_or_else(root_hints);
    let mut hops = Vec::new();
    let end = walk(client, &options, question, &roots, 0, Some((id, &mut hops))).await;
    (hops, end.err())
}

/// The addresses of the root servers, IPv4 first: an IPv6 route is the likelier to be missing.
fn root_hints() -> Vec<SocketAddr> {
    let mut addresses: Vec<IpAddr> = ZoneReader::new(ROOT_HINTS.as_bytes(), Some(Name::root()))
        .filter_map(|entry| match entry {
            Ok(Entry::Record(decoded)) => address(&decoded.record),
            _ => None,
        })
        .collect();
    addresses.sort_by_key(IpAddr::is_ipv6);
    addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// The address an A or AAAA record holds.
fn address(record: &Record<'_>) -> Option<IpAddr> {
    match record.data() {
        RData::A(ip) => Some(ip.into()),
        RData::Aaaa(ip) => Some(ip.into()),
        _ => None,
    }
}

/// Where a response leads.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// The end: an answer, an error rcode, or an authoritative response.
    Done,
    /// Down to the servers of `zone`: the addresses given as glue, else their names to look up.
    Referral {
        zone: Name<'static>,
        glue: Vec<SocketAddr>,
        names: Vec<Name<'static>>,
    },
}

/// Where `message`, from a server of `zone`, leads `question`; an error for a referral that comes no closer.
fn step(message: &Message<'_>, question: &Question<'_>, zone: &Name<'_>) -> anyhow::Result<Step> {
    if message.rcode() != Rcode::NOERROR
        || !message.answer.is_empty()
        || message.header.flags.contains(Flags::AA)
    {
        return Ok(Step::Done);
    }
    let cut = message
        .authority
        .iter()
        .filter(|r| r.rdata.rtype() == RecordType::NS)
        .map(|r| &r.name)
        .find(|cut| {
            question.name.is_within(cut)
                && cut.is_within(zone)
                && cut.label_count() > zone.label_count()
        })
        .ok_or_else(|| anyhow!("no referral below {zone}"))?;
    let names: Vec<Name<'static>> = message
        .authority
        .iter()
        .filter(|r| r.name == *cut)
        .filter_map(|r| match r.data() {
            RData::Ns(name) => Some(name.into_owned()),
            _ => None,
        })
        .collect();
    let mut glue: Vec<IpAddr> = message
        .additional
        .iter()
        .filter(|r| names.contains(&r.name))
        .filter_map(address)
        .collect();
    glue.sort_by_key(IpAddr::is_ipv6);
    Ok(Step::Referral {
        zone: cut.clone().into_owned(),
        glue: glue.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect(),
        names,
    })
}

/// Follows `question` from `servers`, the servers of the root, and returns the last response. Each response goes
/// to `hops` when given, under `id` and its server; the name servers looked up on the way, `depth` deep, do not.
fn walk<'a>(
    client: &'a Client,
    options: &'a Options,
    question: Question<'static>,
    servers: &'a [SocketAddr],
    depth: u8,
    mut hops: Hops<'a>,
) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + 'a>> {
    Box::pin(async move {
        let (mut servers, mut zone) = (servers.to_vec(), Name::root());
        let roots = servers.clone();
        for _ in 0..MAX_HOPS {
            let (server, response) = ask(client, options, &question, &servers).await?;
            let decoded = Message::decode(&response.wire)?;
            if let Some((id, hops)) = &mut hops {
                let report = Report::exchanged(id.at(server), server, &response, &decoded);
                hops.push((report, response.wire.clone()));
            }
            let (cut, glue, names) = match step(&decoded.message, &question, &zone)? {
                Step::Done => return Ok(response.wire),
                Step::Referral { zone, glue, names } => (zone, glue, names),
            };
            servers = match glue {
                glue if glue.is_empty() => look_up(client, options, &names, &roots, depth).await?,
                glue => glue,
            };
            zone = cut;
        }
        bail!("more than {MAX_HOPS} referrals")
    })
}

/// The IPv4 addresses of the first of `names` that has any, each looked up from `roots`.
async fn look_up(
    client: &Client,
    options: &Options,
    names: &[Name<'static>],
    roots: &[SocketAddr],
    depth: u8,
) -> anyhow::Result<Vec<SocketAddr>> {
    if depth >= MAX_DEPTH {
        bail!("name servers without glue more than {MAX_DEPTH} deep");
    }
    for name in names {
        let question = Question::new(name.clone(), RecordType::A);
        let Ok(wire) = walk(client, options, question, roots, depth + 1, None).await else {
            continue;
        };
        let addresses: Vec<SocketAddr> = Message::decode(&wire)?
            .message
            .answer
            .iter()
            .filter_map(address)
            .map(|ip| SocketAddr::new(ip, 53))
            .collect();
        if !addresses.is_empty() {
            return Ok(addresses);
        }
    }
    bail!("no address for the name servers {}", list(names))
}

/// Asks `question` of the first of `servers` to answer, trying [`TRIED`] at most.
async fn ask(
    client: &Client,
    options: &Options,
    question: &Question<'static>,
    servers: &[SocketAddr],
) -> anyhow::Result<(SocketAddr, Response)> {
    let (query, exchange) = (options.query(question.clone()), options.exchange());
    let mut last = anyhow!("no server to ask");
    for &server in servers.iter().take(TRIED) {
        match client.exchange(&query, server, &exchange).await {
            Ok(response) => return Ok((server, response)),
            Err(error) => last = anyhow::Error::from(error).context(format!("{server}")),
        }
    }
    Err(last)
}

/// `names` joined by commas.
fn list(names: &[Name<'_>]) -> String {
    names
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/../../crates/dedens-proto/tests/testdata/{name}.bin",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(path).expect("captured response")
    }

    fn name(text: &str) -> Name<'static> {
        text.parse().expect("a name")
    }

    #[test]
    fn the_root_hints_hold_13_servers_ipv4_first() {
        let roots = root_hints();
        assert_eq!(roots.len(), 26);
        assert!(roots[..13].iter().all(SocketAddr::is_ipv4));
        assert!(roots.contains(&"198.41.0.4:53".parse().expect("a.root-servers.net")));
    }

    #[test]
    fn referrals_lead_down_to_the_glue() {
        let question = Question::new(name("example.com."), RecordType::A);
        let root = captured("referral_root");
        let Step::Referral { zone, glue, names } = step(
            &Message::decode(&root).expect("decodes").message,
            &question,
            &Name::root(),
        )
        .expect("a referral") else {
            panic!("a referral from the root");
        };
        assert_eq!((zone, names.len(), glue.len()), (name("com."), 13, 26));
        assert!(glue[..13].iter().all(SocketAddr::is_ipv4));
        let com = captured("referral_com");
        let Ok(Step::Referral { zone, names, .. }) = step(
            &Message::decode(&com).expect("decodes").message,
            &question,
            &name("com."),
        ) else {
            panic!("a referral from com.");
        };
        assert_eq!(zone, name("example.com."));
        assert!(names.contains(&name("hera.ns.cloudflare.com.")));
    }

    #[test]
    fn a_referral_must_come_closer() {
        let question = Question::new(name("example.com."), RecordType::A);
        let com = captured("referral_root");
        let message = Message::decode(&com).expect("decodes").message;
        // From the servers of com., a referral to com. goes nowhere.
        assert!(step(&message, &question, &name("com.")).is_err());
        // A question outside com. is not led there.
        let other = Question::new(name("example.org."), RecordType::A);
        assert!(step(&message, &other, &Name::root()).is_err());
    }

    #[test]
    fn answers_errors_and_authority_end_the_trace() {
        let question = Question::new(name("example.com."), RecordType::A);
        for capture in ["a", "nxdomain_soa", "any_rfc8482"] {
            let wire = captured(capture);
            let message = Message::decode(&wire).expect("decodes").message;
            assert_eq!(
                step(&message, &question, &Name::root()).ok(),
                Some(Step::Done),
                "{capture}"
            );
        }
    }
}
