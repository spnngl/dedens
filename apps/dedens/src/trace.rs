//! `+trace`: a question followed from the root servers down the referrals (RFC 1034 §4.3.2, §5.3.3), as dig's
//! `+trace`, without recursion or DNSSEC validation (D40).

use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, bail};
use dedens_net::client::Client;
use dedens_proto::text::{Entry, ZoneReader};
use dedens_proto::{Flags, Message, Name, Question, RData, Rcode, Record, RecordType};
use dedens_scenario::{Id, Options, Report};
use tracing::Instrument;

/// IANA's root hints, <https://www.internic.net/domain/named.root>; `just root-hints` refreshes them.
const ROOT_HINTS: &str = include_str!("named.root");

/// Name servers without glue whose address is looked up, one inside the other, at most.
const MAX_DEPTH: u8 = 4;

/// Addresses of a server set tried, in order, before the hop fails.
const TRIED: usize = 3;

/// Exchanges a trace makes at most, the name server lookups included.
const MAX_EXCHANGES: u16 = 100;

/// A response and its wire form.
type Hop = (Report, Vec<u8>);

/// The responses of each hop, and the error that ended the trace early, if any.
pub(crate) type Trail = (Vec<Hop>, Option<anyhow::Error>);

/// Follows `question` from `roots` until an answer, NXDOMAIN, NODATA or an authoritative response.
pub(crate) async fn trace(
    client: &Client,
    options: Options,
    question: Question<'static>,
    id: &Id,
    roots: &[SocketAddr],
) -> Trail {
    let tracer = Tracer {
        client,
        options: Options {
            recurse: Some(false),
            ..options
        },
        roots,
        left: Cell::new(MAX_EXCHANGES),
    };
    let mut hops = Vec::new();
    let end = tracer.walk(&question, 0, Some((id, &mut hops))).await;
    (hops, end.err())
}

/// The addresses of the root servers, from the root hints, IPv4 and IPv6 in turn.
pub(crate) fn root_hints() -> Vec<SocketAddr> {
    let records =
        ZoneReader::new(ROOT_HINTS.as_bytes(), Some(Name::root())).filter_map(
            |entry| match entry {
                Ok(Entry::Record(decoded)) => Some(decoded.record),
                _ => None,
            },
        );
    in_turn(records.filter_map(|record| address(&record)))
}

/// `ips` on port 53, IPv4 and IPv6 in turn, so that the first few tried hold both: either route may be missing.
fn in_turn(ips: impl IntoIterator<Item = IpAddr>) -> Vec<SocketAddr> {
    let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = ips.into_iter().partition(IpAddr::is_ipv4);
    let (mut v4, mut v6) = (v4.into_iter(), v6.into_iter());
    let mut all = Vec::new();
    while let (a, b) = (v4.next(), v6.next())
        && (a.is_some() || b.is_some())
    {
        all.extend(a.into_iter().chain(b).map(|ip| SocketAddr::new(ip, 53)));
    }
    all
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
    /// The end: an answer, NXDOMAIN, NODATA, or an authoritative response.
    Done,
    /// Down to the servers of `zone`: the addresses given as glue, else their names to look up.
    Referral {
        zone: Name<'static>,
        glue: Vec<SocketAddr>,
        names: Vec<Name<'static>>,
    },
}

/// Where `message`, from a server of `zone`, leads `question`; an error for a response that is neither an end nor
/// a referral closer to the name, which sends the question to the next server (RFC 1034 §5.3.3 step 4d).
fn step(message: &Message<'_>, question: &Question<'_>, zone: &Name<'_>) -> anyhow::Result<Step> {
    if let Some(cut) = message.referral() {
        if !(question.name.is_within(cut)
            && cut.is_within(zone)
            && cut.label_count() > zone.label_count())
        {
            bail!("a referral to {cut} from {zone}");
        }
        let names: Vec<Name<'static>> = message
            .authority
            .iter()
            .filter(|r| r.name == *cut)
            .filter_map(|r| match r.data() {
                RData::Ns(name) => Some(name.into_owned()),
                _ => None,
            })
            .collect();
        // Glue is an address of a name server, from the zone of the server that gave it (RFC 2181 §5.4.1).
        let glue = message
            .additional
            .iter()
            .filter(|r| names.contains(&r.name) && r.name.is_within(zone))
            .filter_map(address);
        return Ok(Step::Referral {
            zone: cut.clone().into_owned(),
            glue: in_turn(glue),
            names,
        });
    }
    let nodata = message
        .authority
        .iter()
        .any(|r| r.rdata.rtype() == RecordType::SOA);
    match message.rcode() {
        Rcode::NXDOMAIN => Ok(Step::Done),
        Rcode::NOERROR
            if !message.answer.is_empty() || nodata || message.header.flags.contains(Flags::AA) =>
        {
            Ok(Step::Done)
        }
        Rcode::NOERROR => bail!("neither an answer nor a referral"),
        rcode => bail!("{rcode}"),
    }
}

/// One trace: the exchanges left to it are shared by the hops and the name server lookups.
struct Tracer<'a> {
    client: &'a Client,
    options: Options,
    roots: &'a [SocketAddr],
    left: Cell<u16>,
}

impl Tracer<'_> {
    /// Follows `question` from the roots and returns the last response, each one put in `hops` when given, under
    /// the id and its server; the name servers looked up on the way, `depth` deep, are not.
    async fn walk(
        &self,
        question: &Question<'static>,
        depth: u8,
        mut hops: Option<(&Id, &mut Vec<Hop>)>,
    ) -> anyhow::Result<Vec<u8>> {
        let (mut servers, mut zone) = (self.roots.to_vec(), Name::root());
        loop {
            let (wire, step) = self.hop(question, &servers, &zone, hops.as_mut()).await?;
            let Step::Referral {
                zone: cut,
                glue,
                names,
            } = step
            else {
                return Ok(wire);
            };
            tracing::debug!(zone = %cut, servers = names.len(), glue = glue.len(), "referral");
            servers = match glue {
                glue if glue.is_empty() => self.look_up(&names, &cut, depth).await?,
                glue => glue,
            };
            zone = cut;
        }
    }

    /// Asks `question` of `servers`, the servers of `zone`, until one gives a response that leads somewhere,
    /// trying [`TRIED`] at most.
    async fn hop(
        &self,
        question: &Question<'static>,
        servers: &[SocketAddr],
        zone: &Name<'_>,
        mut hops: Option<&mut (&Id, &mut Vec<Hop>)>,
    ) -> anyhow::Result<(Vec<u8>, Step)> {
        let (query, exchange) = (
            self.options.query(question.clone()),
            self.options.exchange(),
        );
        let mut last = anyhow!("no server to ask");
        for &server in servers.iter().take(TRIED) {
            let left = self.left.get();
            if left == 0 {
                bail!("more than {MAX_EXCHANGES} exchanges");
            }
            self.left.set(left - 1);
            let outcome = async {
                let response = self.client.exchange(&query, server, &exchange).await?;
                let decoded = Message::decode(&response.wire)?;
                if let Some((id, hops)) = &mut hops {
                    hops.push((
                        Report::exchanged(id.at(server), server, &response, &decoded),
                        response.wire.clone(),
                    ));
                }
                anyhow::Ok((step(&decoded.message, question, zone)?, response.wire))
            };
            match outcome
                .instrument(tracing::debug_span!("hop", %zone, %server))
                .await
            {
                Ok((step, wire)) => return Ok((wire, step)),
                Err(error) => last = error.context(format!("{server}")),
            }
        }
        Err(last)
    }

    /// The addresses of the first of `names`, the name servers of `zone`, that has any: A, else AAAA, each looked
    /// up from the roots. A name inside `zone` is skipped: without glue, it leads back to the same referral.
    async fn look_up(
        &self,
        names: &[Name<'static>],
        zone: &Name<'_>,
        depth: u8,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        if depth >= MAX_DEPTH {
            bail!("name servers without glue more than {MAX_DEPTH} deep");
        }
        let mut last = anyhow!("all inside {zone}, without glue");
        for name in names.iter().filter(|name| !name.is_within(zone)) {
            for qtype in [RecordType::A, RecordType::AAAA] {
                tracing::debug!(%name, %qtype, "looking up a name server without glue");
                let question = Question::new(name.clone(), qtype);
                let wire = match Box::pin(self.walk(&question, depth + 1, None)).await {
                    Ok(wire) => wire,
                    Err(error) => {
                        last = error.context(format!("{name} {qtype}"));
                        continue;
                    }
                };
                let addresses = in_turn(
                    Message::decode(&wire)?
                        .message
                        .answer
                        .iter()
                        .filter_map(address),
                );
                if !addresses.is_empty() {
                    return Ok(addresses);
                }
            }
        }
        Err(last.context(format!("no address for the name servers of {zone}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(name: &str) -> Message<'static> {
        let path = format!(
            "{}/../../crates/dedens-proto/tests/testdata/{name}.bin",
            env!("CARGO_MANIFEST_DIR")
        );
        let wire = std::fs::read(path).expect("captured response");
        Message::decode(&wire)
            .expect("decodes")
            .message
            .into_owned()
    }

    fn name(text: &str) -> Name<'static> {
        text.parse().expect("a name")
    }

    fn example() -> Question<'static> {
        Question::new(name("example.com."), RecordType::A)
    }

    #[test]
    fn the_root_hints_hold_13_servers_ipv4_and_ipv6_in_turn() {
        let roots = root_hints();
        assert_eq!(roots.len(), 26);
        for (index, root) in roots.iter().enumerate() {
            assert_eq!(root.is_ipv4(), index % 2 == 0, "{root}");
        }
        assert_eq!(
            roots[0],
            "198.41.0.4:53".parse().expect("a.root-servers.net")
        );
    }

    #[test]
    fn referrals_lead_down_to_the_glue() {
        let Ok(Step::Referral { zone, glue, names }) =
            step(&captured("referral_root"), &example(), &Name::root())
        else {
            panic!("a referral from the root");
        };
        assert_eq!((zone, names.len(), glue.len()), (name("com."), 13, 26));
        assert!(glue[0].is_ipv4() && glue[1].is_ipv6());
        let Ok(Step::Referral { zone, names, glue }) =
            step(&captured("referral_com"), &example(), &name("com."))
        else {
            panic!("a referral from com.");
        };
        assert_eq!(zone, name("example.com."));
        assert!(names.contains(&name("hera.ns.cloudflare.com.")));
        // The cloudflare.com. names are in com., so their addresses are glue there.
        assert_eq!(glue.len(), 12);
    }

    #[test]
    fn glue_is_only_taken_from_inside_the_zone() {
        // A com. server adding a name server in net. and its address: an address the com. servers cannot vouch
        // for (RFC 2181 §5.4.1).
        let mut message = captured("referral_com");
        let record = |text: &str| text.parse::<Record<'static>>().expect("a record");
        message
            .authority
            .push(record("example.com. 172800 IN NS ns.example.net."));
        message
            .additional
            .push(record("ns.example.net. 172800 IN A 192.0.2.1"));
        let Ok(Step::Referral { names, glue, .. }) = step(&message, &example(), &name("com."))
        else {
            panic!("a referral from com.");
        };
        assert_eq!((names.len(), glue.len()), (3, 12));
    }

    #[test]
    fn a_referral_must_come_closer() {
        let message = captured("referral_root");
        // From the servers of com., a referral to com. goes nowhere.
        assert!(step(&message, &example(), &name("com.")).is_err());
        // A question outside com. is not led there.
        let other = Question::new(name("example.org."), RecordType::A);
        assert!(step(&message, &other, &Name::root()).is_err());
    }

    #[test]
    fn answers_nxdomain_and_authority_end_the_trace() {
        for capture in ["a", "nxdomain_soa", "nodata", "any_rfc8482"] {
            assert_eq!(
                step(&captured(capture), &example(), &Name::root()).ok(),
                Some(Step::Done),
                "{capture}"
            );
        }
    }

    #[test]
    fn errors_and_lame_responses_go_to_the_next_server() {
        // SERVFAIL, and a truncated response with neither answer nor referral.
        for capture in ["ede", "truncated"] {
            assert!(
                step(&captured(capture), &example(), &Name::root()).is_err(),
                "{capture}"
            );
        }
    }

    #[test]
    fn families_alternate() {
        let ips = ["192.0.2.1", "192.0.2.2", "2001:db8::1"]
            .map(|ip| ip.parse::<IpAddr>().expect("an address"));
        let order: Vec<bool> = in_turn(ips).iter().map(SocketAddr::is_ipv4).collect();
        assert_eq!(order, [true, false, true]);
    }
}
