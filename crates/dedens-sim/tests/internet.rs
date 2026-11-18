//! The Internet of the captured resolutions (D188, D189): each authoritative server of a capture at its address,
//! IPv4 and IPv6, answering a plain client over UDP and TCP as it answered the capture; and servers misbehaving as
//! broken ones do, one of each [`Conduct`] and a silent one, the others answering as captured.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU8;
use std::time::Duration;

use dedens_net::client::ClientError;
use dedens_net::exchange::{Options, Response};
use dedens_proto::{Flags, Message, Rcode, Transport};
use dedens_server::Pipeline;
use dedens_sim::client::{Carrier, Client};
use dedens_sim::seed::{self, Rng, Seed};
use dedens_sim::topology::Topology;
use dedens_sim::upstream::{Answers, Conduct};
use dedens_testkit::recursion::{self, Authorities, Exchange, Resolution};
use futures_util::future::join_all;

use crate::util::{SECOND, SEEDS};

/// The DNS port, the servers'.
const PORT: u16 = 53;

/// How long the client waits for a server, and how many times it asks: a silent server ends an exchange after
/// one wait, where every other server answers in well under it.
const WAIT: Duration = SECOND;
const TRIES: NonZeroU8 = NonZeroU8::MIN;

/// The stream of the seed the test picks the broken servers from: none of a host's (`topology`'s streams).
const PICKS: u64 = 1 << 61;

/// The step of the simulation: the latencies of its links are tens of milliseconds, the exchanges' order none
/// of a test's concern, and a coarser step keeps a run of a hundred hosts within D164's budget.
const TICK: Duration = Duration::from_millis(10);

/// The conducts a broken server may have, beside silence.
const CONDUCTS: [Conduct; 6] = [
    Conduct::Refuses,
    Conduct::Fails,
    Conduct::Truncates,
    Conduct::NoEdns,
    Conduct::FoldsCase,
    Conduct::Unauthoritative,
];

/// A broken server of a run: a conduct of [`CONDUCTS`], or silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Broken {
    Conducts(Conduct),
    Silent,
}

/// Every capture, loaded in one topology.
fn captures() -> Vec<Resolution> {
    Resolution::all()
        .into_iter()
        .map(|(_, resolution)| resolution)
        .collect()
}

/// The exchanges of `resolutions` a client asks again: one per server, question and transport, the first, as the
/// servers answer the first.
fn asked(resolutions: &[Resolution]) -> Vec<Exchange> {
    let mut asked: BTreeMap<(IpAddr, String, u16, bool), Exchange> = BTreeMap::new();
    for exchange in resolutions
        .iter()
        .flat_map(|resolution| &resolution.exchanges)
    {
        let tcp = exchange.transport == recursion::Transport::Tcp;
        let key = (
            exchange.server,
            exchange.name.to_string(),
            exchange.rtype.0,
            tcp,
        );
        asked.entry(key).or_insert_with(|| exchange.clone());
    }
    asked.into_values().collect()
}

/// The options of the client: every letter of the question in upper case (D184's random case, all bits set), so
/// that a server folding it is caught; one short try.
fn options() -> Options {
    let mut options = Options::default();
    options.random_case = Some([u8::MAX; 32]);
    options.timeout = WAIT;
    options.tries = TRIES;
    options
}

/// Asks every one of `asked` at once, over the transport of its capture.
async fn ask_all(client: &Client, asked: &[Exchange]) -> Vec<Result<Response, ClientError>> {
    let options = options();
    let exchanges = asked.iter().map(|exchange| {
        let carrier = match exchange.transport {
            recursion::Transport::Udp => Carrier::Udp,
            recursion::Transport::Tcp => Carrier::Tcp,
        };
        let server = SocketAddr::new(exchange.server, PORT);
        client.exchange(exchange.query(0), server, carrier, &options)
    });
    join_all(exchanges).await
}

/// The response `authorities` holds for what `response` asked, decoded, its ID cleared.
fn reference(authorities: &Authorities, server: IpAddr, response: &Response) -> Message<'static> {
    let transport = match response.transport {
        Transport::Tcp => recursion::Transport::Tcp,
        _ => recursion::Transport::Udp,
    };
    decoded(&authorities.answer(server, transport, &response.query))
}

/// `wire`, decoded, its ID cleared: servers answer alike but for it.
fn decoded(wire: &[u8]) -> Message<'static> {
    let mut message = Message::decode(wire)
        .expect("a response decodes")
        .message
        .into_owned();
    message.header.id = 0;
    message
}

/// Checks that the response to `exchange`, its server broken or not, is what its conduct makes of the captured one.
fn check(
    authorities: &Authorities,
    exchange: &Exchange,
    broken: Option<Broken>,
    response: Result<Response, ClientError>,
) {
    let (server, name) = (exchange.server, &exchange.name);
    // The client drops a response whose question is not in the case asked: the exchange times out, as it does with
    // a silent server. A name without a letter has no case to fold.
    let folded = broken == Some(Broken::Conducts(Conduct::FoldsCase))
        && name
            .to_string()
            .bytes()
            .any(|byte| byte.is_ascii_alphabetic());
    if folded || broken == Some(Broken::Silent) {
        assert!(response.is_err(), "{server} answered {name}: {response:?}");
        return;
    }
    let response = response
        .map_err(|error| format!("{server}, {name}: {error}"))
        .expect("the server answers");
    let got = decoded(&response.wire);
    let held = reference(authorities, server, &response);
    let conduct = match broken {
        Some(Broken::Conducts(conduct)) => conduct,
        _ => Conduct::Faithful,
    };
    match conduct {
        Conduct::Faithful | Conduct::FoldsCase => assert_eq!(got, held, "{server}, {name}"),
        Conduct::Refuses | Conduct::Fails => {
            let rcode = if conduct == Conduct::Refuses {
                Rcode::REFUSED
            } else {
                Rcode::SERVFAIL
            };
            assert_eq!(got.rcode(), rcode, "{server}");
            assert!(
                got.answer.is_empty() && got.authority.is_empty(),
                "{server}: {got:?}"
            );
        }
        // The client asks again over TCP, where the server answers whole.
        Conduct::Truncates => {
            assert_eq!(response.transport, Transport::Tcp, "{server}");
            assert_eq!(got, held, "{server}");
        }
        // The client asks again without EDNS, as RFC 6891 §7 has it: the server answers without the OPT record.
        Conduct::NoEdns => {
            assert!(got.edns.is_none(), "{server}: {got:?}");
            assert_eq!(got.rcode(), held.rcode(), "{server}");
            // Answered after the FORMERR to the query with EDNS.
            assert!(decoded(&response.query).edns.is_none(), "{server}");
        }
        Conduct::Unauthoritative => {
            assert!(!got.header.flags.contains(Flags::AA), "{server}");
            let mut held = held;
            held.header.flags = held.header.flags.without(Flags::AA);
            assert_eq!(got, held, "{server}");
        }
    }
}

/// Runs the captures under `seed`, with the servers `broken` misbehaving, and has a client ask each exchange again.
fn run(seed: Seed, broken: BTreeMap<IpAddr, Broken>) {
    let resolutions = captures();
    // No resolver: the client asks the servers; an empty pipeline in place of the default one, which forwards.
    let mut topology = Topology::new().resolver(|_| Pipeline::new(Vec::new()));
    for resolution in &resolutions {
        topology = topology.resolution(resolution);
    }
    let authorities = Authorities::new(&resolutions);
    for (exchange_server, conduct) in &broken {
        let held = resolutions
            .iter()
            .flat_map(|resolution| &resolution.exchanges);
        let answers = Answers::default()
            .exchanges(held.filter(|exchange| exchange.server == *exchange_server));
        let answers = match conduct {
            Broken::Conducts(conduct) => answers.conduct(*conduct),
            Broken::Silent => answers.silent(),
        };
        topology = topology.authoritative_at(*exchange_server, answers);
    }
    let mut world = topology.tick(TICK).build(seed);
    let asked = asked(&resolutions);
    world.client_direct(async move |client| {
        let responses = ask_all(&client, &asked).await;
        for (exchange, response) in asked.iter().zip(responses) {
            check(
                &authorities,
                exchange,
                broken.get(&exchange.server).copied(),
                response,
            );
        }
        Ok(())
    });
    world.run().expect("the run passes its checks");
}

/// Every server of every capture, IPv4 and IPv6, answers each exchange as it did, over the transport it did.
#[test]
fn the_servers_answer_as_captured() {
    seed::each(SEEDS, |seed| run(seed, BTreeMap::new()));
}

/// A server at a time of each conduct, the seed picking which, answers as it breaks the captured response; the
/// others as captured.
#[test]
fn a_broken_server_breaks_only_its_answers() {
    let servers: BTreeSet<IpAddr> = captures()
        .iter()
        .flat_map(|resolution| resolution.exchanges.iter().map(|exchange| exchange.server))
        .collect();
    seed::each(SEEDS, |seed| {
        let mut left: Vec<IpAddr> = servers.iter().copied().collect();
        let mut picks = Rng::new(seed, PICKS);
        let brokens = CONDUCTS
            .map(Broken::Conducts)
            .into_iter()
            .chain([Broken::Silent]);
        let broken = brokens
            .map(|kind| {
                let at = picks.below(left.len() as u64);
                (
                    left.swap_remove(usize::try_from(at).expect("below the servers")),
                    kind,
                )
            })
            .collect();
        run(seed, broken);
    });
}
