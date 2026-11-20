//! Captures the minimised resolutions of `testdata/recursion/minimised/` (D188, D198), run by
//! `just capture-minimisation`: runs a [`Resolution`] of each name from the root servers, its questions minimised
//! (RFC 9156), and writes every exchange to `<dir>/<id>.yaml`.
//!
//! Usage: `capture_minimisation <dir> [id]...`, every case of [`CASES`] when no id is given.
//!
//! The resolution sends its questions as a server running it does; the capture is its transport, which sends each
//! zone's to the first of its servers that answered, whichever the resolution drew: the tests steer each zone's
//! questions to one server, the first recorded. [`Minimisation::Strict`] keeps a timeout from changing the questions: the tests replay the same
//! questions whatever the servers that did not answer. Queries set DO alone, with no cookie and no 0x20; a truncated
//! response is asked again over TCP, both recorded, as `capture_recursion` does.

use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dedens_cache::Config;
use dedens_net::client::Client;
use dedens_net::exchange::Options;
use dedens_proto::{Flags, Message, Name, Question, RecordType};
use dedens_resolver::{
    Caches, DEFAULT_CAPACITY, InfraCache, Limits, Marks, Minimisation, Next, Query, Reply,
    Resolution, Resolved, RrsetCache,
};
use dedens_roots::RootHints;
use dedens_testkit::recursion::{self, Exchange, QueryFlag, Transport};

#[path = "../tests/seeded.rs"]
mod seeded;

/// Each case: its id, the name of its file, and the name and type resolved.
const CASES: &[(&str, &str, &str)] = &[
    // An empty non-terminal, _tcp.jabber.org, between the zone and the name.
    ("ent", "_xmpp-server._tcp.jabber.org", "SRV"),
    // 34 labels: the reverse name of 2001:4860:4860::8888, its zones several labels apart.
    (
        "ip6",
        "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa",
        "PTR",
    ),
];

/// The flags of every query.
const FLAGS: &[QueryFlag] = &[QueryFlag::Do];

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .ok_or("usage: capture_minimisation <dir> [id]...")?;
    let ids: Vec<String> = args.collect();
    if let Some(unknown) = ids
        .iter()
        .find(|id| !CASES.iter().any(|(case, ..)| case == id))
    {
        return Err(format!("no case {unknown}").into());
    }
    let cases = CASES
        .iter()
        .filter(|(id, ..)| ids.is_empty() || ids.iter().any(|wanted| wanted == id));
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

/// The resolution of `name` and `rtype` from the root, minimised.
async fn capture(
    name: Name<'static>,
    rtype: RecordType,
) -> Result<recursion::Resolution, Box<dyn Error>> {
    let caches = Arc::new(Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, Config::default())?,
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 64)?,
        roots: RootHints::bundled().clone(),
        tlds: None,
    });
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let started = Instant::now();
    let now = || epoch + started.elapsed();
    let question = Question::new(name.clone(), rtype);
    let mut resolution = Resolution::start(
        question,
        caches,
        now(),
        Limits::default(),
        Minimisation::Strict,
    )?;
    // The tests' draws: the server names looked up are those the replay looks up.
    let mut rng = seeded::Seeded(0);
    let client = Client::new();
    let mut exchanges = Vec::new();
    let mut pinned: HashMap<Name<'static>, IpAddr> = HashMap::new();
    loop {
        let query = match resolution.step(now(), &mut rng) {
            Next::Done(Resolved::Failed(failure)) => {
                return Err(format!("{name} {rtype}: {failure:?}").into());
            }
            Next::Done(_) => break,
            Next::Send(query) => query.clone(),
        };
        let server = pinned
            .get(&query.zone)
            .copied()
            .unwrap_or(query.server.ip());
        match exchange(&client, server, &query, &mut exchanges).await {
            Some((message, rtt)) => {
                pinned.entry(query.zone.clone()).or_insert(server);
                let reply = Reply::Response {
                    message: &message,
                    seen: Marks::default(),
                    rtt: Some(rtt),
                };
                resolution.receive(reply, now());
            }
            None => resolution.receive(Reply::Timeout, now()),
        }
    }
    // Signatures made on demand start at the time of the query: the end of the run is within them all.
    let captured_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(recursion::Resolution {
        captured_at,
        name,
        rtype,
        exchanges,
    })
}

/// The response of `server` to `query`, recorded in `log`: over UDP, again over TCP when truncated; none on
/// an error.
async fn exchange(
    client: &Client,
    server: IpAddr,
    query: &Query,
    log: &mut Vec<Exchange>,
) -> Option<(Message<'static>, Duration)> {
    let Question { name, qtype, .. } = &query.question;
    let mut options = Options::default();
    options.tcp_fallback = false;
    options.cookies = false;
    let mut response = None;
    for transport in [Transport::Udp, Transport::Tcp] {
        options.transport = match transport {
            Transport::Udp => dedens_proto::Transport::Udp,
            Transport::Tcp => dedens_proto::Transport::Tcp,
        };
        let message = recursion::query(0, name, *qtype, FLAGS);
        let exchanged = match client
            .exchange(message, SocketAddr::new(server, 53), &options)
            .await
        {
            Ok(exchanged) => exchanged,
            Err(error) => {
                eprintln!("{server} {name} {qtype} over {transport:?}: {error}");
                return None;
            }
        };
        let decoded = dedens_testkit::message(&exchanged.wire);
        let truncated = decoded.header.flags.contains(Flags::TC);
        log.push(Exchange {
            server,
            zone: query.zone.clone(),
            name: name.clone(),
            rtype: *qtype,
            flags: FLAGS.to_vec(),
            transport,
            response: exchanged.wire,
        });
        response = Some((decoded, exchanged.rtt));
        if !truncated {
            break;
        }
    }
    response
}
