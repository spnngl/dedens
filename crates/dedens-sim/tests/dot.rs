//! The resolver forwarding over DNS over TLS (RFC 7858, D65): rustls over the simulated stream, to an upstream
//! server that speaks TLS only. Each fault of that server ends a client's query as the same fault of a server over
//! TCP does, TLS adding a handshake and nothing else (D133).

use std::cell::Cell;
use std::time::Duration;

use dedens_cache::Config;
use dedens_proto::{Rcode, RecordType, Transport};
use dedens_server::Forward;
use dedens_sim::client::Carrier;
use dedens_sim::resolver::pipeline_forwarding;
use dedens_sim::seed::{self, Rng, Seed};
use dedens_sim::stub::question;
use dedens_sim::topology::Topology;
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::{Answers, Behaviour, Verdict};

use crate::util::{SEEDS, answers};

/// Seeds for the scenario of every fault: a handshake is the slowest thing the simulation does.
const ONE: &[u64] = &[0];

/// Seeds for the run that replays in a second process.
const FEW: &[u64] = &[0, 7];

/// How long the forward stage waits for each try: shorter than its default, as a silent server makes a run last
/// its tries in simulated time, each millisecond a step.
const FORWARD_TIMEOUT: Duration = Duration::from_millis(500);

/// What the upstream server does wrong, by name.
type Fault = (&'static str, fn(Answers) -> Answers);

/// A server without faults.
const NONE: Fault = ("none", |answers| answers);

/// The faults of an upstream server that TCP and TLS share (D133).
const FAULTS: [Fault; 7] = [
    NONE,
    ("silent", Answers::silent),
    ("silent on each connection", |answers| {
        answers.tcp(Behaviour::Silent)
    }),
    ("closes each connection at once", |answers| {
        answers.tcp(Behaviour::Close(0))
    }),
    ("closes each connection after an answer", |answers| {
        answers.tcp(Behaviour::Close(1))
    }),
    ("drops half its responses", |answers| {
        answers.faulty(|_, rng| {
            if rng.below(2) == 0 {
                Verdict::Drop
            } else {
                Verdict::Answer
            }
        })
    }),
    // Past the forward stage's timeout.
    ("answers a second late", |answers| {
        answers.faulty(|_, _| Verdict::Delay(Duration::from_secs(1)))
    }),
];

/// The events of a run where a client asks the resolver `example.com A` over TCP, the resolver forwarding to the
/// one upstream server `add` adds with `fault`, each try waiting [`FORWARD_TIMEOUT`].
fn run(seed: Seed, add: fn(Topology, Answers) -> Topology, (_, fault): Fault) -> Vec<Event> {
    let topology = Topology::new().resolver(|upstreams| {
        let forward = Forward::new(upstreams.iter().cloned())
            .expect("an upstream server")
            .with_timeout(FORWARD_TIMEOUT);
        pipeline_forwarding(Config::default(), forward)
    });
    let mut world = add(topology, fault(answers())).build(seed);
    world.client(async move |stub| {
        stub.ask(question("example.com", RecordType::A), Carrier::Tcp)
            .await?;
        Ok(())
    });
    world.run().expect("the run passes its checks")
}

/// How the client's queries ended.
fn ends(events: &[Event]) -> Vec<&What> {
    events
        .iter()
        .map(|event| &event.what)
        .filter(|what| {
            matches!(
                what,
                What::Answered { .. } | What::Failed { .. } | What::Errored { .. }
            )
        })
        .collect()
}

/// The transports the resolver forwarded over.
fn forwarded(events: &[Event]) -> Vec<Transport> {
    events
        .iter()
        .filter_map(|event| match event.what {
            What::Forwarded { transport, .. } => Some(transport),
            _ => None,
        })
        .collect()
}

/// Checks that `fault` ends the query over DNS over TLS as over TCP, the resolver forwarding over each.
fn ends_as_over_tcp(seed: Seed, fault: Fault) {
    let over_tls = run(seed, Topology::dot_upstream, fault);
    let over_tcp = run(seed, Topology::upstream, fault);
    assert_eq!(ends(&over_tls), ends(&over_tcp), "{}", fault.0);
    let (tls, tcp) = (forwarded(&over_tls), forwarded(&over_tcp));
    assert!(!tls.is_empty(), "{}", fault.0);
    assert!(
        tls.iter().all(|transport| *transport == Transport::Tls),
        "{tls:?}"
    );
    assert!(
        tcp.iter().all(|transport| *transport == Transport::Tcp),
        "{tcp:?}"
    );
}

#[test]
fn each_fault_of_a_dot_server_ends_a_query_as_over_tcp() {
    seed::each(ONE, |seed| {
        for fault in FAULTS {
            ends_as_over_tcp(seed, fault);
        }
    });
}

#[test]
fn a_dot_server_without_faults_gives_the_records() {
    seed::each(ONE, |seed| {
        let events = run(seed, Topology::dot_upstream, NONE);
        assert!(
            matches!(
                ends(&events).as_slice(),
                [What::Answered {
                    rcode: Rcode::NOERROR,
                    answers: 2,
                    ..
                }]
            ),
            "{events:#?}"
        );
    });
}

/// The fault the seed picks.
fn picked(seed: Seed) -> Fault {
    let count = u64::try_from(FAULTS.len()).expect("a few faults");
    let pick = Rng::new(seed, 0).below(count);
    FAULTS[usize::try_from(pick).expect("an index below the count of faults")]
}

/// The seed picks the fault: whichever it is, a query forwarded over TLS ends as over TCP.
#[test]
fn the_seed_picks_the_fault_a_dot_server_shares_with_tcp() {
    seed::each(SEEDS, |seed| ends_as_over_tcp(seed, picked(seed)));
}

/// A run forwarded over TLS replays: what rustls draws (randoms, key shares) changes bytes on the wire, not their
/// lengths nor when they arrive.
#[test]
fn a_dot_forward_replays_in_two_processes() {
    let runs = Cell::new(0);
    seed::in_two_processes(
        module_path!(),
        "a_dot_forward_replays_in_two_processes",
        FEW,
        |seed| {
            runs.set(runs.get() + 1);
            trace::digest(&run(seed, Topology::dot_upstream, picked(seed)))
        },
    );
    assert!(runs.get() > 0);
}
