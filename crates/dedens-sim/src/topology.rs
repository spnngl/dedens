//! A run's hosts: clients, one resolver and the upstream servers, on a simulated network that a seed shapes.

use std::cell::RefCell;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dedens_net::tls::{Presented, Trust};
use dedens_server::{Pipeline, Server, Via};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use turmoil::Sim;

use crate::client::Client;
use crate::dot;
use crate::fault::Fault;
use crate::oracle::Expected;
use crate::resolver::{self, Build, Resolver};
use crate::seed::{Rng, Seed};
use crate::stub::Stub;
use crate::trace::{Event, Trace, What};
use crate::upstream::{self, Answers};

/// The port of the resolver and of the upstream servers.
const PORT: u16 = 53;

/// The longest a run lasts in simulated time, by default: more than the longest query (three tries of five
/// seconds, a try more for each fallback) and the resolver's own tries behind it.
const DURATION: Duration = Duration::from_secs(120);

/// How long into a run the clients start: the hosts have bound their ports by then, as a server that has been up
/// before its clients. turmoil starts hosts in no fixed order, and a datagram or a connection to a port not bound yet
/// is lost or refused.
const START: Duration = Duration::from_millis(5);

/// The counters of the panics `dedensd`'s loop catches and of the restarts they cause (D121).
const CAUGHT: [&str; 2] = [
    "dedensd_task_panics_total",
    "dedensd_listener_restarts_total",
];

/// The start of a run by default, 2026-01-01T00:00:00Z: the same in every run, so that the clocks of the hosts
/// (`turmoil::since_epoch`) do not depend on when the test runs.
const EPOCH: Duration = Duration::from_hours(490_896);

/// What an upstream server speaks.
#[derive(Debug, Clone, Copy)]
enum Speaks {
    /// Plain DNS, on port 53.
    Dns,
    /// DNS over TLS, on [`dot::PORT`], with the certificate of [`dot::certificates`] for [`dot::NAME`].
    Tls,
}

/// What the resolver host runs.
#[derive(Debug, Clone, Copy)]
enum Software {
    /// [`Resolver::serve`], the driver mirroring `dedensd`'s glue (D133).
    Driver,
    /// [`Resolver::serve_dedensd`], `dedensd`'s own serving loop (D182).
    Dedensd,
}

/// Which hosts a run has; [`Topology::build`] makes them.
pub struct Topology {
    upstreams: Vec<(Answers, Speaks)>,
    epoch: SystemTime,
    duration: Duration,
    repair_rate: Option<f64>,
    pipeline: Build,
    software: Software,
}

impl fmt::Debug for Topology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Topology")
            .field("upstreams", &self.upstreams)
            .field("epoch", &self.epoch)
            .field("duration", &self.duration)
            .field("repair_rate", &self.repair_rate)
            .field("software", &self.software)
            .finish_non_exhaustive()
    }
}

impl Default for Topology {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            epoch: UNIX_EPOCH + EPOCH,
            duration: DURATION,
            repair_rate: None,
            pipeline: Rc::new(resolver::pipeline),
            software: Software::Driver,
        }
    }
}

impl Topology {
    /// A topology with no upstream server yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an upstream server answering from `answers`; the resolver asks them in the order added.
    #[must_use]
    pub fn upstream(mut self, answers: Answers) -> Self {
        self.upstreams.push((answers, Speaks::Dns));
        self
    }

    /// Adds an upstream server answering from `answers` over DNS over TLS only (RFC 7858), as [`World::dot_server`]
    /// does; the resolver forwards to it over TLS, trusting its certificate authority.
    #[must_use]
    pub fn dot_upstream(mut self, answers: Answers) -> Self {
        self.upstreams.push((answers, Speaks::Tls));
        self
    }

    /// Starts the simulation at `epoch` by the clocks of its hosts (`turmoil::since_epoch`), as signatures in
    /// captured zones are valid for some date only; by default, 2026-01-01.
    #[must_use]
    pub const fn epoch(mut self, epoch: SystemTime) -> Self {
        self.epoch = epoch;
        self
    }

    /// Ends the run, with an error, after `duration` of simulated time; by default, two minutes.
    #[must_use]
    pub const fn duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// The probability for a link that [`Fault::Loss`] broke to be repaired by each message sent on it; by
    /// default 1, turmoil's. turmoil has no setter for it during a run, so it holds from the start.
    #[must_use]
    pub const fn repair_rate(mut self, rate: f64) -> Self {
        self.repair_rate = Some(rate);
        self
    }

    /// Makes `build` the resolver's pipeline instead of [`resolver::pipeline`] (a cache and a forwarding stage):
    /// the stages, limits and access rules a scenario tests. It gets the upstream servers and runs each time the resolver starts, a bounce included, so a restart begins with an empty cache.
    ///
    /// The cache must keep `shards: 1` ([`resolver::pipeline_with`] forces it): its shards are picked by a hash that
    /// differs from one process to the next, which a trace that must replay cannot have.
    #[must_use]
    pub fn resolver(mut self, build: impl Fn(&[Server]) -> Pipeline + 'static) -> Self {
        self.pipeline = Rc::new(build);
        self
    }

    /// Runs `dedensd`'s serving loop of UDP and TCP on the resolver host ([`Resolver::serve_dedensd`]) in place of
    /// the driver ([`Resolver::serve`]), on the simulated network and clock (D182 lists what no scenario reaches).
    /// The trace then has none of the resolver's `Replied`, `Forwarded` and `Stored`.
    #[must_use]
    pub const fn dedensd(mut self) -> Self {
        self.software = Software::Dedensd;
        self
    }

    /// Makes the simulation: the resolver (`resolver`) and the upstream servers (`upstream-<n>`), on a network
    /// whose latencies and order of hosts follow `seed`. Clients are added to the [`World`].
    #[must_use]
    pub fn build(self, seed: Seed) -> World {
        let mut builder = turmoil::Builder::new();
        builder
            .rng_seed(seed.0)
            .epoch(self.epoch)
            .simulation_duration(self.duration)
            .enable_random_order();
        if let Some(rate) = self.repair_rate {
            builder.repair_rate(rate);
        }
        let mut sim = builder.build();
        let trace = Trace::new();
        let expected: Rc<[Expected]> = self
            .upstreams
            .iter()
            .flat_map(|(answers, _)| answers.expected())
            .collect();
        // Made by the first server over TLS only: a run with none stays as it was before them.
        let mut certificates = None;
        let mut servers = Vec::new();
        for (n, (answers, speaks)) in self.upstreams.into_iter().enumerate() {
            let name = format!("upstream-{n}");
            let host = sim.lookup(name.as_str());
            let rng = Rc::new(RefCell::new(Rng::new(seed, upstream_stream(n))));
            let (answers, trace) = (Rc::new(answers), trace.clone());
            match speaks {
                Speaks::Dns => {
                    sim.host(name, move || {
                        upstream::serve(Rc::clone(&answers), host, Rc::clone(&rng), trace.clone())
                    });
                    servers.push(Server::from(SocketAddr::new(host, PORT)));
                }
                Speaks::Tls => {
                    let (_, presented) = certificates.get_or_insert_with(|| dot::certificates(0));
                    let presented = Arc::clone(presented);
                    sim.host(name, move || {
                        dot::serve(
                            Rc::clone(&answers),
                            host,
                            Arc::clone(&presented),
                            Rc::clone(&rng),
                            trace.clone(),
                        )
                    });
                    servers.push(Server {
                        addr: SocketAddr::new(host, dot::PORT),
                        via: Via::Tls(Some(dot::NAME.into())),
                    });
                }
            }
        }
        let host = sim.lookup("resolver");
        let addrs = servers.iter().map(|server| server.addr).collect();
        let resolver = Resolver {
            upstreams: servers,
            trust: certificates.map(|(ca, _)| Trust::Roots(vec![ca])),
            rng: Rc::new(RefCell::new(Rng::new(seed, 0))),
            trace: trace.clone(),
            build: self.pipeline,
        };
        let software = self.software;
        sim.host("resolver", move || {
            let resolver = resolver.clone();
            async move {
                match software {
                    Software::Driver => resolver.serve(host).await,
                    Software::Dedensd => resolver.serve_dedensd(host).await,
                }
            }
        });
        World {
            sim,
            seed,
            trace,
            expected,
            faults: Vec::new(),
            picks: Rng::new(seed, PICKS),
            resolver: SocketAddr::new(host, PORT),
            upstreams: addrs,
            named: 0,
            dots: 0,
            clients: 0,
        }
    }
}

/// A simulation: its hosts and the trace of what they do.
pub struct World {
    sim: Sim<'static>,
    seed: Seed,
    trace: Trace,
    expected: Rc<[Expected]>,
    faults: Vec<(Duration, Fault)>,
    picks: Rng,
    /// The address of the resolver.
    pub resolver: SocketAddr,
    /// The addresses of the upstream servers, in the order of the topology.
    pub upstreams: Vec<SocketAddr>,
    named: usize,
    dots: usize,
    clients: u64,
}

impl World {
    /// A time from `from` up to `to`, drawn from the seed: when a fault happens, for a scenario where the seed
    /// picks it. The draws do not touch those of the hosts.
    pub fn pick(&mut self, from: Duration, to: Duration) -> Duration {
        let span = u64::try_from(to.saturating_sub(from).as_millis()).unwrap_or(u64::MAX);
        from + Duration::from_millis(self.picks.below(span.saturating_add(1)))
    }

    /// A number below `bound`, drawn from the seed like [`World::pick`]: which fault, or which host, in a
    /// scenario where the seed picks.
    pub fn choose(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.picks.below(bound)).unwrap_or_default()
    }

    /// Makes `fault` at `at` of the run, in simulated time; faults at one time go in the order given. Each is
    /// recorded in the trace.
    pub fn fault(&mut self, at: Duration, fault: Fault) {
        self.faults.push((at, fault));
    }

    /// The simulation, to change the network or the hosts before the run in a way [`Fault`] does not say.
    pub fn sim(&mut self) -> &mut Sim<'static> {
        &mut self.sim
    }

    /// Adds a client host (`client-<n>`) that runs `body` with its [`Stub`]. An error from `body` fails the
    /// run.
    pub fn client<F, Fut>(&mut self, body: F)
    where
        F: FnOnce(Stub) -> Fut,
        Fut: Future<Output = turmoil::Result> + 'static,
    {
        let name = format!("client-{}", self.named);
        self.named += 1;
        let host = self.sim.lookup(name.as_str());
        self.add(name, host, body);
    }

    /// Adds a client host (`client-<n>`) that runs `body` with a bare [`Client`] and no stub: the oracle checks
    /// nothing, for scenarios about the client itself (its pools, its connections, its sockets) against servers it
    /// addresses on its own. An error from `body` fails the run.
    pub fn client_direct<F, Fut>(&mut self, body: F)
    where
        F: FnOnce(Client) -> Fut,
        Fut: Future<Output = turmoil::Result> + 'static,
    {
        let name = format!("client-{}", self.named);
        self.named += 1;
        let host = self.sim.lookup(name.as_str());
        self.clients += 1;
        let rng = Rc::new(RefCell::new(Rng::new(self.seed, self.clients)));
        let body = body(Client::new(rng, host, self.trace.clone()));
        self.sim.client(name, async move {
            tokio::time::sleep(START).await;
            body.await
        });
    }

    /// Adds a DNS-over-TLS server host (`dot-<n>`, port [`dot::PORT`]) answering from `answers` with the
    /// certificate `presented`, and returns its address.
    pub fn dot_server(&mut self, answers: Answers, presented: Arc<Presented>) -> SocketAddr {
        let name = format!("dot-{}", self.dots);
        let host = self.sim.lookup(name.as_str());
        let rng = Rc::new(RefCell::new(Rng::new(self.seed, dot_stream(self.dots))));
        self.dots += 1;
        let (answers, trace) = (Rc::new(answers), self.trace.clone());
        self.sim.host(name, move || {
            dot::serve(
                Rc::clone(&answers),
                host,
                Arc::clone(&presented),
                Rc::clone(&rng),
                trace.clone(),
            )
        });
        SocketAddr::new(host, dot::PORT)
    }

    /// Adds a client host at the address `ip`: a scenario with many sources, in networks of its choice, for the
    /// resolver's access rules and limits. The addresses of the other hosts are 192.168.0.0/16 and up, in the
    /// order of their creation; pick `ip` outside it.
    pub fn client_at<F, Fut>(&mut self, ip: IpAddr, body: F)
    where
        F: FnOnce(Stub) -> Fut,
        Fut: Future<Output = turmoil::Result> + 'static,
    {
        self.add(ip, ip, body);
    }

    fn add<F, Fut>(&mut self, name: impl turmoil::ToIpAddr, host: IpAddr, body: F)
    where
        F: FnOnce(Stub) -> Fut,
        Fut: Future<Output = turmoil::Result> + 'static,
    {
        // The resolver's is the stream 0.
        self.clients += 1;
        let rng = Rc::new(RefCell::new(Rng::new(self.seed, self.clients)));
        let stub = Stub::new(
            Client::new(rng, host, self.trace.clone()),
            host,
            self.resolver,
            self.trace.clone(),
            Rc::clone(&self.expected),
        );
        let body = body(stub);
        self.sim.client(name, async move {
            tokio::time::sleep(START).await;
            body.await
        });
    }

    /// Runs until every client has finished, making the faults at their times, and returns the events of the run.
    ///
    /// A panic of a host after the last client finished is not seen, and a task of a host that spins without
    /// waiting never lets the run end: the driver has none, and a hang is the signal.
    ///
    /// # Errors
    ///
    /// A client that failed, a host that failed or panicked in any of its tasks (a panic `dedensd`'s loop catches
    /// as in production, read from its counters), a run that lasts past its duration, or one that ends before the
    /// time of a fault: that fault would not have been tested.
    pub fn run(self) -> turmoil::Result<Vec<Event>> {
        // turmoil runs every host on this thread: a local recorder sees the counts of all.
        let recorder = DebuggingRecorder::new();
        let events = metrics::with_local_recorder(&recorder, || self.play())?;
        let caught: Vec<_> = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(key, .., value)| {
                CAUGHT.contains(&key.key().name()) && !matches!(value, DebugValue::Counter(0))
            })
            .map(|(key, ..)| key.into_parts().1)
            .collect();
        if caught.is_empty() {
            Ok(events)
        } else {
            Err(format!("dedensd caught panics: {caught:?}").into())
        }
    }

    /// [`World::run`], but for the counters.
    fn play(mut self) -> turmoil::Result<Vec<Event>> {
        self.faults.sort_by_key(|(at, _)| *at);
        let mut faults = self.faults.into_iter().peekable();
        loop {
            let now = self.sim.elapsed();
            while let Some((_, fault)) = faults.next_if(|(at, _)| *at <= now) {
                fault.apply(&mut self.sim);
                let network = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                self.trace.record_at(now, network, What::Fault(fault));
            }
            if self.sim.step()? {
                return match faults.next() {
                    None => Ok(self.trace.events()),
                    Some((at, fault)) => {
                        Err(format!("the run ended at {now:?}, before {fault:?} at {at:?}").into())
                    }
                };
            }
        }
    }
}

/// The streams of the seed: 0 is the resolver's, 1 and up the clients', [`DOTS`] and up the DNS-over-TLS servers',
/// [`PICKS`] the picks of the scenario, and those below it the upstream servers'.
const PICKS: u64 = u64::MAX;

/// The stream of the first DNS-over-TLS server: halfway, far from the clients' and the upstream servers'.
const DOTS: u64 = 1 << 63;

/// The stream of the upstream server `n`.
fn upstream_stream(n: usize) -> u64 {
    PICKS - 1 - n as u64
}

/// The stream of the DNS-over-TLS server `n`.
fn dot_stream(n: usize) -> u64 {
    DOTS + n as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_two_hosts_share_a_stream() {
        let streams: Vec<u64> = (0..4)
            .map(upstream_stream)
            .chain((0..4).map(dot_stream))
            .chain([PICKS])
            .collect();
        let mut distinct = streams.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), streams.len(), "{streams:?}");
        // Apart from the resolver's (0) and the clients' (1 and up).
        assert!(streams.iter().all(|stream| *stream > u64::MAX / 2));
    }

    #[test]
    fn each_client_has_a_host_of_its_own() {
        let mut world = Topology::new().upstream(Answers::new()).build(Seed(1));
        world.client(async |_| Ok(()));
        world.client(async |_| Ok(()));
        assert_eq!(world.clients, 2);
        world.run().expect("the clients end");
    }

    #[test]
    fn a_panic_dedensd_caught_fails_the_run() {
        let mut world = Topology::new().upstream(Answers::new()).build(Seed(1));
        world.client(async |_| {
            metrics::counter!(CAUGHT[0], "listener" => "udp://").increment(1);
            Ok(())
        });
        let failure = world.run().expect_err("the counted panic fails the run");
        assert!(failure.to_string().contains(CAUGHT[0]), "{failure}");
    }

    #[test]
    fn choices_and_times_stay_in_range_and_follow_the_seed() {
        let mut world = Topology::new().build(Seed(5));
        let draws: Vec<usize> = (0..50).map(|_| world.choose(5)).collect();
        assert!(draws.iter().all(|draw| *draw < 5));
        assert!(draws.iter().any(|draw| *draw != draws[0]));
        let (from, to) = (Duration::from_secs(1), Duration::from_secs(2));
        assert!((0..50).all(|_| (from..=to).contains(&world.pick(from, to))));
        let mut again = Topology::new().build(Seed(5));
        assert_eq!(draws, (0..50).map(|_| again.choose(5)).collect::<Vec<_>>());
    }
}
