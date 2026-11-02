//! A run's hosts: clients, one resolver and the upstream servers, on a simulated network that a seed shapes.

use std::cell::RefCell;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use turmoil::Sim;

use crate::client::Client;
use crate::fault::Fault;
use crate::resolver::Resolver;
use crate::seed::{Rng, Seed};
use crate::stub::Stub;
use crate::trace::{Event, Trace, What};
use crate::upstream::{self, Answers, Expected};

/// The port of the resolver and of the upstream servers.
const PORT: u16 = 53;

/// The longest a run lasts in simulated time: more than the longest query (three tries of five seconds, a try
/// more for TCP) and the resolver's own tries behind it.
const DURATION: Duration = Duration::from_secs(120);

/// Which hosts a run has; [`Topology::build`] makes them.
#[derive(Debug, Default)]
pub struct Topology {
    upstreams: Vec<Answers>,
    epoch: Option<SystemTime>,
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
        self.upstreams.push(answers);
        self
    }

    /// Starts the simulation at `epoch` by the clocks of its hosts (`turmoil::since_epoch`), as signatures in
    /// captured zones are valid for some date only; by default, one turmoil picks.
    #[must_use]
    pub const fn epoch(mut self, epoch: SystemTime) -> Self {
        self.epoch = Some(epoch);
        self
    }

    /// Makes the simulation: the resolver (`resolver`) and the upstream servers (`upstream-<n>`), on a network
    /// whose latencies and order of hosts follow `seed`. Clients are added to the [`World`].
    #[must_use]
    pub fn build(self, seed: Seed) -> World {
        let mut builder = turmoil::Builder::new();
        builder
            .rng_seed(seed.0)
            .simulation_duration(DURATION)
            .enable_random_order();
        if let Some(epoch) = self.epoch {
            builder.epoch(epoch);
        }
        let mut sim = builder.build();
        let trace = Trace::new();
        let expected: Rc<[Expected]> = self.upstreams.iter().flat_map(Answers::expected).collect();
        let mut addrs = Vec::new();
        for (n, answers) in self.upstreams.into_iter().enumerate() {
            let name = format!("upstream-{n}");
            let host = sim.lookup(name.as_str());
            addrs.push(SocketAddr::new(host, PORT));
            let (answers, trace) = (Rc::new(answers), trace.clone());
            sim.host(name, move || {
                upstream::serve(Rc::clone(&answers), host, trace.clone())
            });
        }
        let host = sim.lookup("resolver");
        let resolver = Resolver {
            upstreams: addrs.clone(),
            rng: Rc::new(RefCell::new(Rng::new(seed, 0))),
            trace: trace.clone(),
        };
        sim.host("resolver", move || {
            let resolver = resolver.clone();
            async move { resolver.serve(host).await }
        });
        World {
            sim,
            seed,
            trace,
            expected,
            faults: Vec::new(),
            picks: Rng::new(seed, u64::MAX),
            resolver: SocketAddr::new(host, PORT),
            upstreams: addrs,
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

    /// The trace, which fills as the run goes.
    #[must_use]
    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Adds a client host (`client-<n>`) that runs `body` with its [`Stub`]. An error from `body` fails the
    /// run.
    pub fn client<F, Fut>(&mut self, body: F)
    where
        F: FnOnce(Stub) -> Fut,
        Fut: Future<Output = turmoil::Result> + 'static,
    {
        let name = format!("client-{}", self.clients);
        let host = self.sim.lookup(name.as_str());
        // The resolver's is the stream 0.
        self.clients += 1;
        let rng = Rc::new(RefCell::new(Rng::new(self.seed, self.clients)));
        let stub = Stub::new(
            Client::new(rng),
            host,
            self.resolver,
            self.trace.clone(),
            Rc::clone(&self.expected),
        );
        self.sim.client(name, body(stub));
    }

    /// Runs until every client has finished, making the faults at their times, and returns the events of the run.
    ///
    /// # Errors
    ///
    /// A client that failed, a host that failed or panicked in any of its tasks, or a run that lasts past its
    /// duration.
    pub fn run(mut self) -> turmoil::Result<Vec<Event>> {
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
                return Ok(self.trace.events());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
