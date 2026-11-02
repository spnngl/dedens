//! Faults: what a scenario does to the network and to the hosts, and when ([`World::fault`]).
//!
//! turmoil's links do not lose packets by a rate each: each message sent over a healthy link breaks it, both ways,
//! with probability `rate` ([`Fault::Loss`]), and then everything on the link, the message included, is lost; the
//! next message sent repairs it with the probability of [`Topology::repair_rate`], 1 by default. At rate 1 about
//! half of the messages arrive, then. A broken link also forgets what a [`Fault::PartitionOneWay`] did, so the two
//! do not go on one link. A TCP segment that is lost is not sent again: its stream stalls, the way a connection
//! hangs until a timeout.
//!
//! Reordering comes from [`Fault::Latency`]: each message of a link waits `min` plus a share of the way to `max`
//! drawn from the seed (an exponential draw, mostly near `min` with a tail up to `max`), so a later message may
//! arrive first. TCP segments are put back in order on arrival, so streams stay in order.
//!
//! [`World::fault`]: crate::topology::World::fault
//! [`Topology::repair_rate`]: crate::topology::Topology::repair_rate

use std::net::IpAddr;
use std::time::Duration;

use turmoil::Sim;

/// A host that runs software of the simulation and can crash: not a client, which a run waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    /// The resolver.
    Resolver,
    /// The upstream server of that index in the topology.
    Upstream(usize),
}

/// A host of the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    /// The resolver.
    Resolver,
    /// The upstream server of that index in the topology.
    Upstream(usize),
    /// The client of that index among those [`World::client`] added.
    ///
    /// [`World::client`]: crate::topology::World::client
    Client(usize),
    /// The host at that address: a client [`World::client_at`] added.
    ///
    /// [`World::client_at`]: crate::topology::World::client_at
    Host(IpAddr),
}

impl From<Server> for Node {
    fn from(server: Server) -> Self {
        match server {
            Server::Resolver => Self::Resolver,
            Server::Upstream(n) => Self::Upstream(n),
        }
    }
}

impl Node {
    /// The address the host has in the simulation.
    pub(crate) fn ip(self, sim: &Sim<'_>) -> IpAddr {
        match self {
            Self::Resolver => sim.lookup("resolver"),
            Self::Upstream(n) => sim.lookup(format!("upstream-{n}")),
            Self::Client(n) => sim.lookup(format!("client-{n}")),
            Self::Host(ip) => ip,
        }
    }
}

/// One change to the network or to a host, made at a time of the run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fault {
    /// From now on, each message sent over the link between the hosts breaks it with probability `rate`, and what
    /// is on it is lost (see the module's text). 0 ends it.
    Loss {
        /// One end of the link.
        a: Node,
        /// The other end.
        b: Node,
        /// The probability, from 0 to 1, for each message.
        rate: f64,
    },
    /// From now on, each message of the link takes a time from `min` to `max`, drawn from the seed (see the
    /// module's text).
    Latency {
        /// One end of the link.
        a: Node,
        /// The other end.
        b: Node,
        /// The shortest time.
        min: Duration,
        /// The longest time.
        max: Duration,
    },
    /// Drops every message between the hosts, both ways, until [`Fault::Repair`].
    Partition(Node, Node),
    /// Drops the messages `from` the host `to` the other, not the ones coming back, until
    /// [`Fault::RepairOneWay`].
    PartitionOneWay {
        /// The sender whose messages are dropped.
        from: Node,
        /// The receiver.
        to: Node,
    },
    /// Keeps the messages between the hosts on the link, both ways, until [`Fault::Release`].
    Hold(Node, Node),
    /// Delivers what [`Fault::Hold`] kept, and lets messages through again.
    Release(Node, Node),
    /// Lets messages through again, both ways: what a partition dropped stays lost, and what a hold kept stays
    /// kept until [`Fault::Release`].
    Repair(Node, Node),
    /// Lets messages through again from one host to the other.
    RepairOneWay {
        /// The sender.
        from: Node,
        /// The receiver.
        to: Node,
    },
    /// Stops the software of the host: it sends and answers nothing, and loses its memory, until
    /// [`Fault::Bounce`].
    Crash(Server),
    /// Starts the software of the host again.
    Bounce(Server),
}

impl Fault {
    /// Makes the change in `sim`.
    pub(crate) fn apply(self, sim: &mut Sim<'_>) {
        match self {
            Self::Loss { a, b, rate } => sim.set_link_fail_rate(a.ip(sim), b.ip(sim), rate),
            Self::Latency { a, b, min, max } => {
                sim.set_link_latency(a.ip(sim), b.ip(sim), min);
                sim.set_link_max_message_latency(a.ip(sim), b.ip(sim), max.max(min));
            }
            Self::Partition(a, b) => sim.partition(a.ip(sim), b.ip(sim)),
            Self::PartitionOneWay { from, to } => {
                sim.partition_oneway(from.ip(sim), to.ip(sim));
            }
            Self::Hold(a, b) => sim.hold(a.ip(sim), b.ip(sim)),
            Self::Release(a, b) => sim.release(a.ip(sim), b.ip(sim)),
            Self::Repair(a, b) => sim.repair(a.ip(sim), b.ip(sim)),
            Self::RepairOneWay { from, to } => sim.repair_oneway(from.ip(sim), to.ip(sim)),
            Self::Crash(server) => sim.crash(Node::from(server).ip(sim)),
            Self::Bounce(server) => sim.bounce(Node::from(server).ip(sim)),
        }
    }
}
