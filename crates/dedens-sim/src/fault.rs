//! Faults: what a scenario does to the network and to the hosts, and when ([`World::fault`]).
//!
//! turmoil's links do not lose packets one by one: [`Fault::Loss`] breaks a link at a rate for each tick of the
//! simulation, and what is on it, or sent while it is broken, is lost. Reordering comes from [`Fault::Latency`]: each
//! message of a link waits a time drawn from the seed between the two bounds, so a later one may arrive first.
//!
//! [`World::fault`]: crate::topology::World::fault

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
    /// The client added in that order to the world.
    Client(usize),
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
    /// The name the host has in the simulation.
    pub(crate) fn name(self) -> String {
        match self {
            Self::Resolver => "resolver".to_owned(),
            Self::Upstream(n) => format!("upstream-{n}"),
            Self::Client(n) => format!("client-{n}"),
        }
    }
}

/// One change to the network or to a host, made at a time of the run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fault {
    /// From now on, each tick the link between the hosts breaks with probability `rate`, and is repaired the next
    /// tick (turmoil's default): a message is lost when it is on the link at that tick. 0 ends it.
    Loss {
        /// One end of the link.
        a: Node,
        /// The other end.
        b: Node,
        /// The probability, from 0 to 1, for each tick.
        rate: f64,
    },
    /// From now on, each message of the link takes a time from `min` to `max`, drawn from the seed.
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
    /// Lets messages through again, both ways: what a partition dropped stays lost.
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
            Self::Loss { a, b, rate } => sim.set_link_fail_rate(a.name(), b.name(), rate),
            Self::Latency { a, b, min, max } => {
                sim.set_link_latency(a.name(), b.name(), min);
                sim.set_link_max_message_latency(a.name(), b.name(), max.max(min));
            }
            Self::Partition(a, b) => sim.partition(a.name(), b.name()),
            Self::PartitionOneWay { from, to } => sim.partition_oneway(from.name(), to.name()),
            Self::Hold(a, b) => sim.hold(a.name(), b.name()),
            Self::Release(a, b) => sim.release(a.name(), b.name()),
            Self::Repair(a, b) => sim.repair(a.name(), b.name()),
            Self::RepairOneWay { from, to } => sim.repair_oneway(from.name(), to.name()),
            Self::Crash(server) => sim.crash(Node::from(server).name()),
            Self::Bounce(server) => sim.bounce(Node::from(server).name()),
        }
    }
}
