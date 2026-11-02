//! What happened in a run, in order: the events the hosts record, which a scenario asserts on and which two runs
//! of one seed must repeat.

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use dedens_net::exchange::Failure;
use dedens_proto::{Question, Rcode, Transport};

use crate::fault::Fault;

/// One thing that happened, when and to which host.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Simulated time since the start of the run.
    pub at: Duration,
    /// The host it happened on.
    pub host: IpAddr,
    /// What happened.
    pub what: What,
}

/// What a host did.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum What {
    /// A client sent the resolver a query.
    Asked {
        /// The question.
        question: Question<'static>,
        /// The transport of its first query.
        transport: Transport,
    },
    /// A client's query ended with a response.
    Answered {
        /// The question.
        question: Question<'static>,
        /// The response code.
        rcode: Rcode,
        /// Records in the answer section.
        answers: usize,
        /// The transport the response came over: TCP after a truncated one over UDP.
        transport: Transport,
    },
    /// A client's query ended without a response.
    Failed {
        /// The question.
        question: Question<'static>,
        /// Why.
        failure: Failure,
    },
    /// The resolver sent an upstream server a query.
    Forwarded {
        /// The server.
        server: SocketAddr,
        /// The transport of the query.
        transport: Transport,
    },
    /// An upstream server answered a query.
    Served {
        /// The question.
        question: Question<'static>,
        /// The transport it came over.
        transport: Transport,
    },
    /// The attacker on an upstream server's host sent a datagram to `to`.
    Injected {
        /// Who it went to: the sender of the query.
        to: SocketAddr,
        /// The delay the attacker was given.
        after: Duration,
    },
    /// The scenario changed the network or a host. Recorded on the unspecified address: the network.
    Fault(Fault),
}

/// A number standing for `events`, the same in every process for the same events: FNV-1a over their text. Two
/// runs of one seed in two processes are the same when their digests are.
#[must_use]
pub fn digest(events: &[Event]) -> u64 {
    format!("{events:?}")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
}

/// The events of a run, shared by its hosts: they all run on the one thread.
#[derive(Debug, Clone, Default)]
pub struct Trace(Rc<RefCell<Vec<Event>>>);

impl Trace {
    /// An empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `host` did `what`, now.
    pub fn record(&self, host: IpAddr, what: What) {
        self.record_at(turmoil::sim_elapsed().unwrap_or_default(), host, what);
    }

    /// Records that `host` did `what` at `at`.
    pub(crate) fn record_at(&self, at: Duration, host: IpAddr, what: What) {
        self.0.borrow_mut().push(Event { at, host, what });
    }

    /// The events so far, in order.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.0.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn events(rcode: Rcode) -> Vec<Event> {
        let question = crate::stub::question("example.com", dedens_proto::RecordType::A);
        vec![Event {
            at: Duration::from_millis(3),
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            what: What::Answered {
                question,
                rcode,
                answers: 2,
                transport: Transport::Udp,
            },
        }]
    }

    #[test]
    fn the_digest_follows_the_events() {
        assert_eq!(
            digest(&events(Rcode::NOERROR)),
            digest(&events(Rcode::NOERROR))
        );
        assert_ne!(
            digest(&events(Rcode::NOERROR)),
            digest(&events(Rcode::SERVFAIL))
        );
        assert_ne!(digest(&events(Rcode::NOERROR)), digest(&[]));
        // FNV-1a of `[]`, the text of no events.
        assert_eq!(digest(&[]), 0x0961_2b07_b5ec_b5a5);
    }
}
