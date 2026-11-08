//! An attacker on an upstream server's host: it shares the server's port 53 socket, as turmoil cannot spoof a source
//! address, so what it sends reaches the resolver as if the server had: the source address of the response, which
//! RFC 5452 §4.4 and §9.1 have the resolver match, is the one thing it cannot get wrong. turmoil gives ephemeral
//! ports in sequence: a scenario whose attacker must guess the resolver's port may as well know it.

use std::fmt;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

/// What the server just received, for the attacker to react to.
#[derive(Debug, Clone, Copy)]
pub struct Seen<'a> {
    /// The datagram: a query, or what is no query.
    pub query: &'a [u8],
    /// Where it came from.
    pub from: SocketAddr,
    /// What the server answers it, with the ID of the query, if it answers.
    pub genuine: Option<&'a [u8]>,
}

/// A datagram the attacker sends to the sender of the query, from the server's address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injection {
    /// How long after the query it goes out: 0 races the server's answer, a later one is late.
    pub after: Duration,
    /// The datagram: forged, a copy of the answer, or anything else.
    pub wire: Vec<u8>,
}

/// What an attacker does about a datagram it saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    /// What it sends.
    pub injections: Vec<Injection>,
    /// Whether the server sends its own answer: `false` is an attacker that has silenced it, so that the
    /// resolver gets the forgery alone, or nothing.
    pub genuine: bool,
}

impl Reaction {
    /// Sends `injections` beside the server's answer: a race.
    #[must_use]
    pub const fn beside(injections: Vec<Injection>) -> Self {
        Self {
            injections,
            genuine: true,
        }
    }

    /// Sends `injections` in place of the server's answer.
    #[must_use]
    pub const fn instead(injections: Vec<Injection>) -> Self {
        Self {
            injections,
            genuine: false,
        }
    }
}

/// What an attacker does for a datagram it saw.
type React = dyn Fn(&Seen<'_>) -> Reaction;

/// What the attacker sends for each datagram the server receives over UDP. The test gives it: the attacker has no
/// knowledge of DNS of its own.
#[derive(Clone)]
pub struct Attacker(Rc<React>);

impl Attacker {
    /// An attacker that sends what `react` returns.
    #[must_use]
    pub fn new(react: impl Fn(&Seen<'_>) -> Reaction + 'static) -> Self {
        Self(Rc::new(react))
    }

    /// What it sends for `seen`.
    pub(crate) fn react(&self, seen: &Seen<'_>) -> Reaction {
        (self.0)(seen)
    }
}

impl fmt::Debug for Attacker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Attacker(..)")
    }
}
