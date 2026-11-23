//! Zone access lists (D211): who may transfer a zone (RFC 5936 §5, RFC 9103 §9.4), notify the server of its
//! changes (RFC 1996 §5) or update it (RFC 2136 §3.3), by network and TSIG key (RFC 8945). The handlers that ask
//! are steps of their own; a refusal is theirs to answer, REFUSED with EDE 18 (Prohibited, RFC 8914 §4.19).

use std::net::IpAddr;

use dedens_proto::Name;
use dedens_tsig::{Algorithm, Key};

use crate::access::Network;
use crate::pipeline::VerifiedKey;

/// What a client asks of a zone that the zone's access lists guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// AXFR or IXFR of the zone (RFC 5936 §5, RFC 1995).
    Transfer,
    /// NOTIFY of a change to the zone (RFC 1996 §5).
    Notify,
    /// UPDATE of the zone (RFC 2136 §3.3).
    Update,
}

/// A line of an access list: the clients in one of `networks` whose request is signed with `key`, or, without a
/// key, is unsigned. A signed request matches only a line naming its key, by name and algorithm: Knot's
/// `check_addr_key` (`src/knot/updates/acl.c`) and NSD's `acl_key_matches` (`nsd/options.c`) match so.
#[derive(Debug, Clone)]
pub struct Grant {
    networks: Box<[Network]>,
    key: Option<(Name<'static>, Algorithm)>,
}

impl Grant {
    /// The clients in one of `networks`, their requests signed with `key`, or unsigned when `key` is `None`. No
    /// network matches no client.
    #[must_use]
    pub fn new(networks: impl IntoIterator<Item = Network>, key: Option<&Key>) -> Self {
        Self {
            networks: networks.into_iter().collect(),
            key: key.map(|key| (key.name().clone(), key.algorithm())),
        }
    }

    /// Whether the request from `from`, signed with `key` if any, is one of this line's.
    fn matches(&self, from: IpAddr, key: Option<&Key>) -> bool {
        let signer = key.map(|key| (key.name(), key.algorithm()));
        self.key
            .as_ref()
            .map(|(name, algorithm)| (name, *algorithm))
            == signer
            && self.networks.iter().any(|network| network.contains(from))
    }
}

/// The access lists of a zone, one per [`Action`]: a request is permitted when a [`Grant`] of the action's list
/// matches it. The lists are empty by default: nothing is permitted, as RFC 5936 §5 asks of transfers.
#[derive(Debug, Clone, Default)]
pub struct ZoneAccess {
    transfer: Box<[Grant]>,
    notify: Box<[Grant]>,
    update: Box<[Grant]>,
}

impl ZoneAccess {
    /// The same lists, but for `action`'s, which is `grants`.
    #[must_use]
    pub fn with(mut self, action: Action, grants: impl IntoIterator<Item = Grant>) -> Self {
        *self.list_mut(action) = grants.into_iter().collect();
        self
    }

    /// Whether the client at `from`, its request verified as signed with `key` or unsigned, may do `action` to
    /// the zone. The key is a [`VerifiedKey`]: nothing but a verification makes one. An IPv4-mapped IPv6 address is the IPv4 one. The lists are searched in order, each network of each
    /// line: their length is bounded where they are written (D115).
    #[must_use]
    pub fn permits(&self, action: Action, from: IpAddr, key: Option<VerifiedKey<'_>>) -> bool {
        let key = key.map(VerifiedKey::key);
        self.list(action)
            .iter()
            .any(|grant| grant.matches(from, key))
    }

    fn list(&self, action: Action) -> &[Grant] {
        match action {
            Action::Transfer => &self.transfer,
            Action::Notify => &self.notify,
            Action::Update => &self.update,
        }
    }

    const fn list_mut(&mut self, action: Action) -> &mut Box<[Grant]> {
        match action {
            Action::Transfer => &mut self.transfer,
            Action::Notify => &mut self.notify,
            Action::Update => &mut self.update,
        }
    }
}
