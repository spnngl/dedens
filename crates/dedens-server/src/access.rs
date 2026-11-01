//! Client access lists (D91): which networks the server answers, so that it is no open resolver (RFC 5358 §4).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::joint::map::JointPrefixMap;

use crate::metrics::Denied;

/// A network, `ADDRESS/LENGTH`, with no bit set past its length: `192.0.2.1/24` is refused, for it names the host
/// of `192.0.2.0/24`, which is likely what was meant. An IPv6 network matches IPv6 clients only, an IPv4 one IPv4
/// clients only, an IPv4-mapped IPv6 client counting as the IPv4 one (RFC 4291 §2.5.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(try_from = "String")
)]
pub struct Network(IpNet);

/// Why a text is no [`Network`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NetworkError {
    /// Not an address, a slash and a length of its family.
    #[error("`{0}` is not ADDRESS/LENGTH")]
    Malformed(String),
    /// Bits set past the length: the network meant is `meant`.
    #[error("`{given}` has bits set past its length: did you mean `{meant}`?")]
    HostBits {
        /// The text read.
        given: String,
        /// The network with those bits cleared.
        meant: Network,
    },
    /// An IPv6 network of fewer than 96 bits that starts inside `::ffff:0:0/96`, the IPv4-mapped addresses: it
    /// would read as a wider network than it matches, as its clients are read as IPv4 ones.
    #[error(
        "`{0}` starts in the IPv4-mapped range `::ffff:0:0/96`: write the IPv4 network instead"
    )]
    MappedRange(String),
    /// An IPv4-mapped IPv6 network, which no client matches, as its clients are read as IPv4 ones: the network
    /// meant is `meant`.
    #[error("`{given}` is an IPv4 network written as IPv6: did you mean `{meant}`?")]
    Mapped {
        /// The text read.
        given: String,
        /// The same network in IPv4.
        meant: Network,
    },
}

impl FromStr for Network {
    type Err = NetworkError;

    fn from_str(text: &str) -> Result<Self, NetworkError> {
        let malformed = || NetworkError::Malformed(text.to_owned());
        let net: IpNet = text.parse().map_err(|_| malformed())?;
        let given = || text.to_owned();
        if let IpNet::V6(v6) = net
            && let Some(v4) = v6.addr().to_ipv4_mapped()
        {
            return Err(match v6.prefix_len().checked_sub(MAPPED_LEN) {
                Some(len) => NetworkError::Mapped {
                    given: given(),
                    meant: Self(IpNet::V4(
                        Ipv4Net::new(v4, len).map_err(|_| malformed())?.trunc(),
                    )),
                },
                None => NetworkError::MappedRange(given()),
            });
        }
        let meant = net.trunc();
        if meant == net {
            Ok(Self(net))
        } else {
            Err(NetworkError::HostBits {
                given: given(),
                meant: Self(meant),
            })
        }
    }
}

impl TryFrom<String> for Network {
    type Error = NetworkError;

    fn try_from(text: String) -> Result<Self, NetworkError> {
        text.parse()
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The length of the prefix `::ffff:0:0/96` of IPv4-mapped addresses.
const MAPPED_LEN: u8 = 96;

/// What a denied client gets (D91).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(rename_all = "lowercase")
)]
pub enum Denial {
    /// REFUSED with the extended error Prohibited (RFC 8914 §4.19): the client learns it is not served.
    #[default]
    Refuse,
    /// Nothing: the client waits and retries, and a forged source gets no reply to amplify.
    Drop,
}

/// What the longest network holding an address says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    Allow,
    Deny,
}

/// The networks a server answers, and what a client outside them gets (D91).
///
/// The longest network holding the address decides; `deny` wins when both lists hold the same network; an address
/// in no network is denied. The networks sit in a longest-prefix tree, so a lookup costs the address's length at
/// most, however many networks there are.
#[derive(Clone)]
pub struct Access {
    table: JointPrefixMap<IpNet, Rule>,
    denial: Denial,
    denied: Denied,
}

impl fmt::Debug for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Access")
            .field("table", &self.table)
            .field("denial", &self.denial)
            .finish_non_exhaustive()
    }
}

/// The networks of [`Access::local`]: loopback (RFC 1122 §3.2.1.3, RFC 4291 §2.5.3), private (RFC 1918 §3, RFC 4193
/// §3), and link-local (RFC 3927 §2.1, RFC 4291 §2.5.6).
const LOCAL: [IpNet; 8] = [
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(10, 0, 0, 0), 8)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 12)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(192, 168, 0, 0), 16)),
    IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16)),
    IpNet::V6(Ipv6Net::new_assert(Ipv6Addr::LOCALHOST, 128)),
    IpNet::V6(Ipv6Net::new_assert(
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        7,
    )),
    IpNet::V6(Ipv6Net::new_assert(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        10,
    )),
];

impl Access {
    /// Allows `allow` but for `deny`, and answers a client outside them as `denial` says.
    #[must_use]
    pub fn new(
        allow: impl IntoIterator<Item = Network>,
        deny: impl IntoIterator<Item = Network>,
        denial: Denial,
    ) -> Self {
        // Denied last: the same network in both lists is denied.
        let rules = allow
            .into_iter()
            .map(|Network(net)| (net, Rule::Allow))
            .chain(deny.into_iter().map(|Network(net)| (net, Rule::Deny)));
        Self {
            table: rules.collect(),
            denial,
            denied: Denied::new(),
        }
    }

    /// Allows the local networks alone, loopback, private and link-local ones: what a server answers when no list
    /// was written, so that it is no open resolver whatever the address it listens on.
    #[must_use]
    pub fn local(denial: Denial) -> Self {
        Self::new(LOCAL.map(Network), [], denial)
    }

    /// Whether the client at `from` is answered.
    #[must_use]
    pub fn permits(&self, from: IpAddr) -> bool {
        self.table
            .get_lpm(&IpNet::from(from.to_canonical()))
            .is_some_and(|(_, rule)| *rule == Rule::Allow)
    }

    /// What a denied client gets.
    #[must_use]
    pub const fn denial(&self) -> Denial {
        self.denial
    }

    /// Whether the client at `from` is denied, counting the denial.
    pub(crate) fn deny(&self, from: IpAddr) -> bool {
        let denied = !self.permits(from);
        if denied {
            self.denied.count(self.denial);
        }
        denied
    }
}
