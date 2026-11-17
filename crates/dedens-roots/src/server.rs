//! A name server of the root or of a TLD, with its addresses.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::Name;

/// A name server and the addresses the hints give it: none when they give no glue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub(crate) name: Name<'static>,
    pub(crate) ipv4: Box<[Ipv4Addr]>,
    pub(crate) ipv6: Box<[Ipv6Addr]>,
}

impl Server {
    /// Its name.
    #[must_use]
    pub const fn name(&self) -> &Name<'static> {
        &self.name
    }

    /// Its IPv4 addresses.
    #[must_use]
    pub fn ipv4(&self) -> &[Ipv4Addr] {
        &self.ipv4
    }

    /// Its IPv6 addresses.
    #[must_use]
    pub fn ipv6(&self) -> &[Ipv6Addr] {
        &self.ipv6
    }

    /// Its addresses, IPv4 first.
    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        let v4 = self.ipv4.iter().copied().map(IpAddr::V4);
        v4.chain(self.ipv6.iter().copied().map(IpAddr::V6))
    }
}
