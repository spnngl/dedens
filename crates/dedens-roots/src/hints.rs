//! Root hints: the root servers a resolver primes from (RFC 8109 §2), as IANA's `named.root` lists them.

use core::net::IpAddr;
use std::sync::LazyLock;

use dedens_proto::rdata::RData;
use dedens_proto::{Name, RecordType, TextError, ZoneEntry, ZoneReader};

use crate::server::Server;

/// IANA's root hints, <https://www.internic.net/domain/named.root>, written by `just roots`.
const BUNDLED: &str = include_str!("named.root");

/// Why a copy of the root hints is refused; each variant names its line, from 1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HintsError {
    /// The text is not valid zone text (RFC 1035 §5), or a record in it is not.
    #[error(transparent)]
    Text(#[from] TextError),
    /// A `$INCLUDE`: the library reads no file.
    #[error("line {line}: only records are read, no $INCLUDE")]
    NotARecord {
        /// Where the entry ends.
        line: usize,
    },
    /// A record that is not an NS at the root, an A or an AAAA: not root hints.
    #[error(
        "line {line}: a {rtype} record, root hints hold NS records at the root and their addresses"
    )]
    Unexpected {
        /// Where the record ends.
        line: usize,
        /// Its type.
        rtype: RecordType,
    },
    /// No root server with an address: nowhere to prime from.
    #[error("no root server with an address")]
    Empty,
}

/// The root servers, in the order of their NS records, each with the A and AAAA records the hints give its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootHints {
    servers: Box<[Server]>,
}

impl RootHints {
    /// The hints bundled, read once.
    ///
    /// # Panics
    ///
    /// Never: the bundled `named.root` is read by the tests.
    #[must_use]
    pub fn bundled() -> &'static Self {
        static HINTS: LazyLock<RootHints> = LazyLock::new(|| {
            RootHints::read(BUNDLED.as_bytes()).expect("the bundled named.root is valid hints")
        });
        &HINTS
    }

    /// The hints written in `text`, zone text as `named.root` is (RFC 1035 §5): NS records at the root, the A and
    /// AAAA records of their names. An address of a name no NS record names is left out.
    ///
    /// # Errors
    ///
    /// [`HintsError`] at the first line that is not valid zone text, is a `$INCLUDE` or holds another record; and
    /// [`HintsError::Empty`] when no root server has an address.
    pub fn read(text: &[u8]) -> Result<Self, HintsError> {
        let mut reader = ZoneReader::new(text, Some(Name::root()));
        let (mut servers, mut addresses) = (Vec::new(), Vec::new());
        while let Some(entry) = reader.next() {
            let line = reader.line();
            let ZoneEntry::Record(decoded) = entry? else {
                return Err(HintsError::NotARecord { line });
            };
            let record = decoded.record;
            match record.data() {
                RData::Ns(name) if record.name.is_root() => servers.push(Server {
                    name: name.into_owned(),
                    ipv4: Box::default(),
                    ipv6: Box::default(),
                }),
                RData::A(ip) => addresses.push((record.name.clone().into_owned(), IpAddr::V4(ip))),
                RData::Aaaa(ip) => {
                    addresses.push((record.name.clone().into_owned(), IpAddr::V6(ip)));
                }
                _ => {
                    return Err(HintsError::Unexpected {
                        line,
                        rtype: record.rtype(),
                    });
                }
            }
        }
        for server in &mut servers {
            let (mut ipv4, mut ipv6) = (Vec::new(), Vec::new());
            for (_, ip) in addresses.iter().filter(|(owner, _)| *owner == server.name) {
                match *ip {
                    IpAddr::V4(ip) => ipv4.push(ip),
                    IpAddr::V6(ip) => ipv6.push(ip),
                }
            }
            (server.ipv4, server.ipv6) = (ipv4.into(), ipv6.into());
        }
        if servers
            .iter()
            .all(|server| server.addresses().next().is_none())
        {
            return Err(HintsError::Empty);
        }
        Ok(Self {
            servers: servers.into(),
        })
    }

    /// The root servers.
    #[must_use]
    pub fn servers(&self) -> &[Server] {
        &self.servers
    }
}
