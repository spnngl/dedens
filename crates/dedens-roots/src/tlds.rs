//! IANA's TLD list, `tlds.json` (schema <https://data.iana.org/TLD/v1/tlds-schema.json>): each top-level domain's
//! type, status, name servers and DS records.

use core::cmp::Ordering;
use core::net::{Ipv4Addr, Ipv6Addr};
use std::borrow::Cow;
use std::sync::LazyLock;

use dedens_proto::rdata::{Ds, DsError};
use dedens_proto::{DigestType, Name, NameError, SecAlgorithm, TextError};
use serde::Deserialize;

use crate::server::Server;

/// IANA's TLD list, <https://data.iana.org/TLD/v1/tlds.json>, cut by `just roots` to the members read here.
const BUNDLED: &[u8] = include_bytes!("tlds.json");

/// Why a copy of the TLD list is refused; each variant but the first two names its TLD.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TldsError {
    /// Not JSON, or not of the schema: a member missing or of another type, a status or type unknown.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Fewer TLDs than half the bundled list: a copy cut short, not the root zone shrinking.
    #[error("{read} TLDs, fewer than half the {bundled} bundled")]
    Truncated {
        /// The TLDs in the copy.
        read: usize,
        /// The TLDs in the bundled list.
        bundled: usize,
    },
    /// A TLD whose name is not a label.
    #[error("TLD {tld:?}: {error}")]
    Name {
        /// The TLD as written.
        tld: String,
        /// What is wrong with it.
        error: NameError,
    },
    /// A TLD listed twice, whatever the case.
    #[error("TLD {tld:?} listed twice")]
    Duplicate {
        /// The TLD as written.
        tld: String,
    },
    /// A name server whose name is not a domain name.
    #[error("TLD {tld:?}: name server {server:?}: {error}")]
    Server {
        /// The TLD as written.
        tld: String,
        /// The name server as written.
        server: String,
        /// What is wrong with it.
        error: TextError,
    },
    /// A DS digest that is not hexadecimal, or not a digest.
    #[error("TLD {tld:?}: DS digest {digest:?} is not a digest")]
    Digest {
        /// The TLD as written.
        tld: String,
        /// The digest as written.
        digest: String,
    },
}

/// Where a TLD stands in the root zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Status {
    /// Delegated.
    Active,
    /// Once delegated, now removed.
    Retired,
    /// Not delegated, open to an application.
    Eligible,
    /// Not delegated, held back.
    Reserved,
}

/// The status as IANA's list words it: `active`, `retired`, `eligible`, `reserved`.
impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Eligible => "eligible",
            Self::Reserved => "reserved",
        })
    }
}

/// What a TLD is for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A generic TLD.
    Generic,
    /// A country-code TLD.
    CountryCode,
    /// A special-use name (RFC 6761), with what IANA says it is for.
    SpecialUse {
        /// IANA's line on its use.
        purpose: Option<Box<str>>,
    },
    /// A test TLD.
    Test,
}

/// The kind in words: `generic`, `country code`, `special use`, `test`; the purpose is not part of it.
impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Generic => "generic",
            Self::CountryCode => "country code",
            Self::SpecialUse { .. } => "special use",
            Self::Test => "test",
        })
    }
}

/// A top-level domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tld {
    name: Name<'static>,
    kind: Kind,
    status: Status,
    servers: Box<[Server]>,
    ds: Box<[Ds<'static>]>,
}

impl Tld {
    /// Its name, one label.
    #[must_use]
    pub const fn name(&self) -> &Name<'static> {
        &self.name
    }

    /// What it is for.
    #[must_use]
    pub const fn kind(&self) -> &Kind {
        &self.kind
    }

    /// Where it stands in the root zone.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    /// Its name servers, with their glue.
    #[must_use]
    pub fn servers(&self) -> &[Server] {
        &self.servers
    }

    /// Its DS records, hints until checked against the root zone's signed ones (D126).
    #[must_use]
    pub fn ds(&self) -> &[Ds<'static>] {
        &self.ds
    }

    fn label(&self) -> &[u8] {
        self.name.labels().next().unwrap_or_default()
    }
}

/// The TLDs, sorted by name for [`Tlds::get`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlds {
    tlds: Box<[Tld]>,
}

impl Tlds {
    /// The list bundled, read once.
    ///
    /// # Panics
    ///
    /// Never: the bundled `tlds.json` is read by the tests.
    #[must_use]
    pub fn bundled() -> &'static Self {
        static TLDS: LazyLock<Tlds> =
            LazyLock::new(|| Tlds::parse(BUNDLED).expect("the bundled tlds.json is valid"));
        &TLDS
    }

    /// The list in `json`, a `tlds.json` of schema version 1; members not read here are ignored.
    ///
    /// # Errors
    ///
    /// [`TldsError`] when `json` does not follow the schema, holds a TLD that is not a label, twice, or with a
    /// server name or a DS digest that is not one; and [`TldsError::Truncated`] when it holds fewer than half the
    /// TLDs bundled.
    pub fn read(json: &[u8]) -> Result<Self, TldsError> {
        let tlds = Self::parse(json)?;
        let bundled = Self::bundled().tlds.len();
        if tlds.tlds.len() < bundled.div_ceil(2) {
            return Err(TldsError::Truncated {
                read: tlds.tlds.len(),
                bundled,
            });
        }
        Ok(tlds)
    }

    /// The TLD of `name`, its last label whatever the case (RFC 4343); none for the root or a TLD not listed.
    #[must_use]
    pub fn get(&self, name: &Name<'_>) -> Option<&Tld> {
        let label = name.labels().last()?;
        let at = self
            .tlds
            .binary_search_by(|tld| compare(tld.label(), label))
            .ok()?;
        self.tlds.get(at)
    }

    /// The TLDs, by name.
    pub fn iter(&self) -> core::slice::Iter<'_, Tld> {
        self.tlds.iter()
    }

    fn parse(json: &[u8]) -> Result<Self, TldsError> {
        let list: RawList<'_> = serde_json::from_slice(json)?;
        let mut tlds = list
            .domains
            .into_iter()
            .map(RawTld::typed)
            .collect::<Result<Vec<_>, _>>()?;
        tlds.sort_unstable_by(|a, b| compare(a.label(), b.label()));
        for pair in tlds.windows(2) {
            if let [a, b] = pair
                && compare(a.label(), b.label()).is_eq()
            {
                return Err(TldsError::Duplicate {
                    tld: String::from_utf8_lossy(b.label()).into_owned(),
                });
            }
        }
        Ok(Self { tlds: tlds.into() })
    }
}

impl<'t> IntoIterator for &'t Tlds {
    type Item = &'t Tld;
    type IntoIter = core::slice::Iter<'t, Tld>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The order of labels whatever their ASCII case (RFC 4343).
fn compare(a: &[u8], b: &[u8]) -> Ordering {
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

#[derive(Deserialize)]
struct RawList<'a> {
    #[serde(borrow)]
    domains: Vec<RawTld<'a>>,
}

#[derive(Deserialize)]
struct RawTld<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    status: Status,
    #[serde(rename = "type")]
    kind: RawKind,
    #[serde(borrow)]
    nameservers: Vec<RawServer<'a>>,
    #[serde(borrow)]
    ds_records: Vec<RawDs<'a>>,
    #[serde(default, borrow)]
    purpose: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawKind {
    Generic,
    CountryCode,
    SpecialUse,
    Test,
}

#[derive(Deserialize)]
struct RawServer<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
}

#[derive(Deserialize)]
struct RawDs<'a> {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    #[serde(borrow)]
    digest: Cow<'a, str>,
}

impl RawTld<'_> {
    fn typed(self) -> Result<Tld, TldsError> {
        let tld = || self.name.clone().into_owned();
        let name = Name::from_labels([self.name.as_bytes()])
            .map_err(|error| TldsError::Name { tld: tld(), error })?;
        let servers = self.nameservers.iter().map(|server| {
            let name = server.name.parse().map_err(|error| TldsError::Server {
                tld: tld(),
                server: server.name.clone().into_owned(),
                error,
            })?;
            Ok::<_, TldsError>(Server {
                name,
                ipv4: server.ipv4.as_slice().into(),
                ipv6: server.ipv6.as_slice().into(),
            })
        });
        let ds = self.ds_records.iter().map(|ds| {
            let invalid = || TldsError::Digest {
                tld: tld(),
                digest: ds.digest.clone().into_owned(),
            };
            let digest = data_encoding::HEXLOWER_PERMISSIVE
                .decode(ds.digest.as_bytes())
                .map_err(|_| invalid())?;
            let typed = Ds::new(
                ds.key_tag,
                SecAlgorithm(ds.algorithm),
                DigestType(ds.digest_type),
                &digest,
            );
            typed.map(Ds::into_owned).map_err(|_: DsError| invalid())
        });
        Ok(Tld {
            name,
            kind: match self.kind {
                RawKind::Generic => Kind::Generic,
                RawKind::CountryCode => Kind::CountryCode,
                RawKind::SpecialUse => Kind::SpecialUse {
                    purpose: self.purpose.as_deref().map(Box::from),
                },
                RawKind::Test => Kind::Test,
            },
            status: self.status,
            servers: servers.collect::<Result<_, _>>()?,
            ds: ds.collect::<Result<_, _>>()?,
        })
    }
}
