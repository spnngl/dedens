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
    /// A `meta.generated` that is not an RFC 3339 time from 1970 on.
    #[error("generated {0:?} is not a time")]
    Generated(String),
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

/// The TLDs, sorted by name for [`Tlds::get`], and when IANA generated the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlds {
    tlds: Box<[Tld]>,
    generated: u64,
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

    /// When IANA generated the list, its `meta.generated`, in seconds since 1970: how old what it says is.
    #[must_use]
    pub fn generated(&self) -> u64 {
        self.generated
    }

    fn parse(json: &[u8]) -> Result<Self, TldsError> {
        let list: RawList<'_> = serde_json::from_slice(json)?;
        let generated = unix_time(&list.meta.generated)
            .ok_or_else(|| TldsError::Generated(list.meta.generated.clone().into_owned()))?;
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
        Ok(Self {
            tlds: tlds.into(),
            generated,
        })
    }
}

/// Seconds since 1970 of an RFC 3339 time (§5.6), `2026-11-16T23:49:03+00:00`: date, `T`, time, maybe a
/// fraction of a digit or more (dropped), then `Z` or an offset; `None` for another text, a day the month does not
/// have (§5.7) or a time before 1970.
fn unix_time(text: &str) -> Option<u64> {
    let field = |from: usize, to: usize| -> Option<i64> {
        let digits = text.get(from..to)?;
        digits
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| digits.parse().ok())
            .flatten()
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if !separators.iter().all(|&(at, byte)| {
        text.as_bytes()
            .get(at)
            .is_some_and(|b| b.eq_ignore_ascii_case(&byte))
    }) {
        return None;
    }
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, minute, second) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    // The days of each month (§5.7).
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if !(1..=12).contains(&month)
        || !(1..=days).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let rest = text.get(19..)?;
    let zone = match rest.strip_prefix('.') {
        Some(fraction) => {
            let zone = fraction.trim_start_matches(|c: char| c.is_ascii_digit());
            // At least one digit (§5.6).
            if zone.len() == fraction.len() {
                return None;
            }
            zone
        }
        None => rest,
    };
    let offset = match zone.as_bytes() {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (hours, minutes) = (
                field(text.len() - 5, text.len() - 3)?,
                field(text.len() - 2, text.len())?,
            );
            if hours > 23 || minutes > 59 {
                return None;
            }
            let offset = (hours * 60 + minutes) * 60;
            if *sign == b'+' { offset } else { -offset }
        }
        _ => return None,
    };
    // Howard Hinnant's `days_from_civil`.
    let year = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (year.div_euclid(400), year.rem_euclid(400));
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second - offset).ok()
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
    meta: RawMeta<'a>,
    #[serde(borrow)]
    domains: Vec<RawTld<'a>>,
}

#[derive(Deserialize)]
struct RawMeta<'a> {
    #[serde(borrow)]
    generated: Cow<'a, str>,
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
