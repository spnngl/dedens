//! The root's anchors as IANA signs them (RFC 9718 §2.2): every `KeyDigest` with its validity, and when ICANN
//! signed the file, kept by a server in a text of its own between two fetches (D128).

use core::fmt;
use std::collections::{HashMap, HashSet};

use data_encoding::HEXUPPER_PERMISSIVE;
use dedens_proto::rdata::Ds;
use dedens_proto::{DigestType, Name, SecAlgorithm};

use super::{Anchor, TrustAnchors};

/// The first line of the text of [`RootAnchors`]: what it is, and the version of its format.
const HEADER: &str = "dedens root anchors 1";

/// One `KeyDigest` of `root-anchors.xml` (RFC 9718 §2.1.2): the root's DS record, trusted from `validFrom` on and
/// before `validUntil`, in seconds since 1970.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootKey {
    pub(super) ds: Ds<'static>,
    pub(super) valid_from: u64,
    pub(super) valid_until: Option<u64>,
}

impl RootKey {
    /// The DS record.
    #[must_use]
    pub fn ds(&self) -> &Ds<'static> {
        &self.ds
    }

    /// Whether the key is trusted at `now` (RFC 9718 §4.1.1).
    #[must_use]
    pub fn valid_at(&self, now: u64) -> bool {
        self.valid_from <= now && self.valid_until.is_none_or(|until| now < until)
    }
}

/// The root's anchors of a signed `root-anchors.xml`, each with its validity, and when ICANN signed it: what a
/// server keeps of a pair [`TrustAnchors::verified`] checked (D128), written as a text ([`fmt::Display`]) that
/// [`RootAnchors::read`] reads back without the signature.
///
/// ```text
/// dedens root anchors 1
/// signed-at 1742934302
/// ds 19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5 from 1279152000 until 1547164800
/// ds 20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d from 1485993600
/// ds 38696 8 2 683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16 from 1721260800
/// ```
///
/// A key with an end has `until` and that time. The text is as trusted as where it is kept: the
/// signature checked once is not kept with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAnchors {
    pub(super) keys: Vec<RootKey>,
    pub(super) signed_at: u64,
}

/// Why a text is not that of [`RootAnchors`]: its line, from 1, and what is wrong there.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {what}")]
pub struct RootAnchorsError {
    /// The line, from 1.
    pub line: usize,
    /// What is wrong with it.
    pub what: &'static str,
}

impl RootAnchors {
    /// The longest text [`RootAnchors::read`] reads: that of the 64 KiB a `root-anchors.xml` may hold
    /// ([`crate::MAX_XML`]), which lists fewer keys.
    pub const MAX_LEN: usize = 64 << 10;

    /// The keys, as the signed file lists them.
    #[must_use]
    pub fn keys(&self) -> &[RootKey] {
        &self.keys
    }

    /// When ICANN signed the file, in seconds since 1970: the `last_signed_at` of the next
    /// [`TrustAnchors::verified`].
    #[must_use]
    pub fn signed_at(&self) -> u64 {
        self.signed_at
    }

    /// The anchors of the keys valid at `now`, in seconds since 1970; `None` when none is.
    #[must_use]
    pub fn at(&self, now: u64) -> Option<TrustAnchors> {
        valid(&self.keys, now)
    }

    /// The anchors written in `text`, as [`fmt::Display`] writes them: the header line, the signing time, then one
    /// key per line, at least one, each line ending with a line feed. Nothing else is read: not a blank, not a
    /// comment.
    ///
    /// # Errors
    ///
    /// [`RootAnchorsError`] at the first line that is not as written; at line 0 when `text` is longer than
    /// [`RootAnchors::MAX_LEN`], does not end with a line feed or holds no key.
    pub fn read(text: &str) -> Result<Self, RootAnchorsError> {
        if text.len() > Self::MAX_LEN {
            return Err(RootAnchorsError {
                line: 0,
                what: "longer than 64 KiB",
            });
        }
        let body = text.strip_suffix('\n').ok_or(RootAnchorsError {
            line: 0,
            what: "no line feed at the end",
        })?;
        let mut lines = body.split('\n').zip(1..);
        let mut next = |what| lines.next().ok_or(RootAnchorsError { line: 0, what });
        let (header, line) = next("empty")?;
        if header != HEADER {
            return Err(RootAnchorsError {
                line,
                what: "not `dedens root anchors 1`",
            });
        }
        let (signed, line) = next("no signing time")?;
        let signed_at =
            signed
                .strip_prefix("signed-at ")
                .and_then(number)
                .ok_or(RootAnchorsError {
                    line,
                    what: "not `signed-at` and a time",
                })?;
        let keys = lines
            .map(|(text, line)| key(text).ok_or(RootAnchorsError { line, what: KEY }))
            .collect::<Result<Vec<_>, _>>()?;
        if keys.is_empty() {
            return Err(RootAnchorsError {
                line: 0,
                what: "no key",
            });
        }
        Ok(Self { keys, signed_at })
    }
}

/// The root's anchors of the `keys` valid at `now`; `None` when none is.
pub(super) fn valid(keys: &[RootKey], now: u64) -> Option<TrustAnchors> {
    let ds: Vec<_> = keys
        .iter()
        .filter(|key| key.valid_at(now))
        .map(|key| key.ds.clone())
        .collect();
    (!ds.is_empty()).then(|| TrustAnchors {
        zones: HashMap::from([(
            Name::root(),
            Anchor {
                ds,
                dnskeys: Vec::new(),
            },
        )]),
        negative: HashSet::new(),
    })
}

/// What a key's line is when it is not one.
const KEY: &str = "not `ds`, a DS record, `from` and a time, and maybe `until` and a time";

/// The key of `line`, `ds TAG ALGORITHM DIGEST-TYPE DIGEST from TIME [until TIME]`.
fn key(line: &str) -> Option<RootKey> {
    let mut fields = line.split(' ');
    let mut field = || fields.next();
    if field()? != "ds" {
        return None;
    }
    let tag = number(field()?)?;
    let algorithm = SecAlgorithm(number(field()?)?);
    let digest_type = DigestType(number(field()?)?);
    let digest = HEXUPPER_PERMISSIVE.decode(field()?.as_bytes()).ok()?;
    let ds = Ds::new(tag, algorithm, digest_type, &digest)
        .ok()?
        .into_owned();
    if field()? != "from" {
        return None;
    }
    let valid_from = number(field()?)?;
    let valid_until = match field() {
        None => None,
        Some("until") => Some(number(field()?)?),
        Some(_) => return None,
    };
    field().is_none().then_some(RootKey {
        ds,
        valid_from,
        valid_until,
    })
}

/// A decimal number of the type asked, digits only: no sign, no blank.
fn number<T: core::str::FromStr>(text: &str) -> Option<T> {
    text.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| text.parse().ok())
        .flatten()
}

/// The text [`RootAnchors::read`] reads.
impl fmt::Display for RootAnchors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{HEADER}\nsigned-at {}", self.signed_at)?;
        for key in &self.keys {
            write!(f, "ds {} from {}", key.ds, key.valid_from)?;
            if let Some(until) = key.valid_until {
                write!(f, " until {until}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
