//! Trust anchors (RFC 4035 §4.4, RFC 7646, D72); [`TrustAnchors`] says what they are.

#[cfg(feature = "fetch-anchors")]
mod signature;
#[cfg(feature = "fetch-anchors")]
mod xml;

use std::collections::{HashMap, HashSet};

use dedens_proto::rdata::{Dnskey, Ds, RData};
use dedens_proto::{Class, DecodeError, Name, RecordType, TextError, Ttl, ZoneEntry, ZoneReader};
#[cfg(feature = "fetch-anchors")]
pub use signature::{MAX_P7S, MAX_XML, SignedAnchorError};
#[cfg(feature = "fetch-anchors")]
pub use xml::AnchorXmlError;

/// The root's DS records, written by `just roots` from IANA's `root-anchors.xml` (RFC 9718 §2).
const ROOT: &str = include_str!("root.ds");

/// ICANN's CA certificates, which issue the certificate signing `root-anchors.xml` (RFC 9718 §3.2): IANA's
/// `https://data.iana.org/root-anchors/icannbundle.pem`, copied by hand once checked out of band (D127).
#[cfg(feature = "fetch-anchors")]
const ICANN_CA: &str = include_str!("icannbundle.pem");

/// When ICANN signed the `root-anchors.xml` that `src/root.ds` was read from, in seconds since 1970, written by
/// `just roots`: the earliest signing time [`TrustAnchors::verified`] accepts (D127).
#[cfg(feature = "fetch-anchors")]
#[expect(clippy::unreadable_literal, reason = "a number `just roots` writes")]
const ROOT_SIGNED_AT: u64 = include!("root.signed_at");

/// The anchors of a signed `root-anchors.xml` and when ICANN signed it (RFC 5652 §11.3).
#[cfg(feature = "fetch-anchors")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAnchors {
    /// The anchors, as [`TrustAnchors::from_unverified_xml`] reads them.
    pub anchors: TrustAnchors,
    /// The signing time, in seconds since 1970: the `last_signed_at` of the next [`TrustAnchors::verified`].
    pub signed_at: u64,
}

/// The records that anchor one zone (RFC 4035 §4.4): at least one, as only [`TrustAnchors::read`] makes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    ds: Vec<Ds<'static>>,
    dnskeys: Vec<Dnskey<'static>>,
}

impl Anchor {
    /// The DS records, each trusted through the zone's DNSKEY it matches.
    #[must_use]
    pub fn ds(&self) -> &[Ds<'static>] {
        &self.ds
    }

    /// The DNSKEY records, trusted as is.
    #[must_use]
    pub fn dnskeys(&self) -> &[Dnskey<'static>] {
        &self.dnskeys
    }
}

/// Why anchor text is refused (RFC 4035 §4.4); each variant names its line, from 1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorError {
    /// The text is not valid zone text (RFC 1035 §5), or a record in it is not.
    #[error(transparent)]
    Text(#[from] TextError),
    /// A record that is neither a DS nor a DNSKEY: no other record anchors a zone (RFC 4035 §4.4). A CDS or a
    /// CDNSKEY is another type.
    #[error("line {line}: a {rtype} record, a trust anchor is a DS or a DNSKEY")]
    NotAnAnchor {
        /// Where the record ends.
        line: usize,
        /// Its type.
        rtype: RecordType,
    },
    /// A record of a class other than IN: DNSSEC trust anchors are Internet ones.
    #[error("line {line}: class {class}, a trust anchor is class IN")]
    NotInternet {
        /// Where the record ends.
        line: usize,
        /// Its class.
        class: Class,
    },
    /// DS or DNSKEY data written `\# length hex` that is not valid for its type: it would anchor nothing.
    #[error("line {line}: invalid {rtype} data: {reason}")]
    InvalidData {
        /// Where the record ends.
        line: usize,
        /// Its type.
        rtype: RecordType,
        /// What is wrong, an offset in the data.
        reason: DecodeError,
    },
    /// An entry that is not a record, a `$INCLUDE`: the library reads no file.
    #[error("line {line}: only records are read, no $INCLUDE")]
    NotARecord {
        /// Where the entry ends.
        line: usize,
    },
    /// No record at all: a validator with no anchor would call every answer insecure.
    #[error("no DS or DNSKEY record")]
    Empty,
}

/// The trust anchors of a validator: the keys validation starts from (RFC 4033 §2, RFC 4035 §4.4), one
/// [`Anchor`] per zone, and negative trust anchors, the names below which it stops (RFC 7646).
///
/// An anchor is DS records, DNSKEY records or both, per zone. A DNSKEY anchor is trusted as is; a DS anchor is
/// trusted through the DNSKEY that matches it (RFC 4035 §4.4), which is the validator's check, not this type's.
/// The root's anchors are bundled ([`TrustAnchors::root`], RFC 9718), or read from IANA's signed
/// `root-anchors.xml` with the `fetch-anchors` feature (`TrustAnchors::verified`, D127); a user's come from zone
/// text ([`TrustAnchors::read`]). Anchors do not change while running: RFC 5011 is left out (D72).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchors {
    zones: HashMap<Name<'static>, Anchor>,
    negative: HashSet<Name<'static>>,
}

impl TrustAnchors {
    /// The root zone's anchors, bundled: the DS records IANA publishes (RFC 9718 §2.2) that were valid when
    /// `just roots` last ran.
    ///
    /// # Panics
    ///
    /// Never: the bundled `root.ds` is read by the tests.
    #[must_use]
    pub fn root() -> Self {
        Self::read(ROOT).expect("the bundled root.ds is valid anchor text")
    }

    /// The anchors written in `text`, zone text of DS and DNSKEY records as Unbound's `trust-anchor-file` holds:
    /// owners absolute (or after an `$ORIGIN`), TTL and class optional (class IN, TTL 0). Comments and blank lines
    /// are free.
    ///
    /// # Errors
    ///
    /// [`AnchorError`] at the first line that is not valid zone text, holds a record other than a DS or a DNSKEY
    /// or one not of class IN, or is a `$INCLUDE`; and [`AnchorError::Empty`] for a text without a record.
    pub fn read(text: &str) -> Result<Self, AnchorError> {
        let mut reader = ZoneReader::new(text.as_bytes(), None).with_ttl(Ttl::ZERO);
        let mut zones: HashMap<Name<'static>, Anchor> = HashMap::new();
        while let Some(entry) = reader.next() {
            let line = reader.line();
            let ZoneEntry::Record(decoded) = entry? else {
                return Err(AnchorError::NotARecord { line });
            };
            let record = decoded.record;
            let rtype = record.rtype();
            if !matches!(rtype, RecordType::DS | RecordType::DNSKEY) {
                return Err(AnchorError::NotAnAnchor { line, rtype });
            }
            if record.class != Class::IN {
                return Err(AnchorError::NotInternet {
                    line,
                    class: record.class,
                });
            }
            if let Some(reason) = decoded.invalid_rdata {
                return Err(AnchorError::InvalidData {
                    line,
                    rtype,
                    reason,
                });
            }
            let anchor = zones
                .entry(record.name.clone().into_owned())
                .or_insert(Anchor {
                    ds: Vec::new(),
                    dnskeys: Vec::new(),
                });
            match record.data() {
                RData::Ds(ds) => anchor.ds.push(ds.into_owned()),
                RData::Dnskey(key) => anchor.dnskeys.push(key.into_owned()),
                // Checked above: the type is DS or DNSKEY and its data is valid.
                _ => return Err(AnchorError::NotAnAnchor { line, rtype }),
            }
        }
        if zones.is_empty() {
            return Err(AnchorError::Empty);
        }
        Ok(Self {
            zones,
            negative: HashSet::new(),
        })
    }

    /// The anchors of IANA's `root-anchors.xml` valid at `now`, in seconds since 1970, once `p7s`, its detached
    /// CMS signature, is checked against ICANN's bundled CA (RFC 9718 §3.2): see [`TrustAnchors::verified_by`].
    ///
    /// # Errors
    ///
    /// As [`TrustAnchors::verified_by`].
    #[cfg(feature = "fetch-anchors")]
    pub fn verified(
        xml: &[u8],
        p7s: &[u8],
        now: u64,
        last_signed_at: Option<u64>,
    ) -> Result<SignedAnchors, SignedAnchorError> {
        Self::verified_by(xml, p7s, ICANN_CA, now, last_signed_at)
    }

    /// The anchors of `xml`, a `root-anchors.xml`, valid at `now`, once `p7s` is checked as its signature by a
    /// certificate for `dnssec@iana.org` that a CA of `ca`, PEM certificates, issued; both certificates valid at
    /// `now` (RFC 9718 §3.2); signed at or after `last_signed_at`, the [`SignedAnchors::signed_at`] the caller
    /// last accepted, and the bundled anchors' signing time: an older pair, which may list a key since retired, is
    /// not replayed (D127). Then as [`TrustAnchors::from_unverified_xml`].
    ///
    /// # Errors
    ///
    /// [`SignedAnchorError::TooLarge`] when `xml` or `p7s` is longer than its limit, [`SignedAnchorError::Ca`]
    /// when `ca` holds no certificate, [`SignedAnchorError::Signature`] when the signature does not hold or is
    /// older, [`SignedAnchorError::Xml`] when the signed XML is refused.
    #[cfg(feature = "fetch-anchors")]
    pub fn verified_by(
        xml: &[u8],
        p7s: &[u8],
        ca: &str,
        now: u64,
        last_signed_at: Option<u64>,
    ) -> Result<SignedAnchors, SignedAnchorError> {
        for (file, bytes, limit) in [
            ("root-anchors.xml", xml, MAX_XML),
            ("root-anchors.p7s", p7s, MAX_P7S),
        ] {
            if bytes.len() > limit {
                return Err(SignedAnchorError::TooLarge { file, limit });
            }
        }
        let trust = signature::Trust {
            cas: &signature::cas(ca)?,
            now,
            floor: last_signed_at.map_or(ROOT_SIGNED_AT, |last| last.max(ROOT_SIGNED_AT)),
        };
        let signed_at = signature::check(xml, p7s, &trust).map_err(SignedAnchorError::Signature)?;
        Ok(SignedAnchors {
            anchors: Self::from_unverified_xml(xml, now)?,
            signed_at,
        })
    }

    /// The anchors of `xml`, a `root-anchors.xml` (RFC 9718 §2), unsigned: the DS records of its `KeyDigest`
    /// entries valid at `now`, in seconds since 1970. An entry carrying a DNSKEY it does not match is not used
    /// (§4.1.2). Trust it as far as its source: [`TrustAnchors::verified`] checks the signature.
    ///
    /// # Errors
    ///
    /// [`AnchorXmlError`] when `xml` is not the XML of RFC 9718 §2, or no entry is valid at `now`.
    #[cfg(feature = "fetch-anchors")]
    pub fn from_unverified_xml(xml: &[u8], now: u64) -> Result<Self, AnchorXmlError> {
        xml::read(xml, now)
    }

    /// The deepest anchored zone at or above `name`, with its anchor: where the chain of trust of `name` starts.
    #[must_use]
    pub fn closest(&self, name: &Name<'_>) -> Option<(&Name<'static>, &Anchor)> {
        self.zones
            .iter()
            .filter(|(zone, _)| name.is_within(zone))
            .max_by_key(|(zone, _)| zone.label_count())
    }

    /// Adds a negative trust anchor (RFC 7646 §1.1): [`TrustAnchors::negative`] holds for `name` and below it.
    ///
    /// The RFC asks that an anchor end after a limited time (§2.1); it lasts as long as these anchors do, so the
    /// caller drops them when it should end, as `dedensd` does by reloading its configuration (D72).
    pub fn add_negative(&mut self, name: Name<'static>) {
        self.negative.insert(name);
    }

    /// Whether `name` is under a negative trust anchor, so that an answer for it is insecure, not validated.
    ///
    /// An anchor stops validation from its name down, and a positive anchor further down starts it again (RFC
    /// 7646 §1.1: with an NTA at `example.com` and an anchor at `foo.bar.example.com`, `foo.bar.example.com` is
    /// validated). A negative and a positive anchor at the same name: the negative one holds, as the operator
    /// added it to override the other.
    #[must_use]
    pub fn negative(&self, name: &Name<'_>) -> bool {
        let Some(depth) = self
            .negative
            .iter()
            .filter(|zone| name.is_within(zone))
            .map(Name::label_count)
            .max()
        else {
            return false;
        };
        self.closest(name)
            .is_none_or(|(zone, _)| zone.label_count() <= depth)
    }
}
