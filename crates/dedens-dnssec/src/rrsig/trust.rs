//! Trusting a DNSKEY `RRset` because the parent's DS `RRset` vouches for it (RFC 4035 §5.2).

use dedens_proto::rdata::Ds;
use dedens_proto::{DigestType, RData};

use super::error::SigError;
use super::rrset::{Key, RrSet, Signature};
use super::verify::{Verified, verify_any};
use crate::crypto::{self, Budget};

/// Whether the digest of `ds` is that of `key`.
fn vouches(ds: &Ds<'_>, key: &Key<'_>) -> bool {
    ds.key_tag() == key.tag
        && ds.algorithm() == key.dnskey.algorithm()
        && crypto::ds_digest(ds.digest_type(), key.owner, &key.wire)
            .is_ok_and(|digest| digest.as_ref() == ds.digest())
}

/// Authenticates `dnskeys`, the DNSKEY `RRset` of a zone, from its DS `RRset` `ds`: the DNSKEYs a supported DS
/// record digests must sign it (`sigs` hold its RRSIGs). On success every key of the `RRset` is trusted
/// (RFC 4035 §5.2).
///
/// A DS record counts when its digest type and algorithm are supported (RFC 6840 §5.2), and a SHA-1 digest is
/// ignored when a stronger one of the same key (key tag and algorithm) is there (RFC 4509 §3, D73).
///
/// # Errors
///
/// [`SigError::UnsupportedDigest`] or [`SigError::UnsupportedAlgorithm`] when no DS record counts: the zone is
/// insecure, not bogus ([`SigError::is_unsupported`]). [`SigError::NoKeyForDs`] when none of those is the digest
/// of a DNSKEY. Otherwise the error of [`verify_any`] on the `RRset` with the matched keys.
pub fn trusted_keys(
    dnskeys: &RrSet<'_>,
    sigs: &[Signature<'_>],
    ds: &RrSet<'_>,
    now: u32,
    budget: &mut Budget,
) -> Result<Verified, SigError> {
    let mut unsupported = None;
    let mut counted = Vec::new();
    for rdata in ds.rdatas() {
        let RData::Ds(record) = rdata.data() else {
            continue;
        };
        if !crypto::supported_digest(record.digest_type()) {
            unsupported.get_or_insert(SigError::UnsupportedDigest {
                digest: record.digest_type(),
            });
        } else if !crypto::supported(record.algorithm()) {
            unsupported.get_or_insert(SigError::UnsupportedAlgorithm {
                algorithm: record.algorithm(),
            });
        } else {
            counted.push(record);
        }
    }
    if counted.is_empty() {
        return Err(unsupported.unwrap_or(SigError::NoKeyForDs));
    }
    let stronger = |ds: &Ds<'_>| {
        counted.iter().any(|other| {
            other.digest_type() != DigestType::SHA1
                && other.key_tag() == ds.key_tag()
                && other.algorithm() == ds.algorithm()
        })
    };
    let keys: Vec<Key<'_>> = Key::all(dnskeys)
        .into_iter()
        .filter(|key| {
            ds.owner() == key.owner
                && ds.class() == key.class
                && counted
                    .iter()
                    .filter(|ds| ds.digest_type() != DigestType::SHA1 || !stronger(ds))
                    .any(|ds| vouches(ds, key))
        })
        .collect();
    if keys.is_empty() {
        return Err(SigError::NoKeyForDs);
    }
    verify_any(dnskeys, sigs, &keys, now, budget)
}
