//! Trusting a DNSKEY `RRset` because the parent's DS `RRset` vouches for it (RFC 4035 §5.2).

use std::collections::HashMap;

use dedens_proto::rdata::{Ds, RData};
use dedens_proto::{DigestType, SecAlgorithm};

use super::error::SigError;
use super::rrset::{Key, RrSet, Signature};
use super::verify::{MAX_FAILED, Verified, verify_any};
use crate::crypto::{self, Budget};

/// Whether the digest of `ds` is that of `key`.
fn vouches(ds: &Ds<'_>, key: &Key<'_>) -> bool {
    crypto::ds_digest(ds.digest_type(), key.owner, &key.wire)
        .is_ok_and(|digest| digest.as_ref() == ds.digest())
}

/// Authenticates `dnskeys`, the DNSKEY `RRset` of a zone, from its DS `RRset` `ds`, itself authenticated by the
/// parent: the DNSKEYs a supported DS record digests must sign it (`sigs` hold its RRSIGs). On success every key
/// of the `RRset` is trusted (RFC 4035 §5.2).
///
/// A DS record counts when its digest type and algorithm are supported (RFC 6840 §5.2), and a SHA-1 digest is
/// ignored when the `RRset` holds a stronger one that counts, whatever key either names (RFC 4509 §3, D73): a
/// SHA-1 second preimage of one key's DS then vouches for no key. DS records
/// are indexed by key tag and algorithm once, so the digests computed are one per DNSKEY and DS record that
/// share both; as a DNSKEY `RRset` is not authenticated yet, more than [`MAX_FAILED`] of them of another
/// key (a colliding key tag) are refused: the answer is [`SigError::TooManyFailures`].
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
    // Every supported digest but SHA-1 is stronger than it: one that counts drops each SHA-1 DS of the `RRset`.
    if counted
        .iter()
        .any(|ds| ds.digest_type() != DigestType::SHA1)
    {
        counted.retain(|ds| ds.digest_type() != DigestType::SHA1);
    }
    let mut by_key: HashMap<(u16, SecAlgorithm), Vec<&Ds<'_>>> = HashMap::new();
    for record in &counted {
        by_key
            .entry((record.key_tag(), record.algorithm()))
            .or_default()
            .push(record);
    }
    let mut failed = 0;
    let mut keys = Vec::new();
    for key in Key::all(dnskeys) {
        if ds.owner() != key.owner || ds.class() != key.class {
            continue;
        }
        let Some(candidates) = by_key.get(&(key.tag, key.dnskey.algorithm())) else {
            continue;
        };
        if candidates.iter().any(|ds| vouches(ds, &key)) {
            keys.push(key);
        } else {
            failed += 1;
            if failed > MAX_FAILED {
                return Err(SigError::TooManyFailures);
            }
        }
    }
    if keys.is_empty() {
        return Err(SigError::NoKeyForDs);
    }
    verify_any(dnskeys, sigs, &keys, now, budget)
}
