//! Checking an `RRset` against its RRSIG and the DNSKEY that made it (RFC 4035 §5.3).

use dedens_proto::{Name, Ttl};

use super::canonical;
use super::error::SigError;
use super::rrset::{Key, RrSet, Signature};
use crate::crypto::{self, Budget, VerifyError};

/// How many signature checks of one `RRset` may fail before [`verify_any`] gives up (D73).
pub const MAX_FAILED: usize = 8;

/// An `RRset` that a signature authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// How long to keep it (RFC 4035 §5.3.3): the lowest of the `RRset`'s TTL, the RRSIG's TTL, its original TTL
    /// and the seconds left before it expires.
    pub ttl: Ttl,
    /// Where the owner came from a wildcard (RFC 4035 §5.3.4): the closest encloser, the owner's parent whose
    /// `*` child was signed. A positive answer from a wildcard also needs a proof that no closer name exists
    /// (RFC 5155 §8.8).
    pub wildcard: Option<Name<'static>>,
}

/// Whether `a` is before `b` in serial number arithmetic (RFC 1982 §3.2).
const fn serial_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

/// The owner as the signer saw it (RFC 4035 §5.3.2): lowercased, and for a name made by wildcard expansion
/// (the labels field is less than the owner's labels) `*` and the rightmost `labels` labels, which are also
/// returned as the closest encloser.
fn signed_owner(
    owner: &Name<'_>,
    labels: u8,
) -> Result<(Vec<u8>, Option<Name<'static>>), SigError> {
    let wire = canonical::owner(owner);
    let total = owner.label_count();
    let starred = owner.labels().next() == Some(b"*".as_slice());
    let counted = total - usize::from(starred);
    let kept = usize::from(labels);
    if kept > counted {
        return Err(SigError::BadLabels {
            labels,
            owner: counted,
        });
    }
    if kept == counted {
        return Ok((wire, None));
    }
    let encloser = Name::from_labels(owner.labels().skip(total - kept))
        .expect("the rightmost labels of a name are a name");
    let suffix = encloser.wire_len();
    let start = wire.len() - suffix;
    let mut signed = vec![1, b'*'];
    signed.extend_from_slice(wire.get(start..).unwrap_or_default());
    Ok((signed, Some(encloser)))
}

/// The data a signature covers (RFC 4034 §3.1.8.1, RFC 4035 §5.3.2).
fn signed_data(rrset: &RrSet<'_>, sig: &Signature<'_>, owner: &[u8]) -> Vec<u8> {
    let mut data = sig.rrsig.signed_rdata();
    if let Some(signer) = data.get_mut(18..) {
        signer.make_ascii_lowercase();
    }
    for rdata in rrset.canonical_rdatas() {
        data.extend_from_slice(owner);
        data.extend_from_slice(&rrset.rtype().0.to_be_bytes());
        data.extend_from_slice(&rrset.class().0.to_be_bytes());
        data.extend_from_slice(&sig.rrsig.original_ttl.to_be_bytes());
        let len = u16::try_from(rdata.len()).expect("RDATA is at most 65535 bytes");
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(&rdata);
    }
    data
}

/// Checks `rrset` against one RRSIG and one DNSKEY (RFC 4035 §5.3.1 to §5.3.3).
///
/// The checks, in order: the RRSIG covers the `RRset` (owner, class, type); its labels field is not more than the
/// owner's; its signer is at or above the owner; its algorithm is supported; the DNSKEY is the signer's, of its
/// algorithm and key tag; the key is not revoked and has the zone key bit; the time is in the signature's window
/// (RFC 1982 arithmetic, no clock skew: `now` is Unix seconds modulo 2^32). Then one verification is spent from
/// `budget` and the signature checked. A key no signature can use is no key (D71): the algorithm counts as
/// unsupported.
///
/// # Errors
///
/// [`SigError`], whose [`ede`](SigError::ede) gives the Extended DNS Error.
pub fn verify(
    rrset: &RrSet<'_>,
    sig: &Signature<'_>,
    key: &Key<'_>,
    now: u32,
    budget: &mut Budget,
) -> Result<Verified, SigError> {
    let rrsig = &sig.rrsig;
    let key_tag = rrsig.key_tag;
    if !sig.covers(rrset) {
        return Err(SigError::NoSignature);
    }
    let (owner, wildcard) = signed_owner(rrset.owner(), rrsig.labels)?;
    if !rrset.owner().is_within(&rrsig.signer) {
        return Err(SigError::BadSigner);
    }
    if !crypto::supported(rrsig.algorithm) {
        return Err(SigError::UnsupportedAlgorithm {
            algorithm: rrsig.algorithm,
        });
    }
    if !key.matches(sig) {
        return Err(SigError::NoKey { key_tag });
    }
    if key.dnskey.is_revoked() {
        return Err(SigError::RevokedKey { key_tag });
    }
    if !key.dnskey.is_zone_key() {
        return Err(SigError::NotZoneKey { key_tag });
    }
    if serial_lt(rrsig.expiration, rrsig.inception) {
        return Err(SigError::ExpiredBeforeValid { key_tag });
    }
    if serial_lt(now, rrsig.inception) {
        return Err(SigError::NotYetValid {
            key_tag,
            inception: rrsig.inception,
        });
    }
    if serial_lt(rrsig.expiration, now) {
        return Err(SigError::Expired {
            key_tag,
            expiration: rrsig.expiration,
        });
    }
    budget.spend_verification()?;
    crypto::verify(
        rrsig.algorithm,
        key.dnskey.public_key(),
        &signed_data(rrset, sig, &owner),
        rrsig.signature(),
    )
    .map_err(|error| match error {
        VerifyError::BadSignature => SigError::BadSignature { key_tag },
        VerifyError::UnsupportedAlgorithm(_) | VerifyError::UnusableKey => {
            SigError::UnsupportedAlgorithm {
                algorithm: rrsig.algorithm,
            }
        }
    })?;
    let seconds = [
        rrset.ttl().get(),
        sig.ttl.get(),
        rrsig.original_ttl,
        rrsig.expiration.wrapping_sub(now),
    ];
    Ok(Verified {
        ttl: Ttl::from_wire(seconds.into_iter().min().unwrap_or_default()),
        wildcard,
    })
}

/// Authenticates `rrset` by the first of `sigs` and `keys` that verify: each RRSIG that covers it, against each
/// DNSKEY of its signer, algorithm and key tag (RFC 4035 §5.3.3).
///
/// Every signature check spends from `budget`, which the whole validation shares, and at most [`MAX_FAILED`]
/// of them may fail for this `RRset` (D73): a zone can publish many keys and signatures that a validator would
/// otherwise try against each other (`KeyTrap`). When none verifies, the error is the one that came closest to a
/// success, ranked: a bad signature, then a time outside the window, then a key unfit to sign, then a missing
/// key, then an unsupported algorithm, then no signature at all.
///
/// # Errors
///
/// [`SigError`], whose [`ede`](SigError::ede) gives the Extended DNS Error.
pub fn verify_any(
    rrset: &RrSet<'_>,
    sigs: &[Signature<'_>],
    keys: &[Key<'_>],
    now: u32,
    budget: &mut Budget,
) -> Result<Verified, SigError> {
    let mut worst = SigError::NoSignature;
    let mut failed = 0;
    let mut note = |error: SigError| {
        if error.rank() > worst.rank() {
            worst = error;
        }
    };
    for sig in sigs.iter().filter(|sig| sig.covers(rrset)) {
        let mut tried = false;
        for key in keys.iter().filter(|key| key.matches(sig)) {
            tried = true;
            if failed >= MAX_FAILED {
                return Err(SigError::TooManyFailures);
            }
            match verify(rrset, sig, key, now, budget) {
                Ok(verified) => return Ok(verified),
                Err(error @ SigError::BudgetExhausted(_)) => return Err(error),
                Err(error) => {
                    failed += usize::from(matches!(error, SigError::BadSignature { .. }));
                    note(error);
                }
            }
        }
        if !tried {
            note(if crypto::supported(sig.rrsig.algorithm) {
                SigError::NoKey {
                    key_tag: sig.rrsig.key_tag,
                }
            } else {
                SigError::UnsupportedAlgorithm {
                    algorithm: sig.rrsig.algorithm,
                }
            });
        }
    }
    Err(worst)
}
