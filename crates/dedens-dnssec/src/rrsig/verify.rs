//! Checking an `RRset` against its RRSIG and the DNSKEY that made it (RFC 4035 §5.3).

use std::cell::OnceCell;

use dedens_proto::{Name, RecordType, Ttl};

use super::canonical;
use super::error::SigError;
use super::rrset::{Key, RrSet, Signature};
use crate::crypto::{self, Budget, VerifyError};

/// How many signature checks of one `RRset` may fail before [`verify_any`] gives up (D73).
pub const MAX_FAILED: usize = 8;

/// An `RRset` that a signature authenticates.
///
/// A wildcard expansion verifies like any other `RRset`, but only proves that the zone has a wildcard: the caller
/// must also prove that no closer name exists (RFC 4035 §5.3.4, RFC 5155 §8.8), or an attacker replays the
/// wildcard's answer for a name that exists. Hence `must_use`: check [`wildcard`](Self::wildcard).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a wildcard expansion needs a proof that no closer name exists (check `wildcard`)"]
pub struct Verified {
    /// How long to keep it (RFC 4035 §5.3.3): the lowest of the `RRset`'s TTL, the RRSIG's TTL, its original TTL
    /// and the seconds left before it expires.
    pub ttl: Ttl,
    /// Where the owner came from a wildcard (RFC 4035 §5.3.4): the closest encloser, the owner's parent whose
    /// `*` child was signed. `None` for an owner that was signed as it is.
    pub wildcard: Option<Name<'static>>,
}

/// Whether `a` is before `b` in serial number arithmetic (RFC 1982 §3.2).
const fn serial_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

/// One RRSIG against an `RRset`, with what its checks share however many keys it is tried with: the owner as the
/// signer saw it and the signed data, built on first use.
struct Attempt<'s, 'k> {
    sig: &'s Signature<'k>,
    /// The owner in wire form, lowercased; `*` and the rightmost labels for a wildcard expansion.
    owner: Vec<u8>,
    /// The closest encloser of a wildcard expansion.
    wildcard: Option<Name<'static>>,
    data: Option<Vec<u8>>,
}

impl<'s, 'k> Attempt<'s, 'k> {
    /// The checks of RFC 4035 §5.3.1 that need no key, cheapest first, nothing allocated before they pass: the
    /// RRSIG covers the `RRset`; its signer is at or above the owner, and for a DS is not the owner (the DS is
    /// the parent's) and for a DNSKEY is (the zone's own keys sign them: RFC 4035 §5.2); the labels field fits
    /// the owner and the signer (RFC 4035 §5.3.2); the algorithm is supported.
    fn new(rrset: &RrSet<'_>, sig: &'s Signature<'k>) -> Result<Self, SigError> {
        let rrsig = &sig.rrsig;
        if !sig.covers(rrset) {
            return Err(SigError::NoSignature);
        }
        let owner = rrset.owner();
        let at_signer = *owner == rrsig.signer;
        let fits = owner.is_within(&rrsig.signer)
            && match rrset.rtype() {
                RecordType::DS => !at_signer,
                RecordType::DNSKEY => at_signer,
                _ => true,
            };
        if !fits {
            return Err(SigError::BadSigner);
        }
        let total = owner.label_count();
        let starred = owner.labels().next() == Some(b"*".as_slice());
        let counted = total - usize::from(starred);
        let kept = usize::from(rrsig.labels);
        if kept > counted || kept < rrsig.signer.label_count() {
            return Err(SigError::BadLabels {
                labels: rrsig.labels,
                owner: counted,
            });
        }
        if !crypto::supported(rrsig.algorithm) {
            return Err(SigError::UnsupportedAlgorithm {
                algorithm: rrsig.algorithm,
            });
        }
        let wire = canonical::owner(owner);
        let (owner, wildcard) = if kept == counted {
            (wire, None)
        } else {
            // A wildcard expansion: signed as `*` and the rightmost `labels` labels (RFC 4035 §5.3.2).
            let encloser = Name::from_labels(owner.labels().skip(total - kept)).map_err(|_| {
                SigError::BadLabels {
                    labels: rrsig.labels,
                    owner: counted,
                }
            })?;
            let start = wire.len().saturating_sub(encloser.wire_len());
            let mut signed = vec![1, b'*'];
            signed.extend_from_slice(wire.get(start..).unwrap_or_default());
            (signed, Some(encloser))
        };
        Ok(Self {
            sig,
            owner,
            wildcard,
            data: None,
        })
    }

    /// The checks that need the key, then the signature (RFC 4035 §5.3.1 to §5.3.3): the DNSKEY is the signer's,
    /// of the RRSIG's algorithm and key tag; it is not revoked (RFC 5011 §7) and has the zone key bit; `now` is
    /// in the window (RFC 1982 arithmetic, no clock skew). Then one verification is spent from `budget`.
    fn check(
        &mut self,
        rrset: &RrSet<'_>,
        canonical: &[Vec<u8>],
        key: &Key<'_>,
        now: u32,
        budget: &mut Budget,
    ) -> Result<Verified, SigError> {
        let rrsig = &self.sig.rrsig;
        let key_tag = rrsig.key_tag;
        if !key.matches(self.sig) {
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
        let data = self
            .data
            .get_or_insert_with(|| signed_data(rrset, canonical, self.sig, &self.owner));
        crypto::verify(
            rrsig.algorithm,
            key.dnskey.public_key(),
            data,
            rrsig.signature(),
        )
        .map_err(|error| match error {
            VerifyError::BadSignature => SigError::BadSignature { key_tag },
            // A key no signature can use is no key (D71): the signature is disregarded.
            VerifyError::UnusableKey | VerifyError::UnsupportedAlgorithm(_) => {
                SigError::NoKey { key_tag }
            }
        })?;
        let seconds = [
            rrset.ttl().get(),
            self.sig.ttl.get(),
            rrsig.original_ttl,
            rrsig.expiration.wrapping_sub(now),
        ];
        Ok(Verified {
            ttl: Ttl::from_wire(seconds.into_iter().min().unwrap_or_default()),
            wildcard: self.wildcard.clone(),
        })
    }
}

/// The data a signature covers (RFC 4034 §3.1.8.1, RFC 4035 §5.3.2): the RRSIG's fields with the signer
/// lowercased (RFC 6840 §5.1), then each record of `canonical`, the `RRset` in canonical form and order.
fn signed_data(
    rrset: &RrSet<'_>,
    canonical: &[Vec<u8>],
    sig: &Signature<'_>,
    owner: &[u8],
) -> Vec<u8> {
    let mut data = sig.rrsig.signed_rdata();
    if let Some(signer) = data.get_mut(18..) {
        signer.make_ascii_lowercase();
    }
    for rdata in canonical {
        data.extend_from_slice(owner);
        data.extend_from_slice(&rrset.rtype().0.to_be_bytes());
        data.extend_from_slice(&rrset.class().0.to_be_bytes());
        data.extend_from_slice(&sig.rrsig.original_ttl.to_be_bytes());
        // RDATA is at most 65535 bytes (RFC 1035 §3.2.1): the low two bytes are all of its length.
        let [.., high, low] = rdata.len().to_be_bytes();
        data.extend_from_slice(&[high, low]);
        data.extend_from_slice(rdata);
    }
    data
}

/// Checks `rrset` against one RRSIG and one DNSKEY (RFC 4035 §5.3.1 to §5.3.3).
///
/// The checks, in order: the RRSIG covers the `RRset` (owner, class, type); its signer is at or above the owner
/// (not the owner itself for a DS, the owner itself for a DNSKEY); its labels field is not more than the owner's
/// nor less than the signer's; its algorithm is supported; the DNSKEY is the signer's, of its algorithm and key
/// tag; the key is not revoked and has the zone key bit; the time is in the signature's window (RFC 1982
/// arithmetic, no clock skew: `now` is Unix seconds modulo 2^32). Then one verification is spent from `budget`
/// and the signature checked. A key no signature can use is no key ([`SigError::NoKey`], D71).
///
/// Zone cuts are the caller's: this function knows the signer is above the owner, not that the DNSKEY `RRset`
/// is the one of the zone that holds `rrset`. The caller picks `key` from the DNSKEY `RRset` of that zone: the
/// parent's for a DS, the child's own for a DNSKEY, and for any other type the zone below which the owner is not
/// delegated further (NS and glue are not signed by the child, RFC 4035 §2.2).
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
    let mut attempt = Attempt::new(rrset, sig)?;
    attempt.check(rrset, &rrset.canonical_rdatas(), key, now, budget)
}

/// Authenticates `rrset` by the first of `sigs` and `keys` that verify: each RRSIG that covers it, against each
/// DNSKEY of its signer, algorithm and key tag (RFC 4035 §5.3.3). It is enough that one pair verifies; the
/// others, expired, unknown or of an unsupported algorithm, are disregarded (RFC 6840 §5.4, §5.11, §5.12).
///
/// An RRSIG of an algorithm that is not supported is left out whatever the keys, so it can neither
/// authenticate nor make the answer insecure: only the DS records of the zone say which algorithms the zone is
/// signed with ([`trusted_keys`](super::trusted_keys), RFC 4035 §5.2, RFC 6840 §5.2). `RRset`s whose RRSIGs are
/// all left out are [`SigError::NoSignature`], bogus once the zone is known to be signed.
///
/// Every signature check spends from `budget`, which the whole validation shares, and at most [`MAX_FAILED`]
/// RRSIGs or RRSIG and DNSKEY pairs may fail for this `RRset`, for whatever reason but the lack of a key (D73):
/// a zone can publish many keys and signatures that a validator would otherwise try against each other
/// (`KeyTrap`). The canonical form and the signed data are built once, not once per pair. When none verifies,
/// the error is the one that came closest to a success, ranked: a bad signature, then a time outside the
/// window, then a key unfit to sign or an RRSIG unfit for the `RRset`, then a missing key, then no signature.
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
    let canonical = OnceCell::new();
    let mut worst = SigError::NoSignature;
    let mut failed = 0;
    let mut note = |error: SigError| {
        if error.rank() > worst.rank() {
            worst = error;
        }
    };
    for sig in sigs
        .iter()
        .filter(|sig| sig.covers(rrset) && crypto::supported(sig.rrsig.algorithm))
    {
        if failed >= MAX_FAILED {
            return Err(SigError::TooManyFailures);
        }
        let mut candidates = keys.iter().filter(|key| key.matches(sig)).peekable();
        let mut attempt = match Attempt::new(rrset, sig) {
            Ok(attempt) => attempt,
            Err(error) => {
                failed += 1;
                note(error);
                continue;
            }
        };
        if candidates.peek().is_none() {
            note(SigError::NoKey {
                key_tag: sig.rrsig.key_tag,
            });
            continue;
        }
        for key in candidates {
            if failed >= MAX_FAILED {
                return Err(SigError::TooManyFailures);
            }
            let canonical = canonical.get_or_init(|| rrset.canonical_rdatas());
            match attempt.check(rrset, canonical, key, now, budget) {
                Ok(verified) => return Ok(verified),
                Err(error @ SigError::BudgetExhausted(_)) => return Err(error),
                Err(error) => {
                    failed += 1;
                    note(error);
                }
            }
        }
    }
    Err(worst)
}
