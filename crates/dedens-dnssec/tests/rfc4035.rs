//! RFC 4035 §5.3: the checks of an RRSIG over an `RRset`, with the signed zone `example.` of Appendix A (keys of
//! 1024 bits, RSASHA1): wildcard expansion (§5.3.2, Appendix B.6), the labels field, and the limits on failed
//! checks that RFC 4035 leaves open (D73).

mod common;

use common::{
    RFC4034_NS1_SIGNATURE, RFC4034_ZSK, Rrsig, check, dnskey_rdata, name, rrset, rrsig_set,
};
use dedens_dnssec::crypto::Budget;
use dedens_dnssec::rrsig::{self, Key, MAX_FAILED, RrSet, SigError, Signature};

// 2004-04-09T18:36:19Z and 2004-05-09T18:36:19Z.
const INCEPTION: u32 = 1_081_535_779;
const EXPIRATION: u32 = 1_084_127_779;

// spellchecker:off
// `*.w.example. MX 1 ai.example.`, Appendix A, and the same RRSIG in Appendix B.6 over `a.z.w.example.`.
const WILDCARD_SIGNATURE: &str = "OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2
    f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbc
    tvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2X
    TjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw
    4kX18MMR34i8lC36SR5xBni8vHI=";
// `x.w.example. MX 1 xx.example.`, a name the zone has: no wildcard.
const X_W_SIGNATURE: &str = "Il2WTZ+Bkv+OytBx4LItNW5mjB4RCwhOO8y1
    XzPHZmZUTVYL7LaA63f6T9ysVBzJRI3KRjAP
    H3U1qaYnDoN1DrWqmi9RJe4FoObkbcdm7P3I
    kx70ePCoFgRz1Yq+bVVXCvGuAU4xALv3W/Y1
    jNSlwZ2mSWKHfxFQxPtLj8s32+k=";
// spellchecker:on

fn rrsig(type_covered: u16, labels: u8) -> Rrsig<'static> {
    Rrsig {
        type_covered,
        algorithm: 5,
        labels,
        original_ttl: 3600,
        expiration: EXPIRATION,
        inception: INCEPTION,
        key_tag: 38519,
        signer: "example.",
    }
}

fn zsk() -> RrSet<'static> {
    rrset("example.", 48, &[dnskey_rdata(256, 5, RFC4034_ZSK)])
}

/// `owner MX 1 exchange`.
fn mx(owner: &str, exchange: &str) -> RrSet<'static> {
    let mut rdata = 1_u16.to_be_bytes().to_vec();
    rdata.extend(common::canonical_name(exchange));
    rrset(owner, 15, &[rdata])
}

#[test]
fn a_wildcard_expansion_verifies_and_names_the_closest_encloser() {
    // §5.3.2: `a.z.w.example.` has 4 labels, the RRSIG says 2: the signed owner is `*.w.example.`.
    let sigs = rrsig_set("a.z.w.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
    let verified = check(
        &mx("a.z.w.example.", "ai.example."),
        &sigs,
        &zsk(),
        INCEPTION,
    )
    .expect("verifies");
    assert_eq!(verified.wildcard, Some(name("w.example.")));
    // Any other name the wildcard matches has the same signature, whatever its case.
    let sigs = rrsig_set("B.Y.W.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
    let verified = check(
        &mx("B.Y.W.example.", "AI.example."),
        &sigs,
        &zsk(),
        INCEPTION,
    )
    .expect("verifies");
    assert_eq!(verified.wildcard, Some(name("w.example.")));
}

#[test]
fn a_wildcard_signature_does_not_verify_under_another_encloser() {
    // `a.z.v.example.` would be the expansion of `*.v.example.`, which nothing signed.
    let sigs = rrsig_set("a.z.v.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
    assert_eq!(
        check(
            &mx("a.z.v.example.", "ai.example."),
            &sigs,
            &zsk(),
            INCEPTION
        ),
        Err(SigError::BadSignature { key_tag: 38519 })
    );
}

#[test]
fn the_wildcard_itself_has_no_encloser() {
    // The leading `*` is not counted (RFC 4034 §3.1.3): `*.w.example.` has 2 labels, as the RRSIG says.
    let sigs = rrsig_set("*.w.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
    let verified =
        check(&mx("*.w.example.", "ai.example."), &sigs, &zsk(), INCEPTION).expect("verifies");
    assert_eq!(verified.wildcard, None);
}

#[test]
fn a_name_of_the_zone_is_no_wildcard_expansion() {
    let sigs = rrsig_set("x.w.example.", &rrsig(15, 3), X_W_SIGNATURE);
    let verified =
        check(&mx("x.w.example.", "xx.example."), &sigs, &zsk(), INCEPTION).expect("verifies");
    assert_eq!(verified.wildcard, None);
}

#[test]
fn more_labels_than_the_owner_has_is_invalid() {
    // §5.3.1: the labels field is at most the owner's label count.
    let sigs = rrsig_set("w.example.", &rrsig(15, 3), X_W_SIGNATURE);
    assert_eq!(
        check(&mx("w.example.", "xx.example."), &sigs, &zsk(), INCEPTION),
        Err(SigError::BadLabels {
            labels: 3,
            owner: 2
        })
    );
    // `*.w.example.` has 2 labels, not 3.
    let sigs = rrsig_set("*.w.example.", &rrsig(15, 3), X_W_SIGNATURE);
    assert_eq!(
        check(&mx("*.w.example.", "ai.example."), &sigs, &zsk(), INCEPTION),
        Err(SigError::BadLabels {
            labels: 3,
            owner: 2
        })
    );
}

#[test]
fn the_ttl_kept_is_the_least_of_the_rrset_and_the_signature() {
    // §5.3.3: the RRset's TTL 100 is below the original 3600 and the 2^31 seconds left.
    let a = RrSet::group(&common::records(
        "ns1.example.",
        1,
        100,
        &[vec![192, 0, 2, 1]],
    ))
    .pop()
    .expect("one RRset");
    let sigs = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4034_NS1_SIGNATURE);
    let verified = check(&a, &sigs, &zsk(), INCEPTION).expect("verifies");
    assert_eq!(verified.ttl.get(), 100);
}

/// 20 copies of the right key, and a record the signature does not cover: every check fails.
fn keytrap() -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
    let rdata = dnskey_rdata(256, 5, RFC4034_ZSK);
    (
        rrset("ns1.example.", 1, &[vec![192, 0, 2, 2]]),
        rrsig_set("ns1.example.", &rrsig(1, 2), RFC4034_NS1_SIGNATURE),
        rrset("example.", 48, &vec![rdata; 20]),
    )
}

#[test]
fn a_rrset_gives_up_after_a_few_failed_checks() {
    // KeyTrap (CVE-2023-50387): many keys of the one tag, none that verifies.
    let (a, sigs, keys) = keytrap();
    let mut budget = Budget::default();
    let before = budget.verifications_left();
    assert_eq!(
        rrsig::verify_any(
            &a,
            &Signature::all(&sigs),
            &Key::all(&keys),
            INCEPTION,
            &mut budget
        ),
        Err(SigError::TooManyFailures)
    );
    let spent = before.0 - budget.verifications_left().0;
    assert_eq!(usize::try_from(spent), Ok(MAX_FAILED));
}

#[test]
fn the_budget_of_the_whole_validation_stops_the_checks() {
    let (a, sigs, keys) = keytrap();
    let mut budget = Budget::new(
        dedens_dnssec::crypto::Verifications(3),
        Budget::DEFAULT_NSEC3_HASHES,
    );
    let result = rrsig::verify_any(
        &a,
        &Signature::all(&sigs),
        &Key::all(&keys),
        INCEPTION,
        &mut budget,
    );
    assert!(matches!(result, Err(SigError::BudgetExhausted(_))));
    assert_eq!(budget.verifications_left().0, 0);
}
