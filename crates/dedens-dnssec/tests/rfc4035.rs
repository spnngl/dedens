//! RFC 4035 §5.3: the checks of an RRSIG over an `RRset`, with the signed zone `example.` of Appendix A (keys of
//! 1024 bits, RSASHA1): wildcard expansion (§5.3.2, Appendix B.6), the labels field, and the limits on failed
//! checks that RFC 4035 leaves open (D73).
//!
//! RFC 4035 §5.2, §5.4: the denials of existence of Appendix B, from the NSEC records of the example zone of
//! Appendix A, `testdata/zones/rfc4035_appendix_a.zone` (D74).

mod common;
#[path = "common/denial.rs"]
mod support;

use common::{check, name, rrset, rrset_in, rrsig_set};
use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{Fact, Proof, Unproven};
use dedens_dnssec::rrsig::{self, Key, MAX_FAILED, RrSet, SigError, Signature};
use dedens_proto::{Record, RecordType, Ttl};
use dedens_testkit::dnssec::{RFC4035_NS1_SIGNATURE, RFC4035_ZSK, Rrsig, dnskey_rdata};
use dedens_testkit::zone;
use support::{nsec, pick, prove, prove_wildcard};

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
    rrset("example.", 48, &[dnskey_rdata(256, 5, RFC4035_ZSK)])
}

/// `owner MX 1 exchange`.
fn mx(owner: &str, exchange: &str) -> RrSet<'static> {
    let mut rdata = 1_u16.to_be_bytes().to_vec();
    rdata.extend(dedens_testkit::dnssec::canonical_name(exchange));
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
    let sigs = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
    let verified = check(&a, &sigs, &zsk(), INCEPTION).expect("verifies");
    assert_eq!(verified.ttl.get(), 100);
}

/// 20 copies of the right key, and a record the signature does not cover: every check fails.
fn keytrap() -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
    let rdata = dnskey_rdata(256, 5, RFC4035_ZSK);
    (
        rrset("ns1.example.", 1, &[vec![192, 0, 2, 2]]),
        rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE),
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
        Budget::DEFAULT_NSEC3_BLOCKS,
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

/// `ns1.example.` at an address the signature does not cover.
fn forged() -> RrSet<'static> {
    rrset("ns1.example.", 1, &[vec![192, 0, 2, 2]])
}

fn signatures<'a>(sets: &[&'a RrSet<'static>]) -> Vec<Signature<'a>> {
    sets.iter().flat_map(|set| Signature::all(set)).collect()
}

fn verify_any(
    rrset: &RrSet<'_>,
    sigs: &[Signature<'_>],
    keys: &RrSet<'_>,
    now: u32,
) -> Result<rrsig::Verified, SigError> {
    rrsig::verify_any(rrset, sigs, &Key::all(keys), now, &mut Budget::default())
}

#[test]
fn an_rrsig_of_an_unknown_algorithm_is_disregarded_not_a_way_to_insecurity() {
    // RFC 6840 §5.12: an RRSIG of an algorithm the validator does not know is as if absent, and which
    // algorithms a zone is signed with is the DS records' to say (§5.11, RFC 4035 §5.2). Otherwise one forged
    // RRSIG of algorithm 200 would turn a forged answer of a signed zone into an insecure one.
    let unknown = rrsig_set(
        "ns1.example.",
        &Rrsig {
            algorithm: 200,
            ..rrsig(1, 2)
        },
        RFC4035_NS1_SIGNATURE,
    );
    let keys = rrset(
        "example.",
        48,
        &[
            dnskey_rdata(256, 5, RFC4035_ZSK),
            dnskey_rdata(256, 200, RFC4035_ZSK),
        ],
    );
    let result = verify_any(&forged(), &signatures(&[&unknown]), &keys, INCEPTION);
    assert_eq!(result, Err(SigError::NoSignature));
    assert!(!result.unwrap_err().is_unsupported());
    // Beside an RRSIG that is known, the known one decides.
    let known = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
    let result = verify_any(
        &forged(),
        &signatures(&[&unknown, &known]),
        &keys,
        INCEPTION,
    );
    assert_eq!(result, Err(SigError::BadSignature { key_tag: 38519 }));
    // The right data is authenticated by the known RRSIG all the same.
    let a = rrset("ns1.example.", 1, &[vec![192, 0, 2, 1]]);
    assert!(verify_any(&a, &signatures(&[&unknown, &known]), &keys, INCEPTION).is_ok());
}

#[test]
fn a_ds_belongs_to_the_parent_and_a_dnskey_to_its_own_zone() {
    // RFC 4035 §2.4: the DS RRset is signed by the parent's keys, so a DS RRSIG whose signer is the owner (the
    // child's, which the attacker may hold) is invalid. §5.2: a DNSKEY RRset is signed by its own zone.
    let ds = rrset(
        "w.example.",
        43,
        &[[vec![0x96, 0x4b, 5, 1], vec![7; 20]].concat()],
    );
    let by_child = rrsig_set(
        "w.example.",
        &Rrsig {
            signer: "w.example.",
            ..rrsig(43, 2)
        },
        RFC4035_NS1_SIGNATURE,
    );
    assert_eq!(
        verify_any(&ds, &signatures(&[&by_child]), &zsk(), INCEPTION),
        Err(SigError::BadSigner)
    );
    // The parent's signature on it passes the checks of the RRSIG, and fails only as a signature.
    let by_parent = rrsig_set("w.example.", &rrsig(43, 2), RFC4035_NS1_SIGNATURE);
    assert_eq!(
        verify_any(&ds, &signatures(&[&by_parent]), &zsk(), INCEPTION),
        Err(SigError::BadSignature { key_tag: 38519 })
    );
    let dnskey = rrset("w.example.", 48, &[dnskey_rdata(257, 5, RFC4035_ZSK)]);
    let by_parent = rrsig_set("w.example.", &rrsig(48, 2), RFC4035_NS1_SIGNATURE);
    assert_eq!(
        verify_any(&dnskey, &signatures(&[&by_parent]), &zsk(), INCEPTION),
        Err(SigError::BadSigner)
    );
}

#[test]
fn a_signer_below_the_owner_is_invalid() {
    let sigs = rrsig_set(
        "example.",
        &Rrsig {
            signer: "w.example.",
            ..rrsig(15, 2)
        },
        X_W_SIGNATURE,
    );
    assert_eq!(
        verify_any(
            &mx("example.", "xx.example."),
            &signatures(&[&sigs]),
            &zsk(),
            INCEPTION
        ),
        Err(SigError::BadSigner)
    );
}

#[test]
fn fewer_labels_than_the_signer_has_is_invalid() {
    // The signer `w.example.` has 2 labels: 1 would be the expansion of `*.example.`, a wildcard of the parent
    // zone, which the signer's keys do not speak for.
    let sigs = rrsig_set(
        "a.z.w.example.",
        &Rrsig {
            signer: "w.example.",
            ..rrsig(15, 1)
        },
        WILDCARD_SIGNATURE,
    );
    assert_eq!(
        verify_any(
            &mx("a.z.w.example.", "ai.example."),
            &signatures(&[&sigs]),
            &zsk(),
            INCEPTION
        ),
        Err(SigError::BadLabels {
            labels: 1,
            owner: 4
        })
    );
}

#[test]
fn the_class_of_the_rrset_signature_and_key_must_be_the_same() {
    let a = rrset("ns1.example.", 1, &[vec![192, 0, 2, 1]]);
    let sigs = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
    let chaos = rrset_in(3, "ns1.example.", 1, &[vec![192, 0, 2, 1]]);
    assert_eq!(
        verify_any(&chaos, &signatures(&[&sigs]), &zsk(), INCEPTION),
        Err(SigError::NoSignature)
    );
    let chaos_keys = rrset_in(3, "example.", 48, &[dnskey_rdata(256, 5, RFC4035_ZSK)]);
    assert_eq!(
        verify_any(&a, &signatures(&[&sigs]), &chaos_keys, INCEPTION),
        Err(SigError::NoKey { key_tag: 38519 })
    );
}

#[test]
fn the_error_returned_is_the_one_closest_to_a_success() {
    // A missing key, a window that has ended, a signature that does not verify: the last is the closest, and
    // the order of the RRSIGs does not matter.
    let bad = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
    let nokey = rrsig_set(
        "ns1.example.",
        &Rrsig {
            key_tag: 1,
            ..rrsig(1, 2)
        },
        RFC4035_NS1_SIGNATURE,
    );
    for sigs in [signatures(&[&nokey, &bad]), signatures(&[&bad, &nokey])] {
        assert_eq!(
            verify_any(&forged(), &sigs, &zsk(), INCEPTION),
            Err(SigError::BadSignature { key_tag: 38519 })
        );
        assert_eq!(
            verify_any(&forged(), &sigs, &zsk(), EXPIRATION + 1),
            Err(SigError::Expired {
                key_tag: 38519,
                expiration: EXPIRATION
            })
        );
    }
    let only = signatures(&[&nokey]);
    assert_eq!(
        verify_any(&forged(), &only, &zsk(), INCEPTION),
        Err(SigError::NoKey { key_tag: 1 })
    );
    assert_eq!(
        verify_any(&forged(), &[], &zsk(), INCEPTION),
        Err(SigError::NoSignature)
    );
}

#[test]
fn failures_that_cost_no_verification_count_toward_the_cap_too() {
    // KeyTrap by RRSIGs that fail their cheap checks: each is a pair tried, so a zone cannot make the validator
    // walk thousands of them (D73), and none spends the budget.
    for rrsig in [
        // Ended before `now`.
        Rrsig {
            expiration: INCEPTION + 10,
            ..rrsig(1, 2)
        },
        // More labels than the owner.
        Rrsig {
            labels: 9,
            ..rrsig(1, 2)
        },
    ] {
        let sets: Vec<RrSet<'static>> = (0..MAX_FAILED + 2)
            .map(|_| rrsig_set("ns1.example.", &rrsig, RFC4035_NS1_SIGNATURE))
            .collect();
        let sigs: Vec<Signature<'_>> = sets.iter().flat_map(Signature::all).collect();
        let mut budget = Budget::default();
        let before = budget.verifications_left();
        let result = rrsig::verify_any(
            &forged(),
            &sigs,
            &Key::all(&zsk()),
            INCEPTION + 100,
            &mut budget,
        );
        assert_eq!(result, Err(SigError::TooManyFailures));
        assert_eq!(budget.verifications_left(), before);
    }
}

#[test]
fn rrsigs_without_a_key_do_not_count_toward_the_cap() {
    // Nothing is checked for them, and an attacker has nothing to gain: a zone may well sign with keys the
    // validator was not given.
    let sets: Vec<RrSet<'static>> = (0..MAX_FAILED + 2)
        .map(|_| {
            rrsig_set(
                "ns1.example.",
                &Rrsig {
                    key_tag: 1,
                    ..rrsig(1, 2)
                },
                RFC4035_NS1_SIGNATURE,
            )
        })
        .collect();
    let sigs: Vec<Signature<'_>> = sets.iter().flat_map(Signature::all).collect();
    assert_eq!(
        verify_any(&forged(), &sigs, &zsk(), INCEPTION),
        Err(SigError::NoKey { key_tag: 1 })
    );
}

// Denial of existence (D74).

const APEX: &str = "example.";
/// The TTL of every record of Appendix A.
const TTL: Ttl = Ttl::from_wire(3600);

fn nsecs(owners: &[&str]) -> Vec<Record<'static>> {
    pick(&zone("rfc4035_appendix_a.zone"), RecordType::NSEC, owners)
}

fn proof(fact: Fact) -> Proof {
    Proof {
        fact,
        ttl: TTL,
        opt_out: false,
    }
}

const NAME_ERROR: Fact = Fact::NameError { compact: false };

/// B.2: `ml.example.` is covered by `b.example.`, and `*.example.` by the apex.
#[test]
fn b2_name_error() {
    let records = nsecs(&["b.example.", "example."]);
    assert_eq!(
        prove(APEX, "ml.example.", RecordType::A, &records),
        Ok(proof(NAME_ERROR))
    );
    // Without the wildcard's NSEC the response proves less.
    let records = nsecs(&["b.example."]);
    assert_eq!(
        prove(APEX, "ml.example.", RecordType::A, &records),
        Err(Unproven::WildcardNotDenied)
    );
    // Without the name's.
    let records = nsecs(&["example."]);
    assert_eq!(
        prove(APEX, "ml.example.", RecordType::A, &records),
        Err(Unproven::NotCovered)
    );
}

/// The last NSEC of the chain wraps to the apex, and a name below an existing name has it as closest encloser.
#[test]
fn name_errors_after_the_last_name_and_below_a_name() {
    let records = nsecs(&["xx.example.", "example."]);
    assert_eq!(
        prove(APEX, "zzz.example.", RecordType::A, &records),
        Ok(proof(NAME_ERROR))
    );
    // The wildcard `*.ns1.example.` sorts between `ns1.example.` and `ns2.example.`.
    let records = nsecs(&["ns1.example."]);
    assert_eq!(
        prove(APEX, "a.b.ns1.example.", RecordType::A, &records),
        Ok(proof(NAME_ERROR))
    );
}

/// B.3: `ns1.example.` exists and has no MX.
#[test]
fn b3_no_data() {
    let records = nsecs(&["ns1.example."]);
    assert_eq!(
        prove(APEX, "ns1.example.", RecordType::MX, &records),
        Ok(proof(Fact::NoData))
    );
    assert_eq!(
        prove(APEX, "ns1.example.", RecordType::A, &records),
        Err(Unproven::TypePresent)
    );
}

/// The name of an NSEC and the case of the question do not matter (RFC 4343).
#[test]
fn names_compare_without_case() {
    let records = nsecs(&["ns1.example."]);
    assert_eq!(
        prove(APEX, "NS1.Example.", RecordType::MX, &records),
        Ok(proof(Fact::NoData))
    );
}

/// Derived: the owner and next names of NSEC records in capitals, as a signer may write them; the shape is the
/// zone's NSEC of `ns1.example.` and of the apex (RFC 4343, RFC 4034 §6.2 lowercases names to sign, not to send).
#[test]
fn nsec_names_compare_without_case() {
    let types = [RecordType::NS, RecordType::RRSIG, RecordType::NSEC];
    let records = [
        nsec("NS1.EXAMPLE.", "NS2.Example.", &types),
        nsec(
            "EXAMPLE.",
            "A.EXAMPLE.",
            &[
                RecordType::NS,
                RecordType::SOA,
                RecordType::RRSIG,
                RecordType::NSEC,
            ],
        ),
    ];
    assert_eq!(
        prove(APEX, "ns1.example.", RecordType::MX, &records[..1]),
        Err(Unproven::AtDelegation)
    );
    assert_eq!(
        prove(APEX, "ns1a.example.", RecordType::A, &records),
        Ok(proof(NAME_ERROR))
    );
}

/// Derived: RFC 4592 §2.2.1: `a.*.w.example.` exists, so `*.w.example.` is an empty non-terminal. It exists, so
/// `q.w.example.` is answered by it with no data, and an NSEC that lists the wildcard's child as the next name
/// does not deny the wildcard. The chain is the zone's, with `a.*.w.example.` inserted between `ns2.example.`
/// and `x.w.example.`.
#[test]
fn a_wildcard_that_is_an_empty_non_terminal_is_no_data() {
    let types = [RecordType::A, RecordType::RRSIG, RecordType::NSEC];
    let records = [
        nsec("ns2.example.", "a.*.w.example.", &types),
        nsec("a.*.w.example.", "x.w.example.", &types),
    ];
    assert_eq!(
        prove(APEX, "q.w.example.", RecordType::A, &records),
        Ok(proof(Fact::WildcardNoData))
    );
}

/// A name that is an ancestor of names of the zone exists, with no data: the NSEC before it names one below it.
#[test]
fn empty_non_terminal_is_no_data() {
    let records = nsecs(&["x.w.example."]);
    assert_eq!(
        prove(APEX, "y.w.example.", RecordType::A, &records),
        Ok(proof(Fact::NoData))
    );
    // `w.example.` is one too: `*.w.example.` is below it.
    assert_eq!(
        prove(APEX, "w.example.", RecordType::A, &nsecs(&["ns2.example."])),
        Ok(proof(Fact::NoData))
    );
}

/// B.5: `b.example.` has NS, no DS and no SOA: an unsigned delegation, which is what the NSEC proves of DS.
#[test]
fn b5_referral_to_unsigned_zone() {
    let records = nsecs(&["b.example."]);
    assert_eq!(
        prove(APEX, "b.example.", RecordType::DS, &records),
        Ok(proof(Fact::InsecureDelegation))
    );
}

/// B.4: `a.example.` has a DS, so no NSEC proves it absent.
#[test]
fn b4_referral_to_signed_zone() {
    let records = nsecs(&["a.example."]);
    assert_eq!(
        prove(APEX, "a.example.", RecordType::DS, &records),
        Err(Unproven::TypePresent)
    );
}

/// B.6: the RRSIG of `a.z.w.example.` has 2 labels, and the NSEC of `x.y.w.example.` covers `z.w.example.`.
#[test]
fn b6_wildcard_expansion() {
    let records = nsecs(&["x.y.w.example."]);
    assert_eq!(
        prove_wildcard(APEX, "a.z.w.example.", 2, &records),
        Ok(proof(Fact::WildcardAnswer))
    );
    // `y.w.example.` is an empty non-terminal: the NSEC of `x.w.example.` leads below it.
    assert_eq!(
        prove_wildcard(APEX, "a.y.w.example.", 2, &nsecs(&["x.w.example."])),
        Err(Unproven::CloserNameExists)
    );
    // `x.w.example.` exists and has an NSEC of its own.
    assert_eq!(
        prove_wildcard(APEX, "a.x.w.example.", 2, &nsecs(&["x.w.example."])),
        Err(Unproven::CloserNameExists)
    );
    // Labels that leave nothing for the wildcard to replace.
    assert_eq!(
        prove_wildcard(APEX, "a.z.w.example.", 4, &records),
        Err(Unproven::NotExpanded)
    );
}

/// B.7: `*.w.example.` exists and has no AAAA, and `x.y.w.example.` covers `z.w.example.`.
#[test]
fn b7_wildcard_no_data() {
    let records = nsecs(&["x.y.w.example.", "*.w.example."]);
    assert_eq!(
        prove(APEX, "a.z.w.example.", RecordType::AAAA, &records),
        Ok(proof(Fact::WildcardNoData))
    );
    // The wildcard has an MX: the response should have been an answer.
    assert_eq!(
        prove(APEX, "a.z.w.example.", RecordType::MX, &records),
        Err(Unproven::WildcardHasType)
    );
}

/// B.8: the NSEC of the apex has SOA, so it is the child's, and says nothing of a delegation.
#[test]
fn b8_ds_from_the_child() {
    let records = nsecs(&["example."]);
    assert_eq!(
        prove(APEX, "example.", RecordType::DS, &records),
        Err(Unproven::FromChildApex)
    );
    // At the apex, other types are no data as anywhere.
    assert_eq!(
        prove(APEX, "example.", RecordType::AAAA, &records),
        Ok(proof(Fact::NoData))
    );
    assert_eq!(
        prove(APEX, "example.", RecordType::MX, &records),
        Err(Unproven::TypePresent)
    );
}

#[test]
fn other_questions_prove_nothing() {
    let records = nsecs(&["b.example.", "example."]);
    assert_eq!(
        prove(APEX, "ml.other.", RecordType::A, &records),
        Err(Unproven::OutsideZone)
    );
    assert_eq!(
        prove(APEX, "ml.example.", RecordType::A, &[]),
        Err(Unproven::NoUsableRecords)
    );
    // Records of another zone are ignored.
    assert_eq!(
        prove("other.", "ml.other.", RecordType::A, &records),
        Err(Unproven::NoUsableRecords)
    );
}
