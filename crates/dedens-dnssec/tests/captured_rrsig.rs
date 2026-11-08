//! The signatures and DS records of the captured responses (`testdata/dnssec/README.md`) through
//! `dedens_dnssec::rrsig`: every signed `RRset` verifies at `captured_at` with the keys of its signer, fails after
//! its expiration and before its inception, and fails with one byte of its RDATA changed; every zone's DNSKEY
//! `RRset` is vouched for by its DS records, or not, as the README says.

mod common;

use common::try_records;
use dedens_dnssec::crypto::{self, Budget};
use dedens_dnssec::rrsig::{self, Key, RrSet, SigError, Signature};
use dedens_proto::{Message, RecordType};
use dedens_testkit::dnssec::{captured_at, names, response};

/// An `RRset` of a capture and the RRSIG `RRset` at its owner.
struct Signed {
    capture: String,
    data: RrSet<'static>,
    sigs: RrSet<'static>,
}

impl Signed {
    /// The RRSIG records that cover the data.
    fn covering(&self) -> Vec<Signature<'_>> {
        Signature::all(&self.sigs)
            .into_iter()
            .filter(|sig| sig.rrsig().type_covered == self.data.rtype())
            .collect()
    }

    fn verify(&self, keys: &RrSet<'_>, data: &RrSet<'_>, now: u32) -> Result<(), SigError> {
        rrsig::verify_any(
            data,
            &self.covering(),
            &Key::all(keys),
            now,
            &mut Budget::default(),
        )
        .map(drop)
    }
}

/// The `RRsets` of the answer and authority sections that an RRSIG covers.
fn signed(name: &str) -> Vec<Signed> {
    let message: Message<'static> = response(name);
    let sets: Vec<RrSet<'static>> = [&message.answer, &message.authority]
        .into_iter()
        .flat_map(|section| RrSet::group(section))
        .collect();
    let (rrsigs, data): (Vec<_>, Vec<_>) = sets
        .into_iter()
        .partition(|set| set.rtype() == RecordType::RRSIG);
    data.into_iter()
        .filter_map(|data| {
            let sigs = rrsigs.iter().find(|sigs| sigs.owner() == data.owner())?;
            let item = Signed {
                capture: name.to_owned(),
                data,
                sigs: sigs.clone(),
            };
            (!item.covering().is_empty()).then_some(item)
        })
        .collect()
}

/// Every DNSKEY `RRset` of the captured chains.
fn zone_keys() -> Vec<RrSet<'static>> {
    names()
        .iter()
        .filter(|name| name.ends_with("_dnskey") || *name == "root_dnskey")
        .flat_map(|name| {
            let message = response(name);
            RrSet::group(&message.answer)
                .into_iter()
                .filter(|set| set.rtype() == RecordType::DNSKEY)
                .map(RrSet::into_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The DNSKEY `RRset` of the signer of `item`'s first covering RRSIG.
fn keys_of<'a>(zones: &'a [RrSet<'static>], item: &Signed) -> &'a RrSet<'static> {
    let covering = item.covering();
    let signer = &covering.first().expect("covered").rrsig().signer;
    zones
        .iter()
        .find(|zone| zone.owner() == signer)
        .unwrap_or_else(|| unreachable!("{}: no captured DNSKEY of {signer}", item.capture))
}

/// The signed `RRsets` of every capture whose signer's DNSKEY `RRset` is captured (the DS of `rhybar.cz` is signed
/// by `cz`, which is not).
fn every_signed_set(zones: &[RrSet<'static>]) -> Vec<Signed> {
    names()
        .iter()
        .flat_map(|name| signed(name))
        .filter(|item| {
            let covering = item.covering();
            let signer = &covering.first().expect("covered").rrsig().signer;
            zones.iter().any(|zone| zone.owner() == signer)
        })
        .collect()
}

fn unsupported(item: &Signed) -> bool {
    item.covering()
        .iter()
        .all(|sig| !crypto::supported(sig.rrsig().algorithm))
}

#[test]
fn every_signed_rrset_verifies_at_the_capture_time() {
    let zones = zone_keys();
    let now = captured_at();
    let mut verified = 0;
    for item in every_signed_set(&zones) {
        let result = item.verify(keys_of(&zones, &item), &item.data, now);
        let label = format!(
            "{} {} {}",
            item.capture,
            item.data.owner(),
            item.data.rtype()
        );
        match (item.capture.as_str(), item.data.rtype()) {
            // Ed448: `ring` has none (D71); the RRSIGs of an unsupported algorithm are disregarded, and the
            // zone is insecure by its DS (`a_ds_of_an_unsupported_algorithm_is_insecure_not_bogus`).
            ("alg16_a" | "ed448_nl_dnskey", _) => {
                assert_eq!(result, Err(SigError::NoSignature), "{label}");
            }
            // The signatures of `rhybar.cz` ended in October 2025, the A of `sigexpired.bad-dnssec.wb.sidnlabs.nl` in
            // December 2019.
            (
                "bogus_expired"
                | "bogus_sigexpired"
                | "sigexpired_wb_sidnlabs_nl_dnskey"
                | "rhybar_cz_dnskey",
                _,
            ) => assert!(
                matches!(result, Err(SigError::Expired { .. })),
                "{label}: {result:?}"
            ),
            // The A of `sigfail.verteiltesysteme.net`: a signature that does not verify.
            ("bogus_signature", RecordType::A) => assert!(
                matches!(result, Err(SigError::BadSignature { .. })),
                "{label}: {result:?}"
            ),
            _ => {
                assert_eq!(result, Ok(()), "{label}");
                verified += 1;
            }
        }
    }
    assert!(verified > 100, "{verified} RRsets verified");
}

#[test]
fn every_signed_rrset_fails_one_second_after_its_expiration() {
    let zones = zone_keys();
    for item in every_signed_set(&zones)
        .iter()
        .filter(|item| !unsupported(item))
    {
        let last = item
            .covering()
            .iter()
            .map(|sig| sig.rrsig().expiration)
            .max()
            .expect("covered");
        let result = item.verify(keys_of(&zones, item), &item.data, last + 1);
        assert!(
            matches!(result, Err(SigError::Expired { .. })),
            "{} {}: {result:?}",
            item.capture,
            item.data.owner()
        );
    }
}

#[test]
fn every_signed_rrset_fails_one_second_before_its_inception() {
    let zones = zone_keys();
    for item in every_signed_set(&zones)
        .iter()
        .filter(|item| !unsupported(item))
    {
        let first = item
            .covering()
            .iter()
            .map(|sig| sig.rrsig().inception)
            .min()
            .expect("covered");
        let result = item.verify(keys_of(&zones, item), &item.data, first - 1);
        assert!(
            matches!(result, Err(SigError::NotYetValid { .. })),
            "{} {}: {result:?}",
            item.capture,
            item.data.owner()
        );
    }
}

/// `set` with the last byte of its first RDATA that keeps the message decodable inverted in its lowest bit.
fn mutated(set: &RrSet<'_>) -> Option<RrSet<'static>> {
    let rdatas: Vec<Vec<u8>> = set.rdatas().iter().map(|r| r.wire().into_owned()).collect();
    let len = rdatas.first()?.len();
    (0..len).rev().find_map(|at| {
        let mut changed = rdatas.clone();
        *changed.first_mut()?.get_mut(at)? ^= 1;
        let records = try_records(
            &set.owner().to_string(),
            set.rtype().0,
            set.ttl().get(),
            &changed,
        )?;
        RrSet::group(&records).pop()
    })
}

#[test]
fn every_signed_rrset_fails_with_one_byte_changed() {
    let zones = zone_keys();
    let now = captured_at();
    let mut changed = 0;
    for item in every_signed_set(&zones) {
        let keys = keys_of(&zones, &item);
        if item.verify(keys, &item.data, now).is_err() {
            continue;
        }
        let other = mutated(&item.data).expect("a byte that keeps the RDATA decodable");
        assert_ne!(other.canonical_rdatas(), item.data.canonical_rdatas());
        let result = item.verify(keys, &other, now);
        let label = format!(
            "{} {} {}",
            item.capture,
            item.data.owner(),
            item.data.rtype()
        );
        if item.data.rtype() == RecordType::DNSKEY {
            // A changed key may also change its tag, so that no key is the signer's.
            assert!(result.is_err(), "{label}");
        } else {
            assert!(
                matches!(result, Err(SigError::BadSignature { .. })),
                "{label}: {result:?}"
            );
        }
        changed += 1;
    }
    assert!(changed > 100, "{changed} RRsets mutated");
}

#[test]
fn a_wildcard_answer_names_its_closest_encloser() {
    let zones = zone_keys();
    let wildcard = signed("wildcard_answer")
        .into_iter()
        .find(|item| item.data.rtype() == RecordType::MX)
        .expect("an MX RRset");
    let verified = rrsig::verify_any(
        &wildcard.data,
        &wildcard.covering(),
        &Key::all(keys_of(&zones, &wildcard)),
        captured_at(),
        &mut Budget::default(),
    )
    .expect("verifies");
    let encloser = verified.wildcard.expect("expanded from a wildcard");
    assert_eq!(encloser.to_string(), "sidnlabs.nl.");
    assert!(wildcard.data.owner().is_within(&encloser));
    assert_ne!(wildcard.data.owner(), &encloser);
}

/// The expansions of the wildcards of `internet.nl` (NSEC), `ph` and `ws` (opt-out NSEC3) name their zone as the
/// encloser, and `nist.gov`, which signs each name on demand, is no expansion.
#[test]
fn the_wildcards_of_other_zones_name_their_closest_encloser() {
    let zones = zone_keys();
    for (id, rtype, encloser) in [
        (
            "wildcard_answer_nsec",
            RecordType::TXT,
            Some("internet.nl."),
        ),
        ("wildcard_answer_optout", RecordType::A, Some("ph.")),
        ("wildcard_answer_optout_ws", RecordType::A, Some("ws.")),
        ("synthesized_nist_gov_txt", RecordType::TXT, None),
    ] {
        let item = signed(id)
            .into_iter()
            .find(|item| item.data.rtype() == rtype)
            .unwrap_or_else(|| panic!("{id}: no {rtype} RRset"));
        let verified = rrsig::verify_any(
            &item.data,
            &item.covering(),
            &Key::all(keys_of(&zones, &item)),
            captured_at(),
            &mut Budget::default(),
        )
        .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(
            verified.wildcard.map(|name| name.to_string()).as_deref(),
            encloser,
            "{id}"
        );
    }
}

/// The signed DNSKEY `RRset` of a zone and its DS `RRset` from the parent.
fn zone(id: &str) -> (Signed, RrSet<'static>) {
    let dnskey = signed(&format!("{id}_dnskey"))
        .into_iter()
        .find(|item| item.data.rtype() == RecordType::DNSKEY)
        .expect("signed DNSKEY RRset");
    let ds = response(&format!("{id}_ds"));
    let ds = RrSet::group(&ds.answer)
        .into_iter()
        .find(|set| set.rtype() == RecordType::DS)
        .expect("DS RRset");
    (dnskey, ds)
}

/// Whether the DS `RRset` vouches for the zone's DNSKEY `RRset` at `now`.
fn trusted(zone: &Signed, ds: &RrSet<'_>, now: u32) -> Result<(), SigError> {
    rrsig::trusted_keys(
        &zone.data,
        &zone.covering(),
        ds,
        now,
        &mut Budget::default(),
    )
    .map(drop)
}

const ZONES: &[&str] = &[
    "com",
    "net",
    "org",
    "nl",
    "cat",
    "la",
    "cr",
    "dev",
    "stream",
    "nlnetlabs_nl",
    "cloudflare_com",
    "sidnlabs_nl",
    "example_nl",
    "icann_org",
    "cloudflare_net",
    "ripe_net",
    "verteiltesysteme_net",
    "fedoraproject_org",
    "ed25519_nl",
    "debian_org",
    "rootcanary_net",
    "ippacket_stream",
    "rsa2048_ippacket_stream",
    "cz",
    "wb_sidnlabs_nl",
    "bad_dnssec_wb_sidnlabs_nl",
    "internet_nl",
    "nist_gov",
    "ph",
    "ws",
];

#[test]
fn every_dnskey_rrset_is_vouched_for_by_its_ds() {
    for id in ZONES {
        let (dnskey, ds) = zone(id);
        assert_eq!(trusted(&dnskey, &ds, captured_at()), Ok(()), "{id}");
    }
}

#[test]
fn a_zone_whose_keys_signatures_expired_is_not_vouched_for() {
    // `sigexpired.bad-dnssec.wb.sidnlabs.nl`: the DS matches, the DNSKEY set's signature ended in December 2019.
    let (dnskey, ds) = zone("sigexpired_wb_sidnlabs_nl");
    let result = trusted(&dnskey, &ds, captured_at());
    assert!(
        matches!(result, Err(SigError::Expired { .. })),
        "{result:?}"
    );
}

#[test]
fn a_ds_that_matches_no_key_is_bogus_not_insecure() {
    // `dnssec-failed.org` (13) and `rhybar.cz`: the DS names a key the zone does not have.
    for id in ["dnssec_failed_org", "rhybar_cz"] {
        let (dnskey, ds) = zone(id);
        let result = trusted(&dnskey, &ds, captured_at());
        assert_eq!(result, Err(SigError::NoKeyForDs), "{id}");
    }
}

#[test]
fn a_ds_of_an_unsupported_algorithm_is_insecure_not_bogus() {
    // `ed448.nl`: Ed448 (D71); RFC 4035 §5.2, RFC 6840 §5.2.
    let (dnskey, ds) = zone("ed448_nl");
    let error = trusted(&dnskey, &ds, captured_at()).expect_err("not validated");
    assert!(error.is_unsupported(), "{error:?}");
}

#[test]
fn a_changed_digest_is_no_match() {
    // `la` has a SHA-1 and a SHA-256 DS: with SHA-256 present, SHA-1 is ignored (RFC 4509 §3), so changing the
    // SHA-256 digest leaves no key, though the SHA-1 digest is right.
    let (dnskey, ds) = zone("la");
    let mut rdatas: Vec<Vec<u8>> = ds.rdatas().iter().map(|r| r.wire().into_owned()).collect();
    let digest_types: Vec<u8> = rdatas
        .iter()
        .map(|r| r.get(3).copied().unwrap_or(0))
        .collect();
    assert!(
        digest_types.contains(&1) && digest_types.contains(&2),
        "{digest_types:?}"
    );
    for rdata in &mut rdatas {
        if rdata.get(3) == Some(&2) {
            *rdata.last_mut().expect("digest") ^= 1;
        }
    }
    let changed = try_records(&ds.owner().to_string(), 43, 3600, &rdatas).expect("decodes");
    let changed = RrSet::group(&changed).pop().expect("one RRset");
    assert_eq!(
        trusted(&dnskey, &changed, captured_at()),
        Err(SigError::NoKeyForDs)
    );
}
