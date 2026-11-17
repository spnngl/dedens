//! The root's trust anchors read from IANA's `root-anchors.xml` and checked by its signature, with the
//! `fetch-anchors` feature (D127).
//!
//! - RFC 9718 (the root zone's trust anchors) §2 and §4.1: the `KeyDigest` entries valid at a time, those whose
//!   DNSKEY does not match left out; §3.2: the detached CMS signature, by ICANN's `dnssec@iana.org` certificate
//!   issued by ICANN's CA.
//!
//! The XML, its `.p7s` and ICANN's CA bundle are those `just root-anchors` fetched, at the time in
//! `testdata/dnssec/root-anchors.captured_at`.

use std::fs;

use data_encoding::BASE64;
use dedens_dnssec::{AnchorXmlError, SignedAnchorError, TrustAnchors};
use dedens_proto::Name;
use dedens_proto::rdata::Ds;

fn file(name: &str) -> Vec<u8> {
    fs::read(dedens_testkit::path(&format!("dnssec/{name}"))).expect("a captured file")
}

fn captured_at() -> u64 {
    String::from_utf8(file("root-anchors.captured_at"))
        .expect("text")
        .trim()
        .parse()
        .expect("Unix time in seconds")
}

/// The CA certificates of the bundled `icannbundle.pem`, each as PEM.
fn icann_cas() -> Vec<String> {
    let bundle = include_str!("../src/icannbundle.pem");
    let end = "-----END CERTIFICATE-----";
    bundle
        .split_inclusive(end)
        .filter(|pem| pem.contains(end))
        .map(|pem| pem.trim().to_owned())
        .collect()
}

/// The key tags of the root's DS records.
fn tags(anchors: &TrustAnchors) -> Vec<u16> {
    let (_, root) = anchors.closest(&Name::root()).expect("a root anchor");
    root.ds().iter().map(Ds::key_tag).collect()
}

/// Seconds since 1970 of a day at 00:00 UTC (Howard Hinnant's `days_from_civil`, from 1970 on).
fn day(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (year / 400, year % 400);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) * 86_400
}

// --- RFC 9718 §3.2: the signature ---

#[test]
fn s3_2_the_captured_anchors_verify_and_are_the_bundled_ones() {
    let anchors = TrustAnchors::verified(
        &file("root-anchors.xml"),
        &file("root-anchors.p7s"),
        captured_at(),
    );
    assert_eq!(anchors, Ok(TrustAnchors::root()));
}

#[test]
fn s3_2_any_changed_byte_of_the_xml_is_refused() {
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    for at in 0..xml.len() {
        let mut changed = xml.clone();
        changed[at] ^= 1;
        assert_eq!(
            TrustAnchors::verified(&changed, &p7s, now),
            Err(SignedAnchorError::Signature(
                "the message digest is not the XML's"
            )),
            "byte {at}"
        );
    }
}

/// Each byte of `part`, found in the captured `.p7s`, changed in turn: the signature is refused.
fn refused_when_changed(part: &[u8]) {
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    let start = p7s
        .windows(part.len())
        .position(|window| window == part)
        .expect("the part in the .p7s");
    for at in start..start + part.len() {
        let mut changed = p7s.clone();
        changed[at] ^= 1;
        assert!(
            matches!(
                TrustAnchors::verified(&xml, &changed, now),
                Err(SignedAnchorError::Signature(_))
            ),
            "byte {at}"
        );
    }
}

#[test]
fn s3_2_a_changed_byte_of_the_signature_value_is_refused() {
    let p7s = file("root-anchors.p7s");
    // The SignerInfo ends with the RSA signature, 256 bytes for ICANN's 2048-bit key.
    refused_when_changed(&p7s[p7s.len() - 256..]);
}

#[test]
fn s3_2_a_changed_byte_of_the_signed_message_digest_is_refused() {
    let digest = ring::digest::digest(&ring::digest::SHA256, &file("root-anchors.xml"));
    refused_when_changed(digest.as_ref());
}

#[test]
fn s3_2_a_changed_byte_of_the_signers_name_is_refused() {
    refused_when_changed(b"DNSSEC Trust Anchor Verification");
    refused_when_changed(b"dnssec@iana.org");
}

#[test]
fn s3_2_a_signature_out_of_its_certificates_validity_is_refused() {
    let (xml, p7s) = (file("root-anchors.xml"), file("root-anchors.p7s"));
    // The signer's certificate is valid from 2023-03-15 to 2029-03-13.
    for now in [day(2023, 3, 14), day(2029, 3, 14)] {
        assert_eq!(
            TrustAnchors::verified(&xml, &p7s, now),
            Err(SignedAnchorError::Signature(
                "the signer's certificate is not valid now"
            )),
        );
    }
}

#[test]
fn s3_2_the_issuing_ca_alone_verifies() {
    let cas = icann_cas();
    assert_eq!(cas.len(), 2, "ICANN Root CA and ICANN Root CA v2");
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    assert_eq!(
        TrustAnchors::verified_by(&xml, &p7s, &cas[0], now),
        Ok(TrustAnchors::root())
    );
}

#[test]
fn s3_2_a_chain_to_another_ca_is_refused() {
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    let refused = Err(SignedAnchorError::Signature(
        "no trusted CA valid now issued the signer's certificate",
    ));
    // ICANN Root CA v2: a real CA, not the signer's issuer.
    assert_eq!(
        TrustAnchors::verified_by(&xml, &p7s, &icann_cas()[1], now),
        refused
    );
    // The issuer's name with another key: one byte of its RSA modulus changed.
    let pem = &icann_cas()[0];
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut der = BASE64.decode(body.as_bytes()).expect("base64");
    let modulus = der
        .windows(5)
        .position(|window| window == [0x02, 0x82, 0x01, 0x01, 0x00])
        .expect("a 2048-bit modulus");
    der[modulus + 100] ^= 1;
    let lines: Vec<String> = BASE64
        .encode(&der)
        .as_bytes()
        .chunks(64)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect();
    let other_key = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    );
    assert_eq!(
        TrustAnchors::verified_by(&xml, &p7s, &other_key, now),
        refused
    );
}

#[test]
fn s3_2_a_bundle_without_a_certificate_is_refused() {
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    assert_eq!(
        TrustAnchors::verified_by(&xml, &p7s, "", now),
        Err(SignedAnchorError::Ca)
    );
}

// --- RFC 9718 §2, §4.1: the KeyDigest entries ---

#[test]
fn s2_each_key_digest_holds_within_its_validity() {
    let xml = file("root-anchors.xml");
    let at = |now| TrustAnchors::from_xml(&xml, now).map(|anchors| tags(&anchors));
    // 19036 from 2010-07-15 until 2019-01-11, 20326 from 2017-02-02, 38696 from 2024-07-18.
    assert_eq!(at(day(2010, 7, 14)), Err(AnchorXmlError::NoneValid));
    assert_eq!(at(day(2010, 7, 15)), Ok(vec![19036]));
    assert_eq!(at(day(2017, 2, 2)), Ok(vec![19036, 20326]));
    assert_eq!(at(day(2019, 1, 11)), Ok(vec![20326]));
    assert_eq!(at(day(2024, 7, 18)), Ok(vec![20326, 38696]));
}

#[test]
fn s4_1_2_a_key_digest_whose_key_does_not_match_is_left_out() {
    let xml = String::from_utf8(file("root-anchors.xml")).expect("UTF-8");
    let key = xml.find("<PublicKey>").expect("a PublicKey") + "<PublicKey>".len();
    let mut changed = xml.into_bytes();
    // The first key, 20326's: 'A' to 'B' changes its base64.
    changed[key + 1] = if changed[key + 1] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        TrustAnchors::from_xml(&changed, captured_at()).map(|anchors| tags(&anchors)),
        Ok(vec![38696])
    );
}

#[test]
fn s2_text_that_is_not_root_anchors_is_refused() {
    for (xml, error) in [
        ("", AnchorXmlError::Invalid("no TrustAnchor element")),
        (
            "<a/>",
            AnchorXmlError::Invalid("the root element is not TrustAnchor"),
        ),
        (
            "<TrustAnchor>",
            AnchorXmlError::Syntax {
                at: 13,
                what: "an element not closed",
            },
        ),
        (
            "<!DOCTYPE x><TrustAnchor/>",
            AnchorXmlError::Syntax {
                at: 0,
                what: "a DOCTYPE or a CDATA section",
            },
        ),
        (
            "<TrustAnchor>&amp;</TrustAnchor>",
            AnchorXmlError::Syntax {
                at: 13,
                what: "an entity reference",
            },
        ),
        (
            "<TrustAnchor><Zone>.</Zone></TrustAnchor>",
            AnchorXmlError::NoneValid,
        ),
    ] {
        assert_eq!(
            TrustAnchors::from_xml(xml.as_bytes(), captured_at()),
            Err(error),
            "{xml}"
        );
    }
}
