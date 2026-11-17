//! The root's trust anchors read from IANA's `root-anchors.xml` and checked by its signature, with the
//! `fetch-anchors` feature (D127).
//!
//! - RFC 9718 (the root zone's trust anchors) §2 and §4.1: the `KeyDigest` entries valid at a time, those whose
//!   DNSKEY does not match left out; §3.2: the detached CMS signature, by ICANN's `dnssec@iana.org` certificate
//!   issued by ICANN's CA.
//! - RFC 5652 (CMS) §5 and §11: the `SignedData`, its signers and their signed attributes.
//! - RFC 5280 (X.509) §4.1 and §4.2: the signer's certificate, its validity and extensions.
//! - RFC 5011 §2.1 and RFC 4034 §2.1.1: a revoked key or one not of the zone is no anchor.
//!
//! The XML, its `.p7s` and ICANN's CA bundle are those `just roots` fetched, at the time in
//! `testdata/dnssec/root-anchors.captured_at`.

use std::fs;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use data_encoding::{BASE64, HEXUPPER};
use dedens_dnssec::crypto::{ds_digest, key_tag};
use dedens_dnssec::{
    AnchorFile, AnchorXmlError, MAX_P7S, MAX_XML, SignedAnchorError, SignedAnchors, TrustAnchors,
};
use dedens_proto::rdata::Ds;
use dedens_proto::{DigestType, Name};
use x509_cert::TbsCertificate;
use x509_cert::attr::Attribute;
use x509_cert::der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use x509_cert::der::{Any, Decode, DerOrd, Encode};
use x509_cert::ext::pkix::{BasicConstraints, SubjectKeyIdentifier};

/// When ICANN signed the captured pair: its `signingTime`, 2025-03-25 20:25:02 UTC.
const SIGNED_AT: u64 = 1_742_934_302;

/// The anchors of a signed pair at `now`, with no signing time accepted before but the bundled one.
fn verified(xml: &[u8], p7s: &[u8], now: u64) -> Result<TrustAnchors, SignedAnchorError> {
    TrustAnchors::verified(xml, p7s, now, None).map(SignedAnchors::into_anchors)
}

/// As `verified`, against the CAs of `ca`.
fn verified_by(
    xml: &[u8],
    p7s: &[u8],
    ca: &str,
    now: u64,
) -> Result<TrustAnchors, SignedAnchorError> {
    TrustAnchors::verified_by(xml, p7s, ca, now, None).map(SignedAnchors::into_anchors)
}

/// The captured `.p7s` with the captured XML at the capture time: `Err` with `error` from `verified`.
fn refused_as(p7s: &[u8], error: &'static str) {
    assert_eq!(
        verified(&file("root-anchors.xml"), p7s, captured_at()),
        Err(SignedAnchorError::Signature(error))
    );
}

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
    let signed = TrustAnchors::verified(
        &file("root-anchors.xml"),
        &file("root-anchors.p7s"),
        captured_at(),
        None,
    )
    .expect("the captured pair");
    assert_eq!(signed.anchors(), &TrustAnchors::root());
    assert_eq!(signed.signed_at(), SIGNED_AT);
    // The file is `include!`d: a comment line, then the number.
    let bundled = include_str!("../src/root.signed_at")
        .lines()
        .last()
        .map(str::parse);
    assert_eq!(
        bundled,
        Some(Ok(SIGNED_AT)),
        "the bundled anchors' signing time"
    );
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
            verified(&changed, &p7s, now),
            Err(SignedAnchorError::Signature(
                "the message digest is not the XML's"
            )),
            "byte {at}"
        );
    }
}

/// Each byte of `part`, found in the captured `.p7s`, changed in turn: the signature is refused with `error`.
fn refused_when_changed(part: &[u8], error: &'static str) {
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
        assert_eq!(
            verified(&xml, &changed, now),
            Err(SignedAnchorError::Signature(error)),
            "byte {at}"
        );
    }
}

#[test]
fn s3_2_a_changed_byte_of_the_signature_value_is_refused() {
    let p7s = file("root-anchors.p7s");
    // The SignerInfo ends with the RSA signature, 256 bytes for ICANN's 2048-bit key.
    refused_when_changed(&p7s[p7s.len() - 256..], "a signature that does not verify");
}

#[test]
fn s3_2_a_changed_byte_of_the_signed_message_digest_is_refused() {
    let digest = ring::digest::digest(&ring::digest::SHA256, &file("root-anchors.xml"));
    refused_when_changed(digest.as_ref(), "the message digest is not the XML's");
}

#[test]
fn s3_2_a_changed_byte_of_the_signers_name_is_refused() {
    // Its common name: the CA's signature no longer holds.
    refused_when_changed(
        b"DNSSEC Trust Anchor Verification",
        "no trusted CA valid now issued the signer's certificate",
    );
    refused_when_changed(
        b"dnssec@iana.org",
        "the signer's certificate is not for dnssec@iana.org",
    );
}

#[test]
fn s3_2_a_signature_holds_within_its_certificates_validity_only() {
    let (xml, p7s) = (file("root-anchors.xml"), file("root-anchors.p7s"));
    // The signer's certificate is valid from 2023-03-15 21:49:35 to 2029-03-13 21:49:35, both included.
    let (from, until) = (day(2023, 3, 15) + 78_575, day(2029, 3, 13) + 78_575);
    for now in [from, until] {
        assert!(verified(&xml, &p7s, now).is_ok(), "{now}");
    }
    for now in [from - 1, until + 1] {
        assert_eq!(
            verified(&xml, &p7s, now),
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
        verified_by(&xml, &p7s, &cas[0], now),
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
    assert_eq!(verified_by(&xml, &p7s, &icann_cas()[1], now), refused);
    // The issuer's name with another key: one byte of its RSA modulus changed.
    let other_key = issuer_changed(|der| {
        let modulus = der
            .windows(5)
            .position(|window| window == [0x02, 0x82, 0x01, 0x01, 0x00])
            .expect("a 2048-bit modulus");
        der[modulus + 100] ^= 1;
    });
    assert_eq!(verified_by(&xml, &p7s, &other_key, now), refused);
    // The issuer's key under another name: its subject, after its own issuer, renamed.
    let other_name = issuer_changed(|der| {
        let name = b"ICANN Root CA";
        let subject = der
            .windows(name.len())
            .rposition(|window| window == name)
            .expect("the CA's subject");
        der[subject + name.len() - 1] = b'B';
    });
    assert_eq!(verified_by(&xml, &p7s, &other_name, now), refused);
}

/// ICANN Root CA, the signer's issuer, as PEM after `change` of its DER.
fn issuer_changed(change: impl FnOnce(&mut Vec<u8>)) -> String {
    let body: String = icann_cas()[0]
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut der = BASE64.decode(body.as_bytes()).expect("base64");
    change(&mut der);
    let lines: Vec<String> = BASE64
        .encode(&der)
        .as_bytes()
        .chunks(64)
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

/// The captured `.p7s` with the object identifier ending `from`, at its `nth` place (negative: from the end),
/// ending `to` instead.
fn p7s_with_oid(from: &[u8], to: u8, nth: isize) -> Vec<u8> {
    let mut p7s = file("root-anchors.p7s");
    let places: Vec<usize> = p7s
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(at, _)| at + from.len() - 1)
        .collect();
    let place = usize::try_from(nth)
        .ok()
        .or_else(|| places.len().checked_sub(nth.unsigned_abs()))
        .and_then(|index| places.get(index))
        .expect("the object identifier in the .p7s");
    p7s[*place] = to;
    p7s
}

/// id-data, 1.2.840.113549.1.7.1, as DER.
const DATA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];
/// rsaEncryption, 1.2.840.113549.1.1.1, as DER.
const RSA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

#[test]
fn s3_2_signed_content_other_than_data_is_refused() {
    let (xml, now) = (file("root-anchors.xml"), captured_at());
    // The first id-data is the SignedData's content type, which the signer does not sign; 7.2 is signed data.
    assert_eq!(
        verified(&xml, &p7s_with_oid(DATA, 0x02, 0), now),
        Err(SignedAnchorError::Signature(
            "not a detached signature of data"
        ))
    );
}

#[test]
fn s3_2_the_signature_algorithm_follows_the_digest() {
    let (xml, now) = (file("root-anchors.xml"), captured_at());
    // The last rsaEncryption is the SignerInfo's signature algorithm, which the signer does not sign either:
    // 1.11 is sha256WithRSAEncryption, the signer's digest, 1.5 sha1WithRSAEncryption.
    assert!(verified(&xml, &p7s_with_oid(RSA, 0x0b, -1), now).is_ok());
    assert_eq!(
        verified(&xml, &p7s_with_oid(RSA, 0x05, -1), now),
        Err(SignedAnchorError::Signature(
            "a signature algorithm other than RSA with the signer's digest"
        ))
    );
}

#[test]
fn s3_2_a_bundle_without_a_certificate_is_refused() {
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    assert_eq!(verified_by(&xml, &p7s, "", now), Err(SignedAnchorError::Ca));
}

#[test]
fn s3_2_a_file_over_its_limit_is_not_read() {
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    let padded = |bytes: &[u8], len: usize| {
        let mut padded = bytes.to_vec();
        padded.resize(len, b' ');
        padded
    };
    assert_eq!(
        verified(&padded(&xml, MAX_XML), &p7s, now),
        Err(SignedAnchorError::Signature(
            "the message digest is not the XML's"
        ))
    );
    assert_eq!(
        verified(&padded(&xml, MAX_XML + 1), &p7s, now),
        Err(SignedAnchorError::TooLarge {
            file: AnchorFile::Xml,
            limit: MAX_XML
        })
    );
    assert_eq!(
        verified(&xml, &padded(&p7s, MAX_P7S), now),
        Err(SignedAnchorError::Signature("not DER CMS"))
    );
    assert_eq!(
        verified(&xml, &padded(&p7s, MAX_P7S + 1), now),
        Err(SignedAnchorError::TooLarge {
            file: AnchorFile::P7s,
            limit: MAX_P7S
        })
    );
    // The error names the file IANA publishes.
    assert_eq!(
        [AnchorFile::Xml, AnchorFile::P7s].map(|file| file.to_string()),
        ["root-anchors.xml", "root-anchors.p7s"]
    );
}

// --- RFC 9718 §3.2, RFC 5652 §11.3: the signing time ---

#[test]
fn s3_2_a_pair_signed_before_the_last_accepted_is_refused() {
    let (xml, p7s, now) = (
        file("root-anchors.xml"),
        file("root-anchors.p7s"),
        captured_at(),
    );
    let at = |last| TrustAnchors::verified(&xml, &p7s, now, last).map(|signed| signed.signed_at());
    assert_eq!(at(Some(0)), Ok(SIGNED_AT));
    assert_eq!(at(Some(SIGNED_AT)), Ok(SIGNED_AT));
    assert_eq!(
        at(Some(SIGNED_AT + 1)),
        Err(SignedAnchorError::Signature(
            "a signing time before the floor"
        ))
    );
}

#[test]
fn s3_2_a_pair_signed_before_the_bundled_anchors_is_refused() {
    // The signingTime attribute, UTCTime 2025-03-25 20:25:02: a day earlier is refused before its signature is
    // checked, even under an older floor of the caller's, a day later fails the signature, which covers it.
    let with_time = |time: &[u8]| {
        let mut p7s = file("root-anchors.p7s");
        let at = p7s
            .windows(13)
            .position(|window| window == b"250325202502Z")
            .expect("the signing time");
        p7s[at..at + 13].copy_from_slice(time);
        p7s
    };
    let earlier = with_time(b"250324202502Z");
    refused_as(&earlier, "a signing time before the floor");
    assert_eq!(
        TrustAnchors::verified(&file("root-anchors.xml"), &earlier, captured_at(), Some(0)),
        Err(SignedAnchorError::Signature(
            "a signing time before the floor"
        ))
    );
    refused_as(
        &with_time(b"250326202502Z"),
        "a signature that does not verify",
    );
}

// --- RFC 9718 §3.2, RFC 5280 §4.1, §4.2: the signer's certificate ---

/// The captured `.p7s` with the first place of `from`, in the signer's certificate, as `to`.
fn p7s_with(from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut p7s = file("root-anchors.p7s");
    let at = p7s
        .windows(from.len())
        .position(|window| window == from)
        .expect("the bytes in the .p7s");
    p7s[at..at + to.len()].copy_from_slice(to);
    p7s
}

#[test]
fn s3_2_a_signer_without_digital_signature_is_refused() {
    // Its key usage, critical: digital signature and key encipherment, then key encipherment alone.
    let usage = [
        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x00, 0xa0,
    ];
    let mut without = usage;
    without[11] = 0x20;
    refused_as(
        &p7s_with(&usage, &without),
        "the signer's certificate may not sign",
    );
}

#[test]
fn s3_2_a_signer_without_key_usage_is_refused() {
    let p7s = signer_edited(|tbs| {
        let extensions = tbs.extensions.as_mut().expect("extensions");
        extensions.retain(|extension| extension.extn_id != KEY_USAGE);
    });
    refused_as(&p7s, "the signer's certificate has no key usage");
}

#[test]
fn s3_2_a_signer_not_for_e_mail_is_refused() {
    // id-kp-emailProtection, its extended key usage, as id-kp-clientAuth.
    let email = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
    let mut client = email;
    client[7] = 0x02;
    refused_as(
        &p7s_with(&email, &client),
        "the signer's certificate is not for e-mail protection",
    );
}

#[test]
fn s3_2_a_signer_with_a_critical_extension_not_read_is_refused() {
    // Its basic constraints, critical and empty, as certificate policies (2.5.29.32).
    let constraints = [0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00];
    refused_as(
        &p7s_with(&constraints, &[0x55, 0x1d, 0x20]),
        "the signer's certificate has a critical extension not read",
    );
}

#[test]
fn s3_2_a_signer_that_is_a_ca_is_refused() {
    let p7s = signer_edited(|tbs| {
        let extensions = tbs.extensions.as_mut().expect("extensions");
        let constraints = extensions
            .iter_mut()
            .find(|extension| extension.extn_id == BASIC_CONSTRAINTS)
            .expect("basic constraints");
        let ca = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        constraints.extn_value =
            OctetString::new(ca.to_der().expect("DER")).expect("an OCTET STRING");
    });
    refused_as(&p7s, "the signer's certificate is a CA");
}

#[test]
fn s3_2_a_signer_signed_under_two_algorithms_is_refused() {
    // sha256WithRSAEncryption, last the signer's certificate's own, as sha384WithRSAEncryption.
    let sha256_rsa = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    ];
    refused_as(
        &p7s_with_oid(&sha256_rsa, 0x0c, -1),
        "a certificate whose two signature algorithms differ",
    );
}

// --- RFC 9718 §3.2, RFC 5652 §5: the SignedData ---

const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");

/// The captured `.p7s`, its `SignedData` decoded, changed by `edit` and encoded again.
fn p7s_edited(edit: impl FnOnce(&mut SignedData)) -> Vec<u8> {
    let info = ContentInfo::from_der(&file("root-anchors.p7s")).expect("CMS");
    let mut signed: SignedData = info.content.decode_as().expect("SignedData");
    edit(&mut signed);
    let content = Any::encode_from(&signed).expect("DER");
    ContentInfo {
        content_type: info.content_type,
        content,
    }
    .to_der()
    .expect("DER")
}

/// `set` with its elements changed by `edit`, sorted again as DER has them.
fn edit_set<T: DerOrd>(set: &mut SetOfVec<T>, edit: impl FnOnce(&mut Vec<T>)) {
    let mut elements = std::mem::take(set).into_vec();
    edit(&mut elements);
    *set = elements.try_into().expect("a SET OF");
}

/// The captured `.p7s` with the signer's certificate, the one ICANN's CA did not sign itself, changed by `edit`.
fn signer_edited(edit: impl FnOnce(&mut TbsCertificate)) -> Vec<u8> {
    p7s_edited(|signed| {
        let certificates = signed.certificates.as_mut().expect("certificates");
        edit_set(&mut certificates.0, |certificates| {
            let tbs = certificates
                .iter_mut()
                .find_map(|choice| match choice {
                    CertificateChoices::Certificate(certificate)
                        if certificate.tbs_certificate.subject
                            != certificate.tbs_certificate.issuer =>
                    {
                        Some(&mut certificate.tbs_certificate)
                    }
                    _ => None,
                })
                .expect("the signer's certificate");
            edit(tbs);
        });
    })
}

/// The captured `.p7s` with its one `SignerInfo` changed by `edit`.
fn signer_info_edited(edit: impl FnOnce(&mut SignerInfo)) -> Vec<u8> {
    p7s_edited(|signed| {
        edit_set(&mut signed.signer_infos.0, |signers| {
            edit(signers.first_mut().expect("ICANN's one signer"));
        });
    })
}

/// The captured `.p7s` with the signed attributes changed by `edit`.
fn attributes_edited(edit: impl FnOnce(&mut Vec<Attribute>)) -> Vec<u8> {
    signer_info_edited(|signer| {
        edit_set(
            signer.signed_attrs.as_mut().expect("signed attributes"),
            edit,
        );
    })
}

#[test]
fn s3_2_the_captured_signature_encodes_again_as_it_was() {
    assert_eq!(p7s_edited(|_| {}), file("root-anchors.p7s"));
}

#[test]
fn s3_2_attached_content_is_refused() {
    let p7s = p7s_edited(|signed| {
        let xml = OctetString::new(file("root-anchors.xml")).expect("an OCTET STRING");
        signed.encap_content_info.econtent = Some(Any::encode_from(&xml).expect("DER"));
    });
    refused_as(&p7s, "not a detached signature of data");
}

#[test]
fn s3_2_a_signer_named_by_its_key_identifier_is_refused() {
    let p7s = signer_info_edited(|signer| {
        let id = OctetString::new([0x5a; 20]).expect("an OCTET STRING");
        signer.sid = SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(id));
    });
    refused_as(&p7s, "a signer named by its key identifier");
}

#[test]
fn s3_2_a_digest_other_than_sha_2_is_refused() {
    let p7s = signer_info_edited(|signer| {
        signer.digest_alg.oid = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    });
    refused_as(&p7s, "a digest algorithm other than SHA-2");
}

#[test]
fn s3_2_a_digest_the_signed_data_does_not_list_is_refused() {
    // SHA-256, first in the SignedData's digest algorithms, as SHA-384.
    let sha256 = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    refused_as(
        &p7s_with_oid(&sha256, 0x02, 0),
        "a digest algorithm the SignedData does not list",
    );
}

#[test]
fn s3_2_a_signer_without_signed_attributes_is_refused() {
    let p7s = signer_info_edited(|signer| signer.signed_attrs = None);
    refused_as(&p7s, "no signed attributes");
}

#[test]
fn s3_2_a_signed_content_type_other_than_data_is_refused() {
    // The second id-data is the signed contentType attribute's; 7.2 is signed data.
    refused_as(
        &p7s_with_oid(DATA, 0x02, 1),
        "a content type other than data",
    );
}

#[test]
fn s3_2_a_signed_attribute_missing_twice_or_of_two_values_is_refused() {
    let missing = attributes_edited(|attributes| {
        attributes.retain(|attribute| attribute.oid != SIGNING_TIME);
    });
    refused_as(&missing, "a signed attribute missing or twice");
    let twice = attributes_edited(|attributes| {
        let signed_data = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
        let value = Any::encode_from(&signed_data).expect("DER");
        attributes.push(Attribute {
            oid: CONTENT_TYPE,
            values: [value].try_into().expect("a SET OF"),
        });
    });
    refused_as(&twice, "a signed attribute missing or twice");
    let two_values = attributes_edited(|attributes| {
        let digest = attributes
            .iter_mut()
            .find(|attribute| attribute.oid == MESSAGE_DIGEST)
            .expect("the message digest");
        let other = OctetString::new([0; 32]).expect("an OCTET STRING");
        let other = Any::encode_from(&other).expect("DER");
        digest.values.insert(other).expect("another value");
    });
    refused_as(&two_values, "a signed attribute without one value");
}

#[test]
fn s3_2_each_signer_must_verify() {
    let p7s = p7s_edited(|signed| {
        edit_set(&mut signed.signer_infos.0, |signers| {
            let mut other = signers.first().expect("a signer").clone();
            let mut signature = other.signature.as_bytes().to_vec();
            if let Some(last) = signature.last_mut() {
                *last ^= 1;
            }
            other.signature = OctetString::new(signature).expect("an OCTET STRING");
            signers.push(other);
        });
    });
    refused_as(&p7s, "a signature that does not verify");
}

// --- RFC 9718 §2, §4.1: the KeyDigest entries ---

#[test]
fn s2_each_key_digest_holds_within_its_validity() {
    let xml = file("root-anchors.xml");
    let at = |now| TrustAnchors::from_unverified_xml(&xml, now).map(|anchors| tags(&anchors));
    // 19036 from 2010-07-15 until 2019-01-11, 20326 from 2017-02-02, 38696 from 2024-07-18.
    assert_eq!(at(day(2010, 7, 14)), Err(AnchorXmlError::NoneValid));
    assert_eq!(at(day(2010, 7, 15)), Ok(vec![19036]));
    assert_eq!(at(day(2017, 2, 2)), Ok(vec![19036, 20326]));
    assert_eq!(at(day(2019, 1, 11)), Ok(vec![20326]));
    assert_eq!(at(day(2024, 7, 18)), Ok(vec![20326, 38696]));
}

#[test]
fn s2_a_greater_than_sign_in_an_attribute_value_ends_no_tag() {
    let xml = String::from_utf8(file("root-anchors.xml"))
        .expect("UTF-8")
        .replace(
            r#"<KeyDigest id="Kmyv6jo""#,
            r#"<KeyDigest a='1 > 0' b="2 > 1" id="Kmyv6jo""#,
        );
    assert!(xml.contains("1 > 0"), "38696's KeyDigest");
    assert_eq!(
        TrustAnchors::from_unverified_xml(xml.as_bytes(), captured_at())
            .map(|anchors| tags(&anchors)),
        Ok(vec![20326, 38696])
    );
}

#[test]
fn s2_1_2_a_date_reads_in_its_time_zone() {
    let xml = String::from_utf8(file("root-anchors.xml")).expect("UTF-8");
    let with = |from: &str| xml.replace("2024-07-18T00:00:00+00:00", from).into_bytes();
    let at =
        |xml: &[u8], now| TrustAnchors::from_unverified_xml(xml, now).map(|anchors| tags(&anchors));
    let midnight = day(2024, 7, 18);
    for same in [
        "2024-07-18T00:00:00Z",
        "2024-07-18T02:00:00+02:00",
        "2024-07-17T19:30:00-04:30",
        "2024-07-18T14:00:00+14:00",
        "2024-07-17T23:01:00-00:59",
    ] {
        assert_eq!(at(&with(same), midnight - 1), Ok(vec![20326]), "{same}");
        assert_eq!(at(&with(same), midnight), Ok(vec![20326, 38696]), "{same}");
    }
    for wrong in [
        "2024-07-18T00:00:00",
        "2024-07-18 00:00:00Z",
        "2024-07-18T00:00:00.5Z",
        "2024-07-18T00:00:00+15:00",
        "2024-07-18T00:00:00+00:60",
    ] {
        assert_eq!(
            at(&with(wrong), midnight),
            Err(AnchorXmlError::Invalid(
                "a date that is not YYYY-MM-DDThh:mm:ss and a time zone"
            )),
            "{wrong}"
        );
    }
}

#[test]
fn s4_1_2_a_key_digest_whose_key_does_not_match_is_left_out() {
    let xml = String::from_utf8(file("root-anchors.xml")).expect("UTF-8");
    let key = xml.find("<PublicKey>").expect("a PublicKey") + "<PublicKey>".len();
    let other_tag = xml.replace("<KeyTag>38696</KeyTag>", "<KeyTag>38697</KeyTag>");
    let mut other_key = xml.into_bytes();
    // The first key, 20326's: 'A' to 'B' changes its base64.
    other_key[key + 1] = if other_key[key + 1] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let at = |xml: &[u8]| {
        TrustAnchors::from_unverified_xml(xml, captured_at()).map(|anchors| tags(&anchors))
    };
    assert_eq!(at(&other_key), Ok(vec![38696]));
    // 38696's key and digest under another KeyTag: the digest matches the key, the tag does not.
    assert_eq!(at(other_tag.as_bytes()), Ok(vec![20326]));
}

/// The captured XML with 38696's key under `flags`, its `KeyTag` and SHA-256 `Digest` computed again to match.
fn with_flags(flags: u16) -> Vec<u8> {
    let xml = String::from_utf8(file("root-anchors.xml")).expect("UTF-8");
    let (head, entry) = xml.split_at(xml.find(r#"id="Kmyv6jo""#).expect("38696's KeyDigest"));
    let between = |open: &str, close: &str| {
        let start = entry.find(open).expect("an element") + open.len();
        let end = start + entry[start..].find(close).expect("its end");
        entry[start..end].to_owned()
    };
    let key = BASE64
        .decode(between("<PublicKey>", "</PublicKey>").trim().as_bytes())
        .expect("base64");
    let mut rdata = Vec::from(flags.to_be_bytes());
    rdata.extend([3, 8]);
    rdata.extend(key);
    let digest = ds_digest(DigestType(2), &Name::root(), &rdata).expect("SHA-256");
    let entry = entry
        .replace(
            "<KeyTag>38696</KeyTag>",
            &format!("<KeyTag>{}</KeyTag>", key_tag(&rdata)),
        )
        .replace(
            &between("<Digest>", "</Digest>"),
            &HEXUPPER.encode(digest.as_ref()),
        )
        .replace("<Flags>257</Flags>", &format!("<Flags>{flags}</Flags>"));
    format!("{head}{entry}").into_bytes()
}

#[test]
fn s4_1_2_a_key_revoked_or_not_of_the_zone_is_left_out() {
    let at = |xml: &[u8]| {
        TrustAnchors::from_unverified_xml(xml, captured_at()).map(|anchors| tags(&anchors))
    };
    assert_eq!(with_flags(257), file("root-anchors.xml"));
    // A zone key without SEP is kept (RFC 4034 §2.1.1), as 38695; revoked or no zone key, it is left out.
    assert_eq!(at(&with_flags(256)), Ok(vec![20326, 38695]));
    assert_eq!(at(&with_flags(0x0101 | 0x0080)), Ok(vec![20326]));
    assert_eq!(at(&with_flags(1)), Ok(vec![20326]));
}

#[test]
fn s2_2_a_zone_other_than_the_root_is_refused() {
    let xml = String::from_utf8(file("root-anchors.xml"))
        .expect("UTF-8")
        .replace("<Zone>.</Zone>", "<Zone>com.</Zone>");
    assert_eq!(
        TrustAnchors::from_unverified_xml(xml.as_bytes(), captured_at()),
        Err(AnchorXmlError::Invalid("a Zone other than the root"))
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
            TrustAnchors::from_unverified_xml(xml.as_bytes(), captured_at()),
            Err(error),
            "{xml}"
        );
    }
}
