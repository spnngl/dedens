//! The signature of `root-anchors.xml` (RFC 9718 §3.2): a detached CMS `SignedData` (RFC 5652 §5) by ICANN's
//! certificate for `dnssec@iana.org`, which a CA of ICANN's issued (D127).
//!
//! What is checked, as `unbound-anchor` does and more: each signer's signature over the signed attributes, whose
//! message digest is the XML's and whose signing time is not before the last one accepted; the signer's
//! certificate, in the `SignedData`, names `dnssec@iana.org`, has key usage and may sign, is for e-mail
//! protection if it says what for, is not a CA, and has no critical extension this check does not read; a trusted
//! CA signed it; both certificates are valid at the time asked. The signer is named by issuer and serial number,
//! and the CA issues it directly: ICANN's chain has no intermediate. RSA PKCS #1 v1.5 only, the one algorithm
//! ICANN signs with: RSA-PSS is refused. The CA's own certificate is trusted as given: it is not checked as a CA,
//! nor its self-signature (D127).

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use ring::digest;
use ring::signature::{self, RsaParameters, UnparsedPublicKey};
use x509_cert::Certificate;
use x509_cert::attr::Attributes;
use x509_cert::der::asn1::{ObjectIdentifier, OctetStringRef, UtcTime};
use x509_cert::der::{Any, Decode, DecodePem, Encode};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};

use super::xml::AnchorXmlError;

/// Why signed root anchors are refused (RFC 9718 §3.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignedAnchorError {
    /// The CA bundle is not PEM X.509 certificates, or holds none, or text precedes one.
    #[error("the CA bundle is not PEM X.509 certificates")]
    Ca,
    /// The XML or its signature is longer than [`MAX_XML`] or [`MAX_P7S`]: refused before it is read.
    #[error("{file} is longer than {limit} bytes")]
    TooLarge {
        /// `root-anchors.xml` or `root-anchors.p7s`.
        file: &'static str,
        /// Its limit.
        limit: usize,
    },
    /// The signature does not show that a trusted CA's `dnssec@iana.org` certificate signed the XML; says why.
    #[error("the signature of the root anchors does not hold: {0}")]
    Signature(&'static str),
    /// The XML is signed, but refused.
    #[error(transparent)]
    Xml(#[from] AnchorXmlError),
}

/// The e-mail address in the subject of the signer's certificate, `unbound-anchor`'s `P7SIGNER`.
const SIGNER: &[u8] = b"dnssec@iana.org";

/// The longest `root-anchors.xml` read, 35 times IANA's (1 861 bytes in 2025).
pub const MAX_XML: usize = 64 * 1024;
/// The longest `root-anchors.p7s` read, 6 times IANA's (2 523 bytes in 2025): `der` sorts each SET OF it decodes
/// by insertion, quadratic in its elements (3.1 s for 128 KiB of them), so a size bound is a time bound.
pub const MAX_P7S: usize = 16 * 1024;

const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
/// The extensions the signer's certificate may mark critical: those `check_certificate` reads (RFC 5280 §4.2).
const READ_EXTENSIONS: [ObjectIdentifier; 3] = [
    ObjectIdentifier::new_unwrap("2.5.29.15"),
    ObjectIdentifier::new_unwrap("2.5.29.19"),
    ObjectIdentifier::new_unwrap("2.5.29.37"),
];

/// One SHA-2 digest: its OID (RFC 5754 §2), ring's, the OID of RSA with it (RFC 4055 §5) and ring's.
struct Sha2 {
    digest_oid: ObjectIdentifier,
    digest: &'static digest::Algorithm,
    rsa_oid: ObjectIdentifier,
    rsa: &'static RsaParameters,
}

static SHA2: [Sha2; 3] = [
    Sha2 {
        digest_oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
        digest: &digest::SHA256,
        rsa_oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        rsa: &signature::RSA_PKCS1_2048_8192_SHA256,
    },
    Sha2 {
        digest_oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2"),
        digest: &digest::SHA384,
        rsa_oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
        rsa: &signature::RSA_PKCS1_2048_8192_SHA384,
    },
    Sha2 {
        digest_oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3"),
        digest: &digest::SHA512,
        rsa_oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
        rsa: &signature::RSA_PKCS1_2048_8192_SHA512,
    },
];

/// The certificates of a PEM bundle, at least one, and white space between them: text before a certificate, as
/// `openssl x509 -text` writes, is refused. Not x509-cert's `load_pem_chain`, which panics on an empty bundle.
pub(super) fn cas(pem: &str) -> Result<Vec<Certificate>, SignedAnchorError> {
    const END: &str = "-----END CERTIFICATE-----";
    let mut cas = Vec::new();
    for part in pem.split_inclusive(END) {
        let part = part.trim_ascii();
        if part.is_empty() {
            continue;
        }
        if !part.ends_with(END) {
            return Err(SignedAnchorError::Ca);
        }
        cas.push(Certificate::from_pem(part).map_err(|_| SignedAnchorError::Ca)?);
    }
    if cas.is_empty() {
        return Err(SignedAnchorError::Ca);
    }
    Ok(cas)
}

/// What a signature is checked against: the trusted CAs, the time asked and the earliest signing time accepted,
/// in seconds since 1970.
pub(super) struct Trust<'a> {
    pub(super) cas: &'a [Certificate],
    pub(super) now: u64,
    pub(super) floor: u64,
}

/// The signing time of `p7s`, its signers' earliest, once it is checked as a valid signature of `xml` by a
/// certificate one of `trust.cas` issued.
pub(super) fn check(xml: &[u8], p7s: &[u8], trust: &Trust<'_>) -> Result<u64, &'static str> {
    let info = ContentInfo::from_der(p7s).map_err(|_| "not DER CMS")?;
    if info.content_type != SIGNED_DATA {
        return Err("not CMS SignedData");
    }
    let signed: SignedData = info.content.decode_as().map_err(|_| "not DER SignedData")?;
    let content = &signed.encap_content_info;
    if content.econtent_type != DATA || content.econtent.is_some() {
        return Err("not a detached signature of data");
    }
    let certificates: Vec<&Certificate> = signed
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Some(certificate),
            CertificateChoices::Other(_) => None,
        })
        .collect();
    if signed.signer_infos.0.is_empty() {
        return Err("no signer");
    }
    signed
        .signer_infos
        .0
        .iter()
        .map(|signer| check_signer(xml, &signed, signer, &certificates, trust))
        .try_fold(u64::MAX, |earliest, signed_at| Ok(earliest.min(signed_at?)))
}

/// One signer's signature (RFC 5652 §5.4, §5.6) and its certificate; its signing time.
fn check_signer(
    xml: &[u8],
    data: &SignedData,
    signer: &SignerInfo,
    certificates: &[&Certificate],
    trust: &Trust<'_>,
) -> Result<u64, &'static str> {
    let SignerIdentifier::IssuerAndSerialNumber(id) = &signer.sid else {
        return Err("a signer named by its key identifier");
    };
    let certificate = certificates
        .iter()
        .find(|c| {
            c.tbs_certificate.issuer == id.issuer
                && c.tbs_certificate.serial_number == id.serial_number
        })
        .ok_or("the signer's certificate is missing")?;
    check_certificate(certificate, trust.cas, trust.now)?;
    let sha2 = SHA2
        .iter()
        .find(|sha2| sha2.digest_oid == signer.digest_alg.oid)
        .ok_or("a digest algorithm other than SHA-2")?;
    // RFC 5652 §5.1: the SignedData lists each signer's digest algorithm.
    if !data
        .digest_algorithms
        .iter()
        .any(|listed| listed.oid == sha2.digest_oid)
    {
        return Err("a digest algorithm the SignedData does not list");
    }
    let algorithm = signer.signature_algorithm.oid;
    if algorithm != RSA_ENCRYPTION && algorithm != sha2.rsa_oid {
        return Err("a signature algorithm other than RSA with the signer's digest");
    }
    let attributes = signer.signed_attrs.as_ref().ok_or("no signed attributes")?;
    let content_type: ObjectIdentifier = attribute(attributes, CONTENT_TYPE)?
        .decode_as()
        .map_err(|_| WRONG_TYPE)?;
    let message_digest: OctetStringRef<'_> = attribute(attributes, MESSAGE_DIGEST)?
        .decode_as()
        .map_err(|_| WRONG_TYPE)?;
    // UTCTime, as RFC 5652 §11.3 has it until 2049.
    let signed_at = attribute(attributes, SIGNING_TIME)?
        .decode_as::<UtcTime>()
        .map_err(|_| WRONG_TYPE)?
        .to_unix_duration()
        .as_secs();
    if content_type != DATA {
        return Err("a content type other than data");
    }
    if message_digest.as_bytes() != digest::digest(sha2.digest, xml).as_ref() {
        return Err("the message digest is not the XML's");
    }
    if signed_at < trust.floor {
        return Err("signed before the last signing time accepted");
    }
    // Signed as a SET OF, not as the [0] the SignerInfo holds them in (RFC 5652 §5.4). Re-encoded: `der` decodes
    // DER only, so these are the bytes received, a SET OF out of order excepted, which then fails to verify.
    let message = attributes
        .to_der()
        .map_err(|_| "signed attributes that do not encode")?;
    verify(certificate, sha2.rsa, &message, signer.signature.as_bytes())?;
    Ok(signed_at)
}

/// A signed attribute whose value does not decode as its type.
const WRONG_TYPE: &str = "a signed attribute of the wrong type";

/// The one value of the attribute `oid`, which is there once (RFC 5652 §5.3, §11).
fn attribute(attributes: &Attributes, oid: ObjectIdentifier) -> Result<&Any, &'static str> {
    let mut found = attributes.iter().filter(|attribute| attribute.oid == oid);
    let (Some(attribute), None) = (found.next(), found.next()) else {
        return Err("a signed attribute missing or twice");
    };
    let mut values = attribute.values.iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err("a signed attribute without one value");
    };
    Ok(value)
}

/// The signer's certificate: valid at `now`, for `dnssec@iana.org`, allowed to sign, and issued by one of `cas`
/// valid at `now` (RFC 5280 §4.1, §4.2).
fn check_certificate(
    certificate: &Certificate,
    cas: &[Certificate],
    now: u64,
) -> Result<(), &'static str> {
    if !valid_at(certificate, now) {
        return Err("the signer's certificate is not valid now");
    }
    let tbs = &certificate.tbs_certificate;
    let email = tbs
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .any(|name| name.oid == EMAIL_ADDRESS && name.value.value() == SIGNER);
    if !email {
        return Err("the signer's certificate is not for dnssec@iana.org");
    }
    let unread = tbs
        .extensions
        .iter()
        .flatten()
        .any(|extension| extension.critical && !READ_EXTENSIONS.contains(&extension.extn_id));
    if unread {
        return Err("the signer's certificate has a critical extension not read");
    }
    // As unbound-anchor (`get_usage_of_ex`, `get_valid_signers`): a signer without key usage is refused.
    match tbs.get::<KeyUsage>() {
        Ok(Some((_, usage))) if usage.digital_signature() => {}
        Ok(Some(_)) => return Err("the signer's certificate may not sign"),
        Ok(None) => return Err("the signer's certificate has no key usage"),
        Err(_) => return Err("the signer's key usage is not valid"),
    }
    // Extended key usage, when there, names what the key is for (RFC 5280 §4.2.1.12): e-mail, as S/MIME's.
    match tbs.get::<ExtendedKeyUsage>() {
        Ok(None) => {}
        Ok(Some((_, usage))) if usage.0.contains(&EMAIL_PROTECTION) => {}
        Ok(Some(_)) => return Err("the signer's certificate is not for e-mail protection"),
        Err(_) => return Err("the signer's extended key usage is not valid"),
    }
    match tbs.get::<BasicConstraints>() {
        Ok(None) => {}
        Ok(Some((_, constraints))) if !constraints.ca => {}
        Ok(Some(_)) => return Err("the signer's certificate is a CA"),
        Err(_) => return Err("the signer's basic constraints are not valid"),
    }
    // RFC 5280 §4.1.1.2: the algorithm outside the signed part is the one inside it.
    if certificate.signature_algorithm != tbs.signature {
        return Err("a certificate whose two signature algorithms differ");
    }
    let rsa = SHA2
        .iter()
        .find(|sha2| sha2.rsa_oid == certificate.signature_algorithm.oid)
        .ok_or("a certificate signed with another algorithm than RSA with SHA-2")?
        .rsa;
    let signed = tbs
        .to_der()
        .map_err(|_| "a certificate that does not encode")?;
    let signature = certificate
        .signature
        .as_bytes()
        .ok_or("a signature of partial bytes")?;
    let issued = cas.iter().any(|ca| {
        ca.tbs_certificate.subject == tbs.issuer
            && valid_at(ca, now)
            && verify(ca, rsa, &signed, signature).is_ok()
    });
    if issued {
        Ok(())
    } else {
        Err("no trusted CA valid now issued the signer's certificate")
    }
}

/// Whether `now` is within the certificate's validity (RFC 5280 §4.1.2.5), both ends included.
fn valid_at(certificate: &Certificate, now: u64) -> bool {
    let validity = &certificate.tbs_certificate.validity;
    validity.not_before.to_unix_duration().as_secs() <= now
        && now <= validity.not_after.to_unix_duration().as_secs()
}

/// Whether the RSA key of `certificate` signed `message`.
fn verify(
    certificate: &Certificate,
    rsa: &'static RsaParameters,
    message: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    let key = &certificate.tbs_certificate.subject_public_key_info;
    if key.algorithm.oid != RSA_ENCRYPTION {
        return Err("a key other than RSA");
    }
    let key = key
        .subject_public_key
        .as_bytes()
        .ok_or("a key of partial bytes")?;
    UnparsedPublicKey::new(rsa, key)
        .verify(message, signature)
        .map_err(|_| "a signature that does not verify")
}
