//! The signature of `root-anchors.xml` (RFC 9718 §3.2): a detached CMS `SignedData` (RFC 5652 §5) by ICANN's
//! certificate for `dnssec@iana.org`, which a CA of ICANN's issued (D127).
//!
//! What is checked, as `unbound-anchor` does: each signer's signature over the signed attributes, whose message
//! digest is the XML's; the signer's certificate, in the `SignedData`, names `dnssec@iana.org` and may sign; a
//! trusted CA signed it; both certificates are valid at the time asked. The signer is named by issuer and serial
//! number, and the CA issues it directly: ICANN's chain has no intermediate. RSA (PKCS #1 v1.5) only, the one
//! algorithm ICANN signs with.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use ring::digest;
use ring::signature::{self, RsaParameters, UnparsedPublicKey};
use x509_cert::Certificate;
use x509_cert::attr::Attributes;
use x509_cert::der::asn1::{ObjectIdentifier, OctetStringRef};
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::ext::pkix::KeyUsage;

use super::xml::AnchorXmlError;

/// Why signed root anchors are refused (RFC 9718 §3.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignedAnchorError {
    /// The CA bundle is not PEM X.509 certificates, or holds none.
    #[error("the CA bundle is not PEM X.509 certificates")]
    Ca,
    /// The signature does not show that a trusted CA's `dnssec@iana.org` certificate signed the XML; says why.
    #[error("the signature of the root anchors does not hold: {0}")]
    Signature(&'static str),
    /// The XML is signed, but refused.
    #[error(transparent)]
    Xml(#[from] AnchorXmlError),
}

/// The e-mail address in the subject of the signer's certificate, `unbound-anchor`'s `P7SIGNER`.
const SIGNER: &[u8] = b"dnssec@iana.org";

const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

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

/// The certificates of a PEM bundle, at least one, and white space between them. Not x509-cert's
/// `load_pem_chain`, which panics on an empty bundle.
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

/// Whether `p7s` is a valid signature of `xml` at `now`, in seconds since 1970, by a certificate one of `cas`
/// issued.
pub(super) fn check(
    xml: &[u8],
    p7s: &[u8],
    cas: &[Certificate],
    now: u64,
) -> Result<(), &'static str> {
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
        .try_for_each(|signer| check_signer(xml, signer, &certificates, cas, now))
}

/// One signer's signature (RFC 5652 §5.4, §5.6), and its certificate.
fn check_signer(
    xml: &[u8],
    signer: &SignerInfo,
    certificates: &[&Certificate],
    cas: &[Certificate],
    now: u64,
) -> Result<(), &'static str> {
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
    check_certificate(certificate, cas, now)?;
    let sha2 = SHA2
        .iter()
        .find(|sha2| sha2.digest_oid == signer.digest_alg.oid)
        .ok_or("a digest algorithm other than SHA-2")?;
    let algorithm = signer.signature_algorithm.oid;
    if algorithm != RSA_ENCRYPTION && algorithm != sha2.rsa_oid {
        return Err("a signature algorithm other than RSA with the signer's digest");
    }
    let attributes = signer.signed_attrs.as_ref().ok_or("no signed attributes")?;
    let content_type: ObjectIdentifier = attribute(attributes, CONTENT_TYPE)?;
    let message_digest: OctetStringRef<'_> = attribute(attributes, MESSAGE_DIGEST)?;
    if content_type != DATA {
        return Err("a content type other than data");
    }
    if message_digest.as_bytes() != digest::digest(sha2.digest, xml).as_ref() {
        return Err("the message digest is not the XML's");
    }
    // Signed as a SET OF, not as the [0] the SignerInfo holds them in (RFC 5652 §5.4).
    let message = attributes
        .to_der()
        .map_err(|_| "signed attributes that do not encode")?;
    verify(certificate, sha2.rsa, &message, signer.signature.as_bytes())
}

/// The one value of the attribute `oid`, which is there once (RFC 5652 §5.3, §11).
fn attribute<'a, T>(attributes: &'a Attributes, oid: ObjectIdentifier) -> Result<T, &'static str>
where
    T: x509_cert::der::Choice<'a> + x509_cert::der::DecodeValue<'a>,
{
    let mut found = attributes.iter().filter(|attribute| attribute.oid == oid);
    let (Some(attribute), None) = (found.next(), found.next()) else {
        return Err("a signed attribute missing or twice");
    };
    let mut values = attribute.values.iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err("a signed attribute without one value");
    };
    value
        .decode_as()
        .map_err(|_| "a signed attribute of the wrong type")
}

/// The signer's certificate: valid at `now`, for `dnssec@iana.org`, allowed to sign, and issued by one of `cas`
/// valid at `now`.
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
    // As OpenSSL, unbound-anchor's: without the extension, a key may be used for anything (RFC 5280 §4.2.1.3).
    match tbs.get::<KeyUsage>() {
        Ok(Some((_, usage))) if !usage.digital_signature() => {
            return Err("the signer's certificate may not sign");
        }
        Ok(_) => {}
        Err(_) => return Err("the signer's key usage is not valid"),
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
