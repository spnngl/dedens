//! draft-denis-dprive-dnscrypt-11, "Certificates": the fields, the signature, the forbidden client magics, the
//! validity and the choice among several certificates.
//!
//! The certificate is the one of the draft's Appendix 2 (`testdata/dnscrypt/draft-vectors.json`), which `draft.rs`
//! checks byte by byte; here it is changed, cut and signed anew.

use dedens_dnscrypt::{
    Certificate, CertificateBody, CertificateError, ClientMagic, EncryptionSystem,
    InvalidClientMagic, ProviderKey, SecretKey, SigningKey, SystemPolicy, Validity, select,
};
use dedens_testkit::hex;
use ring::signature::Ed25519KeyPair;

use crate::util::{array, seq};

const DRAFT_CERTIFICATE: &str = "444e5343000200003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aab\
     c173a6a49b7a49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c\
     4659cac45961400c358072d6365880d1aeea329adf9121383851ed21a28e3b75\
     e965d0d2cd166254b1b2b3b4b5b6b7b8000000016800000068015180";

fn seed() -> [u8; 32] {
    array(&seq(0, 32))
}

fn provider() -> SigningKey {
    SigningKey::from_seed(&seed()).expect("a seed")
}

fn draft_certificate() -> Vec<u8> {
    hex(DRAFT_CERTIFICATE)
}

fn parse(bytes: &[u8]) -> Result<Certificate, CertificateError> {
    Certificate::parse(bytes, &provider().provider_key())
}

fn magic(last: u8) -> ClientMagic {
    ClientMagic::try_from([1, 2, 3, 4, 5, 6, 7, last]).expect("a client magic")
}

fn body(system: EncryptionSystem, serial: u32, start: u32, end: u32) -> CertificateBody {
    CertificateBody {
        system,
        resolver_key: SecretKey::from_bytes([7; 32]).public_key(),
        client_magic: magic(0x10),
        serial,
        validity: Validity::new(start, end).expect("a validity"),
        extensions: Vec::new(),
    }
}

/// A certificate of `fields`, from `<es-version>` to `<extensions>` as given, signed with the provider key the way
/// the draft says, whatever the fields: what a hostile or faulty provider could publish.
fn signed(es_version: [u8; 2], signed_fields: &[u8]) -> Vec<u8> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed()).expect("a seed");
    let mut cert = b"DNSC".to_vec();
    cert.extend_from_slice(&es_version);
    cert.extend_from_slice(&[0, 0]);
    cert.extend_from_slice(pair.sign(signed_fields).as_ref());
    cert.extend_from_slice(signed_fields);
    cert
}

/// The draft's signed fields, with the 8 bytes of the magic and the two timestamps replaced.
fn fields(client_magic: [u8; 8], start: u32, end: u32) -> Vec<u8> {
    let mut fields = draft_certificate()[72..104].to_vec();
    fields.extend_from_slice(&client_magic);
    fields.extend_from_slice(&1_u32.to_be_bytes());
    fields.extend_from_slice(&start.to_be_bytes());
    fields.extend_from_slice(&end.to_be_bytes());
    fields
}

/// "Certificates": `<signature>` covers `<resolver-pk> <client-magic> <serial> <ts-start> <ts-end>
/// <extensions>`, so a changed byte of any of them, or of the signature, is refused: by the signature, or
/// before it when the change is of `<ts-start>` to after `<ts-end>`.
#[test]
fn signature_covers_every_signed_byte() {
    for at in 8..draft_certificate().len() {
        let mut bytes = draft_certificate();
        bytes[at] ^= 1;
        let refused = [
            CertificateError::BadSignature,
            CertificateError::EmptyValidity,
        ];
        assert!(
            parse(&bytes).is_err_and(|e| refused.contains(&e)),
            "byte {at}"
        );
        if at != 116 {
            assert_eq!(
                parse(&bytes),
                Err(CertificateError::BadSignature),
                "byte {at}"
            );
        }
    }
}

/// "Certificates": the provider's key is the only one that signs.
#[test]
fn another_provider_key_is_refused() {
    let other = ProviderKey::from_bytes([9; 32]);
    assert_eq!(
        Certificate::parse(&draft_certificate(), &other),
        Err(CertificateError::BadSignature)
    );
}

/// "Certificates": `<cert-magic>` is `DNSC`; the minor version is not signed and not read.
#[test]
fn magic_and_minor_version() {
    let mut bytes = draft_certificate();
    bytes[0] = b'X';
    assert_eq!(parse(&bytes), Err(CertificateError::WrongMagic));
    let mut bytes = draft_certificate();
    bytes[7] = 1;
    assert_eq!(parse(&bytes).map(|c| c.body().serial), Ok(1));
}

/// "Certificates": a certificate cut anywhere before its fixed fields end is too short, never a panic.
#[test]
fn every_prefix_is_too_short() {
    let bytes = draft_certificate();
    for len in 0..bytes.len() {
        assert_eq!(
            parse(&bytes[..len]),
            Err(CertificateError::TooShort),
            "length {len}"
        );
    }
}

/// "Certificates": a system this crate does not implement, as `PQDNSCrypt`''s `0x0003` with its 1216-byte key, is
/// ignored as a whole, whatever follows its `<es-version>`: the length of `<resolver-pk>` is not guessed.
#[test]
fn unsupported_system_is_not_read_further() {
    for (es_version, number) in [([0, 3], 3), ([0, 0], 0), ([1, 2], 0x0102)] {
        let mut bytes = b"DNSC".to_vec();
        bytes.extend_from_slice(&es_version);
        bytes.extend_from_slice(&[0xff; 7]);
        assert_eq!(
            parse(&bytes),
            Err(CertificateError::UnsupportedSystem(number))
        );
    }
}

/// "Certificates": the client magic is never eight 0xff bytes, nor starts with seven NUL bytes, nor is
/// `PQResume`.
#[test]
fn forbidden_client_magics() {
    for forbidden in [
        [0xff; 8],
        [0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1],
        *b"PQResume",
    ] {
        assert_eq!(ClientMagic::try_from(forbidden), Err(InvalidClientMagic));
        let bytes = signed([0, 2], &fields(forbidden, 1, 2));
        assert_eq!(
            parse(&bytes),
            Err(CertificateError::ClientMagic(InvalidClientMagic))
        );
    }
    for allowed in [
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0],
        [0, 0, 0, 0, 0, 0, 1, 0],
        [1, 0, 0, 0, 0, 0, 0, 0],
        *b"PQResumf",
    ] {
        assert!(ClientMagic::try_from(allowed).is_ok(), "{allowed:?}");
    }
}

/// "Certificates": `<ts-start>` is strictly earlier than `<ts-end>`; a certificate that is not is refused, even
/// signed.
#[test]
fn empty_and_inverted_validity() {
    assert_eq!(Validity::new(5, 5), Err(CertificateError::EmptyValidity));
    assert_eq!(Validity::new(6, 5), Err(CertificateError::EmptyValidity));
    for (start, end) in [(5, 5), (6, 5)] {
        let bytes = signed([0, 2], &fields([1; 8], start, end));
        assert_eq!(parse(&bytes), Err(CertificateError::EmptyValidity));
    }
    assert!(Validity::new(5, 6).is_ok());
}

/// "Certificates": `<ts-end>` is inclusive, `<ts-start>` too.
#[test]
fn validity_includes_both_ends() {
    let validity = Validity::new(100, 200).expect("a validity");
    assert_eq!(
        [99, 100, 101, 199, 200, 201].map(|now| validity.contains(now)),
        [false, true, true, true, true, false]
    );
    assert!(!validity.contains(u64::from(u32::MAX) + 100));
}

/// "Certificates": extensions are signed with the rest and otherwise ignored, so a certificate with some is read,
/// kept as it was and given back; a changed extension is a bad signature.
#[test]
fn extensions_are_signed_and_ignored() {
    let mut with = body(EncryptionSystem::XChaCha20Poly1305, 4, 1, 2);
    with.extensions = vec![1, 2, 3, 4, 5];
    let certificate = Certificate::sign(&provider(), with.clone());
    assert_eq!(certificate.as_bytes().len(), 124 + 5);
    assert_eq!(
        parse(certificate.as_bytes()).expect("a certificate").body(),
        &with
    );
    let mut bytes = certificate.as_bytes().to_vec();
    bytes[124] ^= 1;
    assert_eq!(parse(&bytes), Err(CertificateError::BadSignature));
}

/// "Certificates": a certificate bigger than a character-string goes in several, which are concatenated before
/// the certificate is read.
#[test]
fn long_certificate_spans_character_strings() {
    let mut long = body(EncryptionSystem::XSalsa20Poly1305, 4, 1, 2);
    long.extensions = vec![0x5a; 300];
    let certificate = Certificate::sign(&provider(), long);
    let txt = certificate.to_txt().expect("a TXT");
    let lengths: Vec<usize> = txt.strings().map(<[u8]>::len).collect();
    assert_eq!(lengths, [255, 169]);
    assert_eq!(
        Certificate::from_txt(&txt, &provider().provider_key()).expect("a certificate"),
        certificate
    );
}

/// "Certificates": of the certificates valid now, the one of the preferred system, and of those the highest
/// serial; a policy that allows one system ignores the other.
#[test]
fn selection_by_validity_system_and_serial() {
    let x = EncryptionSystem::XChaCha20Poly1305;
    let s = EncryptionSystem::XSalsa20Poly1305;
    let certificates: Vec<Certificate> = [
        (s, 9, 0, 1000),
        (x, 1, 0, 1000),
        (x, 2, 0, 50),
        (x, 3, 0, 1000),
        (x, 5, 500, 1000),
    ]
    .into_iter()
    .map(|(system, serial, start, end)| {
        Certificate::sign(&provider(), body(system, serial, start, end))
    })
    .collect();
    let serial_at = |now, policy| {
        select(&certificates, now, policy).map(|c| (c.body().system, c.body().serial))
    };

    assert_eq!(serial_at(100, SystemPolicy::Preferred), Some((x, 3)));
    assert_eq!(serial_at(100, SystemPolicy::Only(x)), Some((x, 3)));
    assert_eq!(serial_at(100, SystemPolicy::Only(s)), Some((s, 9)));
    assert_eq!(serial_at(600, SystemPolicy::Preferred), Some((x, 5)));
    assert_eq!(serial_at(1000, SystemPolicy::Preferred), Some((x, 5)));
    assert_eq!(serial_at(1001, SystemPolicy::Preferred), None);
    assert_eq!(select(&[], 100, SystemPolicy::Preferred), None);
    let only_salsa = &certificates[..1];
    assert_eq!(select(only_salsa, 100, SystemPolicy::Only(x)), None);
    assert_eq!(
        select(only_salsa, 100, SystemPolicy::Preferred).map(|c| c.body().serial),
        Some(9)
    );
}
