//! draft-denis-dprive-dnscrypt-11, "Appendix 2: `DNSCrypt` Test Vectors": the pinned inputs, the keys, the
//! certificate, its retrieval, one query and one response, and the "Negative Cases".
//!
//! The vectors are `testdata/dnscrypt/draft-vectors.json`, copied from the draft by script, see
//! `testdata/dnscrypt/README.md`. They are the system `0x0002`, XChaCha20-Poly1305.

use std::fs;

use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, ClientNonce, ClientSession,
    EncryptionSystem, LowOrderKey, PublicKey, QueryContext, QueryError, QueryPadding, ResolverKey,
    ResolverPublicKey, ResponseContext, ResponseError, SecretKey, SessionError, SigningKey,
    Validity,
};
use dedens_proto::rdata::RData;
use dedens_proto::{Message, RecordType};
use dedens_testkit::hex;
use serde::Deserialize;

use crate::util::{Replay, array, seq};

/// The vectors, in hex, as `testdata/dnscrypt/draft-vectors.json` holds them.
#[derive(Deserialize)]
struct Draft {
    provider_pk: String,
    resolver_pk: String,
    client_pk: String,
    certificate: String,
    certificate_query: String,
    certificate_response: String,
    dns_query: String,
    dns_response: String,
    query_plaintext: String,
    query_packet: String,
    response_plaintext: String,
    response_packet: String,
}

fn draft() -> Draft {
    let json = fs::read(dedens_testkit::path("dnscrypt/draft-vectors.json")).expect("the vectors");
    serde_json::from_slice(&json).expect("the vectors are JSON")
}

fn provider() -> SigningKey {
    SigningKey::from_seed(&array(&seq(0x00, 32))).expect("a seed")
}

fn resolver_secret() -> SecretKey {
    SecretKey::from_bytes(array(&seq(0x20, 32)))
}

fn client_secret() -> SecretKey {
    SecretKey::from_bytes(array(&seq(0x40, 32)))
}

fn client_nonce() -> ClientNonce {
    ClientNonce::from_bytes(array(&seq(0xa0, 12)))
}

fn body() -> CertificateBody {
    CertificateBody {
        resolver_key: ResolverPublicKey::XChaCha20(resolver_secret().public_key()),
        client_magic: ClientMagic::try_from(array(&seq(0xb1, 8))).expect("a client magic"),
        serial: 1,
        validity: Validity::new(0x6800_0000, 0x6801_5180).expect("a validity"),
        extensions: Vec::new(),
    }
}

fn certificate() -> Certificate {
    Certificate::parse(&hex(&draft().certificate), &provider().provider_key())
        .expect("the vector's certificate")
}

/// The query of the vector, sent: its packet, and what the client keeps to read the response.
fn query() -> (Vec<u8>, QueryContext) {
    let session = ClientSession::new(&certificate(), &client_secret()).expect("a session");
    session
        .encrypt_query(
            &hex(&draft().dns_query),
            QueryPadding::to(256),
            client_nonce(),
        )
        .expect("the query")
}

fn resolver() -> ResolverKey {
    ResolverKey::new(&certificate(), resolver_secret()).expect("the certificate's key")
}

/// Appendix 2, "Public Keys and Shared Key": the keys of the pinned inputs.
#[test]
fn public_keys_and_shared_key() {
    let draft = draft();
    assert_eq!(
        provider().provider_key().as_bytes().as_slice(),
        hex(&draft.provider_pk)
    );
    assert_eq!(
        resolver_secret().public_key().as_bytes().as_slice(),
        hex(&draft.resolver_pk)
    );
    assert_eq!(
        client_secret().public_key().as_bytes().as_slice(),
        hex(&draft.client_pk)
    );
}

/// Appendix 2, "Certificate": signing the pinned fields gives the 124 bytes of the vector, and reading them
/// back gives the fields.
#[test]
fn certificate_vector() {
    let signed = Certificate::sign(&provider(), body());
    assert_eq!(signed.as_bytes(), hex(&draft().certificate));
    assert_eq!(certificate(), signed);
    assert_eq!(certificate().body(), &body());
}

/// Appendix 2, "Certificate Retrieval": the question is `2.dnscrypt-cert.example.com` TXT IN, and the TXT answer
/// holds the certificate in one character-string.
#[test]
fn certificate_retrieval() {
    let draft = draft();
    let wire = hex(&draft.certificate_query);
    let question = Message::decode(&wire)
        .expect("the query")
        .message
        .questions
        .remove(0);
    assert_eq!(question.name.to_string(), "2.dnscrypt-cert.example.com.");
    assert_eq!(question.qtype, RecordType::TXT);

    let wire = hex(&draft.certificate_response);
    let message = Message::decode(&wire).expect("the response").message;
    let [record] = message.answer.as_slice() else {
        panic!("one TXT answer");
    };
    let RData::Txt(txt) = record.data() else {
        panic!("a TXT record");
    };
    assert_eq!(txt.strings().count(), 1);
    assert_eq!(
        Certificate::from_txt(&txt, &provider().provider_key()).expect("the certificate"),
        certificate()
    );
    assert_eq!(certificate().to_txt().expect("a TXT"), txt.into_owned());
}

/// Appendix 2, "Client Query (UDP)": the packet of 324 bytes.
#[test]
fn client_query_encrypts_to_the_vector() {
    let (packet, _) = query();
    assert_eq!(packet, hex(&draft().query_packet));
}

/// Appendix 2, "Client Query (UDP)": the resolver reads the packet and finds the DNS query before its padding.
#[test]
fn client_query_decrypts_to_the_dns_query() {
    let draft = draft();
    let resolver = resolver();
    let packet = hex(&draft.query_packet);
    assert_eq!(
        resolver.client_key(&packet),
        Ok(PublicKey::from_bytes(array(&hex(&draft.client_pk))))
    );
    let (plaintext, _) = resolver.decrypt_query(&packet).expect("a query");
    assert_eq!(plaintext, hex(&draft.dns_query));
    assert_eq!(hex(&draft.query_plaintext).len(), 256);
}

/// Appendix 2, "Server Response (UDP)": the client reads the response of the vector.
#[test]
fn server_response_decrypts_to_the_dns_response() {
    let draft = draft();
    let (_, context) = query();
    let plaintext = context
        .decrypt_response(&hex(&draft.response_packet))
        .expect("the response");
    assert_eq!(plaintext, hex(&draft.dns_response));
    assert_eq!(hex(&draft.response_plaintext).len(), 64);
}

/// The context of the resolver for the query of the vector.
fn response_context() -> ResponseContext {
    let (_, context) = resolver()
        .decrypt_query(&hex(&draft().query_packet))
        .expect("a query");
    context
}

/// Appendix 2, "Server Response (UDP)": the resolver's response has the nonces of the vector, a padded
/// plaintext that is a multiple of 64 bytes, and the client reads it.
///
/// The padding length is the resolver's choice (draft "Padding For Resolver Responses"), so the bytes are not
/// the vector's unless the choice is the same.
#[test]
fn server_response_encrypts_for_the_client() {
    let draft = draft();
    let mut rng = Replay::new(&seq(0xc0, 12));
    let packet = response_context()
        .encrypt_response(&hex(&draft.dns_response), Carrier::Udp, &mut rng)
        .expect("a response");
    assert_eq!(packet[8..32], [seq(0xa0, 12), seq(0xc0, 12)].concat());
    assert_eq!((packet.len() - 48) % 64, 0);
    assert!(packet.len() <= 324, "no larger than the query");
    let (_, context) = query();
    assert_eq!(
        context.decrypt_response(&packet).expect("the response"),
        hex(&draft.dns_response)
    );
}

/// "Negative Cases", "Tampered ciphertext": flipping any byte of the packets makes them fail, the resolver drops the query and the client
/// the response.
#[test]
fn negative_tampered_packets_fail() {
    let draft = draft();
    let resolver = resolver();
    let query_packet = hex(&draft.query_packet);
    for at in 0..query_packet.len() {
        let mut packet = query_packet.clone();
        packet[at] ^= 1;
        assert!(resolver.decrypt_query(&packet).is_err(), "query byte {at}");
    }
    let (_, context) = query();
    let response_packet = hex(&draft.response_packet);
    for at in 0..response_packet.len() {
        let mut packet = response_packet.clone();
        packet[at] ^= 1;
        assert!(
            context.decrypt_response(&packet).is_err(),
            "response byte {at}"
        );
    }
}

/// "Negative Cases", "Tampered ciphertext": the error says which check failed, for bytes of each field.
#[test]
fn negative_tampering_is_told_by_field() {
    let draft = draft();
    let resolver = resolver();
    let query_packet = hex(&draft.query_packet);
    for (at, error) in [
        (0, QueryError::UnknownClientMagic),
        (8, QueryError::Authentication),
        (40, QueryError::Authentication),
        (52, QueryError::Authentication),
        (68, QueryError::Authentication),
        (323, QueryError::Authentication),
    ] {
        let mut packet = query_packet.clone();
        packet[at] ^= 1;
        assert_eq!(
            resolver.decrypt_query(&packet).err(),
            Some(error),
            "query byte {at}"
        );
    }
    let (_, context) = query();
    let response_packet = hex(&draft.response_packet);
    for (at, error) in [
        (0, ResponseError::WrongMagic),
        (8, ResponseError::NonceMismatch),
        (32, ResponseError::Authentication),
        (111, ResponseError::Authentication),
    ] {
        let mut packet = response_packet.clone();
        packet[at] ^= 1;
        assert_eq!(
            context.decrypt_response(&packet).err(),
            Some(error),
            "response byte {at}"
        );
    }
    // The resolver half of the nonce is in the authenticated nonce: changed, the tag fails.
    let mut packet = response_packet;
    packet[20] ^= 1;
    assert_eq!(
        context.decrypt_response(&packet),
        Err(ResponseError::Authentication)
    );
}

/// "Negative Cases", "Wrong <client-magic>": a query with another magic than the certificate's is no query for this resolver.
#[test]
fn negative_wrong_client_magic() {
    let mut packet = hex(&draft().query_packet);
    packet[7] = 0;
    assert_eq!(
        resolver().decrypt_query(&packet).err(),
        Some(QueryError::UnknownClientMagic)
    );
}

/// "Negative Cases", "Response nonce mismatch": a response whose client nonce is not the query's is dropped.
#[test]
fn negative_response_nonce_mismatch() {
    let session = ClientSession::new(&certificate(), &client_secret()).expect("a session");
    let other = ClientNonce::from_bytes(array(&seq(0x10, 12)));
    let (_, context) = session
        .encrypt_query(&hex(&draft().dns_query), QueryPadding::to(256), other)
        .expect("the query");
    assert_eq!(
        context.decrypt_response(&hex(&draft().response_packet)),
        Err(ResponseError::NonceMismatch)
    );
}

/// "Negative Cases", "Weak public key": a public key of low order gives an all-zero shared point, and no shared
/// key, on both sides.
///
/// The points are 0, 1, a point of order 8 and the non-canonical encoding of 0 (the prime p, which X25519 reads
/// as 0); the last two are on libsodium's list of blocked points.
#[test]
fn negative_weak_public_key() {
    let system = EncryptionSystem::XChaCha20Poly1305;
    let mut one = [0; 32];
    one[0] = 1;
    let order_8 = array(&hex(
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ));
    let prime = array(&hex(
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ));
    for weak in [[0; 32], one, order_8, prime] {
        let weak = PublicKey::from_bytes(weak);
        assert_eq!(
            client_secret().shared_key(system, &weak).err(),
            Some(SessionError::LowOrderKey(LowOrderKey))
        );
        let mut packet = hex(&draft().query_packet);
        packet[8..40].copy_from_slice(weak.as_bytes());
        assert_eq!(
            resolver().decrypt_query(&packet).err(),
            Some(QueryError::LowOrderKey(LowOrderKey))
        );
    }
    let weak = CertificateBody {
        resolver_key: ResolverPublicKey::XChaCha20(PublicKey::from_bytes([0; 32])),
        ..body()
    };
    let certificate = Certificate::sign(&provider(), weak);
    assert_eq!(
        ClientSession::new(&certificate, &client_secret()).err(),
        Some(SessionError::LowOrderKey(LowOrderKey))
    );
}
