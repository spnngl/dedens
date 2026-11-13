//! A real resolver: Quad9's certificates, one for each encryption system, and an exchange with each, captured from
//! `9.9.9.9:8443` (`testdata/dnscrypt/README.md`). The draft's vectors are `0x0002` only; here `0x0001`,
//! XSalsa20-Poly1305, meets a resolver that is not ours.

use std::fs;

use dedens_dnscrypt::{
    Certificate, ClientNonce, ClientSession, EncryptionSystem, ProviderKey, QueryPadding,
    SecretKey, SystemPolicy, select,
};
use dedens_proto::Message;
use dedens_proto::rdata::RData;
use dedens_testkit::hex;
use serde::Deserialize;

use crate::util::array;

/// `testdata/dnscrypt/quad9.json`.
#[derive(Deserialize)]
struct Capture {
    provider_pk: String,
    captured_at: u64,
    client_secret_key: String,
    client_nonce: String,
    dns_query: String,
    min_packet_len: usize,
}

fn capture() -> Capture {
    let json =
        fs::read(dedens_testkit::path("dnscrypt/quad9.json")).expect("the capture's description");
    serde_json::from_slice(&json).expect("JSON")
}

fn read(name: &str) -> Vec<u8> {
    fs::read(dedens_testkit::path(&format!("dnscrypt/{name}"))).expect("a captured file")
}

fn certificates() -> Vec<Certificate> {
    let provider = ProviderKey::from_bytes(array(&hex(&capture().provider_pk)));
    let wire = read("quad9-cert-response.bin");
    let message = Message::decode(&wire).expect("the response").message;
    message
        .answer
        .iter()
        .filter_map(|record| match record.data() {
            RData::Txt(txt) => Some(
                Certificate::from_txt(&txt, &provider)
                    .expect("a certificate signed by Quad9's key"),
            ),
            _ => None,
        })
        .collect()
}

fn certificate(system: EncryptionSystem) -> Certificate {
    certificates()
        .into_iter()
        .find(|certificate| certificate.body().system() == system)
        .expect("a certificate of the system")
}

/// "Certificates": the answer holds one certificate for each system, both valid when captured, and the system is
/// chosen by the policy.
#[test]
fn certificates_are_read_and_chosen() {
    let now = capture().captured_at;
    let certificates = certificates();
    assert_eq!(certificates.len(), 2);
    let chosen = |policy| select(&certificates, now, policy).map(|c| c.body().system());
    assert_eq!(
        chosen(SystemPolicy::Preferred),
        Some(EncryptionSystem::XChaCha20Poly1305)
    );
    assert_eq!(
        chosen(SystemPolicy::Only(EncryptionSystem::XSalsa20Poly1305)),
        Some(EncryptionSystem::XSalsa20Poly1305)
    );
    assert!(certificates.iter().all(|c| c.is_valid_at(now)));
    let end = certificates
        .iter()
        .map(|c| c.body().validity.end())
        .max()
        .expect("two");
    assert_eq!(
        select(&certificates, u64::from(end) + 1, SystemPolicy::Preferred),
        None
    );
}

/// "Client Queries Over UDP", "Resolver Responses Over UDP": the query that this crate builds is the captured one,
/// and the captured response, from Quad9, is read.
fn exchange(system: EncryptionSystem, name: &str) {
    let capture = capture();
    let session = ClientSession::new(
        &certificate(system),
        &SecretKey::from_bytes(array(&hex(&capture.client_secret_key))),
    )
    .expect("a session");
    let query = hex(&capture.dns_query);
    let (packet, context) = session
        .encrypt_query(
            &query,
            QueryPadding::udp(query.len(), capture.min_packet_len),
            ClientNonce::from_bytes(array(&hex(&capture.client_nonce))),
        )
        .expect("the query");
    assert_eq!(packet, read(&format!("quad9-{name}-query.bin")));

    let response = context
        .decrypt_response(&read(&format!("quad9-{name}-response.bin")))
        .expect("Quad9's response");
    let message = Message::decode(&response).expect("a DNS response").message;
    assert_eq!(message.header.id, 0x1234);
    assert!(!message.answer.is_empty(), "example.com has addresses");
}

#[test]
fn quad9_xsalsa20_poly1305() {
    exchange(EncryptionSystem::XSalsa20Poly1305, "xsalsa20");
}

#[test]
fn quad9_xchacha20_poly1305() {
    exchange(EncryptionSystem::XChaCha20Poly1305, "xchacha20");
}
