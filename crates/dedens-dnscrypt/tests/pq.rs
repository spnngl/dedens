//! draft-denis-dprive-dnscrypt-11, "Post-Quantum Key Exchange (`PQDNSCrypt`)" and "Appendix 3: PQ Test Vector
//! Structure": the pinned inputs, the certificate, a full query, the ticket and its response, a resumed query, and
//! the "Negative Cases", with the downgrade protection and the control field.
//!
//! The vectors are `testdata/dnscrypt/draft-pq-vectors.json`, copied from the draft's "Generated Values" by
//! script, see `testdata/dnscrypt/README.md`; the inputs are the draft's counting bytes. They also check the
//! `x-wing` crate against the draft's X-Wing: the ciphertext and the key derived from the KEM's secret are the
//! draft's only if the KEM's are.

use std::fmt::Write;
use std::fs;

use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, CertificateError, ClientMagic, ClientNonce,
    ClientSession, EncryptionSystem, QueryContext, QueryError, QueryPadding, ResolverKey,
    ResolverPublicKey, ResponseError, Resumption, SigningKey, SystemPolicy, TicketKey, TicketKeys,
    TicketOffer, Validity, XWingSecretKey, select,
};
use dedens_testkit::hex;
use ring::digest::{SHA256, digest};
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;

use crate::util::{Replay, array, seq};

/// The vectors, in hex, as `testdata/dnscrypt/draft-pq-vectors.json` holds them.
#[derive(Deserialize)]
struct Draft {
    provider_pk: String,
    resolver_pk_sha256: String,
    ciphertext_sha256: String,
    signature: String,
    dns_query: String,
    dns_response: String,
    encrypted_query: String,
    query_wire_sha256: String,
    ticket: String,
    control: String,
    resumed_query_wire_sha256: String,
    response_wire_sha256: String,
    resumed_response_wire_sha256: String,
}

fn draft() -> Draft {
    let path = dedens_testkit::path("dnscrypt/draft-pq-vectors.json");
    serde_json::from_str(&fs::read_to_string(path).expect("the vectors")).expect("JSON vectors")
}

fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::new(), |mut text, byte| {
            write!(text, "{byte:02x}").expect("a String takes any text");
            text
        })
}

/// The ticket's `<es-version>`-to-expiry clock: the query is sent at `<ts-start>` plus 300 seconds.
const NOW: u64 = 0x6800_012c;

/// `<ticket-lifetime>`.
const LIFETIME: u32 = 300;

fn provider() -> SigningKey {
    SigningKey::from_seed(&array(&seq(0, 32))).expect("a seed")
}

fn resolver_secret() -> XWingSecretKey {
    XWingSecretKey::from_seed(array(&seq(0x20, 32)))
}

fn magic() -> ClientMagic {
    ClientMagic::try_from([0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18]).expect("a magic")
}

fn body() -> CertificateBody {
    CertificateBody {
        resolver_key: ResolverPublicKey::XWing(resolver_secret().public_key()),
        client_magic: magic(),
        serial: 1,
        validity: Validity::new(0x6800_0000, 0x6801_5180).expect("a validity"),
        extensions: Vec::new(),
    }
}

fn certificate() -> Certificate {
    Certificate::sign(&provider(), body())
}

fn resolver() -> ResolverKey {
    ResolverKey::new(&certificate(), resolver_secret()).expect("the certificate's key")
}

fn ticket_keys() -> TicketKeys {
    TicketKeys::new(TicketKey::new([0, 0, 0, 1], array(&seq(0x80, 32))), None)
}

/// The query of the vector: the encapsulation seed, the nonce and the 64-byte padding are the draft's.
fn query() -> (Vec<u8>, QueryContext) {
    ClientSession::xwing(&certificate(), &mut Replay::new(&seq(0x40, 64)))
        .expect("a session")
        .encrypt_query(
            &hex(&draft().dns_query),
            QueryPadding::to(64),
            ClientNonce::from_bytes(array(&seq(0xb0, 12))),
        )
        .expect("a query")
}

/// What the client holds after the response of the vector, with the response's nonce half of the resolver.
fn resumption() -> Resumption {
    let (packet, context) = query();
    let (_, response) = resolver().decrypt_query(&packet).expect("the query");
    let ticket = ticket_keys()
        .issue(&response, NOW, LIFETIME, &mut Replay::new(&seq(0xd0, 24)))
        .expect("a ticket");
    let sent = response
        .encrypt_response_with(
            &hex(&draft().dns_response),
            Some(&ticket),
            Carrier::Udp,
            &mut Replay::new(&seq(0xc0, 12)),
        )
        .expect("a response");
    context
        .open_response(&sent)
        .expect("the response")
        .resumption
        .expect("a ticket")
}

/// "Appendix 3", "Pinned Inputs", "Generated Values": the provider's key, and the resolver's X-Wing key from its
/// seed.
#[test]
fn keys_from_the_pinned_seeds() {
    let draft = draft();
    assert_eq!(
        hex(&draft.provider_pk),
        provider().provider_key().as_bytes()
    );
    let public = resolver_secret().public_key();
    assert_eq!(public.as_bytes().len(), 1216);
    assert_eq!(sha256(public.as_bytes()), draft.resolver_pk_sha256);
}

/// "Profile Extension and Signature Input": the 1320-byte certificate, its signature and its fields in the
/// table's places, and a client that reads it back.
#[test]
fn certificate_layout_and_signature() {
    let draft = draft();
    let certificate = certificate();
    let wire = certificate.as_bytes();
    assert_eq!(wire.len(), 1320);
    assert_eq!(wire[..4], *b"DNSC");
    assert_eq!(wire[4..8], [0, 3, 0, 0]);
    assert_eq!(wire[8..72], hex(&draft.signature));
    assert_eq!(wire[72..1288], *resolver_secret().public_key().as_bytes());
    assert_eq!(
        wire[1288..],
        hex("a1b2c3d4e5f60718000000016800000068015180505144010003010104c00460")
    );
    let parsed = Certificate::parse(wire, &provider().provider_key()).expect("a certificate");
    assert_eq!(parsed, certificate);
    assert_eq!(parsed.body().system(), EncryptionSystem::XWing);
}

/// "Full X-Wing Query": the client's encapsulation, the cert-context, the key derivation and the encryption give
/// the draft's 1220 bytes, and the resolver reads them.
#[test]
fn full_query_is_the_vector() {
    let draft = draft();
    let (packet, _) = query();
    assert_eq!(packet.len(), 1220);
    assert_eq!(packet[..8], *magic().as_bytes());
    assert_eq!(sha256(&packet[8..1128]), draft.ciphertext_sha256);
    assert_eq!(packet[1128..1140], seq(0xb0, 12));
    assert_eq!(packet[1140..], hex(&draft.encrypted_query));
    assert_eq!(sha256(&packet), draft.query_wire_sha256);

    let (plaintext, _) = resolver().decrypt_query(&packet).expect("the query");
    assert_eq!(plaintext, hex(&draft.dns_query));
}

/// "Full Response and Ticket Issuance": the ticket is the draft's 130 bytes, its control field the 141, and the
/// client reads the response, the ticket and its lifetime.
#[test]
fn ticket_and_response() {
    let draft = draft();
    let (packet, context) = query();
    let (_, response) = resolver().decrypt_query(&packet).expect("the query");
    let ticket = ticket_keys()
        .issue(&response, NOW, LIFETIME, &mut Replay::new(&seq(0xd0, 24)))
        .expect("a ticket");
    assert_eq!(ticket.as_bytes(), hex(&draft.ticket));
    assert_eq!(ticket.lifetime(), LIFETIME);

    let sent = response
        .encrypt_response_with(
            &hex(&draft.dns_response),
            Some(&ticket),
            Carrier::Udp,
            &mut Replay::new(&seq(0xc0, 12)),
        )
        .expect("a response");
    assert_eq!(sent[..8], *b"r6fnvWj8");
    assert_eq!(sent[8..32], [seq(0xb0, 12), seq(0xc0, 12)].concat());
    assert_eq!(sent.len(), 304);
    assert_eq!(sha256(&sent), draft.response_wire_sha256);
    let opened = context.open_response(&sent).expect("the response");
    assert_eq!(opened.message, hex(&draft.dns_response));
    let resumption = opened.resumption.expect("a ticket");
    assert_eq!(resumption.ticket(), hex(&draft.ticket));
    assert_eq!(resumption.lifetime(), LIFETIME);
    assert_eq!(resumption.expires_at(NOW), 0x6800_0258);
    assert_eq!(
        resumption.expires_at(0x6801_5100),
        0x6801_5180,
        "the certificate's end"
    );

    let control = hex(&draft.control);
    let ticket = hex(&draft.ticket);
    assert_eq!(
        TicketOffer::parse(&control).expect("a control"),
        Some(TicketOffer {
            lifetime: LIFETIME,
            ticket: &ticket,
        })
    );
}

/// A response with no ticket has an empty control field, and the ticket does not shorten the TCP response.
#[test]
fn response_without_ticket_has_an_empty_control_field() {
    let draft = draft();
    let (packet, context) = query();
    let (_, response) = resolver().decrypt_query(&packet).expect("the query");
    let sent = response
        .encrypt_response(
            &hex(&draft.dns_response),
            Carrier::Tcp,
            &mut Replay::new(&seq(0xc0, 12)),
        )
        .expect("a response");
    let opened = context.open_response(&sent).expect("the response");
    assert_eq!(opened.message, hex(&draft.dns_response));
    assert!(opened.resumption.is_none());
    assert_eq!(
        context.decrypt_response(&sent),
        Ok(hex(&draft.dns_response))
    );
}

/// "Resumed Query and Response": the resumed query is the draft's 424 bytes, the resolver opens the ticket and the
/// query, and answers it, with no new ticket.
#[test]
fn resumed_query_is_the_vector() {
    let draft = draft();
    let (packet, context) = resumed(&resumption(), QueryPadding::to(256));
    assert_eq!(packet.len(), 424);
    assert_eq!(packet[..10], hex("5051526573756d650082"));
    assert_eq!(packet[10..140], hex(&draft.ticket));
    assert_eq!(packet[140..152], seq(0xf0, 12));
    assert_eq!(sha256(&packet), draft.resumed_query_wire_sha256);

    let query = ticket_keys().open(&packet, NOW).expect("the ticket opens");
    assert_eq!(query.expiry(), 0x6800_0258);
    let (plaintext, response) = resolver()
        .decrypt_resumed(&query, NOW)
        .expect("the resumed query");
    assert_eq!(plaintext, hex(&draft.dns_query));
    let sent = response
        .encrypt_response(
            &hex(&draft.dns_response),
            Carrier::Udp,
            &mut Replay::new(&seq(0x10, 12)),
        )
        .expect("a response");
    assert_eq!(sent[8..32], [seq(0xf0, 12), seq(0x10, 12)].concat());
    assert_eq!(sent.len(), 112);
    assert_eq!(sha256(&sent), draft.resumed_response_wire_sha256);
    let opened = context.open_response(&sent).expect("the response");
    assert_eq!(opened.message, hex(&draft.dns_response));
    assert!(opened.resumption.is_none());
}

fn resumed(resumption: &Resumption, padding: QueryPadding) -> (Vec<u8>, QueryContext) {
    resumption
        .encrypt_query(
            &hex(&draft().dns_query),
            padding,
            ClientNonce::from_bytes(array(&seq(0xf0, 12))),
        )
        .expect("a resumed query")
}

/// A resumed query is answered with a renewed ticket, which the client can resume with in turn: its secret comes
/// from the resumed key.
#[test]
fn a_renewed_ticket_resumes_too() {
    let draft = draft();
    let (packet, context) = resumed(&resumption(), QueryPadding::to(256));
    let query = ticket_keys().open(&packet, NOW).expect("the ticket opens");
    let (_, response) = resolver()
        .decrypt_resumed(&query, NOW)
        .expect("the resumed query");
    let renewed = ticket_keys()
        .issue(
            &response,
            NOW + 100,
            LIFETIME,
            &mut Replay::new(&seq(1, 24)),
        )
        .expect("a ticket");
    assert_eq!(renewed.lifetime(), LIFETIME);
    let sent = response
        .encrypt_response_with(
            &hex(&draft.dns_response),
            Some(&renewed),
            Carrier::Tcp,
            &mut Replay::new(&seq(0x10, 12)),
        )
        .expect("a response");
    let next = context
        .open_response(&sent)
        .expect("the response")
        .resumption
        .expect("a renewed ticket");
    assert_eq!(next.ticket(), renewed.as_bytes());

    let nonce = ClientNonce::from_bytes(array(&seq(0x30, 12)));
    let (packet, context) = next
        .encrypt_query(&hex(&draft.dns_query), QueryPadding::to(256), nonce)
        .expect("a query");
    let query = ticket_keys().open(&packet, NOW + 200).expect("opens");
    let (plaintext, response) = resolver()
        .decrypt_resumed(&query, NOW + 200)
        .expect("the resumed query");
    assert_eq!(plaintext, hex(&draft.dns_query));
    let sent = response
        .encrypt_response(
            &hex(&draft.dns_response),
            Carrier::Udp,
            &mut Replay::new(&seq(0x50, 12)),
        )
        .expect("a response");
    assert_eq!(
        context.decrypt_response(&sent),
        Ok(hex(&draft.dns_response))
    );
}

/// "PQ Query and Response Format": over UDP, a ticket that leaves no room is withheld, the response is not
/// truncated for it.
#[test]
fn ticket_is_withheld_when_udp_has_no_room() {
    let draft = draft();
    // 8 + 2 + 130 + 12 + 16 + 64 bytes: a response of 232 - 48 = 184 bytes at most, and 2 + 141 + 49 is 192.
    let (packet, context) = resumed(&resumption(), QueryPadding::to(64));
    assert_eq!(packet.len(), 232);
    let query = ticket_keys().open(&packet, NOW).expect("the ticket opens");
    let (_, response) = resolver()
        .decrypt_resumed(&query, NOW)
        .expect("the resumed query");
    let renewed = ticket_keys()
        .issue(&response, NOW, LIFETIME, &mut Replay::new(&seq(1, 24)))
        .expect("a ticket");
    let sent = response
        .encrypt_response_with(
            &hex(&draft.dns_response),
            Some(&renewed),
            Carrier::Udp,
            &mut Replay::new(&seq(0x10, 12)),
        )
        .expect("a response");
    assert!(sent.len() <= packet.len());
    let opened = context.open_response(&sent).expect("the response");
    assert_eq!(opened.message, hex(&draft.dns_response));
    assert!(opened.resumption.is_none(), "withheld");
}

/// "Negative Cases" 3, "Corrupted ticket AEAD": a flipped byte anywhere in the ticket, the key id included, is a
/// ticket that does not open.
#[test]
fn negative_corrupted_ticket() {
    let (packet, _) = resumed(&resumption(), QueryPadding::to(256));
    for at in 10..140 {
        let mut changed = packet.clone();
        changed[at] ^= 1;
        assert_eq!(
            ticket_keys().open(&changed, NOW).err(),
            Some(QueryError::Ticket),
            "ticket byte {at}"
        );
    }
    // Another length than the ticket's 130 bytes.
    let mut short = packet[..8].to_vec();
    short.extend_from_slice(&[0, 129]);
    short.extend_from_slice(&packet[10..139]);
    short.extend_from_slice(&packet[140..]);
    assert_eq!(
        ticket_keys().open(&short, NOW).err(),
        Some(QueryError::Ticket)
    );
}

/// "Negative Cases" 3, 8: a resumed query whose ticket is fine and whose ciphertext was changed fails to
/// authenticate, and one under-padded below 256 bytes is still read.
#[test]
fn negative_corrupted_resumed_ciphertext_and_under_padding() {
    let (packet, _) = resumed(&resumption(), QueryPadding::to(256));
    let mut changed = packet.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let query = ticket_keys().open(&changed, NOW).expect("the ticket opens");
    assert_eq!(
        resolver().decrypt_resumed(&query, NOW).err(),
        Some(QueryError::Authentication)
    );

    let (packet, _) = resumed(&resumption(), QueryPadding::to(64));
    assert!(packet.len() < 256);
    let query = ticket_keys().open(&packet, NOW).expect("the ticket opens");
    assert!(resolver().decrypt_resumed(&query, NOW).is_ok());
}

/// "Negative Cases" 4, "Expired or rotated ticket": the resolver drops a ticket past its expiry, and one of a key
/// it no longer has; the key before the last rotation still opens the tickets sealed under it.
#[test]
fn negative_expired_or_rotated_ticket() {
    let (packet, _) = resumed(&resumption(), QueryPadding::to(256));
    assert!(
        ticket_keys().open(&packet, 0x6800_0258).is_ok(),
        "the last second"
    );
    assert_eq!(
        ticket_keys().open(&packet, 0x6800_0259).err(),
        Some(QueryError::TicketExpired)
    );

    let rotated = TicketKeys::new(TicketKey::new([0, 0, 0, 2], array(&seq(0xa0, 32))), None);
    assert_eq!(
        rotated.open(&packet, NOW).err(),
        Some(QueryError::Ticket),
        "the key is gone"
    );
    let overlap = TicketKeys::new(
        TicketKey::new([0, 0, 0, 2], array(&seq(0xa0, 32))),
        Some(TicketKey::new([0, 0, 0, 1], array(&seq(0x80, 32)))),
    );
    assert!(overlap.open(&packet, NOW).is_ok(), "the previous key");
    // The same id with another key is a ticket that does not open, not one that is misread.
    let wrong = TicketKeys::new(TicketKey::new([0, 0, 0, 1], array(&seq(0xa0, 32))), None);
    assert_eq!(wrong.open(&packet, NOW).err(), Some(QueryError::Ticket));
}

/// "Negative Cases" 5, "Ticket context mismatch": a ticket is for the certificate it was issued under, as its
/// `<client-magic>`, `<serial>` and `<ts-end>` say, and for as long as that certificate is valid. The
/// `<es-version>` and the profile hash are those of the one profile there is.
#[test]
fn negative_ticket_context_mismatch() {
    let (packet, _) = resumed(&resumption(), QueryPadding::to(256));
    let query = ticket_keys().open(&packet, NOW).expect("the ticket opens");
    let other = |body: CertificateBody| {
        let certificate = Certificate::sign(&provider(), body);
        ResolverKey::new(&certificate, resolver_secret()).expect("the key")
    };
    assert!(other(body()).decrypt_resumed(&query, NOW).is_ok());
    let changed = [
        CertificateBody {
            client_magic: ClientMagic::try_from([9; 8]).expect("a magic"),
            ..body()
        },
        CertificateBody {
            serial: 2,
            ..body()
        },
        CertificateBody {
            validity: Validity::new(0x6800_0000, 0x6801_5181).expect("a validity"),
            ..body()
        },
    ];
    for body in changed {
        assert_eq!(
            other(body).decrypt_resumed(&query, NOW).err(),
            Some(QueryError::TicketContext)
        );
    }
    // The certificate is not valid yet at `NOW`, though the ticket is.
    let later = CertificateBody {
        validity: Validity::new(0x6800_0300, 0x6801_5180).expect("a validity"),
        ..body()
    };
    assert_eq!(
        other(later).decrypt_resumed(&query, NOW).err(),
        Some(QueryError::TicketContext)
    );
    assert_eq!(
        resolver().decrypt_resumed(&query, 0x6801_5181).err(),
        Some(QueryError::TicketContext),
        "after the certificate"
    );
}

/// "Negative Cases" 6, "Malformed KEM ciphertext": a flipped bit of the ciphertext gives another key by
/// X-Wing's implicit rejection, and the query fails to authenticate, as any forged one does.
#[test]
fn negative_malformed_ciphertext() {
    let (packet, _) = query();
    let resolver = resolver();
    let mut positions: Vec<usize> = (8..1128).step_by(97).collect();
    positions.extend([8, 1127]);
    for at in positions {
        let mut changed = packet.clone();
        changed[at] ^= 0x01;
        assert_eq!(
            resolver.decrypt_query(&changed).err(),
            Some(QueryError::Authentication),
            "ciphertext byte {at}"
        );
    }
    assert_eq!(
        resolver.decrypt_query(&packet[..1127]).err(),
        Some(QueryError::Truncated)
    );
}

/// A certificate as the wire has it, whatever its profile: a forged one, signed with the provider's key.
fn forged(es_version: [u8; 2], extensions: &[u8]) -> Vec<u8> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&array::<32>(&seq(0, 32))).expect("a seed");
    let mut signed = resolver_secret().public_key().as_bytes().to_vec();
    signed.extend_from_slice(magic().as_bytes());
    signed.extend_from_slice(&1_u32.to_be_bytes());
    signed.extend_from_slice(&0x6800_0000_u32.to_be_bytes());
    signed.extend_from_slice(&0x6801_5180_u32.to_be_bytes());
    signed.extend_from_slice(extensions);
    let mut wire = b"DNSC".to_vec();
    wire.extend_from_slice(&es_version);
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(pair.sign(&signed).as_ref());
    wire.extend_from_slice(&signed);
    wire
}

fn parse(wire: &[u8]) -> Result<Certificate, CertificateError> {
    Certificate::parse(wire, &provider().provider_key())
}

/// "Negative Cases" 1 and 2: a PQ certificate whose profile extension is not the 12 bytes of the draft, in its
/// length or in a field, or has another `<es-version>` than the one on the wire, is rejected.
#[test]
fn negative_profile_extension() {
    let profile = hex("505144010003010104c00460");
    assert!(parse(&forged([0, 3], &profile)).is_ok());

    let mut longer = profile.clone();
    longer.push(0);
    for extensions in [
        profile[..11].to_vec(),
        longer,
        Vec::new(),
        // Each field in turn.
        [&profile[..3], &[2], &profile[4..]].concat(),
        [&profile[..4], &[0, 2], &profile[6..]].concat(),
        [&profile[..6], &[2], &profile[7..]].concat(),
        [&profile[..7], &[2], &profile[8..]].concat(),
        [&profile[..8], &[4, 0xc1], &profile[10..]].concat(),
        [&profile[..10], &[4, 0x61]].concat(),
    ] {
        assert_eq!(
            parse(&forged([0, 3], &extensions)).err(),
            Some(CertificateError::PqProfile),
            "{extensions:02x?}"
        );
    }
    // A key that is not 1216 bytes.
    let mut short = forged([0, 3], &profile);
    short.drain(100..101);
    assert!(parse(&short).is_err());
}

/// "Downgrade Protection": a client that picks among the certificates it got takes the PQ one when it is there,
/// whatever the serials; one that requires PQ takes none of the others.
#[test]
fn downgrade_protection() {
    let provider = provider();
    let classical = Certificate::sign(
        &provider,
        CertificateBody {
            resolver_key: ResolverPublicKey::XChaCha20(
                dedens_dnscrypt::SecretKey::from_bytes([7; 32]).public_key(),
            ),
            serial: 9,
            ..body()
        },
    );
    let pq = certificate();
    let both = [classical.clone(), pq.clone()];
    let chosen = |certificates: &[Certificate], policy| {
        select(certificates, NOW, policy).map(|c| c.body().system())
    };
    assert_eq!(
        chosen(&both, SystemPolicy::Preferred),
        Some(EncryptionSystem::XWing)
    );
    assert_eq!(
        chosen(&both, SystemPolicy::Only(EncryptionSystem::XWing)),
        Some(EncryptionSystem::XWing)
    );
    assert_eq!(
        chosen(
            &both,
            SystemPolicy::Only(EncryptionSystem::XChaCha20Poly1305)
        ),
        Some(EncryptionSystem::XChaCha20Poly1305)
    );
    // The PQ certificate stripped on the way: the client that wants PQ gets none, the other falls back.
    let stripped = [classical];
    assert_eq!(
        chosen(&stripped, SystemPolicy::Only(EncryptionSystem::XWing)),
        None
    );
    assert_eq!(
        chosen(&stripped, SystemPolicy::Preferred),
        Some(EncryptionSystem::XChaCha20Poly1305)
    );
    // An expired PQ certificate is no choice either.
    assert_eq!(
        select(
            &[pq],
            0x6801_5181,
            SystemPolicy::Only(EncryptionSystem::XWing)
        ),
        None
    );
}

/// The draft's control field: another magic or version is skipped, whatever follows; a malformed one of the
/// version it defines is an error.
#[test]
fn control_field_parsing() {
    let control = hex(&draft().control);
    assert!(matches!(TicketOffer::parse(&control), Ok(Some(_))));
    assert_eq!(TicketOffer::parse(&[]), Ok(None));
    let mut other_magic = control.clone();
    other_magic[3] = b'X';
    assert_eq!(TicketOffer::parse(&other_magic), Ok(None));
    assert_eq!(TicketOffer::parse(b"PQ"), Ok(None));
    let mut other_version = control.clone();
    other_version[4] = 2;
    assert_eq!(TicketOffer::parse(&other_version), Ok(None));
    assert_eq!(TicketOffer::parse(&other_version[..5]), Ok(None));

    assert!(TicketOffer::parse(&control[..5]).is_err(), "no lifetime");
    assert!(TicketOffer::parse(&control[..140]).is_err(), "cut ticket");
    let mut long = control.clone();
    long.push(0);
    assert!(TicketOffer::parse(&long).is_err(), "bytes after the ticket");
    let mut no_lifetime = control.clone();
    no_lifetime[5..9].fill(0);
    assert!(TicketOffer::parse(&no_lifetime).is_err());
    let mut no_ticket = control[..11].to_vec();
    no_ticket[9..11].fill(0);
    assert!(TicketOffer::parse(&no_ticket).is_err());
}

/// A PQ response whose last byte was changed does not authenticate: the control field is read only after.
#[test]
fn tampered_pq_response_does_not_authenticate() {
    let (packet, context) = query();
    let (_, response) = resolver().decrypt_query(&packet).expect("the query");
    let sent = response
        .encrypt_response(
            &hex(&draft().dns_response),
            Carrier::Tcp,
            &mut Replay::new(&seq(0xc0, 12)),
        )
        .expect("a response");
    let mut changed = sent.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert_eq!(
        context.open_response(&changed).err(),
        Some(ResponseError::Authentication)
    );
}

/// A PQ resolver key does not read a classical session's packet, nor a classical key a PQ query.
#[test]
fn the_two_kinds_of_key_do_not_mix() {
    let (packet, _) = query();
    let classical_secret = dedens_dnscrypt::SecretKey::from_bytes([7; 32]);
    let classical = Certificate::sign(
        &provider(),
        CertificateBody {
            resolver_key: ResolverPublicKey::XChaCha20(classical_secret.public_key()),
            client_magic: ClientMagic::try_from([8; 8]).expect("a magic"),
            ..body()
        },
    );
    assert_eq!(
        ResolverKey::new(&classical, resolver_secret()).err(),
        Some(CertificateError::KeyMismatch)
    );
    assert_eq!(
        ResolverKey::new(&certificate(), classical_secret).err(),
        Some(CertificateError::KeyMismatch)
    );
    assert_eq!(
        ClientSession::new(
            &certificate(),
            &dedens_dnscrypt::SecretKey::from_bytes([1; 32])
        )
        .err(),
        Some(dedens_dnscrypt::SessionError::WrongSystem)
    );
    assert_eq!(
        ClientSession::xwing(&classical, &mut Replay::new(&[0; 64])).err(),
        Some(dedens_dnscrypt::SessionError::WrongSystem)
    );
    let classical_key = ResolverKey::new(&classical, classical_secret_again()).expect("the key");
    // The classical key finds the PQ magic unknown: a different certificate.
    assert_eq!(
        classical_key.decrypt_query(&packet).err(),
        Some(QueryError::UnknownClientMagic)
    );
}

fn classical_secret_again() -> dedens_dnscrypt::SecretKey {
    dedens_dnscrypt::SecretKey::from_bytes([7; 32])
}

/// "PQ Query and Response Format": the control field is sent only when it leaves a byte for the padding marker, so
/// with `<control-len>`, the control field and the response one byte short of the budget the ticket is sent, and at
/// the budget it is withheld.
#[test]
fn ticket_is_sent_only_when_the_marker_still_fits() {
    let draft = draft();
    // 8 + 2 + 130 + 12 + 16 + 128 bytes: a budget of 296 - 48 = 248 bytes of plaintext.
    let (packet, context) = resumed(&resumption(), QueryPadding::to(128));
    assert_eq!(packet.len(), 296);
    let query = ticket_keys().open(&packet, NOW).expect("the ticket opens");
    let (_, response) = resolver()
        .decrypt_resumed(&query, NOW)
        .expect("the resumed query");
    let ticket = ticket_keys()
        .issue(&response, NOW, LIFETIME, &mut Replay::new(&seq(1, 24)))
        .expect("a ticket");
    // The draft's question, and one TXT answer of `length - 46` bytes of text.
    let sized = |length: usize| {
        let mut wire = hex(&draft.dns_response)[..33].to_vec();
        wire.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 0]);
        let text = length - 46;
        wire.extend_from_slice(&[0, u8::try_from(text + 1).expect("short")]);
        wire.push(u8::try_from(text).expect("short"));
        wire.resize(length, b'a');
        wire
    };
    let sent_with = |length: usize| {
        let wire = sized(length);
        let sealed = response
            .encrypt_response_with(
                &wire,
                Some(&ticket),
                Carrier::Udp,
                &mut Replay::new(&seq(0x10, 12)),
            )
            .expect("a response");
        let opened = context.open_response(&sealed).expect("the response");
        assert_eq!(opened.message, wire);
        opened.resumption.is_some()
    };
    // 2 + 141 + 104 = 247 < 248, and 2 + 141 + 105 = 248.
    assert!(sent_with(104));
    assert!(!sent_with(105));
}

/// A packet longer than `MAX_PACKET_LEN` is refused as too long before its ticket is looked at; one of exactly that
/// length is not.
#[test]
fn a_resumed_query_may_be_as_long_as_a_packet() {
    let mut packet = dedens_dnscrypt::RESUME_MAGIC.to_vec();
    packet.resize(dedens_dnscrypt::MAX_PACKET_LEN, 0);
    assert_eq!(
        ticket_keys().open(&packet, NOW).err(),
        Some(QueryError::Ticket)
    );
    packet.push(0);
    assert_eq!(
        ticket_keys().open(&packet, NOW).err(),
        Some(QueryError::TooLong)
    );
}

/// A policy allows the systems it can choose: `Preferred` all, `Only` its own.
#[test]
fn a_policy_allows_the_systems_it_can_choose() {
    let systems = [
        EncryptionSystem::XSalsa20Poly1305,
        EncryptionSystem::XChaCha20Poly1305,
        EncryptionSystem::XWing,
    ];
    for system in systems {
        assert!(SystemPolicy::Preferred.allows(system));
        for only in systems {
            assert_eq!(SystemPolicy::Only(only).allows(system), only == system);
        }
    }
}

/// A resolver key made for another X-Wing key than the certificate's is refused.
#[test]
fn another_x_wing_key_does_not_match_the_certificate() {
    assert_eq!(
        ResolverKey::new(&certificate(), XWingSecretKey::from_seed([9; 32])).err(),
        Some(CertificateError::KeyMismatch)
    );
}
