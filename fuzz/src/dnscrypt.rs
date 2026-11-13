//! Targets of `DNSCrypt` (draft-denis-dprive-dnscrypt, D97): `dedens-dnscrypt`'s certificates and the encryption
//! of queries and responses.
//!
//! Arbitrary bytes against a fixed key only reach the header checks, so the targets that need an authentic packet
//! seal the fuzzer's own DNS message with the crate's public API. What else the input decides (the encryption
//! system, the padding, the byte to flip) is read from its FNV-1a hash, so that any seed, which is a plain message,
//! is a good input.

use std::sync::LazyLock;

use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, ClientNonce, ClientSession,
    EncryptionSystem, ProviderKey, QueryContext, QueryPadding, ResolverKey, ResponseContext,
    SecretKey, SigningKey, Validity,
};
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Question};

use crate::odoh::Fixed;

/// The provider key of Quad9's stamp (`testdata/dnscrypt/quad9.json`): the captured response of its
/// certificates verifies under it.
const QUAD9_PROVIDER_KEY: [u8; 32] = [
    0x67, 0xc8, 0x47, 0xb8, 0xc8, 0x75, 0x8c, 0xd1, 0x20, 0x24, 0x55, 0x43, 0xbe, 0x75, 0x67, 0x46,
    0xdf, 0x34, 0xdf, 0x1d, 0x84, 0xc0, 0x0b, 0x8c, 0x47, 0x03, 0x68, 0xdf, 0x82, 0x1d, 0x86, 0x3e,
];

/// A query for `www.example.com` A.
const DNS_QUERY: [u8; 33] = [
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w',
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
    0x01,
];

/// The `<client-nonce>` of every query the targets make.
const NONCE: [u8; 12] = [4; 12];

/// The most bytes of a TCP response packet the targets expect: under 4096.
const TCP_LIMIT: usize = 4095;

/// The provider of the certificate below, from a seed the fuzzer does not know.
static PROVIDER: LazyLock<SigningKey> =
    LazyLock::new(|| SigningKey::from_seed(&[1; 32]).expect("a seed is a key"));

/// The question of [`DNS_QUERY`], which a response has to carry.
static QUESTIONS: LazyLock<Vec<Question<'static>>> = LazyLock::new(|| {
    Message::decode(&DNS_QUERY)
        .expect("the query")
        .message
        .questions
        .into_iter()
        .map(Question::into_owned)
        .collect()
});

/// The pieces of one exchange, made once, since the key exchange is slow unoptimized: the client's session and
/// the resolver, the client's query packet and its context, and the resolver's context and its response packet.
struct Exchange {
    session: ClientSession,
    resolver: ResolverKey,
    query: Vec<u8>,
    query_context: QueryContext,
    response_context: ResponseContext,
    response: Vec<u8>,
}

fn exchange(system: EncryptionSystem) -> Exchange {
    let secret = SecretKey::from_bytes([2; 32]);
    let certificate = Certificate::sign(
        &PROVIDER,
        CertificateBody {
            system,
            resolver_key: secret.public_key(),
            client_magic: ClientMagic::try_from([9; 8]).expect("a magic"),
            serial: 1,
            validity: Validity::new(1, 2).expect("a validity"),
            extensions: Vec::new(),
        },
    );
    let session =
        ClientSession::new(&certificate, &SecretKey::from_bytes([3; 32])).expect("a good key");
    let (query, query_context) = session
        .encrypt_query(
            &DNS_QUERY,
            QueryPadding::udp(DNS_QUERY.len(), 256),
            ClientNonce::from_bytes(NONCE),
        )
        .expect("a query");
    let resolver = ResolverKey::new(&certificate, secret).expect("the certificate's key");
    let (_, response_context) = resolver.decrypt_query(&query).expect("our own query");
    let mut answer = DNS_QUERY.to_vec();
    answer[2] = 0x81;
    let response = response_context
        .encrypt_response(&answer, Carrier::Udp, &mut Fixed(5))
        .expect("a response");
    Exchange {
        session,
        resolver,
        query,
        query_context,
        response_context,
        response,
    }
}

/// An exchange of each system, the draft's first.
static EXCHANGES: LazyLock<[Exchange; 2]> = LazyLock::new(|| {
    [
        exchange(EncryptionSystem::XChaCha20Poly1305),
        exchange(EncryptionSystem::XSalsa20Poly1305),
    ]
});

/// The FNV-1a hash of `data`, whose bits are the choices of the targets.
fn hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// The exchange of the system the hash `hash` picks.
fn exchange_of(hash: u64) -> &'static Exchange {
    let [classical, salsa] = &*EXCHANGES;
    if hash & 1 == 0 { classical } else { salsa }
}

/// A number below `bound` (not 0) from the bits of `hash` after the first `shift`.
fn below(hash: u64, shift: u32, bound: usize) -> usize {
    let bound = u64::try_from(bound).expect("a small bound");
    usize::try_from((hash >> shift) % bound).expect("below a small bound")
}

/// `packet` with one bit of one byte changed, as the hash `hash` picks.
fn flipped(packet: &[u8], hash: u64) -> Vec<u8> {
    let mut changed = packet.to_vec();
    let at = below(hash, 8, changed.len());
    let mask = u8::try_from((hash >> 40) & 0xff).expect("a byte") | 1;
    changed[at] ^= mask;
    changed
}

/// The number of records of the three sections of `message`.
const fn records(message: &Message<'_>) -> usize {
    message.answer.len() + message.authority.len() + message.additional.len()
}

/// A certificate read from arbitrary bytes as the provider's (draft "Certificates"), and the TXT answers of a DNS
/// message as Quad9's: what reads is signed bytes that hold their fields. A certificate made of the bytes, signed,
/// reads back as it was made, and so does its TXT form.
///
/// # Panics
///
/// When a certificate does not read back as the one that was made.
pub fn parse_dnscrypt_certificate(data: &[u8]) {
    let _ = Certificate::parse(data, &PROVIDER.provider_key());
    if let Ok(decoded) = Message::decode(data) {
        let provider = ProviderKey::from_bytes(QUAD9_PROVIDER_KEY);
        for record in &decoded.message.answer {
            if let RData::Txt(txt) = record.data() {
                let _ = Certificate::from_txt(&txt, &provider);
            }
        }
    }

    let Some((&system, rest)) = data.split_first() else {
        return;
    };
    let Some((magic, rest)) = rest.split_first_chunk::<8>() else {
        return;
    };
    let Some((times, extensions)) = rest.split_first_chunk::<12>() else {
        return;
    };
    let [serial, start, end] = [0, 4, 8].map(|at| {
        let mut word = [0; 4];
        word.copy_from_slice(&times[at..at + 4]);
        u32::from_be_bytes(word)
    });
    let (Ok(client_magic), Ok(validity)) =
        (ClientMagic::try_from(*magic), Validity::new(start, end))
    else {
        return;
    };
    let body = CertificateBody {
        system: if system & 1 == 0 {
            EncryptionSystem::XChaCha20Poly1305
        } else {
            EncryptionSystem::XSalsa20Poly1305
        },
        resolver_key: SecretKey::from_bytes([2; 32]).public_key(),
        client_magic,
        serial,
        validity,
        extensions: extensions.to_vec(),
    };
    let certificate = Certificate::sign(&PROVIDER, body);
    let provider = PROVIDER.provider_key();
    assert_eq!(
        Certificate::parse(certificate.as_bytes(), &provider).as_ref(),
        Ok(&certificate)
    );
    if let Ok(txt) = certificate.to_txt() {
        assert_eq!(
            Certificate::from_txt(&txt, &provider).as_ref(),
            Ok(&certificate)
        );
    }
}

/// Arbitrary bytes as a query packet to a resolver and as a response packet to a client, under each system (draft
/// "Client Queries Over UDP", "Resolver Responses Over UDP"): refused, never a panic. No packet but ours
/// authenticates as a response, the fuzzer holding no key.
///
/// # Panics
///
/// When the client accepts a packet that is not its response.
pub fn dnscrypt_decrypt(data: &[u8]) {
    for exchange in &*EXCHANGES {
        let _ = exchange.resolver.decrypt_query(data);
        if data != exchange.response {
            assert!(exchange.query_context.decrypt_response(data).is_err());
        }
    }
}

/// A query made of arbitrary bytes, padded to a length the input picks (draft "Padding For Client Queries Over
/// UDP"), is read back by the resolver as it was sent: the padding is removed, to the byte, whatever its length.
///
/// The padding a resolver refuses is not reached from here, as only the crate seals a plaintext of its own: its
/// unit tests do.
///
/// # Panics
///
/// When the resolver reads another message than the one sent.
pub fn dnscrypt_unpad(data: &[u8]) {
    let hash = hash(data);
    let exchange = exchange_of(hash);
    // Up to a little over the 4028 bytes a packet can carry, where the query is refused.
    let padding = QueryPadding::to(below(hash, 8, 4100));
    let Ok((packet, _)) =
        exchange
            .session
            .encrypt_query(data, padding, ClientNonce::from_bytes(NONCE))
    else {
        return;
    };
    let (plaintext, _) = exchange
        .resolver
        .decrypt_query(&packet)
        .expect("our own query");
    assert_eq!(plaintext, data);
}

/// An authentic query made of arbitrary bytes, with one bit of the packet changed, is refused by the resolver
/// (draft "Negative Cases", "Tampered ciphertext"); unchanged, it is read.
///
/// # Panics
///
/// When the resolver does not read our own packet, or reads a changed one.
pub fn dnscrypt_tamper_query(data: &[u8]) {
    let hash = hash(data);
    let exchange = exchange_of(hash);
    let Ok((packet, _)) = exchange.session.encrypt_query(
        data,
        QueryPadding::udp(data.len(), 256),
        ClientNonce::from_bytes(NONCE),
    ) else {
        return;
    };
    assert!(exchange.resolver.decrypt_query(&packet).is_ok());
    assert!(
        exchange
            .resolver
            .decrypt_query(&flipped(&packet, hash))
            .is_err()
    );
}

/// The DNS message of `data` as the response to [`DNS_QUERY`]: its ID and its question, which a client requires
/// of a response. `None` when `data` is no message, or does not encode again.
fn response_to_query(data: &[u8]) -> Option<Vec<u8>> {
    let mut message = Message::decode(data).ok()?.message;
    message.header.id = u16::from_be_bytes([DNS_QUERY[0], DNS_QUERY[1]]);
    message.questions.clone_from(&QUESTIONS);
    message.to_vec().ok()
}

/// An authentic response made of arbitrary bytes, with one bit of the packet changed, is refused by the client
/// (draft "Negative Cases", "Tampered ciphertext"); unchanged, it is read.
///
/// # Panics
///
/// When the client does not read the resolver's own packet, or reads a changed one.
pub fn dnscrypt_tamper_response(data: &[u8]) {
    let hash = hash(data);
    let exchange = exchange_of(hash);
    let carrier = if hash & 2 == 0 {
        Carrier::Udp
    } else {
        Carrier::Tcp
    };
    let Some(wire) = response_to_query(data) else {
        return;
    };
    let Ok(packet) = exchange
        .response_context
        .encrypt_response(&wire, carrier, &mut Fixed(5))
    else {
        return;
    };
    assert!(exchange.query_context.decrypt_response(&packet).is_ok());
    assert!(
        exchange
            .query_context
            .decrypt_response(&flipped(&packet, hash))
            .is_err()
    );
}

/// Arbitrary bytes as a resolver's DNS response to the exchange's query, sent over each carrier (draft "Resolver
/// Responses Over UDP", "Resolver Responses Over TCP"): never a panic; a packet that is made fits its carrier, the
/// query's size for UDP and under 4096 bytes for TCP. A message that is the response to the query, by its ID and
/// question, is read by the client, with TC set when records were left out.
///
/// # Panics
///
/// When a packet is larger than its carrier allows, when the client refuses a response to its query, or when
/// records were left out and TC is clear.
pub fn dnscrypt_encrypt_response(data: &[u8]) {
    for exchange in &*EXCHANGES {
        for (carrier, limit) in [
            (Carrier::Udp, exchange.query.len()),
            (Carrier::Tcp, TCP_LIMIT),
        ] {
            let sealed = |response: &[u8]| {
                exchange
                    .response_context
                    .encrypt_response(response, carrier, &mut Fixed(5))
            };
            if let Ok(packet) = sealed(data) {
                assert!(packet.len() <= limit);
                let _ = exchange.query_context.decrypt_response(&packet);
            }
            let Some(wire) = response_to_query(data) else {
                continue;
            };
            let Ok(packet) = sealed(&wire) else {
                continue;
            };
            assert!(packet.len() <= limit);
            let received = exchange
                .query_context
                .decrypt_response(&packet)
                .expect("a response to the query");
            let (Ok(sent), Ok(received)) = (Message::decode(&wire), Message::decode(&received))
            else {
                panic!("a message the client read does not decode");
            };
            if records(&received.message) < records(&sent.message) {
                assert!(received.message.header.flags.contains(Flags::TC));
            }
        }
    }
}
