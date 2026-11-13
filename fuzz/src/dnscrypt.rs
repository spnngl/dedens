//! Targets of `DNSCrypt` (draft-denis-dprive-dnscrypt, D97): `dedens-dnscrypt`'s certificates and the encryption
//! of queries and responses.

use std::sync::LazyLock;

use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, ClientNonce, ClientSession, EncryptionSystem,
    ProviderKey, QueryContext, QueryPadding, ResolverKey, ResponseContext, SecretKey, SigningKey,
    Validity,
};
use dedens_proto::{Message, rdata::RData};

use crate::odoh::Fixed;

/// The provider key of Quad9's stamp (`testdata/dnscrypt/quad9.json`): the captured response of its
/// certificates verifies under it.
const QUAD9_PROVIDER_KEY: [u8; 32] = [
    0x67, 0xc8, 0x47, 0xb8, 0xc8, 0x75, 0x8c, 0xd1, 0x20, 0x24, 0x55, 0x43, 0xbe, 0x75, 0x67, 0x46, 0xdf,
    0x34, 0xdf, 0x1d, 0x84, 0xc0, 0x0b, 0x8c, 0x47, 0x03, 0x68, 0xdf, 0x82, 0x1d, 0x86, 0x3e,
];

/// A query for `www.example.com` A.
const DNS_QUERY: [u8; 33] = [
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w', 0x07, b'e', b'x',
    b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];

/// The provider of the certificate below, from a seed the fuzzer does not know.
static PROVIDER: LazyLock<SigningKey> =
    LazyLock::new(|| SigningKey::from_seed(&[1; 32]).expect("a seed is a key"));

/// The pieces of one exchange, made once, since the key exchange is slow unoptimized: the resolver, the client's
/// query packet and its context, and the resolver's context and its response packet.
struct Exchange {
    resolver: ResolverKey,
    query: Vec<u8>,
    query_context: QueryContext,
    response_context: ResponseContext,
    response: Vec<u8>,
}

static EXCHANGE: LazyLock<Exchange> = LazyLock::new(|| {
    let secret = SecretKey::from_bytes([2; 32]);
    let certificate = Certificate::sign(
        &PROVIDER,
        CertificateBody {
            system: EncryptionSystem::XChaCha20Poly1305,
            resolver_key: secret.public_key(),
            client_magic: ClientMagic::try_from([9; 8]).expect("a magic"),
            serial: 1,
            validity: Validity::new(1, 2).expect("a validity"),
            extensions: Vec::new(),
        },
    );
    let session = ClientSession::new(&certificate, &SecretKey::from_bytes([3; 32])).expect("a good key");
    let (query, query_context) = session
        .encrypt_query(&DNS_QUERY, QueryPadding::udp(DNS_QUERY.len(), 256), ClientNonce::from_bytes([4; 12]))
        .expect("a query");
    let resolver = ResolverKey::new(&certificate, secret).expect("the certificate's key");
    let (_, response_context) = resolver.decrypt_query(&query).expect("our own query");
    let mut answer = DNS_QUERY.to_vec();
    answer[2] = 0x81;
    let response = response_context
        .encrypt_response(&answer, Carrier::Udp, &mut Fixed(5))
        .expect("a response");
    Exchange { resolver, query, query_context, response_context, response }
});

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
    let (Ok(client_magic), Ok(validity)) = (ClientMagic::try_from(*magic), Validity::new(start, end)) else {
        return;
    };
    let body = CertificateBody {
        system: if system & 1 == 0 { EncryptionSystem::XChaCha20Poly1305 } else { EncryptionSystem::XSalsa20Poly1305 },
        resolver_key: SecretKey::from_bytes([2; 32]).public_key(),
        client_magic,
        serial,
        validity,
        extensions: extensions.to_vec(),
    };
    let certificate = Certificate::sign(&PROVIDER, body);
    let provider = PROVIDER.provider_key();
    assert_eq!(Certificate::parse(certificate.as_bytes(), &provider).as_ref(), Ok(&certificate));
    if let Ok(txt) = certificate.to_txt() {
        assert_eq!(Certificate::from_txt(&txt, &provider).as_ref(), Ok(&certificate));
    }
}

/// Arbitrary bytes as a query packet to a resolver and as a response packet to a client (draft "Client Queries Over
/// UDP", "Resolver Responses Over UDP"): refused, never a panic. A packet of our own with one bit changed is
/// refused too, and no packet but ours authenticates as a response, the fuzzer holding no key.
///
/// # Panics
///
/// When a changed packet, or a packet that is not ours, is accepted by the client.
pub fn dnscrypt_decrypt(data: &[u8]) {
    let exchange = &*EXCHANGE;
    let _ = exchange.resolver.decrypt_query(data);
    if data != exchange.response {
        assert!(exchange.query_context.decrypt_response(data).is_err());
    }
    let [high, low, mask, ..] = *data else {
        return;
    };
    let mask = mask | 1;
    for (packet, is_query) in [(&exchange.query, true), (&exchange.response, false)] {
        let at = usize::from(u16::from_be_bytes([high, low])) % packet.len();
        let mut changed = packet.clone();
        changed[at] ^= mask;
        if is_query {
            assert!(exchange.resolver.decrypt_query(&changed).is_err());
        } else {
            assert!(exchange.query_context.decrypt_response(&changed).is_err());
        }
    }
}

/// Arbitrary bytes as a resolver's DNS response to the exchange's query, sent over each carrier (draft "Resolver
/// Responses Over UDP", "Resolver Responses Over TCP"): never a panic; a packet that is made fits its carrier,
/// the query's size for UDP and under 4096 bytes for TCP.
///
/// # Panics
///
/// When a packet is larger than its carrier allows.
pub fn dnscrypt_encrypt_response(data: &[u8]) {
    let exchange = &*EXCHANGE;
    for (carrier, limit) in [(Carrier::Udp, exchange.query.len()), (Carrier::Tcp, 4095)] {
        if let Ok(packet) = exchange.response_context.encrypt_response(data, carrier, &mut Fixed(5)) {
            assert!(packet.len() <= limit);
            let _ = exchange.query_context.decrypt_response(&packet);
        }
    }
}
