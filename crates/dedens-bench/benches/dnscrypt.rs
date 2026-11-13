//! `DNSCrypt` (D97): the certificate, the shared key and the encryption of a query and a response on the captured
//! responses, for both classical systems, with the padding the draft asks of a UDP query. One call each;
//! the nonces are fixed bytes, since a CSPRNG's cost is the platform's.

use core::convert::Infallible;
use std::hint::black_box;

use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, ClientNonce, ClientSession,
    EncryptionSystem, QueryContext, RESPONSE_OVERHEAD, ResolverKey, ResponseContext, SecretKey,
    SigningKey, Validity,
};
use dedens_testkit::{captured, query};
use divan::Bencher;
use rand_core::{TryCryptoRng, TryRng};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

struct Fixed;

impl TryRng for Fixed {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0x0707_0707)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0x0707_0707_0707_0707)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(7);
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

const SYSTEMS: [EncryptionSystem; 2] = [
    EncryptionSystem::XChaCha20Poly1305,
    EncryptionSystem::XSalsa20Poly1305,
];

/// Each system on each captured response.
const RESPONSES: [(EncryptionSystem, &str); 6] = [
    (EncryptionSystem::XChaCha20Poly1305, "a"),
    (EncryptionSystem::XChaCha20Poly1305, "mx"),
    (EncryptionSystem::XChaCha20Poly1305, "txt_large"),
    (EncryptionSystem::XSalsa20Poly1305, "a"),
    (EncryptionSystem::XSalsa20Poly1305, "mx"),
    (EncryptionSystem::XSalsa20Poly1305, "txt_large"),
];

fn provider() -> SigningKey {
    SigningKey::from_seed(&[1; 32]).expect("a seed is a key")
}

fn certificate(system: EncryptionSystem, resolver: &SecretKey) -> Certificate {
    Certificate::sign(
        &provider(),
        CertificateBody {
            system,
            resolver_key: resolver.public_key(),
            client_magic: ClientMagic::try_from([9; 8]).expect("a magic"),
            serial: 1,
            validity: Validity::new(1, 2).expect("a validity"),
            extensions: Vec::new(),
        },
    )
}

/// Both ends of one exchange: the resolver's key, the client's session and the DNS query it sends.
fn parties(system: EncryptionSystem, case: &str) -> (ResolverKey, ClientSession, Vec<u8>) {
    let secret = SecretKey::from_bytes([2; 32]);
    let certificate = certificate(system, &secret);
    let session =
        ClientSession::new(&certificate, &SecretKey::from_bytes([3; 32])).expect("a good key");
    let resolver = ResolverKey::new(&certificate, secret).expect("the certificate's key");
    let response = captured(case);
    let id = u16::from_be_bytes([response[0], response[1]]);
    (
        resolver,
        session,
        query(case, id).to_vec().expect("a query fits"),
    )
}

/// One exchange of `case` up to the response: the client's context, the resolver's and the sealed response.
///
/// A response's padding is a function of the shared key and the client nonce, so two systems would seal the same
/// message to different lengths, and the benches would compare the ciphers on unequal plaintexts. The nonce is the
/// first of `[0; 12]`, `[1; 12]`, ... whose response is the shortest of 64 (no extra block of padding): the
/// same plaintext length, the same packet length, for both systems.
fn exchange(system: EncryptionSystem, case: &str) -> (QueryContext, ResponseContext, Vec<u8>) {
    let (resolver, session, query) = parties(system, case);
    let response = captured(case);
    let mut best: Option<(QueryContext, ResponseContext, Vec<u8>)> = None;
    for byte in 0..64 {
        let (packet, client) = session
            .encrypt_query(&query, padding(&query), ClientNonce::from_bytes([byte; 12]))
            .expect("encrypts");
        let (_, context) = resolver.decrypt_query(&packet).expect("decrypts");
        let sealed = context
            .encrypt_response(&response, Carrier::Tcp, &mut Fixed)
            .expect("encrypts");
        if best
            .as_ref()
            .is_none_or(|(_, _, shortest)| sealed.len() < shortest.len())
        {
            best = Some((client, context, sealed));
        }
    }
    let best = best.expect("a nonce");
    let unpadded = response.len() + RESPONSE_OVERHEAD;
    assert_eq!(
        best.2.len(),
        unpadded + 64 - response.len() % 64,
        "no extra block"
    );
    best
}

fn padding(query: &[u8]) -> dedens_dnscrypt::QueryPadding {
    dedens_dnscrypt::QueryPadding::udp(query.len(), 256)
}

#[divan::bench]
fn certificate_parse(bencher: Bencher<'_, '_>) {
    let provider = provider();
    let certificate = certificate(
        EncryptionSystem::XChaCha20Poly1305,
        &SecretKey::from_bytes([2; 32]),
    );
    let key = provider.provider_key();
    bencher.bench_local(|| {
        Certificate::parse(black_box(certificate.as_bytes()), &key).expect("verifies")
    });
}

#[divan::bench(args = SYSTEMS)]
fn session_new(bencher: Bencher<'_, '_>, system: EncryptionSystem) {
    let certificate = certificate(system, &SecretKey::from_bytes([2; 32]));
    let client = SecretKey::from_bytes([3; 32]);
    bencher
        .bench_local(|| ClientSession::new(black_box(&certificate), &client).expect("a good key"));
}

#[divan::bench(args = SYSTEMS)]
fn encrypt_query(bencher: Bencher<'_, '_>, system: EncryptionSystem) {
    let (_, session, query) = parties(system, "a");
    bencher.bench_local(|| {
        session
            .encrypt_query(
                black_box(&query),
                padding(&query),
                ClientNonce::from_bytes([7; 12]),
            )
            .expect("encrypts")
    });
}

#[divan::bench(args = SYSTEMS)]
fn decrypt_query(bencher: Bencher<'_, '_>, system: EncryptionSystem) {
    let (resolver, session, query) = parties(system, "a");
    let (packet, _) = session
        .encrypt_query(&query, padding(&query), ClientNonce::from_bytes([7; 12]))
        .expect("encrypts");
    bencher.bench_local(|| {
        resolver
            .decrypt_query(black_box(&packet))
            .expect("decrypts")
    });
}

#[divan::bench(args = SYSTEMS)]
fn decrypt_query_with(bencher: Bencher<'_, '_>, system: EncryptionSystem) {
    let (resolver, session, query) = parties(system, "a");
    let (packet, _) = session
        .encrypt_query(&query, padding(&query), ClientNonce::from_bytes([7; 12]))
        .expect("encrypts");
    let shared = resolver
        .shared_key(&resolver.client_key(&packet).expect("a key"))
        .expect("a good key");
    bencher.bench_local(|| {
        resolver
            .decrypt_query_with(black_box(&packet), &shared)
            .expect("decrypts")
    });
}

#[divan::bench(args = RESPONSES)]
fn encrypt_response(bencher: Bencher<'_, '_>, (system, case): (EncryptionSystem, &str)) {
    let (_, context, _) = exchange(system, case);
    let response = captured(case);
    bencher.bench_local(|| {
        context
            .encrypt_response(black_box(&response), Carrier::Tcp, &mut Fixed)
            .expect("encrypts")
    });
}

#[divan::bench(args = RESPONSES)]
fn decrypt_response(bencher: Bencher<'_, '_>, (system, case): (EncryptionSystem, &str)) {
    let (client, _, sealed) = exchange(system, case);
    bencher.bench_local(|| {
        client
            .decrypt_response(black_box(&sealed))
            .expect("decrypts")
    });
}
