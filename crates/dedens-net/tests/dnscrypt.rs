//! The `DNSCrypt` client (draft-denis-dprive-dnscrypt "Client Queries Over UDP", "Client Queries Over TCP",
//! "Certificates", "Key Management", "Padding For Client Queries Over UDP", "Negative Cases"; D98) against a resolver
//! on the loopback address, built from `dedens-dnscrypt`'s own resolver half: the certificates it serves and the
//! packets it gets are the test's to see and to script.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroU16};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::net::{TcpListener, UdpSocket};
use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, EncryptionSystem, LowOrderKey, PublicKey,
    QUERY_OVERHEAD, RESPONSE_MAGIC, ResolverKey, SecretKey, SigningKey, Validity,
};
use dedens_net::client::{Client, ClientError};
use dedens_net::dnscrypt::DnsCryptError;
use dedens_net::entropy::Entropy;
use dedens_net::exchange::Options;
use dedens_net::stamp::{DnsCrypt, Endpoint, Properties};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Rcode, Record, RecordType, Transport, Ttl};

use crate::util::loopback::Peer;
use crate::util::{query, response, wire};

/// The provider name of the resolvers of these tests.
const PROVIDER: &str = "2.dnscrypt-cert.test.example.";

/// What the resolver does with the next sealed query.
#[derive(Debug, Clone, Copy)]
enum Act {
    /// Answers it.
    Answer,
    /// Answers with TC set and no records, over UDP.
    Truncate,
    /// Answers with a packet that has the nonce of the query and a tag that does not match.
    Forge,
    /// Drops it.
    Silent,
}

/// A sealed query the resolver opened.
#[derive(Debug)]
struct Seen {
    carrier: Carrier,
    packet_len: usize,
    client_key: PublicKey,
    from: Option<SocketAddr>,
}

/// What the resolver serves and has seen.
struct Script {
    signer: SigningKey,
    /// The keys of the certificates it answers queries of.
    keys: Vec<ResolverKey>,
    /// The certificates it serves.
    served: Vec<Certificate>,
    /// What to do with the sealed queries, in order; then [`Act::Answer`].
    acts: VecDeque<Act>,
    /// Whether the certificates come truncated over UDP.
    truncate_certificates: bool,
    /// The certificate queries, over UDP and over TCP.
    fetched: (u32, u32),
    seen: Vec<Seen>,
}

/// The seconds since 1970, which the client reads the certificates' validity against.
fn now() -> u32 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970");
    u32::try_from(since.as_secs()).expect("before 2106")
}

/// The signing key of the provider.
fn signer(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).expect("a seed")
}

/// A certificate of `serial` for the resolver key `secret`, from `start` to `end` seconds after now (negative:
/// before).
fn certificate(
    signer: &SigningKey,
    secret: &SecretKey,
    serial: u32,
    start: i64,
    end: i64,
) -> Certificate {
    let at = |offset: i64| u32::try_from(i64::from(now()) + offset).expect("a time");
    Certificate::sign(
        signer,
        CertificateBody {
            system: EncryptionSystem::XChaCha20Poly1305,
            resolver_key: secret.public_key(),
            client_magic: ClientMagic::try_from([serial.to_be_bytes()[3]; 8]).expect("a magic"),
            serial,
            validity: Validity::new(at(start), at(end)).expect("a validity"),
            extensions: Vec::new(),
        },
    )
}

/// A certificate that is valid now.
fn valid(signer: &SigningKey, secret: &SecretKey, serial: u32) -> Certificate {
    certificate(signer, secret, serial, -3600, 86400)
}

/// The packets of a certificate request or a sealed query, answered by `script`.
fn handle(
    script: &RefCell<Script>,
    packet: &[u8],
    carrier: Carrier,
    from: Option<SocketAddr>,
) -> Option<Vec<u8>> {
    let mut script = script.borrow_mut();
    if let Ok(decoded) = Message::decode(packet)
        && !decoded.message.header.flags.contains(Flags::QR)
    {
        assert_eq!(
            decoded.message.questions[0].qtype,
            RecordType::TXT,
            "the only query in the clear is the certificates'"
        );
        match carrier {
            Carrier::Udp => script.fetched.0 += 1,
            Carrier::Tcp => script.fetched.1 += 1,
        }
        let mut answer = response(&decoded.message, Rcode::NOERROR);
        if carrier == Carrier::Udp && script.truncate_certificates {
            answer.header.flags = answer.header.flags.with(Flags::TC);
        } else {
            for certificate in &script.served {
                answer.answer.push(Record::new(
                    decoded.message.questions[0].name.clone().into_owned(),
                    Class::IN,
                    Ttl::ZERO,
                    &RData::Txt(certificate.to_txt().expect("a TXT")),
                ));
            }
        }
        return Some(wire(&answer));
    }
    let (plaintext, context, key) = script.keys.iter().find_map(|key| {
        let (plaintext, context) = key.decrypt_query(packet).ok()?;
        Some((plaintext, context, key.client_key(packet).ok()?))
    })?;
    script.seen.push(Seen {
        carrier,
        packet_len: packet.len(),
        client_key: key,
        from,
    });
    let act = script.acts.pop_front().unwrap_or(Act::Answer);
    let query = Message::decode(&plaintext).expect("a DNS query").message;
    let mut answer = response(&query, Rcode::NOERROR);
    match act {
        Act::Silent => return None,
        Act::Forge => {
            return Some([&RESPONSE_MAGIC[..], &packet[40..52], &[1; 12], &[0; 48]].concat());
        }
        Act::Truncate if carrier == Carrier::Udp => {
            answer.header.flags = answer.header.flags.with(Flags::TC);
        }
        Act::Truncate | Act::Answer => {}
    }
    let mut entropy = Entropy::new().expect("randomness");
    Some(
        context
            .encrypt_response(&wire(&answer), carrier, &mut entropy)
            .expect("a response"),
    )
}

/// A resolver on UDP and TCP of one loopback port, with the first of `secrets` for its certificates; `served` are
/// served as they are given.
struct Resolver {
    script: Rc<RefCell<Script>>,
    stamp: DnsCrypt,
}

impl Resolver {
    /// A resolver with the certificate of serial 1, valid now.
    async fn start() -> Self {
        let signer = signer(1);
        let secret = SecretKey::from_bytes([2; 32]);
        let certificate = valid(&signer, &secret, 1);
        Self::with(
            signer,
            vec![ResolverKey::new(&certificate, secret).expect("a key")],
            vec![certificate],
        )
        .await
    }

    async fn with(signer: SigningKey, keys: Vec<ResolverKey>, served: Vec<Certificate>) -> Self {
        let (socket, listener) = loop {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
            let addr = socket.local_addr().expect("an address");
            if let Ok(listener) = TcpListener::bind(addr).await {
                break (socket, listener);
            }
        };
        let addr = socket.local_addr().expect("an address");
        let stamp = DnsCrypt {
            properties: Properties::default(),
            address: Endpoint {
                ip: addr.ip(),
                port: NonZeroU16::new(addr.port()),
            },
            public_key: *signer.provider_key().as_bytes(),
            provider_name: PROVIDER
                .trim_end_matches('.')
                .parse()
                .expect("a provider name"),
        };
        let script = Rc::new(RefCell::new(Script {
            signer,
            keys,
            served,
            acts: VecDeque::new(),
            truncate_certificates: false,
            fetched: (0, 0),
            seen: Vec::new(),
        }));
        let shared = Rc::clone(&script);
        compio::runtime::spawn(async move {
            let mut buf = Vec::with_capacity(65535);
            loop {
                buf.clear();
                let BufResult(received, back) = socket.recv_from(buf).await;
                buf = back;
                let Ok((_, from)) = received else { return };
                if let Some(reply) = handle(&shared, &buf, Carrier::Udp, Some(from)) {
                    let _ = socket.send_to(reply, from).await;
                }
            }
        })
        .detach();
        let shared = Rc::clone(&script);
        compio::runtime::spawn(async move {
            loop {
                let mut peer = Peer::accept(&listener).await;
                let shared = Rc::clone(&shared);
                compio::runtime::spawn(async move {
                    while let Some(packet) = peer.read().await {
                        match handle(&shared, &packet, Carrier::Tcp, None) {
                            Some(reply) => peer.write(&[reply]).await,
                            None => return,
                        }
                    }
                })
                .detach();
            }
        })
        .detach();
        Self { script, stamp }
    }

    fn script(&self) -> std::cell::RefMut<'_, Script> {
        self.script.borrow_mut()
    }
}

/// Options that give up in under a second.
fn quick() -> Options {
    let mut options = Options::default();
    options.timeout = Duration::from_millis(300);
    options.tries = NonZeroU8::MIN.saturating_add(1);
    options
}

/// "Client Queries Over UDP", "Certificates": the certificates are asked for in the clear, the query goes sealed
/// from a packet of at least 256 bytes whose plaintext is a multiple of 64, and the response, opened, is a DNS
/// message with the query's ID.
#[compio::test]
async fn a_query_goes_sealed_and_gets_its_response_opened() {
    let resolver = Resolver::start().await;
    let client = Client::new();
    let response = client
        .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Udp);
    let sent = Message::decode(&response.query).expect("a query").message;
    let got = Message::decode(&response.wire).expect("a response").message;
    assert_eq!(got.header.id, sent.header.id);
    assert!(got.header.flags.contains(Flags::QR));
    let info = response.dnscrypt.expect("the certificate");
    assert_eq!((info.es_version, info.serial), (2, 1));
    let script = resolver.script();
    assert_eq!(script.fetched, (1, 0));
    let [seen] = &script.seen[..] else {
        panic!("one query: {:?}", script.seen)
    };
    assert_eq!(seen.carrier, Carrier::Udp);
    assert!(seen.packet_len >= 256, "{}", seen.packet_len);
    assert_eq!((seen.packet_len - QUERY_OVERHEAD) % 64, 0);
}

/// "Key Management": every query has a client key and a source port of its own, and the certificate is not fetched
/// again for the next.
#[compio::test]
async fn each_query_has_its_own_key_and_socket_and_the_certificate_is_kept() {
    let resolver = Resolver::start().await;
    let client = Client::new();
    for _ in 0..2 {
        client
            .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
            .await
            .expect("a response");
    }
    let script = resolver.script();
    assert_eq!(script.fetched, (1, 0), "fetched once");
    let [first, second] = &script.seen[..] else {
        panic!("two queries")
    };
    assert_ne!(first.client_key, second.client_key);
    assert_ne!(first.from, second.from);
}

/// "Client Queries Over TCP": the query is framed and padded to a multiple of 64 bytes, and the certificates come
/// over TCP too.
#[compio::test]
async fn a_tcp_exchange_seals_over_tcp_all_through() {
    let resolver = Resolver::start().await;
    let mut options = Options::default();
    options.transport = Transport::Tcp;
    let response = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Tcp);
    let script = resolver.script();
    assert_eq!(script.fetched, (0, 1));
    let [seen] = &script.seen[..] else {
        panic!("one query")
    };
    assert_eq!(seen.carrier, Carrier::Tcp);
    assert_eq!((seen.packet_len - QUERY_OVERHEAD) % 64, 0);
}

/// "Resolver Responses Over UDP": a truncated response is asked again over TCP, and the next UDP queries are
/// larger, so that their response fits.
#[compio::test]
async fn a_truncated_response_is_asked_again_over_tcp_and_the_next_query_is_larger() {
    let resolver = Resolver::start().await;
    resolver.script().acts.push_back(Act::Truncate);
    let client = Client::new();
    let response = client
        .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
        .await
        .expect("a response");
    assert_eq!((response.transport, response.sends), (Transport::Tcp, 2));
    client
        .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
        .await
        .expect("a response");
    let script = resolver.script();
    let seen: Vec<_> = script
        .seen
        .iter()
        .map(|s| (s.carrier, s.packet_len))
        .collect();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].0, Carrier::Udp);
    assert_eq!(seen[1].0, Carrier::Tcp);
    assert_eq!(seen[2].0, Carrier::Udp);
    assert!(seen[2].1 >= 512 && seen[2].1 > seen[0].1, "{seen:?}");
}

/// "Certificates": a truncated answer to the certificates' query is asked again over TCP.
#[compio::test]
async fn truncated_certificates_are_asked_again_over_tcp() {
    let resolver = Resolver::start().await;
    resolver.script().truncate_certificates = true;
    Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
        .await
        .expect("a response");
    assert_eq!(resolver.script().fetched, (1, 1));
}

/// "Certificates": of the certificates served, those the provider's key did not sign and those not valid now are
/// left; of the rest, the highest serial is used.
#[compio::test]
async fn the_valid_certificate_of_the_highest_serial_is_used() {
    let signer = signer(1);
    let other = self::signer(9);
    let secret = SecretKey::from_bytes([2; 32]);
    let served = vec![
        valid(&signer, &secret, 3),
        certificate(&signer, &secret, 7, -7200, -3600),
        valid(&other, &secret, 9),
        valid(&signer, &secret, 5),
        certificate(&signer, &secret, 8, 3600, 7200),
    ];
    let keys = served
        .iter()
        .filter_map(|certificate| {
            ResolverKey::new(certificate, SecretKey::from_bytes([2; 32])).ok()
        })
        .collect();
    let resolver = Resolver::with(signer, keys, served).await;
    let client = Client::new();
    let response = client
        .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.dnscrypt.map(|info| info.serial), Some(5));
    // The listing has all those the provider signed, valid or not.
    let listing = client
        .dnscrypt_certificates(&resolver.stamp, &Options::default())
        .await
        .expect("a listing");
    let serials: Vec<_> = listing
        .certificates
        .iter()
        .map(|info| info.serial)
        .collect();
    assert_eq!(serials, [3, 7, 5, 8]);
}

/// "Certificates": a resolver that serves no valid certificate is not asked.
#[compio::test]
async fn no_valid_certificate_is_an_error() {
    let signer = signer(1);
    let secret = SecretKey::from_bytes([2; 32]);
    let expired = certificate(&signer, &secret, 1, -7200, -3600);
    let key = ResolverKey::new(&expired, secret).expect("a key");
    let resolver = Resolver::with(signer, vec![key], vec![expired]).await;
    let error = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
        .await
        .expect_err("no certificate");
    assert!(
        matches!(error, ClientError::DnsCrypt(DnsCryptError::NoCertificate)),
        "{error:?}"
    );
    assert!(resolver.script().seen.is_empty());
}

/// "Negative Cases" case 5: a resolver key of low order is refused before any query is sent.
#[compio::test]
async fn a_resolver_key_of_low_order_is_refused() {
    let signer = signer(1);
    let low = Certificate::sign(
        &signer,
        CertificateBody {
            system: EncryptionSystem::XChaCha20Poly1305,
            resolver_key: PublicKey::from_bytes([0; 32]),
            client_magic: ClientMagic::try_from([4; 8]).expect("a magic"),
            serial: 1,
            validity: Validity::new(now() - 3600, now() + 3600).expect("a validity"),
            extensions: Vec::new(),
        },
    );
    let resolver = Resolver::with(signer, Vec::new(), vec![low]).await;
    let error = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
        .await
        .expect_err("a low order key");
    assert!(
        matches!(
            error,
            ClientError::DnsCrypt(DnsCryptError::LowOrderKey(LowOrderKey))
        ),
        "{error:?}"
    );
    assert!(error.is_local());
}

/// "Key Management", "Negative Cases" case 1: a resolver that rotated its certificate drops the queries of the
/// old one, so a try that gets no response fetches the certificates again.
#[compio::test]
async fn a_rotated_certificate_is_fetched_again_after_a_silent_try() {
    let resolver = Resolver::start().await;
    let client = Client::new();
    client
        .exchange_dnscrypt(query(), &resolver.stamp, &quick())
        .await
        .expect("a response");
    {
        let mut script = resolver.script();
        let secret = SecretKey::from_bytes([3; 32]);
        let rotated = valid(&script.signer, &secret, 2);
        script.keys = vec![ResolverKey::new(&rotated, secret).expect("a key")];
        script.served = vec![rotated];
    }
    let response = client
        .exchange_dnscrypt(query(), &resolver.stamp, &quick())
        .await
        .expect("a response");
    assert_eq!(response.dnscrypt.map(|info| info.serial), Some(2));
    assert_eq!(response.sends, 2);
    assert_eq!(resolver.script().fetched.0, 2);
}

/// "Resolver Responses Over UDP", "Negative Cases" case 4: a response that does not authenticate is disregarded,
/// the wait goes on for another, and the certificate is fetched again for the next try.
#[compio::test]
async fn a_forged_response_is_disregarded_and_the_certificate_fetched_again() {
    let resolver = Resolver::start().await;
    resolver.script().acts.push_back(Act::Forge);
    let response = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &quick())
        .await
        .expect("a response");
    assert_eq!(response.sends, 2);
    assert_eq!(resolver.script().fetched.0, 2);
}

/// "Client Queries Over TCP": a connection closed with no response ends the try, and the next one fetches the
/// certificates again.
#[compio::test]
async fn a_closed_tcp_connection_ends_the_try() {
    let resolver = Resolver::start().await;
    resolver.script().acts.push_back(Act::Silent);
    let mut options = quick();
    options.transport = Transport::Tcp;
    let response = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    assert_eq!(response.sends, 2);
    assert_eq!(resolver.script().fetched.1, 2);
}

/// A resolver that never answers is a timeout, not an error of the certificates.
#[compio::test]
async fn a_silent_resolver_is_a_timeout() {
    let resolver = Resolver::start().await;
    resolver.script().acts.extend([Act::Silent; 3]);
    let error = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &quick())
        .await
        .expect_err("no response");
    assert!(!error.is_local(), "{error:?}");
}
