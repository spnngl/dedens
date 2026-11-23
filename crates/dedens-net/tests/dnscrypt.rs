//! The `DNSCrypt` client (draft-denis-dprive-dnscrypt "Client Queries Over UDP", "Client Queries Over TCP",
//! "Certificates", "Key Management", "Padding For Client Queries Over UDP", "Negative Cases"; D98) against a resolver
//! on the loopback address, built from `dedens-dnscrypt`'s own resolver half: the certificates it serves and the
//! packets it gets are the test's to see and to script.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroU16};
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::net::UdpSocket;
use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, LowOrderKey, PublicKey, QUERY_OVERHEAD,
    RESPONSE_MAGIC, RESUME_MAGIC, ResolverKey, ResolverPublicKey, SecretKey, SessionError,
    SigningKey, TicketKey, TicketKeys, Validity, XWingSecretKey,
};
use dedens_net::client::{Client, ClientError};
use dedens_net::dnscrypt::DnsCryptError;
use dedens_net::entropy::Entropy;
use dedens_net::exchange::Options;
use dedens_net::io::{Compio, Io, TimedOut};
use dedens_net::stamp::{DnsCrypt, Endpoint, Properties};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Rcode, Record, RecordType, Transport, Ttl};

use crate::util::loopback::{Peer, one_port};
use crate::util::{cookie_of, query, response, wire};

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
    /// What the packet holds in place of the client's key: the key, the X-Wing ciphertext, or the ticket of a
    /// resumed query.
    client_key: Vec<u8>,
    resumed: bool,
    from: Option<SocketAddr>,
    /// Whether the query, opened, carries a DNS cookie.
    cookie: bool,
}

/// What is wrong with the first response to a certificates' query, whatever carried it: a relay asks the resolver
/// over UDP all the same.
#[derive(Clone, Copy)]
enum Fault {
    /// No response.
    Silent,
    /// Truncated, with no certificate.
    Truncated,
    /// Another ID than the query's.
    WrongId,
    /// The QR bit is clear: it is a query, not a response.
    NotAResponse,
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
    /// Whether UDP gets no certificate at all, as at a resolver serving them over TCP only.
    mute_udp_certificates: bool,
    /// What is wrong with the certificates' response over UDP, if anything.
    certificate_fault: Option<Fault>,
    /// The certificate queries, over UDP and over TCP.
    fetched: (u32, u32),
    /// The certificate queries that carry a DNS cookie.
    fetched_with_cookie: u32,
    /// The size of the certificate queries over UDP.
    fetch_sizes: Vec<usize>,
    /// The keys of the tickets issued to the full queries of PQ certificates; none, none is issued.
    tickets: Option<TicketKeys>,
    /// The lifetime of the tickets it issues, in seconds.
    ticket_life: u32,
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
            resolver_key: ResolverPublicKey::XChaCha20(secret.public_key()),
            client_magic: ClientMagic::try_from([serial.to_be_bytes()[3]; 8]).expect("a magic"),
            serial,
            validity: Validity::new(at(start), at(end)).expect("a validity"),
            extensions: Vec::new(),
        },
    )
}

/// A PQ certificate of `serial` for the X-Wing key `secret`, valid now.
fn pq_certificate(signer: &SigningKey, secret: &XWingSecretKey, serial: u32) -> Certificate {
    Certificate::sign(
        signer,
        CertificateBody {
            resolver_key: ResolverPublicKey::XWing(secret.public_key()),
            client_magic: ClientMagic::try_from([serial.to_be_bytes()[3]; 8]).expect("a magic"),
            serial,
            validity: Validity::new(now() - 3600, now() + 86400).expect("a validity"),
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
        script.fetched_with_cookie += u32::from(cookie_of(packet).is_some());
        match carrier {
            Carrier::Udp => {
                script.fetched.0 += 1;
                script.fetch_sizes.push(packet.len());
            }
            Carrier::Tcp => script.fetched.1 += 1,
        }
        if carrier == Carrier::Udp && script.mute_udp_certificates {
            return None;
        }
        let mut answer = response(&decoded.message, Rcode::NOERROR);
        let mut truncated = carrier == Carrier::Udp && script.truncate_certificates;
        match script.certificate_fault.take() {
            Some(Fault::Silent) => return None,
            Some(Fault::Truncated) => truncated = true,
            Some(Fault::WrongId) => answer.header.id = answer.header.id.wrapping_add(1),
            Some(Fault::NotAResponse) => answer.header.flags = Flags::from_word(0),
            None => {}
        }
        if truncated {
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
    let at = u64::from(now());
    let resumed = packet.starts_with(&RESUME_MAGIC);
    let (plaintext, context, client_key) = if resumed {
        let tickets = script.tickets.as_ref()?;
        let query = tickets.open(packet, at).ok()?;
        let (plaintext, context) = script
            .keys
            .iter()
            .find_map(|key| key.decrypt_resumed(&query, at).ok())?;
        (plaintext, context, packet[10..140].to_vec())
    } else {
        script.keys.iter().find_map(|key| {
            let (plaintext, context) = key.decrypt_query(packet).ok()?;
            let kex = if context.is_pq() { 1120 } else { 32 };
            Some((plaintext, context, packet[8..8 + kex].to_vec()))
        })?
    };
    script.seen.push(Seen {
        carrier,
        packet_len: packet.len(),
        client_key,
        resumed,
        from,
        cookie: cookie_of(&plaintext).is_some(),
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
    // A ticket goes with the response to a full query of a PQ certificate.
    let ticket = script
        .tickets
        .as_ref()
        .filter(|_| !resumed)
        .and_then(|tickets| tickets.issue(&context, at, script.ticket_life, &mut entropy));
    Some(
        context
            .encrypt_response_with(&wire(&answer), ticket.as_ref(), carrier, &mut entropy)
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

    /// A resolver with a classical certificate of serial 5 and a PQ one of serial 1, and tickets.
    async fn start_pq() -> Self {
        let signer = signer(1);
        let secret = SecretKey::from_bytes([2; 32]);
        let classical = valid(&signer, &secret, 5);
        let pq_secret = XWingSecretKey::from_seed([3; 32]);
        let pq = pq_certificate(&signer, &pq_secret, 1);
        let resolver = Self::with(
            signer,
            vec![
                ResolverKey::new(&classical, secret).expect("a key"),
                ResolverKey::new(&pq, pq_secret).expect("a key"),
            ],
            vec![classical, pq],
        )
        .await;
        resolver.script().tickets =
            Some(TicketKeys::new(TicketKey::new([0, 0, 0, 1], [9; 32]), None));
        resolver
    }

    /// A resolver as [`Resolver::start`]'s on TCP alone: its UDP port is closed, and refuses the datagrams.
    async fn start_tcp_only() -> Self {
        let signer = signer(1);
        let secret = SecretKey::from_bytes([2; 32]);
        let certificate = valid(&signer, &secret, 1);
        let keys = vec![ResolverKey::new(&certificate, secret).expect("a key")];
        Self::serve(signer, keys, vec![certificate], false).await
    }

    async fn with(signer: SigningKey, keys: Vec<ResolverKey>, served: Vec<Certificate>) -> Self {
        Self::serve(signer, keys, served, true).await
    }

    async fn serve(
        signer: SigningKey,
        keys: Vec<ResolverKey>,
        served: Vec<Certificate>,
        udp: bool,
    ) -> Self {
        let (socket, listener) = one_port().await;
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
            mute_udp_certificates: false,
            certificate_fault: None,
            fetched: (0, 0),
            fetched_with_cookie: 0,
            fetch_sizes: Vec::new(),
            tickets: None,
            ticket_life: 300,
            seen: Vec::new(),
        }));
        let shared = Rc::clone(&script);
        let socket = udp.then_some(socket);
        compio::runtime::spawn(async move {
            let Some(socket) = socket else { return };
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
    // D98: the cookies of the default options are not sent, in the clear or sealed.
    assert!(!seen.cookie);
    assert_eq!(script.fetched_with_cookie, 0);
    assert!(info.valid_from <= now() - 3590 && info.valid_until >= now() + 86_000);
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
    // No TC came back, so the floor of the padding stays.
    assert_eq!(first.packet_len, second.packet_len);
}

/// "Client Queries Over TCP": the query is framed and padded to a multiple of 64 bytes; the certificates come over
/// UDP, which every resolver serves them over, whatever the transport of the queries.
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
    assert_eq!(script.fetched, (1, 0));
    let [seen] = &script.seen[..] else {
        panic!("one query")
    };
    assert_eq!(seen.carrier, Carrier::Tcp);
    assert_eq!((seen.packet_len - QUERY_OVERHEAD) % 64, 0);
    assert!(!seen.cookie);
    assert_eq!(script.fetched_with_cookie, 0);
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

/// "Certificates": the retry over TCP is the certificates' own, whatever the options of the query ask for.
#[compio::test]
async fn truncated_certificates_are_asked_again_over_tcp_though_the_query_has_no_fallback() {
    let resolver = Resolver::start().await;
    resolver.script().truncate_certificates = true;
    let mut options = Options::default();
    options.tcp_fallback = false;
    Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    assert_eq!(resolver.script().fetched, (1, 1));
}

/// "Certificates": a resolver that serves them over TCP alone is asked there once UDP got no answer.
#[compio::test]
async fn certificates_are_asked_over_tcp_when_udp_gets_none() {
    let resolver = Resolver::start().await;
    resolver.script().mute_udp_certificates = true;
    let response = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &quick())
        .await
        .expect("a response");
    assert_eq!(response.dnscrypt.map(|info| info.serial), Some(1));
    assert_eq!(
        resolver.script().fetched,
        (2, 1),
        "two tries over UDP, then TCP"
    );
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
    assert!(!error.is_local());
    assert!(resolver.script().seen.is_empty());
}

/// "Negative Cases" case 5: a resolver key of low order is refused before any query is sent.
#[compio::test]
async fn a_resolver_key_of_low_order_is_refused() {
    let signer = signer(1);
    let low = Certificate::sign(
        &signer,
        CertificateBody {
            resolver_key: ResolverPublicKey::XChaCha20(PublicKey::from_bytes([0; 32])),
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
            ClientError::DnsCrypt(DnsCryptError::Session(SessionError::LowOrderKey(
                LowOrderKey
            )))
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
    assert_eq!(resolver.script().fetched.0, 2);
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

/// What a relay got: the prefix and the inner packet's length, and the length of the response it passed back, if any.
#[derive(Debug)]
struct Relayed {
    carrier: Carrier,
    prefix: Vec<u8>,
    inner_len: usize,
    passed: Option<usize>,
}

impl Relayed {
    /// A packet a mute relay got and dropped.
    fn dropped(carrier: Carrier, packet: &[u8]) -> Self {
        Self {
            carrier,
            prefix: packet[..28].to_vec(),
            inner_len: packet.len() - 28,
            passed: None,
        }
    }
}

/// The `Anonymized DNSCrypt` relay of the tests (draft "Anonymized `DNSCrypt`"), on UDP and TCP of one loopback
/// port: it reads the prefix as the draft writes it, passes the inner packet to the address in it over UDP, whatever
/// carried it, and drops a response longer than the inner packet. A `mute` relay drops everything.
struct LoopbackRelay {
    stamp: dedens_net::stamp::Relay,
    seen: Rc<RefCell<Vec<Relayed>>>,
}

impl LoopbackRelay {
    async fn start(mute: bool) -> Self {
        Self::with(mute, true).await
    }

    /// A relay on TCP alone: its UDP port is closed, and refuses the datagrams.
    async fn start_tcp_only() -> Self {
        Self::with(false, false).await
    }

    async fn with(mute: bool, udp: bool) -> Self {
        let (socket, listener) = one_port().await;
        let addr = socket.local_addr().expect("an address");
        let seen = Rc::new(RefCell::new(Vec::new()));
        let log = Rc::clone(&seen);
        let socket = udp.then_some(socket);
        compio::runtime::spawn(async move {
            let Some(socket) = socket else { return };
            let mut buf = Vec::with_capacity(65535);
            loop {
                buf.clear();
                let BufResult(received, back) = socket.recv_from(buf).await;
                buf = back;
                let Ok((_, from)) = received else { return };
                if mute {
                    log.borrow_mut().push(Relayed::dropped(Carrier::Udp, &buf));
                } else if let Some(reply) = Self::relay(&log, Carrier::Udp, &buf).await {
                    let _ = socket.send_to(reply, from).await;
                }
            }
        })
        .detach();
        let log = Rc::clone(&seen);
        compio::runtime::spawn(async move {
            loop {
                let mut peer = Peer::accept(&listener).await;
                let log = Rc::clone(&log);
                compio::runtime::spawn(async move {
                    while let Some(packet) = peer.read().await {
                        if mute {
                            log.borrow_mut()
                                .push(Relayed::dropped(Carrier::Tcp, &packet));
                            continue;
                        }
                        let Some(reply) = Self::relay(&log, Carrier::Tcp, &packet).await else {
                            return;
                        };
                        if !peer.offer(&[reply]).await {
                            return;
                        }
                    }
                })
                .detach();
            }
        })
        .detach();
        Self {
            stamp: dedens_net::stamp::Relay {
                address: Endpoint {
                    ip: addr.ip(),
                    port: NonZeroU16::new(addr.port()),
                },
            },
            seen,
        }
    }

    /// The response of the resolver named in `packet`, if it is not longer than the inner packet.
    async fn relay(
        log: &RefCell<Vec<Relayed>>,
        carrier: Carrier,
        packet: &[u8],
    ) -> Option<Vec<u8>> {
        assert_eq!(
            &packet[..10],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]
        );
        let ip: [u8; 16] = packet[10..26].try_into().expect("16 bytes");
        let port = u16::from_be_bytes([packet[26], packet[27]]);
        let target = SocketAddr::new(std::net::Ipv6Addr::from(ip).to_canonical(), port);
        let inner = &packet[28..];
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
        // Connected: a datagram from another address is no reply.
        socket.connect(target).await.expect("connected");
        let BufResult(sent, _) = socket.send(inner.to_vec()).await;
        sent.expect("sent");
        let received = compio::time::timeout(
            Duration::from_millis(250),
            socket.recv(Vec::with_capacity(65535)),
        )
        .await;
        let reply = match received {
            Ok(BufResult(Ok(_), reply)) if reply.len() <= inner.len() => Some(reply),
            _ => None,
        };
        log.borrow_mut().push(Relayed {
            carrier,
            prefix: packet[..28].to_vec(),
            inner_len: inner.len(),
            passed: reply.as_ref().map(Vec::len),
        });
        reply
    }
}

/// The prefix of the draft for a resolver at `addr`: the magic, the address as 16 bytes, the port.
fn prefix_for(addr: SocketAddr) -> Vec<u8> {
    let mut prefix = vec![0xff; 8];
    prefix.extend([0, 0]);
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            prefix.extend([0; 10]);
            prefix.extend([0xff, 0xff]);
            prefix.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => prefix.extend(ip.octets()),
    }
    prefix.extend(addr.port().to_be_bytes());
    prefix
}

/// The test relay passes the resolver's reply alone: a datagram to its socket from another address is no reply.
#[compio::test]
async fn the_relay_passes_no_reply_from_another_address() {
    let resolver = UdpSocket::bind("127.0.0.1:0").await.expect("a socket");
    let relay = LoopbackRelay::start(false).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("a socket");
    let packet = [
        prefix_for(resolver.local_addr().expect("an address")),
        vec![0x5a; 32],
    ]
    .concat();
    let at = relay.stamp.address.socket_addr();
    client.send_to(packet, at).await.0.expect("sent");
    let BufResult(received, _) = resolver.recv_from(Vec::with_capacity(64)).await;
    let (_, from) = received.expect("the packet passed");
    let other = UdpSocket::bind("127.0.0.1:0").await.expect("a socket");
    other.send_to(vec![1; 16], from).await.0.expect("sent");
    resolver.send_to(vec![2; 16], from).await.0.expect("sent");
    let BufResult(received, reply) = client.recv_from(Vec::with_capacity(64)).await;
    received.expect("a reply");
    assert_eq!(reply, [2; 16]);
}

/// "Anonymized `DNSCrypt`": the certificates' query and a sealed query over UDP both go to the relay, prefixed with
/// the resolver's address; the certificates' query is padded, so that the relay passes the response back.
#[compio::test]
async fn certificates_and_queries_go_through_the_relay_over_udp() {
    let resolver = Resolver::start().await;
    let relay = LoopbackRelay::start(false).await;
    let response = Client::new()
        .exchange_dnscrypt_via(
            query(),
            &resolver.stamp,
            &[relay.stamp],
            &Options::default(),
        )
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Udp);
    let prefix = prefix_for(resolver.stamp.address.socket_addr());
    let seen = relay.seen.borrow();
    let [certificates, sealed] = &seen[..] else {
        panic!("two packets: {seen:?}")
    };
    for relayed in [certificates, sealed] {
        assert_eq!(relayed.carrier, Carrier::Udp);
        assert_eq!(relayed.prefix, prefix);
        assert!(relayed.passed.is_some(), "{relayed:?}");
    }
    assert_eq!(certificates.inner_len, 1200, "{certificates:?}");
    let script = resolver.script();
    assert_eq!(script.fetched, (1, 0));
    assert_eq!(script.seen.len(), 1);
    assert_eq!(script.seen[0].carrier, Carrier::Udp);
}

/// "Anonymized `DNSCrypt`": a relay passes the inner packet over UDP even when the client came over TCP, and drops a
/// response longer than it, so the sealed query over TCP is a large one.
#[compio::test]
async fn a_tcp_query_through_the_relay_is_the_largest_packet() {
    let resolver = Resolver::start().await;
    let relay = LoopbackRelay::start(false).await;
    let mut options = Options::default();
    options.transport = Transport::Tcp;
    let response = Client::new()
        .exchange_dnscrypt_via(query(), &resolver.stamp, &[relay.stamp], &options)
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Tcp);
    let seen = relay.seen.borrow();
    let sealed = seen.last().expect("a packet");
    assert_eq!(sealed.carrier, Carrier::Tcp);
    assert_eq!(
        sealed.prefix,
        prefix_for(resolver.stamp.address.socket_addr())
    );
    assert_eq!(sealed.inner_len, 4096);
    assert!(sealed.passed.is_some());
    let script = resolver.script();
    assert_eq!(script.seen.len(), 1);
    assert_eq!(
        script.seen[0].carrier,
        Carrier::Udp,
        "the relay asks over UDP"
    );
    assert_eq!(script.seen[0].packet_len, 4096);
}

/// D101, "Anonymized `DNSCrypt`": through a relay over TCP, a PQ query is the largest packet too, its X-Wing
/// ciphertext leaving less room for the padding than a classical key does.
#[compio::test]
async fn a_pq_tcp_query_through_the_relay_is_the_largest_packet() {
    let resolver = Resolver::start_pq().await;
    let relay = LoopbackRelay::start(false).await;
    let mut options = Options::default();
    options.transport = Transport::Tcp;
    let response = Client::new()
        .exchange_dnscrypt_via(query(), &resolver.stamp, &[relay.stamp], &options)
        .await
        .expect("a response");
    assert_eq!(response.dnscrypt.map(|info| info.es_version), Some(3));
    let script = resolver.script();
    assert_eq!(script.seen.len(), 1);
    assert_eq!(script.seen[0].packet_len, 4096);
}

/// D101: a PQ query has no floor, so the floor that truncated responses raised to the largest packet leaves its
/// queries, resumed or not, the room their ciphertext or ticket takes.
#[compio::test]
async fn pq_queries_fit_once_the_floor_is_the_largest_packet() {
    let resolver = Resolver::start_pq().await;
    let mut options = Options::default();
    options.dnscrypt.resume = true;
    let client = Client::new();
    // Each truncated response doubles the floor, 256 bytes at first: 4096 after four.
    for _ in 0..4 {
        resolver.script().acts.push_back(Act::Truncate);
        client
            .exchange_dnscrypt(query(), &resolver.stamp, &options)
            .await
            .expect("a response over TCP");
    }
    let response = client
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Udp);
}

/// "Anonymized `DNSCrypt`": a truncated response through the relay is asked again over TCP to the relay, with the
/// largest inner packet, and the next UDP queries are larger.
#[compio::test]
async fn a_truncated_response_through_the_relay_is_asked_again_larger() {
    let resolver = Resolver::start().await;
    resolver.script().acts.push_back(Act::Truncate);
    let relay = LoopbackRelay::start(false).await;
    let client = Client::new();
    let options = Options::default();
    let response = client
        .exchange_dnscrypt_via(query(), &resolver.stamp, &[relay.stamp], &options)
        .await
        .expect("a response");
    assert_eq!((response.transport, response.sends), (Transport::Tcp, 2));
    client
        .exchange_dnscrypt_via(query(), &resolver.stamp, &[relay.stamp], &options)
        .await
        .expect("a response");
    let seen = relay.seen.borrow();
    let sealed: Vec<_> = seen
        .iter()
        .skip(1)
        .map(|relayed| (relayed.carrier, relayed.inner_len))
        .collect();
    assert_eq!(sealed.len(), 3, "{sealed:?}");
    assert_eq!(sealed[0].0, Carrier::Udp);
    assert_eq!(sealed[1], (Carrier::Tcp, 4096));
    assert_eq!(sealed[2].0, Carrier::Udp);
    assert!(
        sealed[2].1 >= 512 && sealed[2].1 > sealed[0].1,
        "{sealed:?}"
    );
}

/// "Anonymized `DNSCrypt`", D100: of several relays one is picked for each query, and one that failed is not picked
/// for the next try: with one that drops everything, the query still gets its response by the other.
#[compio::test]
async fn a_relay_that_fails_is_skipped_by_the_next_try() {
    let resolver = Resolver::start().await;
    let mute = LoopbackRelay::start(true).await;
    let live = LoopbackRelay::start(false).await;
    let mut options = quick();
    options.tries = NonZeroU8::new(3).expect("three");
    let client = Client::new();
    let queries = 16;
    for _ in 0..queries {
        let response = client
            .exchange_dnscrypt_via(
                query(),
                &resolver.stamp,
                &[mute.stamp, live.stamp],
                &options,
            )
            .await
            .expect("a response");
        assert!(response.dnscrypt.is_some());
    }
    assert!(
        live.seen.borrow().iter().any(|r| r.passed.is_some()),
        "the live relay passed the query"
    );
    // The certificates' query over UDP then over TCP, or one sealed query, before the relay is skipped for good.
    assert!(mute.seen.borrow().len() <= 3, "{:?}", mute.seen.borrow());
    assert_eq!(resolver.script().seen.len(), queries);
}

/// D100: a relay that is down, its port closed, refuses the packets: it costs a try, as a mute one does, not the
/// exchange, and the queries get their responses by the other.
#[compio::test]
async fn a_relay_that_refuses_is_skipped_by_the_next_try() {
    let resolver = Resolver::start().await;
    let closed = {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
        socket.local_addr().expect("an address")
    };
    let down = dedens_net::stamp::Relay {
        address: Endpoint {
            ip: closed.ip(),
            port: NonZeroU16::new(closed.port()),
        },
    };
    let live = LoopbackRelay::start(false).await;
    let mut options = quick();
    options.tries = NonZeroU8::new(3).expect("three");
    let client = Client::new();
    let queries = 16;
    for _ in 0..queries {
        client
            .exchange_dnscrypt_via(query(), &resolver.stamp, &[down, live.stamp], &options)
            .await
            .expect("a response");
    }
    assert_eq!(resolver.script().seen.len(), queries);
}

/// D98: a resolver reached direct that refuses the sealed query is the exchange's error at once, as there is no
/// other way to it; its certificates came over TCP.
#[compio::test]
async fn a_resolver_that_refuses_the_query_is_an_error() {
    let resolver = Resolver::start_tcp_only().await;
    let error = Client::new()
        .exchange_dnscrypt(query(), &resolver.stamp, &quick())
        .await
        .expect_err("refused");
    assert!(
        matches!(&error, ClientError::Udp(error) if error.kind() == io::ErrorKind::ConnectionRefused),
        "{error:?}"
    );
    assert_eq!(resolver.script().fetched, (0, 1));
}

/// D100: a relay that refuses the sealed query costs a try too, though it passed the certificates' query (over TCP,
/// its UDP port closed).
#[compio::test]
async fn a_relay_that_refuses_the_query_is_skipped_by_the_next_try() {
    let resolver = Resolver::start().await;
    let half = LoopbackRelay::start_tcp_only().await;
    let live = LoopbackRelay::start(false).await;
    let mut options = quick();
    options.tries = NonZeroU8::new(3).expect("three");
    let client = Client::new();
    // The relay is picked at random until it fails: 16 queries miss it with a chance of 2^-16.
    let queries = 16;
    for _ in 0..queries {
        client
            .exchange_dnscrypt_via(
                query(),
                &resolver.stamp,
                &[half.stamp, live.stamp],
                &options,
            )
            .await
            .expect("a response");
    }
    assert_eq!(resolver.script().seen.len(), queries);
}

/// "Anonymized `DNSCrypt`": the same resolver asked direct and through a relay is two resolvers: the second query goes
/// to the relay, not to the address the first one knew.
#[compio::test]
async fn a_stamp_asked_direct_and_through_a_relay_is_asked_both_ways() {
    let resolver = Resolver::start().await;
    let relay = LoopbackRelay::start(false).await;
    let client = Client::new();
    let options = Options::default();
    client
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    assert!(relay.seen.borrow().is_empty());
    client
        .exchange_dnscrypt_via(query(), &resolver.stamp, &[relay.stamp], &options)
        .await
        .expect("a response");
    assert_eq!(relay.seen.borrow().len(), 2, "the certificates, the query");
    assert_eq!(resolver.script().fetched, (2, 0), "each asked its own");
}

/// "Anonymized `DNSCrypt`": a certificates' response through the relay that is truncated, or that never comes over
/// UDP, is asked again over TCP with the large inner packet.
#[compio::test]
async fn certificates_through_the_relay_go_over_tcp_when_udp_fails() {
    for fault in [Fault::Truncated, Fault::Silent] {
        let resolver = Resolver::start().await;
        resolver.script().certificate_fault = Some(fault);
        let relay = LoopbackRelay::start(false).await;
        let mut options = quick();
        options.tries = NonZeroU8::MIN;
        let listing = Client::new()
            .dnscrypt_certificates_via(&resolver.stamp, &[relay.stamp], &options)
            .await
            .expect("a listing");
        assert_eq!(listing.response.transport, Transport::Tcp);
        assert_eq!(listing.certificates.len(), 1);
        let seen: Vec<_> = relay
            .seen
            .borrow()
            .iter()
            .map(|relayed| (relayed.carrier, relayed.inner_len))
            .collect();
        assert_eq!(seen, [(Carrier::Udp, 1200), (Carrier::Tcp, 4096)]);
        assert_eq!(resolver.script().fetched, (2, 0), "the relay asks over UDP");
    }
}

/// "Anonymized `DNSCrypt`", "Relay Behavior": a response to the certificates' query must have the query's ID and be a
/// response; one that is not is disregarded as a spoof is, and the certificates come over TCP.
#[compio::test]
async fn a_certificates_response_that_is_not_the_answer_is_disregarded() {
    for fault in [Fault::WrongId, Fault::NotAResponse] {
        let resolver = Resolver::start().await;
        resolver.script().certificate_fault = Some(fault);
        let relay = LoopbackRelay::start(false).await;
        let mut options = quick();
        options.tries = NonZeroU8::MIN;
        let listing = Client::new()
            .dnscrypt_certificates_via(&resolver.stamp, &[relay.stamp], &options)
            .await
            .expect("a listing");
        assert_eq!(listing.response.transport, Transport::Tcp);
        assert_eq!(resolver.script().fetched, (2, 0), "the relay asks over UDP");
    }
}

/// "Anonymized `DNSCrypt`", D100: with the only relay silent there is no response, and no query goes direct: the
/// resolver hears of no one.
#[compio::test]
async fn a_silent_relay_is_an_error_and_no_query_goes_direct() {
    let resolver = Resolver::start().await;
    let mute = LoopbackRelay::start(true).await;
    let error = Client::new()
        .exchange_dnscrypt_via(query(), &resolver.stamp, &[mute.stamp], &quick())
        .await
        .expect_err("no response");
    assert!(!error.is_local(), "{error:?}");
    let script = resolver.script();
    assert_eq!(script.fetched, (0, 0));
    assert!(script.seen.is_empty());
}

/// D101, "Certificate Retrieval Amplification": the query for the certificates is padded to cover the rollover set;
/// over UDP the PQ certificate is preferred to a classical one of a higher serial, and the query goes with an X-Wing
/// ciphertext, a new one each time, no ticket used unless asked for.
#[compio::test]
async fn a_pq_certificate_is_preferred_and_each_query_has_a_new_ciphertext() {
    let resolver = Resolver::start_pq().await;
    let client = Client::new();
    let mut infos = Vec::new();
    for _ in 0..2 {
        let response = client
            .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
            .await
            .expect("a response");
        infos.push(response.dnscrypt.expect("the certificate"));
    }
    assert!(
        infos
            .iter()
            .all(|info| (info.es_version, info.serial) == (3, 1))
    );
    let script = resolver.script();
    assert_eq!(script.fetch_sizes, [3072]);
    let [first, second] = &script.seen[..] else {
        panic!("two queries")
    };
    assert!(first.packet_len >= 1220 && first.packet_len == second.packet_len);
    assert!(!first.resumed && !second.resumed);
    assert_ne!(
        first.client_key, second.client_key,
        "a fresh encapsulation each"
    );
}

/// D101, "Downgrade Protection": `dnscrypt.pq` takes a PQ certificate only: a resolver whose PQ certificate was
/// stripped is refused, and one that never had any, as the client that is not told falls back.
#[compio::test]
async fn pq_required_is_not_downgraded() {
    let resolver = Resolver::start_pq().await;
    let mut options = Options::default();
    options.dnscrypt.pq = true;
    let client = Client::new();
    let response = client
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    assert_eq!(response.dnscrypt.map(|info| info.es_version), Some(3));

    // The PQ certificate is stripped on the way: the certificate in use is no longer served.
    let stripped = Resolver::start().await;
    let error = Client::new()
        .exchange_dnscrypt(query(), &stripped.stamp, &options)
        .await
        .expect_err("no PQ certificate");
    assert!(
        matches!(error, ClientError::DnsCrypt(DnsCryptError::NoCertificate)),
        "{error:?}"
    );
    assert!(stripped.script().seen.is_empty(), "nothing was sent sealed");
    let response = Client::new()
        .exchange_dnscrypt(query(), &stripped.stamp, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.dnscrypt.map(|info| info.es_version), Some(2));
}

/// D101, "Stateless Resumption": with `dnscrypt.resume`, the response to the first query brings a ticket, the next
/// queries are resumed with it, with no ciphertext, and a resolver that drops the ticket gets a full query again.
#[compio::test]
async fn resumed_queries_use_the_ticket_and_a_dropped_ticket_falls_back() {
    let resolver = Resolver::start_pq().await;
    let mut options = quick();
    options.dnscrypt.resume = true;
    let client = Client::new();
    for _ in 0..3 {
        client
            .exchange_dnscrypt(query(), &resolver.stamp, &options)
            .await
            .expect("a response");
    }
    {
        let script = resolver.script();
        let kinds: Vec<_> = script.seen.iter().map(|seen| seen.resumed).collect();
        assert_eq!(kinds, [false, true, true]);
        assert!(script.seen[1].packet_len < script.seen[0].packet_len);
        assert!(
            script.seen[1].packet_len >= 256,
            "a resumed query keeps the floor of the padding"
        );
        assert_eq!(
            script.seen[1].client_key, script.seen[2].client_key,
            "the same ticket"
        );
        assert_eq!(script.fetched, (1, 0), "the certificates once");
    }

    // The resolver lost its ticket keys: the resumed query is dropped, the next try is a full one.
    resolver.script().tickets = Some(TicketKeys::new(TicketKey::new([0, 0, 0, 2], [8; 32]), None));
    client
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    let script = resolver.script();
    let kinds: Vec<_> = script.seen.iter().map(|seen| seen.resumed).collect();
    assert_eq!(
        kinds,
        [false, true, true, false],
        "the dropped one is not seen"
    );
}

/// D101: a ticket is of the certificate it was issued under: the certificate changed, the resumed query is not made.
#[compio::test]
async fn a_ticket_of_another_certificate_is_not_used() {
    let resolver = Resolver::start_pq().await;
    let mut options = quick();
    options.dnscrypt.resume = true;
    let client = Client::new();
    for _ in 0..2 {
        client
            .exchange_dnscrypt(query(), &resolver.stamp, &options)
            .await
            .expect("a response");
    }
    {
        // A newer PQ certificate, and a forged response: the client fetches the certificates again.
        let mut script = resolver.script();
        let secret = XWingSecretKey::from_seed([4; 32]);
        let certificate = pq_certificate(&script.signer, &secret, 2);
        script
            .keys
            .push(ResolverKey::new(&certificate, secret).expect("a key"));
        script.served.push(certificate);
        script.acts.push_back(Act::Forge);
    }
    client
        .exchange_dnscrypt(query(), &resolver.stamp, &options)
        .await
        .expect("a response");
    let script = resolver.script();
    let kinds: Vec<_> = script.seen.iter().map(|seen| seen.resumed).collect();
    assert_eq!(
        kinds,
        [false, true, true, false],
        "the resumed query that is forged an answer to, then a full one"
    );
}

/// D101: without `dnscrypt.resume` a ticket is not kept, and no query is resumed.
#[compio::test]
async fn tickets_are_not_used_unless_asked_for() {
    let resolver = Resolver::start_pq().await;
    let client = Client::new();
    for _ in 0..2 {
        client
            .exchange_dnscrypt(query(), &resolver.stamp, &Options::default())
            .await
            .expect("a response");
    }
    assert!(resolver.script().seen.iter().all(|seen| !seen.resumed));
}

/// Compio on a clock that stands still until the test moves it: `now` is `start` plus the offset the test sets, so a
/// ticket expires at an instant the test names.
#[derive(Debug, Clone)]
struct Stepped {
    start: Instant,
    offset: Rc<Cell<Duration>>,
}

impl Stepped {
    fn new() -> Self {
        Self {
            start: Compio.now(),
            offset: Rc::default(),
        }
    }

    fn set(&self, offset: Duration) {
        self.offset.set(offset);
    }
}

impl Io for Stepped {
    type Udp = <Compio as Io>::Udp;
    type Stream = <Compio as Io>::Stream;
    type Listener = <Compio as Io>::Listener;
    type Task = <Compio as Io>::Task;

    fn now(&self) -> Instant {
        self.start + self.offset.get()
    }

    fn unix_time(&self) -> u64 {
        Compio.unix_time()
    }

    fn spawn(&self, task: impl Future<Output = ()> + 'static) -> Self::Task {
        Compio.spawn(task)
    }

    fn detach(&self, task: impl Future<Output = ()> + 'static) {
        Compio.detach(task);
    }

    async fn timeout_at<F: Future>(
        &self,
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, TimedOut> {
        let left = deadline.saturating_duration_since(self.now());
        Compio.timeout_at(Compio.now() + left, future).await
    }

    fn random(&self, bytes: &mut [u8]) -> io::Result<()> {
        Compio.random(bytes)
    }

    async fn udp_bind(&self, addr: SocketAddr) -> io::Result<Self::Udp> {
        Compio.udp_bind(addr).await
    }

    async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<Self::Stream> {
        Compio.tcp_connect(addr).await
    }
}

/// Whether the response of an exchange says the query was resumed.
async fn resumed_with(client: &Client<Stepped>, resolver: &Resolver, options: &Options) -> bool {
    let response = client
        .exchange_dnscrypt(query(), &resolver.stamp, options)
        .await
        .expect("a response");
    response.dnscrypt.expect("DNSCrypt information").resumed
}

/// D101: a ticket expires when its lifetime has run on the clock of the exchanges, from the response that brought it
/// (S3 of the review of step 14), on a clock the test sets: a millisecond before it is resumed, at its end it is a full
/// query, and the response says which it was.
#[compio::test]
async fn a_ticket_is_used_until_its_lifetime_has_run_on_the_exchanges_clock() {
    let resolver = Resolver::start_pq().await;
    let mut options = quick();
    options.dnscrypt.resume = true;
    let clock = Stepped::new();
    let client = Client::with_io(clock.clone());
    assert!(!resumed_with(&client, &resolver, &options).await);
    assert!(resumed_with(&client, &resolver, &options).await);
    clock.set(Duration::from_millis(299_999));
    assert!(
        resumed_with(&client, &resolver, &options).await,
        "a millisecond left"
    );
    clock.set(Duration::from_secs(300));
    assert!(
        !resumed_with(&client, &resolver, &options).await,
        "expired at the instant its lifetime ends"
    );
    assert!(
        resumed_with(&client, &resolver, &options).await,
        "the new ticket"
    );
    let kinds: Vec<_> = resolver
        .script()
        .seen
        .iter()
        .map(|seen| seen.resumed)
        .collect();
    assert_eq!(kinds, [false, true, true, false, true]);
}

/// D101, "Stateless Resumption": the ticket is bound to the certificate by its client magic and the end of its
/// validity, not by its serial (S2 of the review): the certificates are asked for again after an hour, and one of
/// another magic ends the ticket, one of another serial and the same magic and validity keeps it.
#[compio::test]
async fn a_ticket_follows_the_client_magic_and_validity_of_its_certificate() {
    for (magic, resumed) in [(1, true), (9, false)] {
        let resolver = Resolver::start_pq().await;
        resolver.script().ticket_life = 7200;
        let mut options = quick();
        options.dnscrypt.resume = true;
        let clock = Stepped::new();
        let client = Client::with_io(clock.clone());
        assert!(!resumed_with(&client, &resolver, &options).await);
        {
            // The provider issues serial 2 for another key, with the magic and validity of serial 1 or not.
            let mut script = resolver.script();
            let first = script
                .served
                .iter()
                .find(|certificate| certificate.body().serial == 1)
                .expect("the PQ certificate")
                .body()
                .clone();
            let secret = XWingSecretKey::from_seed([4; 32]);
            let certificate = Certificate::sign(
                &script.signer,
                CertificateBody {
                    resolver_key: ResolverPublicKey::XWing(secret.public_key()),
                    client_magic: ClientMagic::try_from([magic; 8]).expect("a magic"),
                    serial: 2,
                    validity: first.validity,
                    extensions: Vec::new(),
                },
            );
            script
                .keys
                .push(ResolverKey::new(&certificate, secret).expect("a key"));
            script.served.push(certificate);
        }
        clock.set(Duration::from_secs(3700));
        assert_eq!(
            resumed_with(&client, &resolver, &options).await,
            resumed,
            "magic {magic}"
        );
        let script = resolver.script();
        assert_eq!(script.fetched.0, 2, "the certificates were asked for again");
    }
}
