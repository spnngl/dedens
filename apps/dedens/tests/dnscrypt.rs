//! `@sdns://…` (D98): `DNSCrypt` against a resolver on the loopback address, built from `dedens-dnscrypt`'s resolver
//! half, and the usage errors. Real stamps and resolvers: `just providers`.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, EncryptionSystem, ResolverKey, SecretKey,
    SigningKey, Validity,
};
use dedens_net::entropy::Entropy;
use dedens_net::stamp::{DnsCrypt, Endpoint, Properties, Stamp};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Record, Ttl};
use dedens_testkit::relay::Relay;
use predicates::str::contains;

use crate::util::{dedens, run};

/// The provider name of the resolver.
const PROVIDER: &str = "2.dnscrypt-cert.test.example";

/// The serial of its certificate.
const SERIAL: u32 = 20_261_113;

/// A `DNSCrypt` resolver on one loopback port, UDP and TCP; its stamp.
struct Resolver {
    stamp: String,
}

/// The certificate and the key of the resolver, valid now.
fn keys(signer: &SigningKey) -> (Certificate, ResolverKey) {
    let secret = SecretKey::from_bytes([2; 32]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    let now = u32::try_from(now).expect("before 2106");
    let certificate = Certificate::sign(
        signer,
        CertificateBody {
            system: EncryptionSystem::XChaCha20Poly1305,
            resolver_key: secret.public_key(),
            client_magic: ClientMagic::try_from([7; 8]).expect("a magic"),
            serial: SERIAL,
            validity: Validity::new(now - 3600, now + 86_400).expect("a validity"),
            extensions: Vec::new(),
        },
    );
    let key = ResolverKey::new(&certificate, secret).expect("a key");
    (certificate, key)
}

/// What the resolver sends back to `packet`: the certificate to the request in the clear, an answer of 192.0.2.1
/// to a sealed query.
fn handle(
    certificate: &Certificate,
    key: &ResolverKey,
    packet: &[u8],
    carrier: Carrier,
) -> Option<Vec<u8>> {
    if let Ok(decoded) = Message::decode(packet)
        && !decoded.message.header.flags.contains(Flags::QR)
    {
        let mut answer = decoded.message.clone().into_owned();
        answer.header.flags = answer.header.flags.with(Flags::QR);
        // The padding of a relayed query is not echoed: a relay drops a response longer than the query.
        answer.edns = None;
        answer.answer.push(Record::new(
            decoded.message.questions[0].name.clone().into_owned(),
            Class::IN,
            Ttl::ZERO,
            &RData::Txt(certificate.to_txt().expect("a TXT")),
        ));
        return Some(answer.to_vec().expect("encodes"));
    }
    let (plaintext, context) = key.decrypt_query(packet).ok()?;
    let query = Message::decode(&plaintext).expect("a query").message;
    let mut answer = query.clone().into_owned();
    answer.header.flags = answer.header.flags.with(Flags::QR);
    answer.answer.push(Record::new(
        query.questions[0].name.clone().into_owned(),
        Class::IN,
        Ttl::from_wire(60),
        &RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    let mut entropy = Entropy::new().expect("randomness");
    Some(
        context
            .encrypt_response(&answer.to_vec().expect("encodes"), carrier, &mut entropy)
            .expect("a response"),
    )
}

impl Resolver {
    fn start() -> Self {
        let signer = SigningKey::from_seed(&[1; 32]).expect("a seed");
        let (certificate, key) = keys(&signer);
        let key = Arc::new(key);
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
            let addr = udp.local_addr().expect("an address");
            if let Ok(tcp) = TcpListener::bind(addr) {
                break (udp, tcp);
            }
        };
        let addr = udp.local_addr().expect("an address");
        let (c, k) = (certificate.clone(), Arc::clone(&key));
        thread::spawn(move || {
            let mut buf = vec![0; 65535];
            while let Ok((len, from)) = udp.recv_from(&mut buf) {
                if let Some(reply) = handle(&c, &k, &buf[..len], Carrier::Udp) {
                    let _ = udp.send_to(&reply, from);
                }
            }
        });
        thread::spawn(move || {
            for stream in tcp.incoming() {
                let (c, k) = (certificate.clone(), Arc::clone(&key));
                thread::spawn(move || serve(stream.expect("a connection"), &c, &k));
            }
        });
        let stamp = Stamp::DnsCrypt(DnsCrypt {
            properties: Properties::default(),
            address: Endpoint {
                ip: addr.ip(),
                port: NonZeroU16::new(addr.port()),
            },
            public_key: *signer.provider_key().as_bytes(),
            provider_name: PROVIDER.parse().expect("a provider name"),
        });
        Self {
            stamp: format!("@{stamp}"),
        }
    }
}

/// Answers the framed packets of one TCP connection.
fn serve(mut stream: impl Read + Write, certificate: &Certificate, key: &ResolverKey) {
    loop {
        let mut length = [0; 2];
        if stream.read_exact(&mut length).is_err() {
            return;
        }
        let mut packet = vec![0; usize::from(u16::from_be_bytes(length))];
        if stream.read_exact(&mut packet).is_err() {
            return;
        }
        if let Some(reply) = handle(certificate, key, &packet, Carrier::Tcp) {
            let framed = [
                &u16::try_from(reply.len()).expect("short").to_be_bytes()[..],
                &reply,
            ]
            .concat();
            if stream.write_all(&framed).is_err() {
                return;
            }
        }
    }
}

/// D98: a stamp names the resolver and its port; the query is sealed, over UDP and over TCP with `+tcp`, and the
/// status line names the certificate.
#[test]
fn a_stamp_is_asked_over_udp_and_tcp() {
    let resolver = Resolver::start();
    let line = format!("DNSCrypt X25519-XChaCha20Poly1305 serial {SERIAL}");
    for (args, transport) in [(&[][..], "UDP"), (&["+tcp"], "TCP")] {
        let out = run(&[&[&resolver.stamp, "example.com"], args].concat(), 0);
        assert!(out.contains(&format!("over {transport} ({line})")), "{out}");
        assert!(out.contains("192.0.2.1"), "{out}");
    }
    let out = run(&[&resolver.stamp, "example.com", "--json"], 0);
    assert!(out.contains("\"dnscrypt\":{\"certificate\":{\"system\":\"X25519-XChaCha20Poly1305\""));
    assert_eq!(
        run(&[&resolver.stamp, "example.com", "+short"], 0).trim(),
        "192.0.2.1"
    );
}

/// D98: `+dnscrypt-cert` lists the certificates, not an answer.
#[test]
fn the_certificates_are_listed_on_request() {
    let resolver = Resolver::start();
    let out = run(&[&resolver.stamp, "example.com", "+dnscrypt-cert"], 0);
    assert!(
        out.contains(&format!(
            "X25519-XChaCha20Poly1305 serial {SERIAL} valid 20"
        )),
        "{out}"
    );
    assert!(!out.contains("192.0.2.1"), "{out}");
    let out = run(
        &[&resolver.stamp, "+dnscrypt-cert", "+short", "example.com"],
        0,
    );
    assert!(out.starts_with("X25519-XChaCha20Poly1305 serial"), "{out}");
    let out = run(
        &[&resolver.stamp, "+dnscrypt-cert", "--json", "example.com"],
        0,
    );
    assert!(out.contains("\"certificates\":[{\"system\""), "{out}");
}

/// D100: `+dnscrypt-relay` sends the certificates' query and the sealed ones through the relay, given as an address
/// or as a relay stamp, over UDP and over TCP with `+tcp`; the response is the resolver's, all the same.
#[test]
fn a_relay_carries_the_certificates_and_the_queries() {
    let resolver = Resolver::start();
    let relay = Relay::start();
    let address = format!("+dnscrypt-relay={}", relay.addr);
    let out = run(&[&resolver.stamp, "example.com", &address], 0);
    assert!(
        out.contains("over UDP") && out.contains("192.0.2.1"),
        "{out}"
    );
    assert_eq!(relay.seen(), (2, 0), "the certificates, then the query");
    let stamp = Stamp::Relay(dedens_net::stamp::Relay {
        address: Endpoint {
            ip: relay.addr.ip(),
            port: NonZeroU16::new(relay.addr.port()),
        },
    });
    let stamp = format!("+dnscrypt-relay={stamp}");
    let out = run(&[&resolver.stamp, "example.com", "+tcp", &stamp], 0);
    assert!(
        out.contains("over TCP") && out.contains("192.0.2.1"),
        "{out}"
    );
    assert_eq!(
        relay.seen(),
        (3, 1),
        "the certificates over UDP, the query over TCP"
    );
    let out = run(
        &[&resolver.stamp, "+dnscrypt-cert", "example.com", &address],
        0,
    );
    assert!(out.contains(&format!("serial {SERIAL}")), "{out}");
    assert_eq!(relay.seen(), (4, 1), "the certificates only");
}

/// D100: a relay that does not answer is no reply, and nothing goes direct to the resolver.
#[test]
fn a_silent_relay_exits_9() {
    let resolver = Resolver::start();
    let silent = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
    let relay = format!(
        "+dnscrypt-relay={}",
        silent.local_addr().expect("an address")
    );
    dedens()
        .args([
            &resolver.stamp,
            "example.com",
            &relay,
            "+tries=1",
            "+time=100ms",
        ])
        .assert()
        .code(9);
}

/// D98: a stamp goes with no other transport, `+dnscrypt-cert` needs a stamp, a relay stamp names no resolver.
#[test]
fn dnscrypt_usage_errors_exit_2() {
    // Quad9's resolver and a relay of dnscrypt-resolvers' v3/relays.md: stamps that parse.
    let resolver = SocketAddr::from(([9, 9, 9, 9], 8443));
    let stamp = format!(
        "@{}",
        Stamp::DnsCrypt(DnsCrypt {
            properties: Properties::default(),
            address: Endpoint {
                ip: resolver.ip(),
                port: NonZeroU16::new(resolver.port()),
            },
            public_key: [1; 32],
            provider_name: "2.dnscrypt-cert.quad9.net".parse().expect("a name"),
        })
    );
    let relay = "@sdns://gQ8xNDYuNzAuODIuMzo0NDM";
    for args in [
        &[&stamp, "+tls", "example.com"][..],
        &[&stamp, "+quic", "example.com"],
        &[&stamp, "+https", "example.com"],
        &[&stamp, "+coap", "example.com"],
        &[&stamp, "+trace", "example.com"],
        &[&stamp, "+odoh-proxy=https://127.0.0.1:1", "example.com"],
        &["+dnscrypt-cert", "example.com"],
        &["+dnscrypt-cert", "@127.0.0.1", "example.com"],
        &["+dnscrypt-cert", &stamp, "+tls", "example.com"],
        &[relay, "example.com"],
        // D100: the relay goes with a stamp, no other transport, and is an address or a relay stamp.
        &[&stamp, "+dnscrypt-relay=192.0.2.1", "+tls", "example.com"],
        &[&stamp, "+dnscrypt-relay=192.0.2.1", "+trace", "example.com"],
        &["+dnscrypt-relay=192.0.2.1", "example.com"],
        &["+dnscrypt-relay=192.0.2.1", "@127.0.0.1", "example.com"],
        &[&stamp, "+dnscrypt-relay=relay.example", "example.com"],
        &[&stamp, "+dnscrypt-relay=192.0.2.1:0", "example.com"],
        &[
            &stamp,
            &format!("+dnscrypt-relay={}", &stamp[1..]),
            "example.com",
        ],
        &["@sdns://AQ", "example.com"],
        &["@sdns://", "example.com"],
    ] {
        dedens().args(args).assert().code(2);
    }
    dedens()
        .args([relay, "example.com"])
        .assert()
        .code(2)
        .stderr(contains("relay"));
}

/// D98: a resolver that does not answer, not even with its certificates, is no reply: exit 9, as for any server.
#[test]
fn a_silent_resolver_exits_9() {
    let silent = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
    let addr = silent.local_addr().expect("an address");
    let stamp = Stamp::DnsCrypt(DnsCrypt {
        properties: Properties::default(),
        address: Endpoint {
            ip: addr.ip(),
            port: NonZeroU16::new(addr.port()),
        },
        public_key: [1; 32],
        provider_name: PROVIDER.parse().expect("a provider name"),
    });
    dedens()
        .args([
            &format!("@{stamp}"),
            "example.com",
            "+tries=1",
            "+time=100ms",
        ])
        .assert()
        .code(9);
}
