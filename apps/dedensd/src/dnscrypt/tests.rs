//! The key sets of the resolver (D99): rotation and expiry on the Unix times given, the certificate answer, the stamp
//! and the key file.

use dedens_dnscrypt::Certificate;
use dedens_net::io::Compio;
use dedens_proto::{Question, Rcode};

use super::*;

const SEED: [u8; 32] = [7; 32];
const PROVIDER: &str = "2.dnscrypt-cert.test.example";
/// A Unix time of 2026, so that certificates fit their 32 bits.
const T0: u64 = 1_800_000_000;

fn provider() -> ProviderName {
    PROVIDER.parse().expect("a provider name")
}

fn service(systems: Vec<EncryptionSystem>) -> Service {
    Service::new(&SEED, provider(), systems, T0, &Compio).expect("a service")
}

fn both() -> Vec<EncryptionSystem> {
    vec![
        EncryptionSystem::XChaCha20Poly1305,
        EncryptionSystem::XSalsa20Poly1305,
    ]
}

fn certificate_query(name: &str, qtype: RecordType) -> Vec<u8> {
    let question = Question::new(name.parse().expect("a name"), qtype);
    Message::query(7, question).to_vec().expect("encodes")
}

/// A key pair is made per system, every [`ROTATION`], and kept while its certificate is valid: the ones of the last
/// day are accepted, the older erased (draft, "Key Management").
#[test]
fn keys_rotate_every_twelve_hours_and_expire_after_a_day() {
    let service = service(vec![EncryptionSystem::XChaCha20Poly1305]);
    let first = service.keys(T0, &Compio);
    assert_eq!(first.len(), 1);
    assert_eq!(first.refresh_at, T0 + ROTATION);
    // Not due: the same set is handed out.
    assert!(Arc::ptr_eq(
        &first,
        &service.keys(T0 + ROTATION - 1, &Compio)
    ));
    let second = service.keys(T0 + ROTATION, &Compio);
    assert_eq!(second.len(), 2);
    // The certificate of the first is valid to its last second, included.
    let third = service.keys(T0 + VALIDITY, &Compio);
    assert_eq!(third.len(), 3);
    assert_eq!(third.refresh_at, T0 + VALIDITY + 1);
    let fourth = service.keys(T0 + VALIDITY + 1, &Compio);
    assert_eq!(fourth.len(), 2);
    // The next rotation, 12 hours after the third key pair, comes before the second's certificate expires.
    assert_eq!(fourth.refresh_at, T0 + VALIDITY + ROTATION);
}

/// The first certificate starts [`BACKDATE`] before the service was made, ends a day after, and its key is not
/// another system's.
#[test]
fn a_certificate_is_backdated_and_lasts_a_day() {
    let service = service(both());
    let set = service.keys(T0, &Compio);
    assert_eq!(set.len(), 2);
    for issued in &set.keys {
        let body = issued.certificate.body();
        assert_eq!(u64::from(body.validity.start()), T0 - BACKDATE);
        assert_eq!(u64::from(body.validity.end()), T0 + VALIDITY);
        assert!(issued.certificate.is_valid_at(T0));
        assert!(!issued.certificate.is_valid_at(T0 + VALIDITY + 1));
    }
    let [one, other] = set.keys.as_slice() else {
        panic!("two key pairs");
    };
    assert_ne!(one.system(), other.system());
    assert_ne!(
        one.certificate.body().resolver_key,
        other.certificate.body().resolver_key
    );
}

/// A query is found by its client magic, which is that of the key pair it was sealed for.
#[test]
fn a_packet_finds_its_key_by_magic() {
    let service = service(both());
    let set = service.keys(T0, &Compio);
    for issued in &set.keys {
        let mut packet = issued.resolver.client_magic().as_bytes().to_vec();
        packet.extend_from_slice(&[0; 40]);
        let found = set.find(&packet).expect("its key pair");
        assert!(Arc::ptr_eq(found, issued));
    }
    assert!(set.find(&[9; 48]).is_none());
    assert!(set.find(&[9; 7]).is_none());
}

/// The answer to the certificate query holds one certificate per system, signed by the provider key; the newest
/// when several are valid; echoes the ID, the question and EDNS.
#[test]
fn the_certificate_query_is_answered_with_the_newest_of_each_system() {
    let service = service(both());
    let _ = service.keys(T0, &Compio);
    let set = service.keys(T0 + ROTATION, &Compio);
    assert_eq!(set.len(), 4);
    let query = certificate_query(PROVIDER, RecordType::TXT);
    let wire = set
        .certificates(&query, service.provider())
        .expect("an answer");
    let answer = Message::decode(&wire).expect("a message").message;
    assert_eq!(answer.header.id, 7);
    assert!(answer.header.flags.contains(Flags::QR));
    assert!(answer.header.flags.contains(Flags::AA));
    assert_eq!(answer.rcode(), Rcode::NOERROR);
    assert!(answer.edns.is_some());
    let provider = SigningKey::from_seed(&SEED).expect("a seed").provider_key();
    let certificates: Vec<Certificate> = answer
        .answer
        .iter()
        .map(|record| match record.data() {
            RData::Txt(txt) => Certificate::from_txt(&txt, &provider).expect("signed"),
            other => panic!("not a TXT: {other:?}"),
        })
        .collect();
    assert_eq!(certificates.len(), 2);
    for certificate in &certificates {
        assert_eq!(
            certificate.body().serial,
            u32::try_from(T0 + ROTATION).expect("fits")
        );
    }
    assert_ne!(certificates[0].body().system, certificates[1].body().system);
}

/// Only the clear certificate query is answered: the provider's name, TXT, class IN, a query. The name's case does
/// not matter.
#[test]
fn only_the_certificate_query_is_answered() {
    let service = service(both());
    let set = service.keys(T0, &Compio);
    let ask = |query: &[u8]| set.certificates(query, service.provider());
    assert!(ask(&certificate_query(PROVIDER, RecordType::TXT)).is_some());
    assert!(
        ask(&certificate_query(
            "2.DNSCRYPT-cert.test.example",
            RecordType::TXT
        ))
        .is_some()
    );
    assert!(ask(&certificate_query(PROVIDER, RecordType::A)).is_none());
    assert!(
        ask(&certificate_query(
            "2.dnscrypt-cert.other.example",
            RecordType::TXT
        ))
        .is_none()
    );
    assert!(ask(&certificate_query("example.com", RecordType::TXT)).is_none());
    let mut response = Message::decode(&certificate_query(PROVIDER, RecordType::TXT))
        .expect("a message")
        .message
        .into_owned();
    response.header.flags = response.header.flags.with(Flags::QR);
    assert!(ask(&response.to_vec().expect("encodes")).is_none());
    let mut other_class = Message::decode(&certificate_query(PROVIDER, RecordType::TXT))
        .expect("a message")
        .message
        .into_owned();
    other_class.questions[0].qclass = Class::CH;
    assert!(ask(&other_class.to_vec().expect("encodes")).is_none());
    assert!(ask(&[0; 5]).is_none());
    assert!(ask(&[7; 64]).is_none());
}

/// A certificate answer fits the 512 bytes a UDP client without EDNS may take: two certificates.
#[test]
fn the_certificate_answer_is_small() {
    let service = service(both());
    let set = service.keys(T0, &Compio);
    let wire = set
        .certificates(
            &certificate_query(PROVIDER, RecordType::TXT),
            service.provider(),
        )
        .expect("an answer");
    assert!(wire.len() < 512, "{} bytes", wire.len());
}

/// The stamp names the provider key, and the port unless it is 443.
#[test]
fn the_stamp_names_the_provider_key_and_the_port() {
    let service = service(both());
    let key = *SigningKey::from_seed(&SEED)
        .expect("a seed")
        .provider_key()
        .as_bytes();
    for (addr, port) in [
        ("192.0.2.1:443", None),
        ("192.0.2.1:8443", NonZeroU16::new(8443)),
    ] {
        let text = service.stamp(addr.parse().expect("an address")).to_string();
        let Stamp::DnsCrypt(stamp) = text.parse().expect("a stamp") else {
            panic!("not a resolver stamp");
        };
        assert_eq!(stamp.public_key, key);
        assert_eq!(stamp.address.port, port);
        assert_eq!(stamp.provider_name, provider());
    }
}

/// `dnscrypt-keygen` prints a seed and the stamp of its provider key.
#[test]
fn keygen_prints_a_seed_and_its_stamp() {
    let text = keygen("2.dnscrypt-cert.example.net", "192.0.2.7:4433").expect("a key");
    let mut lines = text.lines();
    let hex = lines
        .next()
        .and_then(|line| line.strip_prefix("secret_key: "))
        .expect("the key line");
    assert_eq!(hex.len(), 64);
    assert!(hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let stamp = lines
        .next()
        .and_then(|line| line.strip_prefix("stamp: "))
        .expect("the stamp line");
    let Stamp::DnsCrypt(stamp) = stamp.parse().expect("a stamp") else {
        panic!("not a resolver stamp");
    };
    assert_eq!(
        stamp.address.socket_addr(),
        "192.0.2.7:4433".parse().expect("an address")
    );
    assert_eq!(
        stamp.provider_name.to_string(),
        "2.dnscrypt-cert.example.net"
    );
    assert!(lines.next().is_none());
    // The seed is the one the stamp's key comes from.
    let mut seed = [0u8; 32];
    for (byte, pair) in seed.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex");
    }
    assert_eq!(
        SigningKey::from_seed(&seed)
            .expect("a seed")
            .provider_key()
            .as_bytes(),
        &stamp.public_key
    );
}

#[test]
fn keygen_refuses_what_a_stamp_cannot_hold() {
    assert!(keygen("example.net", "192.0.2.7").is_err());
    assert!(keygen("2.dnscrypt-cert.example.net", "example.net").is_err());
}

/// A key file is read as `ODoH`'s is (D115): 64 hex digits, readable by its owner alone.
#[cfg(unix)]
#[test]
fn the_key_file_is_read_and_checked() {
    use std::os::unix::fs::PermissionsExt as _;

    let path = std::env::temp_dir().join(format!("dedensd-dnscrypt-key-{}", std::process::id()));
    let section = Section {
        provider: provider(),
        key: path.clone(),
        systems: both(),
    };
    assert!(section.service().is_err(), "no file");
    std::fs::write(&path, "00".repeat(32)).expect("written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");
    assert!(section.service().is_err(), "readable by others");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    let service = section.service().expect("a service");
    assert_eq!(service.keys(service.unix(0), &Compio).len(), 2);
    std::fs::write(&path, "zz").expect("written");
    assert!(section.service().is_err(), "not hexadecimal");
    std::fs::remove_file(&path).expect("removed");
}

#[test]
fn a_service_needs_a_system() {
    assert!(Service::new(&SEED, provider(), Vec::new(), T0, &Compio).is_err());
}

/// Seconds count from the service's making.
#[test]
fn time_counts_from_the_start() {
    let service = service(both());
    assert_eq!(service.unix(0), T0);
    assert_eq!(service.unix(90), T0 + 90);
}

/// The draft allows a key pair 24 hours at most ("Key Management"): twelve, and a certificate valid for the day, read
/// off in seconds.
#[test]
fn keys_rotate_every_twelve_hours_and_certificates_last_a_day() {
    let service = service(both());
    let first = service.keys(T0, &Compio);
    assert_eq!(first.refresh_at, T0 + 43_200);
    assert_eq!(service.keys(T0 + 43_199, &Compio).len(), 2);
    assert_eq!(service.keys(T0 + 43_200, &Compio).len(), 4);
    let last = service.keys(T0 + 86_400, &Compio);
    assert_eq!(
        last.last_end(),
        Some(u32::try_from(T0 + 86_400 + 86_400).expect("fits"))
    );
}
