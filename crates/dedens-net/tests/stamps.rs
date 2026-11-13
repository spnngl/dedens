//! DNS stamps (draft-denis-dns-stamps-02, "DNS Stamps Format Overview", "`DNSCrypt` Stamps", "Anonymized `DNSCrypt` Relay
//! Stamps", Appendix A and B; D102): every `DNSCrypt` and relay stamp of the lists `DNSCrypt/dnscrypt-resolvers`
//! publishes read and written back byte for byte, the draft's examples of the other kinds refused by name, and the
//! fields cut short or too long refused. The lists are in `testdata/stamps/`, with their source and date.

use dedens_net::stamp::{
    DEFAULT_PORT, DnsCrypt, Endpoint, Properties, ProviderName, Relay, Stamp, StampError,
};
use dedens_proto::{decode_base64url, encode_base64url};

/// `v3/public-resolvers.md`, as published: `DNSCrypt` and DNS-over-HTTPS servers.
const RESOLVERS: &str = include_str!("testdata/stamps/public-resolvers.md");
/// `v3/relays.md`: the Anonymized `DNSCrypt` relays.
const RELAYS: &str = include_str!("testdata/stamps/relays.md");

/// The stamps of a list: the lines that start with `sdns://`.
fn stamps(list: &str) -> Vec<&str> {
    list.lines()
        .filter(|line| line.starts_with("sdns://"))
        .collect()
}

/// The bytes behind the `sdns://` of a stamp.
fn payload(stamp: &str) -> Vec<u8> {
    let text = stamp.strip_prefix("sdns://").expect("a stamp");
    decode_base64url(text.as_bytes()).expect("base64url")
}

/// A stamp of these bytes.
fn stamp_of(payload: &[u8]) -> String {
    format!("sdns://{}", encode_base64url(payload))
}

/// The first stamp of a list of the given kind, as the list has it.
fn first_of(list: &str, kind: u8) -> &str {
    stamps(list)
        .into_iter()
        .find(|stamp| payload(stamp).first() == Some(&kind))
        .expect("a stamp of the kind")
}

/// A `DNSCrypt` payload from its fields.
fn dnscrypt(props: u64, address: &[u8], key: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01];
    out.extend_from_slice(&props.to_le_bytes());
    for field in [address, key, name] {
        out.push(u8::try_from(field.len()).expect("a short field"));
        out.extend_from_slice(field);
    }
    out
}

/// The fields of the first `DNSCrypt` stamp of the resolvers list.
fn resolver() -> DnsCrypt {
    match first_of(RESOLVERS, 0x01).parse() {
        Ok(Stamp::DnsCrypt(resolver)) => Some(resolver),
        _ => None,
    }
    .expect("a DNSCrypt stamp")
}

const RESOLVERS_N: usize = 401;
const RELAYS_N: usize = 315;
const OTHERS_N: usize = 497;

#[test]
fn published_dnscrypt_and_relay_stamps_read_back_byte_for_byte() {
    let (mut resolvers, mut relays, mut others) = (0, 0, 0);
    for stamp in stamps(RESOLVERS).into_iter().chain(stamps(RELAYS)) {
        match payload(stamp).first() {
            Some(0x01) => {
                assert!(matches!(stamp.parse(), Ok(Stamp::DnsCrypt(_))), "{stamp}");
                resolvers += 1;
            }
            Some(0x81) => {
                assert!(matches!(stamp.parse(), Ok(Stamp::Relay(_))), "{stamp}");
                relays += 1;
            }
            _ => {
                assert!(
                    matches!(stamp.parse::<Stamp>(), Err(StampError::Unsupported { .. })),
                    "{stamp}"
                );
                others += 1;
                continue;
            }
        }
        let read: Stamp = stamp.parse().expect("a stamp");
        assert_eq!(read.to_string(), stamp);
        assert_eq!(read.to_string().parse(), Ok(read));
    }
    assert_eq!(
        (resolvers, relays, others),
        (RESOLVERS_N, RELAYS_N, OTHERS_N)
    );
}

#[test]
fn published_relays_are_all_relays_most_of_them_without_a_port() {
    let relays: Vec<Relay> = stamps(RELAYS)
        .iter()
        .map(|stamp| match stamp.parse() {
            Ok(Stamp::Relay(relay)) => Some(relay),
            _ => None,
        })
        .collect::<Option<_>>()
        .expect("a relay");
    let without = relays.iter().filter(|r| r.address.port.is_none()).count();
    assert_eq!((without, relays.len()), (237, 315));
}

#[test]
fn the_published_properties_and_ports_are_kept() {
    let all: Vec<Stamp> = stamps(RESOLVERS)
        .into_iter()
        .filter_map(|stamp| stamp.parse().ok())
        .collect();
    let dnscrypt = || {
        all.iter().filter_map(|stamp| match stamp {
            Stamp::DnsCrypt(resolver) => Some(resolver),
            Stamp::Relay(_) => None,
        })
    };
    assert!(
        dnscrypt().any(|r| r.properties.dnssec && r.properties.no_logs && r.properties.no_filter)
    );
    assert!(dnscrypt().any(|r| !r.properties.no_filter));
    assert!(dnscrypt().any(|r| !r.properties.no_logs));
    assert!(dnscrypt().any(|r| r.address.port.is_none()));
    assert!(dnscrypt().any(|r| r.address.port.is_some()));
    assert!(dnscrypt().any(|r| r.address.ip.is_ipv6()));
}

#[test]
fn draft_examples_of_other_kinds_are_refused_naming_the_kind() {
    // Appendix A.1 and B.1 (plain DNS), A.3 (`DoH`), B.3 (`DoT`); B.2 is in its own test.
    for (stamp, kind, name) in [
        ("sdns://AAEAAAAAAAAACjE5Mi4wLjIuNTM", 0x00, "plain DNS"),
        ("sdns://AAEAAAAAAAAADlsyMDAxOmRiODo6MV0", 0x00, "plain DNS"),
        (
            "sdns://AgIAAAAAAAAAAAAAD2Rucy5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5",
            0x02,
            "DNS-over-HTTPS",
        ),
        (
            "sdns://AwYAAAAAAAAACTE5Mi4wLjIuMQAPZG90LmV4YW1wbGUuY29tCwwxOTguNTEuMTAwLjELMjAzLjAuMTEzLjE",
            0x03,
            "DNS-over-TLS",
        ),
    ] {
        let error = stamp.parse::<Stamp>().expect_err(stamp);
        assert_eq!(error, StampError::Unsupported { kind, name });
        assert!(error.to_string().contains(name), "{error}");
    }
}

#[test]
fn the_draft_doh_example_with_hashes_is_not_canonical_base64url_and_is_refused() {
    // Appendix B.2 is `DoH`, so refused as a kind, but its text is no one payload'"'"'s canonical form: the unused bits of
    // its last character are not zero, so it is refused as base64url, before its kind is read (an erratum of the
    // draft). With the bits cleared, the draft'"'"'s own payload is refused by kind.
    let text = "sdns://AgAAAAAAAAAAACCRERERERERERERERERERERERERERERERERERERERERESAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiD2Rucy5leGFtcGxlLmNvbQovZG5zLXF1ZXJ5";
    assert_eq!(text.parse::<Stamp>(), Err(StampError::Base64));
    let body = &text[..text.len() - 1];
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    // Of the 64 last characters, the 4 that have the draft'"'"'s other bits and zero unused ones read as `DoH`.
    let read: Vec<StampError> = alphabet
        .chars()
        .filter_map(|c| format!("{body}{c}").parse::<Stamp>().err())
        .filter(|error| *error != StampError::Base64)
        .collect();
    let doh = StampError::Unsupported {
        kind: 0x02,
        name: "DNS-over-HTTPS",
    };
    assert_eq!(read, [doh.clone(), doh.clone(), doh.clone(), doh]);
}

#[test]
fn every_kind_the_draft_defines_but_these_two_is_refused_by_name() {
    for (kind, name) in [
        (0x00, "plain DNS"),
        (0x02, "DNS-over-HTTPS"),
        (0x03, "DNS-over-TLS"),
        (0x04, "DNS-over-QUIC"),
        (0x05, "Oblivious DoH target"),
        (0x85, "Oblivious DoH relay"),
    ] {
        assert_eq!(
            stamp_of(&[kind]).parse::<Stamp>(),
            Err(StampError::Unsupported { kind, name })
        );
    }
    for kind in [0x06, 0x7f, 0x80, 0x82, 0x86, 0xff] {
        assert_eq!(
            stamp_of(&[kind]).parse::<Stamp>(),
            Err(StampError::UnknownKind(kind))
        );
    }
}

#[test]
fn the_draft_dnscrypt_example_starts_as_written() {
    // Appendix A.2: `DNSCrypt` at 198.51.100.1:5553, the three properties, `2.dnscrypt-cert.example.com`. The draft
    // gives the key and the end of the stamp as "...", so the key here is a published one; what comes before it is
    // the draft's text.
    let resolver = DnsCrypt {
        properties: Properties {
            dnssec: true,
            no_logs: true,
            no_filter: true,
        },
        address: "198.51.100.1:5553".parse().map_or_else(
            |_| panic!("an address"),
            |address: std::net::SocketAddr| Endpoint {
                ip: address.ip(),
                port: std::num::NonZeroU16::new(address.port()),
            },
        ),
        provider_name: "2.dnscrypt-cert.example.com".parse().expect("a name"),
        ..resolver()
    };
    let stamp = Stamp::DnsCrypt(resolver).to_string();
    assert!(
        stamp.starts_with("sdns://AQcAAAAAAAAAETE5OC41MS4xMDAuMTo1NTUz"),
        "{stamp}"
    );
    assert_eq!(stamp.parse::<Stamp>().expect("read").to_string(), stamp);
}

#[test]
fn a_cut_stamp_is_refused_at_every_length() {
    for kind in [0x01, 0x81] {
        let whole = payload(first_of(
            if kind == 0x01 { RESOLVERS } else { RELAYS },
            kind,
        ));
        for cut in 0..whole.len() {
            let stamp = stamp_of(&whole[..cut]);
            let error = stamp.parse::<Stamp>().expect_err(&stamp);
            assert!(
                matches!(error, StampError::Empty | StampError::Truncated(_)),
                "cut at {cut}: {error:?}"
            );
        }
    }
    assert_eq!("sdns://".parse::<Stamp>(), Err(StampError::Empty));
}

#[test]
fn a_stamp_with_bytes_after_its_last_field_is_refused() {
    for kind in [0x01, 0x81] {
        let mut bytes = payload(first_of(
            if kind == 0x01 { RESOLVERS } else { RELAYS },
            kind,
        ));
        bytes.push(0);
        assert_eq!(
            stamp_of(&bytes).parse::<Stamp>(),
            Err(StampError::Trailing(1))
        );
        bytes.extend_from_slice(&[1, 2]);
        assert_eq!(
            stamp_of(&bytes).parse::<Stamp>(),
            Err(StampError::Trailing(3))
        );
    }
}

#[test]
fn a_length_past_the_end_of_the_payload_is_refused() {
    let mut bytes = payload(first_of(RESOLVERS, 0x01));
    // The address length, behind the kind and the properties.
    bytes[9] = u8::MAX;
    assert_eq!(
        stamp_of(&bytes).parse::<Stamp>(),
        Err(StampError::Truncated("address"))
    );
}

#[test]
fn a_provider_public_key_of_another_length_is_refused() {
    let resolver = resolver();
    let address = resolver.address.to_string();
    let name = resolver.provider_name.to_string();
    for len in [0, 1, 31, 33, 64, 255] {
        let key = vec![7; len];
        let bytes = dnscrypt(0, address.as_bytes(), &key, name.as_bytes());
        assert_eq!(
            stamp_of(&bytes).parse::<Stamp>(),
            Err(StampError::KeyLength(len))
        );
    }
}

#[test]
fn a_provider_name_a_stamp_cannot_carry_is_refused() {
    let resolver = resolver();
    let address = resolver.address.to_string();
    let label = "a".repeat(64);
    for name in [
        "",
        ".",
        "2.dnscrypt-cert.example.com.",
        "2.dnscrypt-cert..example.com",
        "2.dnscrypt-cert.example.com ",
        // A byte that is not a letter, written the way a name shows it, not as it was.
        "\\050.dnscrypt-cert.example.com",
        &label,
    ] {
        let bytes = dnscrypt(0, address.as_bytes(), &resolver.public_key, name.as_bytes());
        assert!(
            matches!(
                stamp_of(&bytes).parse::<Stamp>(),
                Err(StampError::ProviderName(_))
            ),
            "{name:?}"
        );
    }
    // Bytes that are not UTF-8.
    let bytes = dnscrypt(0, address.as_bytes(), &resolver.public_key, &[0xff, 0xfe]);
    assert!(matches!(
        stamp_of(&bytes).parse::<Stamp>(),
        Err(StampError::ProviderName(_))
    ));
}

#[test]
fn a_provider_name_of_more_than_255_characters_is_refused() {
    // Four labels of 60 bytes, each byte written as an escape: a name of 245 bytes in the wire form, 963 characters.
    let text = vec!["\\001".repeat(60); 4].join(".");
    assert_eq!(
        text.parse::<ProviderName>(),
        Err(StampError::ProviderName(text))
    );
}

#[test]
fn the_case_of_a_provider_name_is_kept() {
    let resolver = resolver();
    let address = resolver.address.to_string();
    let name = b"2.DNSCrypt-Cert.Example.COM";
    let stamp = stamp_of(&dnscrypt(0, address.as_bytes(), &resolver.public_key, name));
    assert_eq!(stamp.parse::<Stamp>().expect("read").to_string(), stamp);
}

#[test]
fn an_address_that_is_not_an_ip_address_with_a_port_or_not_is_refused() {
    let resolver = resolver();
    let name = resolver.provider_name.to_string();
    for address in [
        "",
        "192.0.2.1:",
        "192.0.2.1:0",
        "192.0.2.1:65536",
        "192.0.2.1:+80",
        "192.0.2.1:-80",
        "192.0.2.1:8 0",
        "192.0.2.1:80:80",
        " 192.0.2.1",
        "192.0.2.1 ",
        "192.0.2",
        "192.0.2.256",
        "192.0.2.1.5",
        "dns.example.com",
        "dns.example.com:443",
        "2001:db8::1",
        "2001:db8::1:443",
        "[2001:db8::1",
        "[2001:db8::1]x",
        "[2001:db8::1]:",
        "[2001:db8::1]:0",
        "[2001:db8::1]:65536",
        // Text that is not the one the address is written as.
        "192.0.2.1:080",
        "192.0.2.1:00080",
        "[2001:0db8::1]",
        "[2001:DB8::1]",
        "[2001:db8:0:0:0:0:0:1]",
        "[0:0:0:0:0:0:0:1]:53",
        "[192.0.2.1]",
        "[]",
        "[",
    ] {
        let bytes = dnscrypt(0, address.as_bytes(), &resolver.public_key, name.as_bytes());
        assert_eq!(
            stamp_of(&bytes).parse::<Stamp>(),
            Err(StampError::Address(address.to_owned())),
            "{address:?}"
        );
    }
    // The same of a relay.
    for address in ["", "192.0.2.1:0", "[::1", "::1", "relay.example:443"] {
        let mut bytes = vec![0x81, u8::try_from(address.len()).expect("short")];
        bytes.extend_from_slice(address.as_bytes());
        assert_eq!(
            stamp_of(&bytes).parse::<Stamp>(),
            Err(StampError::Address(address.to_owned()))
        );
    }
}

#[test]
fn an_address_reads_with_its_port_or_without_and_is_written_as_it_was() {
    let resolver = resolver();
    let name = resolver.provider_name.to_string();
    for (address, socket) in [
        ("192.0.2.1", "192.0.2.1:443"),
        ("192.0.2.1:5353", "192.0.2.1:5353"),
        ("192.0.2.1:443", "192.0.2.1:443"),
        ("192.0.2.1:65535", "192.0.2.1:65535"),
        ("[2001:db8::1]", "[2001:db8::1]:443"),
        ("[2001:db8::1]:5353", "[2001:db8::1]:5353"),
        ("[::1]:1", "[::1]:1"),
    ] {
        let stamp = stamp_of(&dnscrypt(
            0,
            address.as_bytes(),
            &resolver.public_key,
            name.as_bytes(),
        ));
        let Ok(Stamp::DnsCrypt(read)) = stamp.parse() else {
            panic!("{address}: not read");
        };
        assert_eq!(read.address.to_string(), address);
        assert_eq!(read.address.socket_addr().to_string(), socket);
        assert_eq!(Stamp::DnsCrypt(read).to_string(), stamp);
    }
    assert_eq!(DEFAULT_PORT, 443);
}

#[test]
fn a_relay_without_a_port_reads_as_dnscrypt_proxy_does() {
    let mut bytes = vec![0x81, 9];
    bytes.extend_from_slice(b"192.0.2.1");
    let stamp = stamp_of(&bytes);
    let Ok(Stamp::Relay(Relay { address })) = stamp.parse() else {
        panic!("not a relay");
    };
    assert_eq!(address.port, None);
    assert_eq!(address.socket_addr().to_string(), "192.0.2.1:443");
    assert_eq!(Stamp::Relay(Relay { address }).to_string(), stamp);
}

#[test]
fn reserved_properties_are_ignored_when_read_and_zero_when_written() {
    let resolver = resolver();
    let address = resolver.address.to_string();
    let name = resolver.provider_name.to_string();
    let stamp = stamp_of(&dnscrypt(
        !0b111,
        address.as_bytes(),
        &resolver.public_key,
        name.as_bytes(),
    ));
    let Ok(Stamp::DnsCrypt(read)) = stamp.parse() else {
        panic!("not read");
    };
    assert_eq!(read.properties, Properties::default());
    let written = payload(&Stamp::DnsCrypt(read).to_string());
    assert_eq!(written[1..9], [0; 8]);
    // Each of the three the draft defines is its own bit (Table 2).
    for (bits, expected) in [
        (1, (true, false, false)),
        (2, (false, true, false)),
        (4, (false, false, true)),
        (7, (true, true, true)),
    ] {
        let stamp = stamp_of(&dnscrypt(
            bits,
            address.as_bytes(),
            &resolver.public_key,
            name.as_bytes(),
        ));
        let Ok(Stamp::DnsCrypt(read)) = stamp.parse() else {
            panic!("not read");
        };
        let Properties {
            dnssec,
            no_logs,
            no_filter,
        } = read.properties;
        assert_eq!((dnssec, no_logs, no_filter), expected);
        assert_eq!(
            payload(&Stamp::DnsCrypt(read).to_string())[1],
            u8::try_from(bits).expect("a byte")
        );
    }
}

#[test]
fn text_that_is_not_one_canonical_base64url_stamp_is_refused() {
    let stamp = first_of(RELAYS, 0x81);
    let body = stamp.strip_prefix("sdns://").expect("a stamp");
    assert_eq!(
        body.parse::<Stamp>().expect_err("no scheme"),
        StampError::Scheme
    );
    assert_eq!(
        format!("SDNS://{body}").parse::<Stamp>(),
        Err(StampError::Scheme)
    );
    assert_eq!(
        format!("https://{body}").parse::<Stamp>(),
        Err(StampError::Scheme)
    );
    assert_eq!(
        format!("sdns://{body}=").parse::<Stamp>(),
        Err(StampError::Base64)
    );
    assert_eq!(
        format!("{stamp}\n").parse::<Stamp>(),
        Err(StampError::Base64)
    );
    assert_eq!(
        format!("sdns://{}", body.replace('g', "+")).parse::<Stamp>(),
        Err(StampError::Base64)
    );
    // The unused bits of the last character are zero in the one text a payload has: a stamp whose payload is not a
    // multiple of three bytes, with one of them set, is the same bytes in another text.
    let odd = stamps(RELAYS)
        .into_iter()
        .find(|stamp| !payload(stamp).len().is_multiple_of(3))
        .expect("a stamp whose payload is not a multiple of three bytes");
    let mut text = odd.to_owned();
    let last = text.pop().expect("a character");
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let value = alphabet
        .iter()
        .position(|&c| char::from(c) == last)
        .expect("base64url");
    text.push(char::from(alphabet[value ^ 1]));
    assert_eq!(text.parse::<Stamp>(), Err(StampError::Base64));
}
