//! RFC 7871: EDNS Client Subnet (§6).

mod common;

use std::net::IpAddr;

use common::{decode_options, option_wire};
use dedens_proto::Violation;
use dedens_proto::edns::{ClientSubnet, EdnsOption, OptionCode};

fn options(data: &[u8]) -> (Vec<EdnsOption<'static>>, Vec<Violation>) {
    let decoded = decode_options(&option_wire(8, data));
    (
        decoded.message.edns.expect("OPT record").options,
        decoded.violations,
    )
}

#[test]
fn s6_the_example_of_a_24_bit_prefix() {
    let (options, violations) = options(&[0, 1, 24, 0, 192, 0, 2]);
    assert_eq!(violations, []);
    let [EdnsOption::ClientSubnet(subnet)] = options.as_slice() else {
        panic!("one option")
    };
    assert_eq!(subnet.address(), "192.0.2.0".parse::<IpAddr>().unwrap());
    assert_eq!((subnet.source_prefix(), subnet.scope_prefix()), (24, 0));
}

#[test]
fn s6_ipv6_uses_family_2() {
    let (options, violations) = options(&[0, 2, 32, 16, 0x20, 0x01, 0x0d, 0xb8]);
    assert_eq!(violations, []);
    let [EdnsOption::ClientSubnet(subnet)] = options.as_slice() else {
        panic!("one option")
    };
    assert_eq!(subnet.address(), "2001:db8::".parse::<IpAddr>().unwrap());
    assert_eq!(subnet.scope_prefix(), 16);
}

#[test]
fn s6_only_the_source_prefix_octets_are_sent() {
    let subnet = ClientSubnet::new("10.1.2.3".parse().unwrap(), 32, 0).unwrap();
    let message = dedens_proto::Message {
        edns: Some(dedens_proto::Edns {
            options: vec![EdnsOption::ClientSubnet(subnet)],
            ..Default::default()
        }),
        ..Default::default()
    };
    let wire = message.to_vec().unwrap();
    assert_eq!(wire[wire.len() - 8..], [0, 1, 32, 0, 10, 1, 2, 3]);
}

#[test]
fn s6_bits_past_the_source_prefix_must_be_zero() {
    let address: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(ClientSubnet::new(address, 24, 0).is_err());
    let (_, violations) = options(&[0, 1, 24, 0, 192, 0, 2]);
    assert_eq!(violations, []);
    let (options, violations) = options(&[0, 1, 20, 0, 192, 0, 0x2F]);
    assert_eq!(violations.len(), 1, "bits set past /20");
    assert!(matches!(options.as_slice(), [EdnsOption::Unknown { .. }]));
}

#[test]
fn s6_prefixes_are_limited_by_the_family() {
    let v4: IpAddr = "0.0.0.0".parse().unwrap();
    assert!(ClientSubnet::new(v4, 33, 0).is_err());
    assert!(ClientSubnet::new(v4, 0, 33).is_err());
    assert!(ClientSubnet::new("::".parse().unwrap(), 128, 128).is_ok());
}

#[test]
fn s6_unknown_families_and_wrong_lengths_are_invalid() {
    for data in [
        &[0u8, 3, 8, 0, 1][..],
        &[0, 1, 24, 0, 192, 0],
        &[0, 1, 24, 0, 192, 0, 2, 0],
        &[0, 1],
    ] {
        let (options, violations) = options(data);
        assert!(
            matches!(
                violations.as_slice(),
                [Violation::InvalidOption {
                    code: OptionCode::CLIENT_SUBNET,
                    ..
                }]
            ),
            "{data:?}"
        );
        assert!(matches!(options.as_slice(), [EdnsOption::Unknown { .. }]));
    }
}
