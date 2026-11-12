//! EDNS(0) and its options.
//!
//! - RFC 6891: EDNS(0) (§6).
//! - RFC 3225 §3: the DO bit is the top bit of the OPT record's flags.

use dedens_proto::edns::{EdnsFlags, EdnsOption, OptionCode, UnknownOption};
use dedens_proto::{
    EncodeError, Message, Name, Opcode, Query, Question, Rcode, RecordType, Violation,
};
use dedens_testkit::captured;
use proptest::prelude::*;

use crate::util::{decode_options, opt_message, option_wire};

fn question() -> Question<'static> {
    Question::new(Name::root(), RecordType::A)
}

#[test]
fn s6_1_2_a_query_ends_with_the_opt_record() {
    let wire = Message::query(7, question()).to_vec().unwrap();
    assert_eq!(
        wire[wire.len() - 11..],
        [0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(wire[10..12], [0, 1], "ARCOUNT counts the OPT record");
}

#[test]
fn s6_1_2_fields_of_the_opt_record() {
    let mut wire = opt_message(&[]);
    wire[17..21].copy_from_slice(&[0x05, 0x01, 0xFF, 0xFF]);
    let decoded = Message::decode(&wire).unwrap();
    let edns = decoded.message.edns.unwrap();
    assert_eq!(edns.udp_payload, 1232);
    assert_eq!((edns.ext_rcode, edns.version), (5, 1));
    assert_eq!(edns.flags, EdnsFlags::from_bits(0xFFFF));
    assert!(edns.flags.contains(EdnsFlags::DO));
    assert!(
        decoded.message.additional.is_empty(),
        "the OPT record is lifted out of the section"
    );
    assert_eq!(decoded.violations, []);
}

#[test]
fn s6_1_3_the_do_bit_is_the_top_flag_bit() {
    let mut message = Message::query(1, question());
    message.edns.as_mut().unwrap().flags = EdnsFlags::DO;
    let wire = message.to_vec().unwrap();
    assert_eq!(wire[wire.len() - 6..wire.len() - 2], [0, 0, 0x80, 0]);
}

#[test]
fn s6_1_3_the_extended_rcode_is_split_between_header_and_opt() {
    let mut message = Message::query(1, question());
    message.set_rcode(Rcode(16)).unwrap(); // BADVERS
    assert_eq!(message.header.rcode, Rcode(0));
    assert_eq!(message.edns.as_ref().unwrap().ext_rcode, 1);
    let wire = message.to_vec().unwrap();
    assert_eq!(Message::decode(&wire).unwrap().message.rcode(), Rcode(16));
}

#[test]
fn s6_1_3_a_large_rcode_needs_edns() {
    let mut message = Message {
        edns: None,
        ..Message::default()
    };
    assert_eq!(
        message.set_rcode(Rcode(16)),
        Err(EncodeError::RcodeNeedsEdns)
    );
    assert_eq!(
        message.set_rcode(Rcode(4096)),
        Err(EncodeError::RcodeOutOfRange)
    );
    assert_eq!(message, Message::default(), "unchanged after an error");
    message.set_rcode(Rcode::NXDOMAIN).unwrap();
    assert_eq!(message.rcode(), Rcode::NXDOMAIN);
}

#[test]
fn s6_1_1_one_opt_record_at_most() {
    let mut wire = opt_message(&[]);
    wire[11] = 2;
    wire.extend_from_slice(&[0, 0, 41, 0x02, 0, 0, 0, 0, 0, 0, 0]);
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::MultipleOpt]);
    assert_eq!(
        decoded.message.edns.unwrap().udp_payload,
        1232,
        "the first one is used"
    );
    assert_eq!(
        decoded.message.additional.len(),
        1,
        "the second one is kept opaque"
    );
}

#[test]
fn s6_1_3_a_rejected_opt_record_keeps_its_ttl_field() {
    // Extended rcode 0x80 sets the top bit of the TTL field, which RFC 2181 §8 would make a TTL of 0.
    let mut wire = opt_message(&[]);
    wire[11] = 2;
    wire.extend_from_slice(&[0, 0, 41, 0x02, 0, 0x80, 0, 0x80, 0, 0, 0]);
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.message.additional[0].ttl.get(), 0x8000_8000);
}

#[test]
fn s6_1_3_the_header_rcode_holds_four_bits() {
    let mut message = Message::default();
    message.header.rcode = Rcode(16);
    assert_eq!(message.to_vec(), Err(EncodeError::RcodeOutOfRange));
    message.header.rcode = Rcode(0);
    message.header.opcode = Opcode(16);
    assert_eq!(message.to_vec(), Err(EncodeError::OpcodeOutOfRange));
}

#[test]
fn s6_1_1_opt_belongs_to_the_additional_section() {
    let mut wire = opt_message(&[]);
    wire[7] = 1; // ANCOUNT instead of ARCOUNT
    wire[11] = 0;
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::OptOutsideAdditional]);
    assert_eq!(decoded.message.edns, None);
    assert_eq!(decoded.message.answer.len(), 1);
}

#[test]
fn s6_1_2_the_owner_of_opt_is_the_root() {
    let mut wire = vec![0x12, 0x34, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    wire.extend_from_slice(&[1, b'a', 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::OptOwnerNotRoot]);
    assert_eq!(decoded.message.edns, None);
}

#[test]
fn s6_1_2_options_keep_their_order() {
    let mut options = option_wire(0xFF01, b"one");
    options.extend(option_wire(0xFF00, b""));
    let decoded = decode_options(&options);
    let codes: Vec<_> = decoded
        .message
        .edns
        .unwrap()
        .options
        .iter()
        .map(EdnsOption::code)
        .collect();
    assert_eq!(codes, [OptionCode(0xFF01), OptionCode(0xFF00)]);
}

#[test]
fn s6_1_2_an_unknown_option_is_kept() {
    let decoded = decode_options(&option_wire(0xFF01, b"data"));
    assert_eq!(decoded.violations, []);
    assert_eq!(
        decoded.message.edns.unwrap().options,
        [EdnsOption::Unknown(
            UnknownOption::new(OptionCode(0xFF01), b"data").expect("untyped code")
        )]
    );
}

#[test]
fn s6_1_2_an_unknown_option_has_no_typed_form() {
    // A valid client cookie must be the typed option, so the same option is never two different values.
    assert!(UnknownOption::new(OptionCode::COOKIE, &[1; 8]).is_err());
    // Invalid data for a typed code is kept as bytes, as when read (D9).
    let short = UnknownOption::new(OptionCode::COOKIE, &[1; 7]).expect("invalid cookie");
    assert_eq!(
        (short.code(), short.data()),
        (OptionCode::COOKIE, [1; 7].as_slice())
    );
    assert!(UnknownOption::new(OptionCode(0xFF01), &vec![0; 65536]).is_err());
}

/// The captured response `cookie`, its OPT record, last, cut to an RDATA of `rdlength` bytes: its COOKIE option
/// runs past it.
fn cookie_opt_cut_to(rdlength: u16) -> Vec<u8> {
    let mut wire = captured("cookie");
    let at = wire.len() - 30;
    assert_eq!(wire[at..at + 4], [0, 28, 0, 10], "RDLENGTH, then COOKIE");
    wire[at..at + 2].copy_from_slice(&rdlength.to_be_bytes());
    wire.truncate(at + 2 + usize::from(rdlength));
    wire
}

#[test]
fn s6_1_2_options_that_overrun_the_rdata_leave_it_unread() {
    // The cookie's data cut by a byte, and the option's header cut after its code.
    for rdlength in [27, 2] {
        let wire = cookie_opt_cut_to(rdlength);
        let decoded = Message::decode(&wire).expect("decodes");
        assert_eq!(decoded.violations, [Violation::OptOptionOverrun]);
        assert_eq!(decoded.message.edns, None);
        let opt = decoded.message.additional.last().expect("kept opaque");
        assert_eq!(opt.rtype(), RecordType::OPT);
        let query = Query::read(&wire).expect("reads");
        assert_eq!(query.violations(), [Violation::OptOptionOverrun]);
        assert!(query.edns().is_none());
    }
}

#[test]
fn s6_1_1_an_opt_record_after_an_overrun_one_is_another() {
    let mut wire = cookie_opt_cut_to(27);
    wire[11] += 1;
    let ours = Message::query(1, question()).to_vec().unwrap();
    wire.extend_from_slice(&ours[ours.len() - 11..]);
    let overrun_then_multiple = [Violation::OptOptionOverrun, Violation::MultipleOpt];
    let decoded = Message::decode(&wire).expect("decodes");
    assert_eq!(decoded.violations, overrun_then_multiple);
    assert_eq!(decoded.message.edns, None);
    let query = Query::read(&wire).expect("reads");
    assert_eq!(query.violations(), overrun_then_multiple);
    assert!(query.edns().is_none());
}

proptest! {
    #[test]
    fn round_trip(edns in crate::util::edns()) {
        let message = Message { edns: Some(edns), ..Message::default() };
        let wire = message.to_vec().unwrap();
        prop_assert_eq!(wire.len(), 12 + message.edns.as_ref().unwrap().wire_len());
        let decoded = Message::decode(&wire).unwrap();
        prop_assert_eq!(decoded.violations, []);
        prop_assert_eq!(decoded.message, message);
    }
}

mod padding {
    //! RFC 7830 (padding), RFC 7828 (TCP keepalive) and RFC 5001 (NSID) options.

    use dedens_proto::Message;
    use dedens_proto::edns::{Edns, EdnsOption, OptionCode, UnknownOption};

    use crate::util::{decode_options, option_wire};

    fn options(code: u16, data: &[u8]) -> Vec<EdnsOption<'static>> {
        decode_options(&option_wire(code, data))
            .message
            .edns
            .expect("OPT record")
            .options
    }

    fn encoded(option: EdnsOption<'_>) -> Vec<u8> {
        let message = Message {
            edns: Some(Edns {
                options: vec![option],
                ..Edns::default()
            }),
            ..Message::default()
        };
        message.to_vec().expect("fits")
    }

    #[test]
    fn rfc7830_s3_padding_is_its_length_in_zero_bytes() {
        assert_eq!(options(12, &[0; 5]), [EdnsOption::Padding(5)]);
        assert_eq!(options(12, &[]), [EdnsOption::Padding(0)]);
        let wire = encoded(EdnsOption::Padding(3));
        assert_eq!(wire[wire.len() - 7..], [0, 12, 0, 3, 0, 0, 0]);
    }

    #[test]
    fn rfc7830_s3_padding_content_is_ignored() {
        assert_eq!(options(12, &[1, 2]), [EdnsOption::Padding(2)]);
    }

    #[test]
    fn rfc7828_s3_the_timeout_is_absent_in_a_query() {
        assert_eq!(options(11, &[]), [EdnsOption::Keepalive(None)]);
        assert_eq!(options(11, &[0, 100]), [EdnsOption::Keepalive(Some(100))]);
    }

    #[test]
    fn rfc7828_s3_other_lengths_are_invalid() {
        for data in [&[1u8][..], &[1, 2, 3]] {
            let decoded = decode_options(&option_wire(11, data));
            assert_eq!(decoded.violations.len(), 1);
            assert_eq!(
                decoded.message.edns.expect("OPT record").options,
                [EdnsOption::Unknown(
                    UnknownOption::new(OptionCode::KEEPALIVE, data).expect("invalid keepalive")
                )]
            );
        }
    }

    #[test]
    fn rfc5001_s2_nsid_is_empty_in_a_query_and_opaque_in_a_response() {
        assert_eq!(options(3, &[]), [EdnsOption::Nsid(b"".as_slice().into())]);
        assert_eq!(
            options(3, b"ns1.example"),
            [EdnsOption::Nsid(b"ns1.example".as_slice().into())]
        );
    }
}

mod subnet {
    //! RFC 7871: EDNS Client Subnet (§6).

    use std::net::IpAddr;

    use dedens_proto::Violation;
    use dedens_proto::edns::{ClientSubnet, EdnsOption, OptionCode};

    use crate::util::{decode_options, option_wire};

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
            edns: Some(dedens_proto::edns::Edns {
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
        assert!(matches!(options.as_slice(), [EdnsOption::Unknown(_)]));
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
            assert!(matches!(options.as_slice(), [EdnsOption::Unknown(_)]));
        }
    }
}

mod cookie {
    //! RFC 7873: DNS cookies (§4).

    use dedens_proto::Violation;
    use dedens_proto::edns::{Cookie, EdnsOption, OptionCode, UnknownOption};

    use crate::util::{decode_options, option_wire};

    const CLIENT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn options(data: &[u8]) -> (Vec<EdnsOption<'static>>, Vec<Violation>) {
        let decoded = decode_options(&option_wire(10, data));
        (
            decoded.message.edns.expect("OPT record").options,
            decoded.violations,
        )
    }

    #[test]
    fn s4_1_a_client_cookie_alone() {
        let (options, violations) = options(&CLIENT);
        assert_eq!(violations, []);
        assert_eq!(
            options,
            [EdnsOption::Cookie(Cookie::new(CLIENT, None).unwrap())]
        );
    }

    #[test]
    fn s4_2_a_server_cookie_is_8_to_32_bytes() {
        for len in [8, 16, 32] {
            let mut data = CLIENT.to_vec();
            data.extend(vec![9; len]);
            let (options, violations) = options(&data);
            assert_eq!(violations, [], "{len}");
            let [EdnsOption::Cookie(cookie)] = options.as_slice() else {
                panic!("one cookie")
            };
            assert_eq!(cookie.client(), CLIENT);
            assert_eq!(cookie.server().map(<[u8]>::len), Some(len));
        }
    }

    #[test]
    fn s4_other_lengths_are_kept_unknown() {
        for len in [0, 7, 9, 15, 41] {
            let data = vec![0; len];
            let (options, violations) = options(&data);
            assert!(
                matches!(
                    violations.as_slice(),
                    [Violation::InvalidOption {
                        code: OptionCode::COOKIE,
                        ..
                    }]
                ),
                "{len}"
            );
            assert_eq!(
                options,
                [EdnsOption::Unknown(
                    UnknownOption::new(OptionCode::COOKIE, &data).expect("invalid cookie")
                )]
            );
        }
    }

    /// §5.2: with several COOKIE options in a request only the first is considered, a later one is ignored even if its
    /// length is invalid (so no violation) or its data differs.
    #[test]
    fn s5_2_only_the_first_cookie_option_is_read() {
        let first = option_wire(10, &CLIENT);
        for later in [vec![0; 7], vec![9; 41], vec![5; 8], vec![6; 16]] {
            let mut wire = first.clone();
            wire.extend(option_wire(10, &later));
            wire.extend(option_wire(65001, &[1]));
            let decoded = decode_options(&wire);
            assert_eq!(decoded.violations, [], "{later:?}");
            let options = decoded.message.edns.expect("OPT record").options;
            assert_eq!(
                options,
                [
                    EdnsOption::Cookie(Cookie::new(CLIENT, None).unwrap()),
                    EdnsOption::Unknown(UnknownOption::new(OptionCode(65001), &[1]).unwrap())
                ],
                "{later:?}"
            );
        }
    }

    #[test]
    fn s4_a_server_cookie_of_bad_size_cannot_be_built() {
        assert!(Cookie::new(CLIENT, Some(&[0; 7])).is_err());
        assert!(Cookie::new(CLIENT, Some(&[0; 33])).is_err());
    }
}

mod extended_error {
    //! RFC 8914: Extended DNS Errors (§2).

    use dedens_proto::Violation;
    use dedens_proto::edns::{EdnsOption, ExtendedError, InfoCode, OptionCode, UnknownOption};

    use crate::util::{decode_options, option_wire};

    fn options(data: &[u8]) -> (Vec<EdnsOption<'static>>, Vec<Violation>) {
        let decoded = decode_options(&option_wire(15, data));
        (
            decoded.message.edns.expect("OPT record").options,
            decoded.violations,
        )
    }

    #[test]
    fn s2_info_code_and_text() {
        let (options, violations) = options(&[0, 15, b'n', b'o']);
        assert_eq!(violations, []);
        assert_eq!(
            options,
            [EdnsOption::Ede(ExtendedError {
                code: InfoCode::BLOCKED,
                text: "no".into()
            })]
        );
    }

    #[test]
    fn s2_the_text_may_be_empty() {
        let (options, violations) = options(&[0, 3]);
        assert_eq!(violations, []);
        assert_eq!(
            options,
            [EdnsOption::Ede(ExtendedError {
                code: InfoCode::STALE_ANSWER,
                text: "".into()
            })]
        );
    }

    #[test]
    fn s2_the_text_is_utf8() {
        let data = [0, 0, 0xFF, 0xFE];
        let (options, violations) = options(&data);
        assert!(matches!(
            violations.as_slice(),
            [Violation::InvalidOption {
                code: OptionCode::EDE,
                ..
            }]
        ));
        assert_eq!(
            options,
            [EdnsOption::Unknown(
                UnknownOption::new(OptionCode::EDE, &data).expect("invalid EDE")
            )]
        );
    }

    #[test]
    fn s2_without_an_info_code_it_is_invalid() {
        let (options, violations) = options(&[7]);
        assert_eq!(violations.len(), 1);
        assert!(matches!(options.as_slice(), [EdnsOption::Unknown(_)]));
    }

    #[test]
    fn s4_registered_codes_have_names() {
        assert_eq!(InfoCode::BLOCKED.to_string(), "Blocked");
        assert_eq!(InfoCode::DNSSEC_BOGUS.0, 6);
        assert_eq!(InfoCode(1000).to_string(), "EDE1000");
    }
}
