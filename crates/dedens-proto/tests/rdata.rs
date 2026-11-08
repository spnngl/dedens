//! Record data by type, on the wire and in text.

mod srv {
    //! RFC 2782: SRV records.

    use dedens_proto::RecordType;
    use dedens_proto::rdata::RData;
    use proptest::prelude::*;

    use crate::util::{decode_record, encode_record, name_of, record, record_wire};

    fn srv_rdata(priority: u16, weight: u16, port: u16, target: &[u8]) -> Vec<u8> {
        [
            &priority.to_be_bytes()[..],
            &weight.to_be_bytes(),
            &port.to_be_bytes(),
            target,
        ]
        .concat()
    }

    #[test]
    fn srv_fields_are_priority_weight_port_target() {
        let wire = srv_rdata(1, 2, 5060, b"\x03sip\x07example\x03com\x00");
        let decoded = decode_record(&record_wire(RecordType::SRV, &wire)).unwrap();
        let RData::Srv(srv) = decoded.record.data() else {
            panic!("not SRV")
        };
        assert_eq!((srv.priority, srv.weight, srv.port), (1, 2, 5060));
        assert_eq!(srv.target, name_of(&[b"sip", b"example", b"com"]));
    }

    #[test]
    fn the_root_target_means_no_service() {
        let decoded =
            decode_record(&record_wire(RecordType::SRV, &srv_rdata(0, 0, 0, &[0]))).unwrap();
        let RData::Srv(srv) = decoded.record.data() else {
            panic!("not SRV")
        };
        assert!(srv.target.is_root());
    }

    #[test]
    fn invalid_rdata_is_an_error() {
        // The target may hold a pointer (RFC 3597 §4), so the bytes cannot be kept opaque (D9).
        assert!(decode_record(&record_wire(RecordType::SRV, &[0, 1, 0, 2, 0, 3])).is_err());
    }

    proptest! {
        #[test]
        fn round_trip(rec in record()) {
            let wire = encode_record(&rec);
            prop_assert_eq!(decode_record(&wire)?.record, rec);
        }
    }
}

mod aaaa {
    //! RFC 3596: AAAA records (§2), `ip6.arpa` reverse names (§2.5).

    use std::net::{IpAddr, Ipv6Addr};

    use dedens_proto::rdata::RData;
    use dedens_proto::{Class, DecodeErrorKind, Name, Record, RecordType, Ttl};
    use proptest::prelude::*;

    use crate::util::{decode_record, encode_record, record_wire};

    #[test]
    fn s2_2_aaaa_is_sixteen_octets() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let decoded = decode_record(&record_wire(RecordType::AAAA, &addr.octets())).unwrap();
        assert_eq!(decoded.record.data(), RData::Aaaa(addr));
        assert_eq!(decoded.invalid_rdata, None);
    }

    #[test]
    fn s2_2_other_lengths_are_kept_opaque() {
        for len in [0, 4, 15, 17] {
            let decoded = decode_record(&record_wire(RecordType::AAAA, &vec![1; len])).unwrap();
            assert_eq!(
                decoded.invalid_rdata.map(|e| e.kind),
                Some(DecodeErrorKind::RdataLength),
                "{len}"
            );
            assert!(matches!(decoded.record.data(), RData::Opaque(_)));
        }
    }

    /// The example of §2.5.
    #[test]
    fn s2_5_ip6_arpa_is_nibbles_low_order_first() {
        let addr: IpAddr = "4321:0:1:2:3:4:567:89ab".parse().unwrap();
        let expected: Name<'_> =
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA."
                .parse()
                .unwrap();
        assert_eq!(Name::reverse(addr), expected);
        assert_eq!(
            Name::reverse(addr).to_string(),
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa."
        );
    }

    #[test]
    fn s2_1_the_type_is_28() {
        assert_eq!(RData::Aaaa(Ipv6Addr::LOCALHOST).rtype(), RecordType(28));
    }

    proptest! {
        #[test]
        fn round_trip(octets in any::<[u8; 16]>()) {
            let rec = Record::new(Name::root(), Class::IN, Ttl::ZERO, &RData::Aaaa(Ipv6Addr::from(octets)));
            let wire = encode_record(&rec);
            prop_assert_eq!(decode_record(&wire)?.record, rec);
        }
    }
}

mod unknown {
    //! RFC 3597: unknown RR types are kept as opaque RDATA (§4), and written in a generic text form (§5).

    use dedens_proto::rdata::{Opaque, RData};
    use dedens_proto::{Class, DecodeError, DecodeErrorKind, DecodedRecord, RecordType};
    use proptest::prelude::*;

    use crate::util::{decode_answer, decode_record, encode_record, record, record_wire};

    #[test]
    fn s4_unknown_types_keep_their_bytes() {
        let decoded = decode_record(&record_wire(RecordType(65280), &[0xDE, 0xAD])).unwrap();
        assert_eq!(decoded.invalid_rdata, None);
        assert_eq!(
            decoded.record.data(),
            RData::Opaque(Opaque::new(RecordType(65280), &[0xDE, 0xAD]).unwrap())
        );
    }

    #[test]
    fn s4_empty_rdata_is_valid() {
        let decoded = decode_record(&record_wire(RecordType(65280), &[])).unwrap();
        assert_eq!(decoded.invalid_rdata, None);
    }

    /// Decodes a record whose RDATA is `rdata` after a question for `a.`: a pointer to offset 12 means `a.`.
    fn after_a(rtype: RecordType, rdata: &[u8]) -> Result<DecodedRecord<'static>, DecodeError> {
        let header = [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        let question = [1, b'a', 0, 0, 1, 0, 1];
        decode_answer(&[&header[..], &question, &record_wire(rtype, rdata)].concat())
    }

    #[test]
    fn s4_names_of_rfc_1035_types_are_decompressed() {
        // MINFO: two names; MB: one.
        let minfo = after_a(RecordType::MINFO, &[0xC0, 12, 1, b'b', 0xC0, 12]).unwrap();
        assert_eq!(minfo.invalid_rdata, None);
        let RData::Opaque(o) = &minfo.record.data() else {
            panic!("not opaque")
        };
        assert_eq!(o.data(), [1, b'a', 0, 1, b'b', 1, b'a', 0]);
        let mb = after_a(RecordType::MB, &[0xC0, 12]).unwrap();
        assert!(matches!(&mb.record.data(), RData::Opaque(o) if o.data() == [1, b'a', 0]));
    }

    #[test]
    fn s4_names_of_older_types_with_names_are_decompressed_too() {
        // NAPTR: order, preference, flags, services, regexp, replacement.
        let rdata = [&[0, 1, 0, 2, 1, b'u', 0, 0][..], &[0xC0, 12]].concat();
        let naptr = after_a(RecordType::NAPTR, &rdata).unwrap();
        assert!(
            matches!(&naptr.record.data(), RData::Opaque(o) if o.data() == [0, 1, 0, 2, 1, b'u', 0, 0, 1, b'a', 0])
        );
        // SRV prohibits compression (RFC 2782), but older servers compressed (RFC 2052).
        let srv = after_a(RecordType::SRV, &[0, 1, 0, 2, 0, 3, 0xC0, 12]).unwrap();
        assert!(matches!(&srv.record.data(), RData::Srv(s) if s.target.to_string() == "a."));
    }

    #[test]
    fn s4_invalid_rdata_with_names_is_an_error() {
        // Bytes holding a pointer mean nothing outside their message (D9).
        assert!(after_a(RecordType::RP, &[0xC0, 12]).is_err());
        assert!(after_a(RecordType::SRV, &[0, 1, 0xC0, 12]).is_err());
    }

    #[test]
    fn s4_opaque_rdata_never_holds_pointers() {
        assert!(Opaque::new(RecordType::RP, &[0xC0, 0, 0]).is_err());
        assert!(Opaque::new(RecordType::RP, &[0, 0]).is_ok());
        assert!(
            Opaque::new(RecordType::RP, &[0, 0, 7]).is_err(),
            "bytes after the fields"
        );
        assert!(
            Opaque::new(RecordType(65280), &[0xC0, 0]).is_ok(),
            "unknown types are not parsed"
        );
    }

    #[test]
    fn s4_rdlength_must_fit_in_the_message() {
        let mut wire = record_wire(RecordType(65280), &[1, 2, 3]);
        wire.pop();
        let err = decode_record(&wire).unwrap_err();
        assert_eq!(err.kind, DecodeErrorKind::RdataLength);
    }

    #[test]
    fn s4_known_types_with_a_bad_length_are_kept_opaque_unless_compressible() {
        let a = decode_record(&record_wire(RecordType::A, &[1, 2, 3])).unwrap();
        assert!(a.invalid_rdata.is_some() && matches!(a.record.data(), RData::Opaque(_)));
        // MX holds a compressible name: its RDATA cannot be kept as bytes (D9).
        assert!(decode_record(&record_wire(RecordType::MX, &[0, 1])).is_err());
    }

    #[test]
    fn s5_unknown_types_print_as_typenn() {
        assert_eq!(RecordType(65280).to_string(), "TYPE65280");
        assert_eq!(Class(3).to_string(), "CH");
        assert_eq!(Class(4000).to_string(), "CLASS4000");
    }

    proptest! {
        #[test]
        fn opaque_round_trip(rec in record()) {
            let wire = encode_record(&rec);
            prop_assert_eq!(decode_record(&wire)?.record, rec);
        }
    }

    #[test]
    fn s5_generic_text_form() {
        let rec: dedens_proto::Record<'_> =
            "a.example. 60 CLASS32 TYPE731 \\# 6 abcd (\n ef 01 23 45 )"
                .parse()
                .unwrap();
        assert_eq!((rec.class, rec.rtype()), (Class(32), RecordType(731)));
        assert_eq!(
            rec.data(),
            RData::Opaque(
                Opaque::new(RecordType(731), &[0xab, 0xcd, 0xef, 1, 0x23, 0x45]).unwrap()
            )
        );
        assert_eq!(
            rec.to_string(),
            "a.example.\t60\tCLASS32\tTYPE731\t\\# 6 abcdef012345"
        );

        let rec: dedens_proto::Record<'_> = r"b.example. 60 HS TYPE62347 \# 0".parse().unwrap();
        assert_eq!(
            (rec.class, rec.data().to_string()),
            (Class::HS, r"\# 0".to_owned())
        );

        // A known type written generically reads as its typed form, the same as its own text form.
        let generic: dedens_proto::Record<'_> =
            r"e.example. 60 IN A \# 4 0A000001".parse().unwrap();
        assert_eq!(generic.data(), RData::A([10, 0, 0, 1].into()));
        let typed: dedens_proto::Record<'_> =
            "e.example. 60 CLASS1 TYPE1 10.0.0.2".parse().unwrap();
        assert_eq!(
            (typed.class, typed.data()),
            (Class::IN, RData::A([10, 0, 0, 2].into()))
        );
        assert_eq!(
            generic.generic().to_string(),
            "e.example.\t60\tIN\tA\t\\# 4 0a000001"
        );
    }

    #[test]
    fn s5_generic_text_errors() {
        for bad in [
            r"x. 60 TYPE731 \# 3 abcd",
            r"x. 60 TYPE731 \# 2 abc",
            r"x. 60 TYPE731 \# 1 zz",
            r"x. 60 TYPE731 \#",
            "x. 60 TYPE731 abcd",
            // A pointer inside RDATA means nothing in text.
            r"x. 60 NS \# 2 c00c",
            r"x. 60 TYPE731 \# 65536 00",
        ] {
            assert!(
                bad.parse::<dedens_proto::Record<'_>>().is_err(),
                "accepted {bad}"
            );
        }
    }
}

mod dname {
    //! RFC 6672 §2.1: the RDATA of a DNAME is one domain name, never compressed.

    use dedens_proto::Name;

    #[test]
    fn a_name_is_read_from_its_rdata_in_place() {
        let wire = b"\x03dev\x07example\x03com\x00";
        let name = Name::from_uncompressed(wire).expect("a name");
        assert_eq!(name.to_string(), "dev.example.com.");
        assert_eq!(
            name,
            "DEV.example.COM.".parse::<Name<'_>>().expect("a name")
        );
        let root = Name::from_uncompressed(b"\x00").expect("the root");
        assert!(root.is_root());
    }

    #[test]
    fn bytes_that_are_not_one_name_are_refused() {
        for wire in [
            &b""[..],
            b"\x03dev",
            b"\x03dev\x00x",
            b"\x03dev\x00\x00",
            // A compression pointer: RFC 6672 §2.1 leaves no room for one.
            b"\x03dev\xc0\x00",
            b"\xc0\x00",
            // A label over 63 bytes.
            &[&[64][..], &[b'a'; 64], b"\x00"].concat(),
        ] {
            assert!(Name::from_uncompressed(wire).is_err(), "{wire:?}");
        }
    }
}

mod caa {
    //! RFC 8659: CAA records (§4), presentation format (§4.1.1).

    use dedens_proto::rdata::{Caa, RData};
    use dedens_proto::{DecodeErrorKind, RecordType};
    use proptest::prelude::*;

    use crate::util::{decode_record, encode_record, record, record_wire};

    #[test]
    fn s4_1_fields_are_flags_tag_and_value() {
        let wire = [&[0x80, 5][..], b"issue", b"ca.example"].concat();
        let decoded = decode_record(&record_wire(RecordType::CAA, &wire)).unwrap();
        let RData::Caa(caa) = decoded.record.data() else {
            panic!("not CAA")
        };
        assert!(caa.is_critical());
        assert_eq!(
            (caa.tag(), caa.value()),
            (&b"issue"[..], &b"ca.example"[..])
        );
    }

    #[test]
    fn s4_1_1_only_the_critical_bit_is_defined_and_the_rest_is_kept() {
        let wire = [&[0x01, 3][..], b"foo"].concat();
        let decoded = decode_record(&record_wire(RecordType::CAA, &wire)).unwrap();
        let RData::Caa(caa) = decoded.record.data() else {
            panic!("not CAA")
        };
        assert!(!caa.is_critical());
        assert_eq!(caa.flags(), 1);
    }

    #[test]
    fn s4_1_1_tags_are_one_to_fifteen_letters_or_digits() {
        assert!(Caa::new(0, b"issuewild", b"").is_ok());
        assert!(Caa::new(0, b"", b"").is_err());
        assert!(Caa::new(0, b"sixteen-chars-ab", b"").is_err());
        assert!(Caa::new(0, b"is sue", b"").is_err());
        let bad_tag = [&[0, 2][..], b"a-"].concat();
        let decoded = decode_record(&record_wire(RecordType::CAA, &bad_tag)).unwrap();
        assert!(decoded.invalid_rdata.is_some());
    }

    #[test]
    fn s4_1_1_a_tag_longer_than_the_rdata_is_kept_opaque() {
        let decoded = decode_record(&record_wire(RecordType::CAA, &[0, 9, b'a'])).unwrap();
        assert_eq!(
            decoded.invalid_rdata.map(|e| e.kind),
            Some(DecodeErrorKind::RdataLength)
        );
    }

    proptest! {
        #[test]
        fn round_trip(rec in record()) {
            let wire = encode_record(&rec);
            prop_assert_eq!(decode_record(&wire)?.record, rec);
        }
    }

    #[test]
    fn s4_1_1_presentation_format() {
        for (text, flags, tag, value) in [
            (
                r#"certs.example.com. 60 CAA 0 issue "ca1.example.net""#,
                0,
                "issue",
                "ca1.example.net",
            ),
            (
                r#"nocerts.example.com. 60 CAA 0 issue ";""#,
                0,
                "issue",
                ";",
            ),
            (
                r#"account.example.com. 60 CAA 0 issue "ca1.example.net; account=230123""#,
                0,
                "issue",
                "ca1.example.net; account=230123",
            ),
            (
                r#"new.example.com. 60 CAA 128 tbs "Unknown""#,
                128,
                "tbs",
                "Unknown",
            ),
            (
                r"x. 60 CAA 0 iodef mailto:security@example.com",
                0,
                "iodef",
                "mailto:security@example.com",
            ),
        ] {
            let rec: dedens_proto::Record<'_> = text.parse().unwrap();
            let RData::Caa(caa) = &rec.data() else {
                unreachable!("CAA text reads as CAA")
            };
            assert_eq!(
                (caa.flags(), caa.tag(), caa.value()),
                (flags, tag.as_bytes(), value.as_bytes())
            );
            assert_eq!(
                rec.to_string().parse::<dedens_proto::Record<'_>>().unwrap(),
                rec
            );
        }
        let rec: dedens_proto::Record<'_> =
            r#"x. 60 CAA 0 issue "ca1.example.net""#.parse().unwrap();
        assert_eq!(rec.data().to_string(), r#"0 issue "ca1.example.net""#);
        for bad in [
            r#"x. 60 CAA 0 is-sue "v""#,
            r#"x. 60 CAA 256 issue "v""#,
            "x. 60 CAA 0 issue",
        ] {
            assert!(
                bad.parse::<dedens_proto::Record<'_>>().is_err(),
                "accepted {bad}"
            );
        }
    }
}
