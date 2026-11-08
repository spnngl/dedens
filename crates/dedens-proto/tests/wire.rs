//! The wire format: header, question, names and their compression, record data kept as checked bytes.
//!
//! - RFC 1035: header (§4.1.1), question (§4.1.2), name presentation (§5.1), RDATA (§3.3); the name codec's tests
//!   are in `src/name.rs`.
//! - RFC 1035 §4.1.4: message compression in the encoder.
//! - RFC 2181: TTL range (§8) and label contents (§11).
//! - RFC 4343: case-insensitive comparison, case preserved.
//! - D28: records keep their RDATA as checked wire bytes, read as typed data on demand.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use dedens_proto::rdata::{Mx, Opaque, RData, Soa, Srv, Txt, TxtError};
use dedens_proto::{
    Class, DecodeErrorKind, HEADER_LEN, Header, MAX_NAME_LEN, Message, Name, Opcode, Question,
    Rcode, Record, RecordType, Ttl, ttl_offsets,
};
use dedens_testkit::dns;
use proptest::prelude::*;

use crate::util::{
    decode_answer, decode_record, encode_record, name, name_of, rec, record, record_wire,
};

// --- RFC 1035 ---

#[test]
fn s5_1_special_characters_are_escaped() {
    let name = name_of(&[b"a.b\\c\"d(e)f;g@h$i j"]);
    assert_eq!(name.to_string(), r#"a\.b\\c\"d\(e\)f\;g\@h\$i\032j."#);
}

/// A header with QDCOUNT 1, then `question`.
fn one_question(question: &[u8]) -> Vec<u8> {
    [&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0][..], question].concat()
}

/// The example of §3.5: 10.2.0.52 is `52.0.2.10.IN-ADDR.ARPA`.
#[test]
fn s3_5_in_addr_arpa_reverses_the_octets() {
    let addr = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 52));
    let expected: Name<'_> = "52.0.2.10.IN-ADDR.ARPA.".parse().unwrap();
    assert_eq!(Name::reverse(addr), expected);
    assert_eq!(Name::reverse(addr).to_string(), "52.0.2.10.in-addr.arpa.");
}

#[test]
fn s4_1_2_question_layout() {
    let wire = one_question(&[3, b'w', b'w', b'w', 0, 0, 28, 0, 1]);
    let message = Message::decode(&wire).unwrap().message;
    let q = &message.questions[0];
    assert_eq!(*q, Question::new(name_of(&[b"www"]), RecordType::AAAA));
    assert_eq!(q.qclass, Class::IN);
    assert_eq!(message.to_vec().unwrap(), wire);
}

#[test]
fn s4_1_2_question_cut_short() {
    let err = Message::decode(&one_question(&[0, 0, 1, 0])).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::UnexpectedEnd);
    // QTYPE and QCLASS are read together, so the error points at QTYPE.
    assert_eq!(err.offset, 13);
}

#[test]
fn s4_1_1_header_is_12_bytes() {
    assert_eq!(HEADER_LEN, 12);
    assert_eq!(Message::default().to_vec().unwrap(), [0; 12]);
    assert_eq!(Header::default().opcode, Opcode::QUERY);
    assert_eq!(Header::default().rcode, Rcode::NOERROR);
}

fn decoded(rtype: RecordType, rdata: &[u8]) -> RData<'static> {
    let d = decode_record(&record_wire(rtype, rdata)).expect("decodes");
    assert_eq!(d.invalid_rdata, None);
    d.record.data().into_owned()
}

/// RFC 1035 §3.2.1: RDLENGTH is 16 bits. Pins the boundary of each constructor with a long field (D125): the
/// largest RDATA is a record that reads back, one byte more is refused; `tests/text.rs` checks the same from text.
/// `Record::new` has nothing to refuse, and this test never reaches the fallback of `RData::with_wire`.
#[test]
fn s3_2_1_typed_rdata_up_to_65535_bytes_makes_a_record() {
    use dedens_proto::rdata::{
        Caa, Dnskey, Ds, Opaque, Rrsig, SvcParam, SvcParamKey, SvcParams, Svcb,
    };
    use dedens_proto::{Class, DigestType, Record, SecAlgorithm, Ttl};

    let longest = name_of(&[&[b'a'; 63], &[b'a'; 63], &[b'a'; 63], &[b'a'; 61]]);
    assert_eq!(longest.wire_len(), 255);
    let sig = vec![7; 65262];
    // Parameters alone hold up to 65532 bytes; `Svcb::new` counts its priority and target besides.
    let params = |value: usize| {
        SvcParams::new(vec![SvcParam::Unknown {
            key: SvcParamKey(9),
            value: vec![1; value].into(),
        }])
    };
    let largest = [
        // 255 strings of 255 bytes and one of 254, each behind its length byte.
        RData::Txt(
            Txt::new(
                vec![&[b't'; 255][..]; 255]
                    .into_iter()
                    .chain([&[b't'; 254][..]]),
            )
            .expect("65535 bytes"),
        ),
        RData::Opaque(
            Opaque::new(RecordType(731), &vec![3; 65535])
                .expect("65535 bytes")
                .into_owned(),
        ),
        RData::Dnskey(
            Dnskey::new(256, SecAlgorithm(15), &vec![2; 65531])
                .expect("65535 bytes")
                .into_owned(),
        ),
        RData::Ds(
            Ds::new(1, SecAlgorithm(15), DigestType(2), &vec![4; 65531])
                .expect("65535 bytes")
                .into_owned(),
        ),
        RData::Caa(
            Caa::new(0, b"issue", &vec![5; 65528])
                .expect("65535 bytes")
                .into_owned(),
        ),
        RData::Rrsig(
            Rrsig::new(
                RecordType::A,
                SecAlgorithm(15),
                0,
                0,
                0,
                0,
                1,
                longest.clone(),
                &sig,
            )
            .expect("65535 bytes"),
        ),
        RData::Svcb(
            Svcb::new(1, Name::root(), params(65528).expect("65532 bytes")).expect("65535 bytes"),
        ),
        // 2 + 255 + 4 + 65274.
        RData::Svcb(
            Svcb::new(1, longest.clone(), params(65274).expect("65278 bytes"))
                .expect("65535 bytes"),
        ),
    ];
    for data in &largest {
        let record = Record::new(Name::root(), Class::IN, Ttl::ZERO, data);
        assert_eq!(record.rdata.wire().len(), 65535, "{:?}", data.rtype());
        assert_eq!(record.data(), *data);
    }
    assert!(Txt::new(vec![&[0; 255][..]; 256]).is_err());
    assert!(Opaque::new(RecordType(731), &vec![0; 65536]).is_err());
    assert!(Dnskey::new(256, SecAlgorithm(15), &vec![0; 65532]).is_err());
    assert!(Ds::new(1, SecAlgorithm(15), DigestType(2), &vec![0; 65532]).is_err());
    assert!(Caa::new(0, b"issue", &vec![0; 65529]).is_err());
    assert!(
        Rrsig::new(
            RecordType::A,
            SecAlgorithm(15),
            0,
            0,
            0,
            0,
            1,
            Name::root(),
            &vec![0; 65263]
        )
        .is_err()
    );
    assert!(params(65529).is_err());
    let one_over = params(65275).expect("within the limit of the parameters");
    assert!(Svcb::new(1, longest, one_over).is_err());
}

#[test]
fn s3_4_1_a_is_four_octets() {
    assert_eq!(
        decoded(RecordType::A, &[192, 0, 2, 1]),
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    let bad = decode_record(&record_wire(RecordType::A, &[1, 2, 3])).unwrap();
    assert_eq!(
        bad.invalid_rdata.map(|e| e.kind),
        Some(DecodeErrorKind::RdataLength)
    );
}

#[test]
fn s3_3_domain_name_types() {
    let wire = b"\x03ns1\x07example\x00";
    let n = name_of(&[b"ns1", b"example"]);
    assert_eq!(decoded(RecordType::NS, wire), RData::Ns(n.clone()));
    assert_eq!(decoded(RecordType::CNAME, wire), RData::Cname(n.clone()));
    assert_eq!(decoded(RecordType::PTR, wire), RData::Ptr(n));
}

#[test]
fn s3_3_9_mx_is_preference_then_exchange() {
    let rdata = decoded(RecordType::MX, b"\x00\x0a\x04mail\x00");
    assert_eq!(
        rdata,
        RData::Mx(Mx {
            preference: 10,
            exchange: name_of(&[b"mail"])
        })
    );
}

#[test]
fn s3_3_13_soa_has_two_names_and_five_integers() {
    let mut wire = b"\x02ns\x00\x05admin\x00".to_vec();
    for v in [1u32, 2, 3, 4, 5] {
        wire.extend_from_slice(&v.to_be_bytes());
    }
    let RData::Soa(Soa {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    }) = decoded(RecordType::SOA, &wire)
    else {
        panic!("not SOA")
    };
    assert_eq!((mname, rname), (name_of(&[b"ns"]), name_of(&[b"admin"])));
    assert_eq!([serial, refresh, retry, expire, minimum], [1, 2, 3, 4, 5]);
}

#[test]
fn s3_3_14_txt_is_one_or_more_character_strings() {
    let rdata = decoded(RecordType::TXT, b"\x03foo\x00\x03bar");
    let strings = [&b"foo"[..], b"", b"bar"];
    assert_eq!(rdata, RData::Txt(Txt::new(strings).unwrap()));
    let RData::Txt(txt) = rdata else {
        unreachable!("TXT")
    };
    assert!(txt.strings().eq(strings));
    // No string at all, or a string that overruns the RDATA, is invalid.
    assert!(
        decode_record(&record_wire(RecordType::TXT, &[]))
            .unwrap()
            .invalid_rdata
            .is_some()
    );
    assert!(
        decode_record(&record_wire(RecordType::TXT, b"\x05ab"))
            .unwrap()
            .invalid_rdata
            .is_some()
    );
}

#[test]
fn s3_3_character_strings_hold_255_octets() {
    assert!(Txt::new([&[0; 255][..]]).is_ok());
    assert_eq!(Txt::new([&[0; 256][..]]), Err(TxtError::StringTooLong));
    assert_eq!(Txt::new([]), Err(TxtError::Empty));
}

#[test]
fn s3_3_invalid_rdata_of_compressible_types_is_an_error() {
    for rtype in [
        RecordType::NS,
        RecordType::CNAME,
        RecordType::PTR,
        RecordType::SOA,
        RecordType::MX,
    ] {
        assert!(decode_record(&record_wire(rtype, &[1])).is_err(), "{rtype}");
    }
}

#[test]
fn s4_1_4_names_in_rdata_follow_pointers_into_the_message() {
    // "example" at 12 in the question; the answer is a CNAME pointing at it.
    let mut msg = one_question(b"\x07example\x00\x00\x01\x00\x01");
    msg[7] = 1;
    msg.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 0, 0, 2, 0xC0, 12]);
    let d = decode_answer(&msg).unwrap();
    assert_eq!(d.record.data(), RData::Cname(name_of(&[b"example"])));
}

#[test]
fn s4_1_4_rdlength_bounds_a_name_in_rdata() {
    // The name runs past RDLENGTH: the RDATA is cut short, not read into the next field.
    let wire = record_wire(RecordType::NS, b"\x03abc");
    assert!(decode_record(&wire).is_err());
}

proptest! {
    #[test]
    fn records_round_trip(rec in record()) {
        let wire = encode_record(&rec);
        let d = decode_record(&wire)?;
        prop_assert_eq!(d.invalid_rdata, None);
        prop_assert_eq!(d.record, rec);
    }

    /// Each question name ends in a pointer to the longest earlier suffix of it, matched byte for byte, which a
    /// brute-force compressor finds among all the suffixes of the names before it (§4.1.4). 12 names of up to 12
    /// labels hold fewer suffixes than the table, and the message ends well short of what a pointer reaches.
    #[test]
    fn s4_1_4_names_end_in_a_pointer_to_the_longest_earlier_suffix(
        names in prop::collection::vec(prop::collection::vec(0..4_usize, 1..=12), 1..=12),
    ) {
        const LABELS: [&[u8]; 4] = [b"a", b"b", b"A", b"ab"];
        let mut message = Message::default();
        let mut expected = HEADER_LEN;
        let mut earlier = std::collections::HashSet::<Vec<u8>>::new();
        for indices in &names {
            let labels: Vec<&[u8]> = indices.iter().map(|&i| LABELS[i]).collect();
            let suffixes: Vec<(usize, Vec<u8>)> = (0..labels.len())
                .map(|k| {
                    let before = labels[..k].iter().map(|l| 1 + l.len()).sum();
                    let wire = labels[k..].iter().flat_map(|l| [&[u8::try_from(l.len()).unwrap()][..], l].concat()).chain([0]).collect();
                    (before, wire)
                })
                .collect();
            let whole = suffixes[0].1.len();
            expected += suffixes
                .iter()
                .find(|(_, wire)| earlier.contains(wire))
                .map_or(whole, |&(before, _)| before + 2);
            expected += 4;
            earlier.extend(suffixes.into_iter().map(|(_, wire)| wire));
            message.questions.push(Question::new(name_of(&labels), RecordType::A));
        }
        prop_assert_eq!(message.to_vec().unwrap().len(), expected);
    }

    #[test]
    fn s3_5_every_octet_is_a_decimal_label([a, b, c, d] in any::<[u8; 4]>()) {
        let name = Name::reverse(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
        prop_assert_eq!(name.to_string(), format!("{d}.{c}.{b}.{a}.in-addr.arpa."));
    }
}

// --- RFC 1035 §4.1.4 ---

fn a() -> RData<'static> {
    RData::A(Ipv4Addr::new(192, 0, 2, 1))
}

fn answer(records: Vec<dedens_proto::Record<'static>>) -> Message<'static> {
    Message {
        answer: records,
        ..Message::default()
    }
}

/// How many times `needle` appears in `haystack`.
fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn hundreds_of_distinct_names_are_all_compressed() {
    let mut message = Message::query(1, Question::new(dns("example."), RecordType::A));
    message.edns = None;
    message.answer = (0..250)
        .map(|n| {
            rec(
                &format!("h{n}.example."),
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )
        })
        .collect();
    let wire = message.to_vec().unwrap();
    // Header, question; each record: its own label, a pointer to `example.`, fixed fields, address.
    let records: usize = (0..250)
        .map(|n| 1 + format!("h{n}").len() + 2 + 10 + 4)
        .sum();
    assert_eq!(wire.len(), 12 + 9 + 4 + records);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_repeated_name_costs_a_two_byte_pointer() {
    let message = answer(vec![rec("example.com", a()), rec("example.com", a())]);
    let wire = message.to_vec().unwrap();
    // header, "example.com" (13 bytes), 10 fixed + 4 RDATA; then pointer (2) and again 14.
    assert_eq!(wire.len(), 12 + 13 + 14 + 2 + 14);
    assert_eq!(wire[12 + 13 + 14..][..2], [0xC0, 12]);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_shared_suffix_is_pointed_to() {
    let message = answer(vec![rec("example.com", a()), rec("www.example.com", a())]);
    let wire = message.to_vec().unwrap();
    // "www" label, then a pointer to "example.com" at offset 12.
    assert_eq!(wire[12 + 13 + 14..][..6], [3, b'w', b'w', b'w', 0xC0, 12]);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn the_longest_earlier_suffix_wins_and_is_itself_compressed() {
    let message = answer(vec![
        rec("a.example.com", a()),
        rec("b.example.com", a()),
        rec("b.example.com", a()),
        rec("com", a()),
    ]);
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07example\x03com\x00"), 1);
    assert_eq!(occurrences(&wire, b"\x01b"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_question_name_is_pointed_to_by_the_answer() {
    let mut message = Message::query(1, Question::new(dns("example.com"), RecordType::A));
    message.edns = None;
    message.answer = vec![rec("example.com", a())];
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07example"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn rdata_names_of_rfc_1035_types_are_compressed() {
    let message = answer(vec![
        rec(
            "example.com",
            RData::Mx(Mx {
                preference: 10,
                exchange: dns("mail.example.com"),
            }),
        ),
        rec("example.com", RData::Ns(dns("ns.example.com"))),
    ]);
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07example"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn rdata_names_of_other_types_are_not_compressed_nor_pointed_to() {
    let srv = Srv {
        priority: 1,
        weight: 1,
        port: 80,
        target: dns("example.com"),
    };
    let message = answer(vec![
        rec("_http._tcp.test", RData::Srv(srv)),
        rec("example.com", a()),
        rec("example.com", a()),
    ]);
    let wire = message.to_vec().unwrap();
    // The name inside the SRV RDATA stays whole, and the later owners do not point into it: they hold the
    // name once more, the third points to the second.
    assert_eq!(occurrences(&wire, b"\x07example\x03com\x00"), 2);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_record_set_written_again_from_its_decoding_is_the_same_bytes() {
    let message = answer((0..3).map(|_| rec("www.example.com", a())).collect());
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x03www"), 1);
    let decoded = Message::decode(&wire).unwrap().message;
    assert_eq!(decoded.to_vec().unwrap(), wire);
}

#[test]
fn names_keep_their_case_and_only_match_byte_for_byte() {
    let message = answer(vec![rec("Example.COM", a()), rec("example.com", a())]);
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07Example\x03COM\x00"), 1);
    assert_eq!(occurrences(&wire, b"\x07example\x03com\x00"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn pointers_only_reach_the_first_16384_bytes() {
    let filler = rec(
        "filler.test",
        RData::Txt(dedens_proto::rdata::Txt::new([&[b'x'; 255][..]]).unwrap()),
    );
    let mut records = vec![filler; 70];
    records.push(rec("late.example", a()));
    records.push(rec("late.example", a()));
    let message = answer(records);
    let wire = message.to_vec().unwrap();
    assert!(wire.len() > 0x4000 + 100);
    assert_eq!(occurrences(&wire, b"\x04late\x07example\x00"), 2);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_full_name_table_only_costs_compression() {
    let records = (0..400)
        .map(|i| rec(&format!("host{i}.example.com"), a()))
        .collect();
    let message = answer(records);
    let wire = message.to_vec().unwrap();
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

// --- RFC 2181 ---

#[test]
fn s8_a_ttl_with_the_top_bit_set_is_zero() {
    assert_eq!(Ttl::from_wire(0x8000_0000), Ttl::ZERO);
    assert_eq!(Ttl::from_wire(u32::MAX), Ttl::ZERO);
    assert_eq!(Ttl::from_wire(0x7FFF_FFFF), Ttl::MAX);
    assert_eq!(Ttl::new(0x8000_0000), None);
}

#[test]
fn s8_a_decoded_record_has_the_clamped_ttl() {
    let mut wire = record_wire(RecordType::A, &[1, 2, 3, 4]);
    wire[5..9].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert_eq!(decode_record(&wire).unwrap().record.ttl, Ttl::ZERO);
}

#[test]
fn s11_any_octet_is_valid_in_a_label() {
    for half in [0u8..=127, 128..=255] {
        let octets: Vec<u8> = half.collect();
        let name = Name::from_labels(octets.chunks(63)).unwrap();
        let rec = Record::new(name.clone(), Class::IN, Ttl::ZERO, &RData::Ptr(name));
        let wire = encode_record(&rec);
        assert_eq!(decode_record(&wire).unwrap().record, rec);
    }
}

proptest! {
    #[test]
    fn ttl_round_trip(ttl in 0..=Ttl::MAX.get()) {
        prop_assert_eq!(Ttl::new(ttl).map(Ttl::get), Some(ttl));
    }
}

// --- RFC 4343 ---

#[test]
fn s3_ascii_letters_compare_without_case() {
    assert_eq!(
        name_of(&[b"WWW", b"Example", b"COM"]),
        name_of(&[b"www", b"example", b"com"])
    );
}

#[test]
fn s3_only_ascii_letters_fold() {
    // 0xC9 is not the upper case of 0xE9 at the octet level, and `[` (0x5B) is not `{` (0x7B).
    assert_ne!(name_of(&[&[0xC9]]), name_of(&[&[0xE9]]));
    assert_ne!(name_of(&[b"["]), name_of(&[b"{"]));
}

#[test]
fn s3_label_boundaries_are_not_letters() {
    // `a.bc` and `ab.c` differ only in a length byte.
    assert_ne!(name_of(&[b"a", b"bc"]), name_of(&[b"ab", b"c"]));
}

#[test]
fn s3_case_is_preserved_through_decoding() {
    // A question for WwW.: the header with QDCOUNT 1, the name, type A, class IN.
    let wire = [
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'W', b'w', b'W', 0, 0, 1, 0, 1,
    ];
    let message = Message::decode(&wire).unwrap().message;
    let decoded = &message.questions[0].name;
    assert_eq!(decoded.to_wire(&mut [0; MAX_NAME_LEN]), &wire[12..17]);
    assert_eq!(decoded.to_string(), "WwW.");
}

#[test]
fn equal_names_hash_alike() {
    let set: HashSet<Name<'_>> = [name_of(&[b"EXAMPLE"]), name_of(&[b"example"])].into();
    assert_eq!(set.len(), 1);
}

proptest! {
    #[test]
    fn case_never_changes_identity(name in name()) {
        let flipped = Name::from_labels(name.labels().map(<[u8]>::to_ascii_uppercase).collect::<Vec<_>>().iter().map(Vec::as_slice))?;
        prop_assert_eq!(&flipped, &name);
        prop_assert_eq!(HashSet::from([flipped, name]).len(), 1);
    }
}

// --- D28 ---

fn mx_response() -> Message<'static> {
    let mut response = Message::query(1, Question::new(dns("example.com"), RecordType::MX));
    response.answer = vec![rec(
        "example.com",
        RData::Mx(Mx {
            preference: 10,
            exchange: dns("mail.example.com"),
        }),
    )];
    response
}

#[test]
fn rdata_with_a_compressed_name_outlives_its_message_once_owned() {
    let response = mx_response();
    let wire = response.to_vec().expect("encodes");
    // The exchange is a label and a pointer to the question name.
    assert!(wire.ends_with(&[
        0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0
    ]));
    let owned = Message::decode(&wire)
        .expect("decodes")
        .message
        .into_owned();
    drop(wire);
    assert_eq!(owned, response);
    let again = owned.to_vec().expect("encodes");
    assert_eq!(Message::decode(&again).expect("decodes").message, response);
}

#[test]
fn records_compare_names_in_rdata_without_case() {
    let lower = rec("example.com", RData::Ns(dns("ns.example.com")));
    let upper = rec("example.com", RData::Ns(dns("NS.Example.COM")));
    assert_eq!(lower, upper);
}

#[test]
fn invalid_rdata_reads_as_opaque_and_is_written_as_received() {
    // An A record with 3 bytes of RDATA (D9).
    let wire = crate::util::record_wire(RecordType::A, &[192, 0, 2]);
    let decoded = crate::util::decode_record(&wire).expect("decodes");
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data(), RData::Opaque(o) if o.data() == [192, 0, 2]));
    let response = Message {
        answer: vec![decoded.record],
        ..Message::default()
    };
    let again = response.to_vec().expect("encodes");
    assert!(again.ends_with(&[0, 3, 192, 0, 2]));
}

#[test]
fn opaque_bytes_unreadable_as_their_type_stay_opaque() {
    let bad =
        Opaque::new(RecordType::A, &[1, 2, 3]).expect("invalid A RDATA is kept as bytes (D9)");
    let record = Record::new(
        dns("example.com"),
        Class::IN,
        Ttl::ZERO,
        &RData::Opaque(bad),
    );
    assert!(matches!(record.data(), RData::Opaque(o) if o.data() == [1, 2, 3]));
}

/// One value has one form: bytes that read as a typed type are refused, and so are bytes for a type with names
/// that do not read as it, which could hold a pointer written out as is (RFC 3597 §4).
#[test]
fn opaque_refuses_typed_and_name_bytes() {
    assert!(Opaque::new(RecordType::A, &[192, 0, 2, 1]).is_err());
    assert!(Opaque::new(RecordType::TXT, &[1, b'a']).is_err());
    for (rtype, data) in [
        (RecordType::NS, &[0xC0, 0x0C][..]),
        (RecordType::NS, &[3, b'a']),
        (RecordType::NS, &[0xFF]),
        (RecordType::SRV, &[0, 1, 0, 2, 0, 3, 0xC0, 0x0C]),
    ] {
        assert!(Opaque::new(rtype, data).is_err(), "{rtype} {data:?}");
    }
}

/// The TTL field of a stray OPT record holds the extended RCODE, version and DO bit (RFC 6891 §6.1.3): a cache
/// rewriting TTLs must leave it alone.
#[test]
fn ttl_offsets_skip_a_stray_opt_record() {
    let mut wire = vec![0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    wire.extend([0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
    let mut offsets = Vec::new();
    ttl_offsets(&wire, |at| offsets.push(at)).expect("readable");
    assert_eq!(offsets, Vec::<u16>::new());
}

#[test]
fn ttl_offsets_locate_every_record_ttl() {
    let mut response = mx_response();
    response.additional.push(rec(
        "mail.example.com",
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    let mut wire = response.to_vec().expect("encodes");
    let mut offsets = Vec::new();
    ttl_offsets(&wire, |at| offsets.push(at)).expect("reads");
    assert_eq!(offsets.len(), 2, "the OPT record is not a record");
    for at in offsets.into_iter().map(usize::from) {
        wire[at..at + 4].copy_from_slice(&7_u32.to_be_bytes());
    }
    let decoded = Message::decode(&wire).expect("decodes").message;
    let ttls: Vec<_> = decoded
        .answer
        .iter()
        .chain(&decoded.additional)
        .map(|r| r.ttl)
        .collect();
    assert_eq!(ttls, [Ttl::new(7).expect("valid TTL"); 2]);
}

#[test]
fn a_message_over_65535_bytes_is_refused() {
    let error = Message::decode(&vec![0; 65536]).expect_err("too long");
    assert!(matches!(error.kind, DecodeErrorKind::Invalid(_)));
}
