//! RFC 9718 (the root zone's trust anchors, §2) and RFC 4035 §4.4 (what a trust anchor is): the bundled
//! `src/root.ds` and the text of anchors read from a file.

mod common;

use std::fs;
use std::path::PathBuf;

use common::{dnskey_rdata, name};
use dedens_dnssec::anchor::{AnchorError, TrustAnchors};
use dedens_dnssec::crypto::{ds_digest, key_tag};
use dedens_proto::rdata::{Ds, RData};
use dedens_proto::{Class, Message, RecordType};

// RFC 9718 §2.3 (the DS RRset and the DNSKEY of KSK-2017, key tag 20326).
const EXAMPLE: &str = "\
. 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
. 172800 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
. 172800 IN DNSKEY 257 3 8 ( AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
    +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv
    ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF
    0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e
    oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd
    RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN
    R1AkUTV74bU= )
";

fn read_err(text: &str) -> AnchorError {
    TrustAnchors::read(text).expect_err("refused")
}

#[test]
fn s2_bundled_anchors_are_the_roots_ds_records() {
    let anchors = TrustAnchors::root();
    let (zone, anchor) = anchors.closest(&name("example.com.")).expect("the root");
    assert_eq!(zone, &name("."));
    assert_eq!(anchor.dnskeys(), []);
    let mut tags: Vec<u16> = anchor.ds().iter().map(Ds::key_tag).collect();
    tags.sort_unstable();
    // KSK-2017 and KSK-2024 (RFC 9718 §2.2); the key of tag 19036 is retired.
    assert_eq!(tags, [20326, 38696]);
    for ds in anchor.ds() {
        assert_eq!(ds.digest_type(), dedens_proto::DigestType::SHA256);
    }
}

#[test]
fn s2_bundled_anchors_match_the_captured_root_dnskeys() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/root_dnskey.bin");
    let wire = fs::read(path).expect("captured root DNSKEY response");
    let decoded = Message::decode(&wire).expect("decodes");
    let message = decoded.message.into_owned();
    let root = name(".");
    let keys: Vec<(Vec<u8>, bool)> = message
        .answer
        .iter()
        .filter_map(|r| match r.data() {
            RData::Dnskey(k) => Some((
                dnskey_rdata_of(k.flags(), u8::from(k.algorithm()), k.public_key()),
                k.is_secure_entry_point(),
            )),
            _ => None,
        })
        .collect();
    assert!(keys.iter().any(|(_, sep)| *sep), "the root has a KSK");

    let anchors = TrustAnchors::root();
    let (_, anchor) = anchors.closest(&root).expect("the root");
    for ds in anchor.ds() {
        let matching = keys.iter().filter(|(rdata, _)| {
            key_tag(rdata) == ds.key_tag()
                && rdata.get(3) == Some(&u8::from(ds.algorithm()))
                && ds_digest(ds.digest_type(), &root, rdata)
                    .is_ok_and(|digest| digest.as_ref() == ds.digest())
        });
        assert_eq!(matching.count(), 1, "key tag {}", ds.key_tag());
    }
}

/// DNSKEY RDATA of the fields, protocol 3 (RFC 4034 §2.1.2).
fn dnskey_rdata_of(flags: u16, algorithm: u8, key: &[u8]) -> Vec<u8> {
    let mut rdata = flags.to_be_bytes().to_vec();
    rdata.extend([3, algorithm]);
    rdata.extend(key);
    rdata
}

#[test]
fn s2_3_example_reads_as_ds_and_dnskey_of_the_root() {
    let anchors = TrustAnchors::read(EXAMPLE).unwrap();
    let (zone, anchor) = anchors.closest(&name("www.example.")).expect("the root");
    assert_eq!(zone, &name("."));
    assert_eq!(anchor.ds().len(), 2);
    let [key] = anchor.dnskeys() else {
        panic!("one DNSKEY");
    };
    assert_eq!((key.flags(), key.is_secure_entry_point()), (257, true));
    let rdata = dnskey_rdata_of(key.flags(), u8::from(key.algorithm()), key.public_key());
    assert_eq!(key_tag(&rdata), 20326);
    // The text and the helper of the other tests give the same key.
    let again = dnskey_rdata(
        257,
        8,
        &EXAMPLE[EXAMPLE.find("AwEA").unwrap()..EXAMPLE.rfind(" )").unwrap()],
    );
    assert_eq!(rdata, again);
}

#[test]
fn s4_4_anchors_per_zone_and_the_closest_one_wins() {
    let anchors = TrustAnchors::read(
        "; the root, a zone and an island\n\n. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n\
         Example.COM. IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118\n\
         $ORIGIN org.\nisland IN DS 1 13 2 00\n",
    )
    .unwrap();
    let zone = |n: &str| {
        anchors
            .closest(&name(n))
            .map(|(z, _)| z.to_string().to_ascii_lowercase())
    };
    assert_eq!(zone("www.example.com."), Some("example.com.".into()));
    assert_eq!(zone("EXAMPLE.com."), Some("example.com.".into()));
    assert_eq!(zone("com."), Some(".".into()));
    assert_eq!(zone("example.net."), Some(".".into()));
    assert_eq!(zone("a.island.org."), Some("island.org.".into()));
    assert_eq!(zone("."), Some(".".into()));
}

#[test]
fn s4_4_no_anchor_above_the_name_is_none() {
    let anchors = TrustAnchors::read(
        "example.com. IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118\n",
    )
    .unwrap();
    assert_eq!(anchors.closest(&name("example.net.")), None);
    assert_eq!(anchors.closest(&name("com.")), None);
    assert!(anchors.closest(&name("example.com.")).is_some());
}

#[test]
fn s4_4_ttl_and_class_are_optional() {
    let anchors = TrustAnchors::read(
        "a. DS 1 13 2 00\nb. 60 DS 1 13 2 00\nc. IN DS 1 13 2 00\nd. IN 60 DNSKEY 257 3 13 AAAA\n",
    )
    .unwrap();
    for zone in ["a.", "b.", "c.", "d."] {
        assert!(anchors.closest(&name(zone)).is_some(), "{zone}");
    }
}

#[test]
fn s4_4_both_kinds_of_one_zone_are_kept_together() {
    let anchors =
        TrustAnchors::read("a. DS 1 13 2 00\na. DNSKEY 257 3 13 AAAA\na. DS 2 13 2 00\n").unwrap();
    let (_, anchor) = anchors.closest(&name("a.")).unwrap();
    assert_eq!((anchor.ds().len(), anchor.dnskeys().len()), (2, 1));
}

#[test]
fn s4_4_only_ds_and_dnskey_anchor_a_zone() {
    assert_eq!(
        read_err("a. DS 1 13 2 00\nb. TXT x\n"),
        AnchorError::NotAnAnchor {
            line: 2,
            rtype: RecordType::TXT
        }
    );
    // A CDS is another type (RFC 7344): the child's wish for its DS, not an anchor.
    assert!(matches!(
        read_err("a. CDS 1 13 2 00\n"),
        AnchorError::NotAnAnchor {
            line: 1,
            rtype: RecordType::CDS
        }
    ));
    assert!(matches!(
        read_err("a. CDNSKEY 257 3 13 AAAA\n"),
        AnchorError::NotAnAnchor {
            line: 1,
            rtype: RecordType::CDNSKEY
        }
    ));
}

#[test]
fn s4_4_class_in_only() {
    assert_eq!(
        read_err("a. DS 1 13 2 00\nb. CH DS 1 13 2 00\n"),
        AnchorError::NotInternet {
            line: 2,
            class: Class::CH
        }
    );
}

#[test]
fn s4_4_data_that_is_not_a_ds_or_a_dnskey_is_refused_at_its_last_line() {
    // RFC 3597 §5 form with too few bytes for a DS (4 fixed bytes and a digest).
    let AnchorError::InvalidData { line, rtype, .. } =
        read_err("a. DS 1 13 2 00\nb. DS \\# 2 0001\n")
    else {
        panic!("invalid data");
    };
    assert_eq!((line, rtype), (2, RecordType::DS));
    let AnchorError::InvalidData { line, rtype, .. } = read_err("a. DNSKEY \\# 2 0001\n") else {
        panic!("invalid data");
    };
    assert_eq!((line, rtype), (1, RecordType::DNSKEY));
}

#[test]
fn s4_4_text_errors_name_their_line() {
    let AnchorError::Text(e) = read_err("a. DS 1 13 2 00\n\nb. DS x 13 2 00\n") else {
        panic!("text error");
    };
    assert_eq!(e.line, 3);
    // A relative name without an `$ORIGIN` has nothing to be relative to.
    let AnchorError::Text(e) = read_err("a. DS 1 13 2 00\nrel DS 1 13 2 00\n") else {
        panic!("text error");
    };
    assert_eq!(e.line, 2);
}

#[test]
fn s4_4_include_is_refused() {
    assert_eq!(
        read_err("a. DS 1 13 2 00\n$INCLUDE other.ds\n"),
        AnchorError::NotARecord { line: 2 }
    );
}

#[test]
fn s4_4_no_record_is_no_anchor() {
    assert_eq!(read_err(""), AnchorError::Empty);
    assert_eq!(read_err("; only a comment\n\n"), AnchorError::Empty);
    assert_eq!(read_err("$ORIGIN a.\n"), AnchorError::Empty);
}
