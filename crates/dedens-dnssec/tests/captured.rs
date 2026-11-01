//! The DNSSEC responses captured by `just capture-dnssec` (`testdata/capture.yaml`, described in
//! `testdata/README.md`): they decode without a violation, re-encode to an equal message, show what the README
//! says they do, and their signatures are valid at `captured_at` but where they are not meant to be.

use std::fs;

use dedens_proto::{Message, Rcode, Record, RecordType};

mod common;

use common::{capture, captured_at, dir, names};

fn records<'a>(message: &'a Message<'static>) -> impl Iterator<Item = &'a Record<'static>> {
    message
        .answer
        .iter()
        .chain(&message.authority)
        .chain(&message.additional)
}

/// The RDATA bytes of `record`, read through its generic form (RFC 3597 §5, `\# length hex`) so that this test
/// stands whatever types `dedens-proto` reads.
fn rdata(record: &Record<'_>) -> Vec<u8> {
    let generic = record.data().generic().to_string();
    let hex = generic
        .strip_prefix("\\# ")
        .and_then(|rest| rest.split_once(' '))
        .map_or("", |(_, hex)| hex);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The fixed fields of an RRSIG (RFC 4034 §3.1) this test reads.
struct Rrsig {
    algorithm: u8,
    expiration: u32,
    inception: u32,
}

fn rrsigs(message: &Message<'static>) -> Vec<Rrsig> {
    records(message)
        .filter(|r| r.rtype() == RecordType::RRSIG)
        .map(|r| {
            let bytes = rdata(r);
            let fixed = bytes.first_chunk::<16>().expect("RRSIG fixed fields");
            let [
                _,
                _,
                algorithm,
                _,
                _,
                _,
                _,
                _,
                e0,
                e1,
                e2,
                e3,
                i0,
                i1,
                i2,
                i3,
            ] = *fixed;
            Rrsig {
                algorithm,
                expiration: u32::from_be_bytes([e0, e1, e2, e3]),
                inception: u32::from_be_bytes([i0, i1, i2, i3]),
            }
        })
        .collect()
}

fn types<'a>(records: &'a [Record<'static>]) -> impl Iterator<Item = RecordType> + 'a {
    records.iter().map(Record::rtype)
}

#[test]
fn every_capture_decodes_and_round_trips() {
    let names = names();
    for name in &names {
        let message = capture(name);
        let wire = message.to_vec().expect("encodes");
        let again = Message::decode(&wire).expect("decodes again");
        assert_eq!(again.violations, [], "{name}");
        assert_eq!(again.message, message, "{name}");
    }
    // One file per query of capture.yaml.
    let yaml = fs::read_to_string(dir().join("capture.yaml")).expect("capture.yaml");
    let queries = yaml.lines().filter(|l| l.starts_with("  - ")).count();
    assert_eq!(names.len(), queries);
}

/// The captures with a signature out of its window: rhybar.cz's all ended in October 2025, and the DNSKEY set of
/// dnssec-failed.org carries an old one next to its current one.
const EXPIRED: [&str; 3] = [
    "bogus_expired",
    "rhybar_cz_dnskey",
    "dnssec_failed_org_dnskey",
];

#[test]
fn signatures_are_valid_at_the_capture_time_but_the_expired_ones() {
    let now = captured_at();
    for name in names().iter().filter(|n| !EXPIRED.contains(&n.as_str())) {
        for sig in rrsigs(&capture(name)) {
            assert!(sig.inception <= now && now <= sig.expiration, "{name}");
        }
    }
    // The expired ones: every signature of rhybar.cz's A answer ended before the capture.
    assert!(
        rrsigs(&capture("bogus_expired"))
            .iter()
            .all(|sig| sig.expiration < now)
    );
}

/// The signing algorithms, DS digest types and NSEC3 parameters a validator must meet.
#[test]
fn the_set_covers_the_algorithms_digests_and_nsec3_parameters() {
    let (mut algorithms, mut digests, mut nsec3) = (Vec::new(), Vec::new(), Vec::new());
    for name in names() {
        let message = capture(&name);
        algorithms.extend(rrsigs(&message).iter().map(|s| s.algorithm));
        for record in records(&message) {
            let bytes = rdata(record);
            match record.rtype() {
                RecordType::DS => digests.push(bytes[3]),
                // Hash algorithm, flags, iterations, salt length (RFC 5155 §3.2).
                RecordType::NSEC3 => {
                    nsec3.push((bytes[1] & 1 == 1, bytes[2..4].to_vec(), bytes[4]));
                }
                _ => {}
            }
        }
    }
    for algorithm in [5, 7, 8, 10, 13, 14, 15, 16] {
        assert!(algorithms.contains(&algorithm), "algorithm {algorithm}");
    }
    for digest in [1, 2, 4] {
        assert!(digests.contains(&digest), "digest {digest}");
    }
    assert!(nsec3.iter().any(|&(optout, _, _)| optout), "opt-out");
    assert!(
        nsec3.iter().any(|(_, iterations, _)| iterations != &[0, 0]),
        "iterations"
    );
    assert!(nsec3.iter().any(|&(_, _, salt)| salt > 0), "salt");
}

/// What a kind of response must hold: its files, the rcode and the record types of the answer and authority sections.
type Shape = (
    &'static [&'static str],
    Rcode,
    &'static [RecordType],
    &'static [RecordType],
);

const NO_ANSWER_NSEC: &[RecordType] = &[RecordType::SOA, RecordType::NSEC, RecordType::RRSIG];
const NO_ANSWER_NSEC3: &[RecordType] = &[RecordType::SOA, RecordType::NSEC3, RecordType::RRSIG];
const SIGNED_CHAIN: &[RecordType] = &[RecordType::CNAME, RecordType::A, RecordType::RRSIG];
const SIGNED_A: &[RecordType] = &[RecordType::A, RecordType::RRSIG];

const SHAPES: [Shape; 10] = [
    (
        &["root_dnskey"],
        Rcode::NOERROR,
        &[RecordType::DNSKEY, RecordType::RRSIG],
        &[],
    ),
    (
        &["nxdomain_root_nsec", "nxdomain_nsec"],
        Rcode::NXDOMAIN,
        &[],
        NO_ANSWER_NSEC,
    ),
    (
        &[
            "nxdomain_nsec3",
            "nxdomain_nsec3_optout",
            "nxdomain_nsec3_salt",
            "nxdomain_nsec3_iterations",
        ],
        Rcode::NXDOMAIN,
        &[],
        NO_ANSWER_NSEC3,
    ),
    (
        &[
            "nxname_cloudflare",
            "nodata_compact",
            "nodata_root_nsec",
            "nodata_nsec",
            "ent_nsec",
            "jm_ds",
        ],
        Rcode::NOERROR,
        &[],
        NO_ANSWER_NSEC,
    ),
    (
        &[
            "nodata_nsec3",
            "nodata_nsec3_optout",
            "nodata_nsec3_iterations",
            "ent_nsec3",
            "google_com_ds",
            "wildcard_nodata",
        ],
        Rcode::NOERROR,
        &[],
        NO_ANSWER_NSEC3,
    ),
    (
        &["wildcard_answer"],
        Rcode::NOERROR,
        &[RecordType::MX, RecordType::RRSIG],
        &[RecordType::NSEC3, RecordType::RRSIG],
    ),
    (
        &[
            "cname_cross_zone",
            "cname_deep_zone",
            "cname_to_insecure",
            "bogus_signature",
        ],
        Rcode::NOERROR,
        SIGNED_CHAIN,
        &[],
    ),
    (
        &["dname_answer"],
        Rcode::NOERROR,
        &[
            RecordType::DNAME,
            RecordType::CNAME,
            RecordType::AAAA,
            RecordType::RRSIG,
        ],
        &[],
    ),
    (
        &["alg8_a", "alg16_a", "bogus_expired"],
        Rcode::NOERROR,
        SIGNED_A,
        &[],
    ),
    (&["google_com_a"], Rcode::NOERROR, &[RecordType::A], &[]),
];

#[test]
fn each_capture_shows_what_the_readme_says() {
    for &(names, rcode, answer, authority) in &SHAPES {
        for name in names {
            let message = capture(name);
            assert_eq!(message.rcode(), rcode, "{name}");
            for (section, wanted) in [(&message.answer, answer), (&message.authority, authority)] {
                for rtype in wanted {
                    assert!(types(section).any(|t| t == *rtype), "{name}: no {rtype}");
                }
            }
            assert_eq!(
                answer.is_empty(),
                message.answer.is_empty(),
                "{name}: answer section"
            );
        }
    }
    // An unsigned zone's answer carries no signature.
    assert!(rrsigs(&capture("google_com_a")).is_empty());
}
