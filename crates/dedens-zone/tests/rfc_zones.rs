//! The example zones of the RFCs and the fuzzing seed of `testdata/zones/`, loaded: RFC 1035 §5.3 (the ISI master
//! file, with its `$INCLUDE`), RFC 4035 appendix A, RFC 5155 appendix A.

use dedens_proto::rdata::RData;
use dedens_proto::{Class, RecordType, Ttl};
use dedens_testkit::dns;
use dedens_zone::{ErrorKind, Limits};

use crate::util::{errors, load_files, zone_file};

const ISI_INCLUDE: &str = "<SUBSYS>ISI-MAILBOXES.TXT";

fn isi() -> dedens_zone::Loaded {
    let mailboxes = zone_file("rfc1035_isi_mailboxes.zone");
    load_files(
        "ISI.EDU.",
        &zone_file("rfc1035_isi.zone"),
        Ttl::new(3600),
        &[(ISI_INCLUDE, &mailboxes)],
        &Limits::default(),
    )
    .expect("the RFC's zone")
}

// --- RFC 1035 §5.3 ---

#[test]
fn s5_3_the_isi_zone_loads_with_the_include() {
    let loaded = isi();
    let zone = &loaded.zone;
    assert_eq!(zone.apex(), &dns("isi.edu."));
    assert_eq!(zone.class(), Class::IN);
    assert_eq!(zone.soa().serial, 20);
    assert_eq!(loaded.report.files, ["zone.db", ISI_INCLUDE]);
    assert_eq!(loaded.report.warnings, []);
    // The apex: SOA, 3 NS, 2 MX; A, 1; VENERA 2; VAXA 2; 3 MB; STOOGES 3 MG.
    assert_eq!(zone.record_count(), 1 + 3 + 2 + 1 + 2 + 2 + 3 + 3);
    let stooges = zone.node(&dns("stooges.isi.edu.")).expect("STOOGES");
    let mg = stooges.rrset(RecordType::MG).expect("MG");
    assert_eq!(mg.rdatas().len(), 3);
    assert_eq!(mg.ttl(), Ttl::new(3600).expect("a TTL"));
}

#[test]
fn s5_3_the_isi_origin_is_matched_whatever_the_case() {
    let loaded = isi();
    let venera = loaded.zone.node(&dns("Venera.ISI.edu.")).expect("VENERA");
    let a = venera.rrset(RecordType::A).expect("A");
    assert_eq!(a.rdatas().len(), 2);
}

// --- RFC 4035 appendix A ---

#[test]
fn a_the_signed_zone_loads_with_its_signatures_kept_apart() {
    let loaded = load_files(
        "example.",
        &zone_file("rfc4035_appendix_a.zone"),
        None,
        &[],
        &Limits::default(),
    )
    .expect("the RFC's zone");
    let zone = &loaded.zone;
    assert_eq!(zone.soa().serial, 1_081_539_377);
    // The delegations a and b hold glue, so nothing is reported.
    assert_eq!(loaded.report.warnings, []);
    let apex = zone.node(zone.apex()).expect("the apex");
    assert!(apex.rrset(RecordType::SOA).is_some());
    assert!(apex.signatures(RecordType::SOA).is_some());
    assert!(apex.rrsets().all(|(t, _)| t != RecordType::RRSIG));
    let nsec = apex.rrset(RecordType::NSEC).expect("NSEC");
    let first = nsec.rdatas().first().expect("an NSEC record");
    assert!(matches!(first.data(), RData::Nsec(_)));
}

// --- RFC 5155 appendix A ---

#[test]
fn a_the_nsec3_zone_loads() {
    let loaded = load_files(
        "example.",
        &zone_file("rfc5155_appendix_a.zone"),
        None,
        &[],
        &Limits::default(),
    )
    .expect("the RFC's zone");
    let zone = &loaded.zone;
    let hashed = dns("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.");
    let node = zone.node(&hashed).expect("a hashed owner");
    assert!(node.rrset(RecordType::NSEC3).is_some());
    assert!(node.signatures(RecordType::NSEC3).is_some());
}

// --- the fuzzing seed ---

/// The seed with the records of another class than IN made IN: it holds `mail CH A`, whose class the records after
/// it keep (RFC 1035 §5.1), then a CLASS32 and an HS record.
fn every_type_in_class_in() -> String {
    zone_file("every_type.zone")
        .replace("mail\tCH\tA", "mail\tIN\tA")
        .replace("a\tCLASS32\tTYPE731", "a\tIN\tTYPE731")
        .replace("b\tHS\tTYPE62347", "b\tIN\tTYPE62347")
}

#[test]
fn every_type_is_refused_for_its_other_classes() {
    let text = zone_file("every_type.zone");
    let report = load_files("example.", &text, None, &[], &Limits::default())
        .expect_err("records of the class CH, CLASS32 and HS");
    let found = errors(report);
    let first = found.first().expect("an error");
    assert!(
        matches!(
            first,
            (
                Some(15),
                ErrorKind::ClassMismatch {
                    found: Class::CH,
                    ..
                }
            )
        ),
        "{first:?}"
    );
    assert!(
        found
            .iter()
            .all(|(_, k)| matches!(k, ErrorKind::ClassMismatch { .. }))
    );
}

#[test]
fn every_type_is_refused_for_the_name_outside_the_zone() {
    let report = load_files(
        "example.",
        &every_type_in_class_in(),
        None,
        &[],
        &Limits::default(),
    )
    .expect_err("a name outside the zone");
    let kinds: Vec<ErrorKind> = errors(report).into_iter().map(|(_, k)| k).collect();
    assert_eq!(
        kinds,
        [ErrorKind::OutsideZone {
            owner: dns("1.2.0.192.in-addr.arpa."),
        }]
    );
}

#[test]
fn every_type_loads_without_it() {
    let text: String = every_type_in_class_in()
        .lines()
        .filter(|l| !l.starts_with("1.2.0.192"))
        .flat_map(|l| [l, "\n"])
        .collect();
    let loaded = load_files("example.", &text, None, &[], &Limits::default()).expect("every type");
    assert_eq!(loaded.report.warnings, []);
}
