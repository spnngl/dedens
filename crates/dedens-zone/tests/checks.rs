//! The checks of a load, each on a broken variant of a valid zone: RFC 1035 §5.2 (one class, one SOA at the apex, an
//! NS there, records inside the zone), RFC 2181 §5.2 (TTLs of an `RRset`) and §10.1 (CNAME), RFC 6672 §2.3 and §2.4
//! (DNAME).

use dedens_proto::{Class, RecordType};
use dedens_testkit::dns;
use dedens_zone::{ErrorKind, Limits, WarningKind};

use crate::util::{APEX, NEXT_LINE, load, load_extra, refused, zone_file};

/// The error `kind` at the first line after the apex.
fn first(kind: ErrorKind) -> Vec<(Option<usize>, ErrorKind)> {
    vec![(Some(NEXT_LINE), kind)]
}

// --- RFC 1035 §5.2 ---

#[test]
fn s5_2_a_zone_holds_one_class() {
    assert_eq!(
        refused("x CH A 192.0.2.9\n"),
        first(ErrorKind::ClassMismatch {
            found: Class::CH,
            zone: Class::IN,
        })
    );
}

#[test]
fn s5_2_a_record_outside_the_zone_is_refused() {
    assert_eq!(
        refused("x.other. A 192.0.2.9\n"),
        first(ErrorKind::OutsideZone {
            owner: dns("x.other."),
        })
    );
    // A name that only ends like the zone's is no name below it.
    assert_eq!(
        refused("xexample. A 192.0.2.9\n"),
        first(ErrorKind::OutsideZone {
            owner: dns("xexample."),
        })
    );
}

#[test]
fn s5_2_the_soa_is_at_the_apex() {
    assert_eq!(
        refused("x SOA ns hostmaster 1 1d 2h 4w 1h\n"),
        first(ErrorKind::SoaNotAtApex)
    );
}

#[test]
fn s5_2_one_soa_only() {
    assert_eq!(
        refused("@ SOA ns hostmaster 2 1d 2h 4w 1h\n"),
        first(ErrorKind::MultipleSoa)
    );
    // The same SOA twice is one record (RFC 2181 §5).
    let again = load_extra("@ SOA ns hostmaster 1 1d 2h 4w 1h\n").expect("a repeated SOA merges");
    assert_eq!(again.zone.record_count(), 3);
}

#[test]
fn s5_2_a_zone_needs_its_soa() {
    let text = "$ORIGIN example.\n$TTL 1h\n@ NS ns\nns A 192.0.2.1\n";
    let errors = crate::util::errors(load(text).expect_err("no SOA"));
    assert_eq!(errors, [(None, ErrorKind::NoSoa)]);
}

#[test]
fn s5_2_a_zone_needs_an_ns_at_its_apex() {
    let text = "$ORIGIN example.\n$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\nns A 192.0.2.1\n";
    let errors = crate::util::errors(load(text).expect_err("no NS"));
    assert_eq!(errors, [(None, ErrorKind::NoApexNs)]);
    // An NS below the apex is a delegation, not the zone's own.
    let text = format!("{text}sub NS ns.other.\n");
    let errors = crate::util::errors(load(&text).expect_err("no NS at the apex"));
    assert_eq!(errors, [(None, ErrorKind::NoApexNs)]);
}

#[test]
fn s5_1_a_text_error_is_reported_with_its_line_and_ends_the_file() {
    let found = refused("x A not-an-address\ny CH A 192.0.2.9\n");
    assert_eq!(found.len(), 1, "{found:?}");
    let (line, kind) = found.first().expect("an error");
    assert_eq!(*line, Some(NEXT_LINE));
    assert!(matches!(kind, ErrorKind::Text(_)), "{kind:?}");
}

#[test]
fn s5_every_error_is_reported() {
    let found =
        refused("x CH A 192.0.2.9\ny.other. A 192.0.2.9\nz SOA ns hostmaster 1 1d 2h 4w 1h\n");
    let lines: Vec<Option<usize>> = found.iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [Some(6), Some(7), Some(8)]);
}

#[test]
fn rdata_invalid_for_its_type_is_refused() {
    // RFC 3597 §5: the generic form of an A record of 3 bytes.
    assert!(matches!(
        refused("x A \\# 3 010203\n").as_slice(),
        [(Some(NEXT_LINE), ErrorKind::InvalidRdata(_))]
    ));
}

// --- RFC 2181 §5.2 ---

#[test]
fn s5_2_records_of_an_rrset_with_other_ttls_take_the_lowest() {
    let loaded = load_extra("x 600 A 192.0.2.9\nx 300 A 192.0.2.10\nx 900 A 192.0.2.11\n")
        .expect("a warning only");
    let node = loaded.zone.node(&dns("x.example.")).expect("x");
    let a = node.rrset(RecordType::A).expect("A");
    assert_eq!(a.ttl().get(), 300);
    assert_eq!(a.rdatas().len(), 3);
    let warnings: Vec<_> = loaded
        .report
        .warnings
        .iter()
        .map(|w| (w.at.line, &w.kind))
        .collect();
    assert_eq!(
        warnings,
        [(
            NEXT_LINE,
            &WarningKind::DifferentTtls {
                rtype: RecordType::A,
                kept: 300,
            }
        )]
    );
}

#[test]
fn s5_2_a_duplicate_with_another_ttl_counts_too() {
    let loaded = load_extra("x 600 A 192.0.2.9\nx 300 A 192.0.2.9\n").expect("a warning only");
    let node = loaded.zone.node(&dns("x.example.")).expect("x");
    let a = node.rrset(RecordType::A).expect("A");
    assert_eq!((a.ttl().get(), a.rdatas().len()), (300, 1));
    assert_eq!(loaded.report.warnings.len(), 1);
}

#[test]
fn s5_2_the_same_ttl_says_nothing() {
    let loaded =
        load_extra("x 600 A 192.0.2.9\nx 600 A 192.0.2.10\nx 600 A 192.0.2.9\n").expect("a zone");
    assert_eq!(loaded.report.warnings, []);
    assert_eq!(loaded.zone.record_count(), 3 + 2);
}

// --- RFC 2181 §10.1 ---

#[test]
fn s10_1_a_cname_stands_alone() {
    assert_eq!(
        refused("x CNAME ns\nx A 192.0.2.9\n"),
        first(ErrorKind::CnameWithOtherData {
            other: RecordType::A
        })
    );
    // Whichever comes first.
    assert_eq!(
        refused("x A 192.0.2.9\nx CNAME ns\n"),
        vec![(
            Some(NEXT_LINE + 1),
            ErrorKind::CnameWithOtherData {
                other: RecordType::A
            }
        )]
    );
}

#[test]
fn s10_1_a_cname_at_the_apex_is_beside_the_soa() {
    assert_eq!(
        refused("@ CNAME ns\n"),
        first(ErrorKind::CnameWithOtherData {
            other: RecordType::NS
        })
    );
}

#[test]
fn s10_1_a_cname_may_hold_dnssec_data() {
    // The signed zone of RFC 4035 appendix A with `ns2.example.`'s A record made a CNAME: its NSEC and the
    // signatures stay.
    let text = zone_file("rfc4035_appendix_a.zone").replace(
        "ns2.example.   3600 IN A   192.0.2.2",
        "ns2.example.   3600 IN CNAME ns1.example.",
    );
    let loaded = crate::util::load_files("example.", &text, None, &[], &Limits::default())
        .expect("a CNAME with its NSEC and RRSIG");
    let ai = loaded.zone.node(&dns("ns2.example.")).expect("ns2");
    assert!(ai.rrset(RecordType::CNAME).is_some());
    assert!(ai.rrset(RecordType::NSEC).is_some());
    // ...but not with the NSEC and another type.
    let text = format!("{text}ns2.example. 3600 IN TXT \"x\"\n");
    let refused = crate::util::load_files("example.", &text, None, &[], &Limits::default())
        .expect_err("a TXT beside the CNAME");
    assert_eq!(
        crate::util::errors(refused)
            .into_iter()
            .map(|(_, k)| k)
            .collect::<Vec<_>>(),
        [ErrorKind::CnameWithOtherData {
            other: RecordType::TXT
        }]
    );
}

#[test]
fn s10_1_one_cname_per_name() {
    assert_eq!(
        refused("x CNAME ns\nx CNAME other.example.\n"),
        vec![(Some(NEXT_LINE + 1), ErrorKind::MultipleCname)]
    );
    // The same CNAME twice is one record.
    let loaded = load_extra("x CNAME ns\nx CNAME ns\n").expect("a repeated CNAME merges");
    assert_eq!(loaded.zone.record_count(), 4);
}

// --- RFC 6672 §2.3, §2.4 ---

#[test]
fn s2_4_one_dname_per_name() {
    assert_eq!(
        refused("d DNAME \\# 11 0161076578616d706c6500\nd DNAME \\# 11 0162076578616d706c6500\n"),
        vec![(Some(NEXT_LINE + 1), ErrorKind::MultipleDname)]
    );
}

#[test]
fn s2_4_a_dname_and_a_cname_do_not_share_a_name() {
    assert_eq!(
        refused("d DNAME \\# 11 0161076578616d706c6500\nd CNAME ns\n"),
        vec![(Some(NEXT_LINE + 1), ErrorKind::CnameWithDname)]
    );
}

#[test]
fn s2_3_a_dname_does_not_share_a_name_with_a_delegation() {
    assert_eq!(
        refused("d DNAME \\# 11 0161076578616d706c6500\nd NS ns.other.\n"),
        vec![(Some(NEXT_LINE + 1), ErrorKind::DnameWithNs)]
    );
}

#[test]
fn s2_3_a_dname_may_share_the_apex_with_its_ns() {
    let loaded =
        load_extra("@ DNAME \\# 15 056f74686572076578616d706c6500\n").expect("a DNAME at the apex");
    let apex = loaded.zone.node(&dns("example.")).expect("the apex");
    assert!(apex.is_dname_owner());
}

#[test]
fn the_error_report_reads_with_file_line_and_column() {
    let report = load_extra(
        "x CH A 192.0.2.9\ny IN CNAME ns\ny IN TXT \"z\"\nw IN A 192.0.2.9\nw IN 1 A 192.0.2.10\n",
    )
    .expect_err("refused");
    insta::assert_snapshot!(report);
    let text = format!("{APEX}x 5 A 192.0.2.9\nx 6 A 192.0.2.10\nsub NS ns.sub\n");
    let loaded = load(&text).expect("warnings only");
    insta::assert_snapshot!(loaded.report);
}
