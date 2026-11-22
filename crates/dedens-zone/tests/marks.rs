//! What a name is to answers: RFC 1034 §4.2.1 (delegations and what is below them), RFC 9471 §2 (glue), RFC 6672 §2.4
//! (a DNAME's subtree), and the shape of the zone: canonical order, empty non-terminals (RFC 4592 §2.2.2),
//! wildcards (RFC 4592 §2.1.1).

use dedens_proto::{Name, RecordType};
use dedens_testkit::dns;
use dedens_zone::{Kind, Limits, Loaded, Warning, WarningKind};

use crate::util::{NEXT_LINE, load_extra, load_files, zone_file};

fn signed() -> Loaded {
    load_files(
        "example.",
        &zone_file("rfc4035_appendix_a.zone"),
        None,
        &[],
        &Limits::default(),
    )
    .expect("the RFC's zone")
}

fn kind(loaded: &Loaded, name: &str) -> Kind {
    loaded.zone.node(&dns(name)).expect("a node").kind()
}

// --- RFC 1034 §4.2.1 ---

#[test]
fn s4_2_1_a_delegation_point_and_what_is_below_it() {
    let loaded = signed();
    assert_eq!(kind(&loaded, "example."), Kind::Authoritative);
    assert_eq!(kind(&loaded, "a.example."), Kind::Delegation);
    assert_eq!(kind(&loaded, "b.example."), Kind::Delegation);
    // The glue is below the cut.
    assert_eq!(kind(&loaded, "ns1.a.example."), Kind::Occluded);
    assert_eq!(kind(&loaded, "ns2.a.example."), Kind::Occluded);
    assert_eq!(kind(&loaded, "ns1.example."), Kind::Authoritative);
    assert_eq!(kind(&loaded, "ai.example."), Kind::Authoritative);
}

#[test]
fn s4_2_1_data_below_a_delegation_is_kept_even_when_no_glue() {
    let loaded = load_extra("sub NS ns.other.\nwww.sub A 192.0.2.9\ndeep.www.sub A 192.0.2.10\n")
        .expect("a zone");
    assert_eq!(kind(&loaded, "sub.example."), Kind::Delegation);
    assert_eq!(kind(&loaded, "www.sub.example."), Kind::Occluded);
    assert_eq!(kind(&loaded, "deep.www.sub.example."), Kind::Occluded);
    assert_eq!(kind(&loaded, "ns.example."), Kind::Authoritative);
    let www = loaded.zone.node(&dns("www.sub.example.")).expect("www.sub");
    assert!(www.rrset(RecordType::A).is_some());
}

#[test]
fn s4_2_1_a_delegation_below_a_delegation_is_occluded() {
    let loaded = load_extra("sub NS ns.other.\ndeeper.sub NS ns.other.\n").expect("a zone");
    assert_eq!(kind(&loaded, "deeper.sub.example."), Kind::Occluded);
}

// --- RFC 9471 §2 ---

#[test]
fn s2_a_name_server_inside_its_delegation_needs_an_address() {
    let loaded =
        load_extra("sub NS ns.sub\nsub NS ns.other.\nsub NS ns2.sub\nns2.sub AAAA 2001:db8::1\n")
            .expect("a warning only");
    assert_eq!(
        loaded.report.warnings,
        [Warning {
            at: loaded.report.warnings.first().expect("a warning").at,
            kind: WarningKind::MissingGlue {
                delegation: dns("sub.example."),
                target: dns("ns.sub.example."),
            },
        }]
    );
    assert_eq!(
        loaded.report.warnings.first().map(|w| w.at.line),
        Some(NEXT_LINE)
    );
}

#[test]
fn s2_the_delegation_itself_as_name_server_needs_an_address() {
    let loaded = load_extra("sub NS sub\n").expect("a warning only");
    assert!(matches!(
        loaded.report.warnings.as_slice(),
        [Warning {
            kind: WarningKind::MissingGlue { .. },
            ..
        }]
    ));
}

// --- RFC 6672 §2.4 ---

#[test]
fn s2_4_names_below_a_dname_are_kept_and_reported_once() {
    let loaded = load_extra("d DNAME \\# 15 056f74686572076578616d706c6500\nx.d A 192.0.2.9\ny.d A 192.0.2.10\nz.d.d A 192.0.2.11\n")
        .expect("a warning only");
    let d = loaded.zone.node(&dns("d.example.")).expect("d");
    assert_eq!((d.kind(), d.is_dname_owner()), (Kind::Authoritative, true));
    assert_eq!(kind(&loaded, "x.d.example."), Kind::Occluded);
    assert_eq!(kind(&loaded, "z.d.d.example."), Kind::Occluded);
    assert_eq!(
        kind(&loaded, "d.d.example."),
        Kind::Occluded,
        "an empty non-terminal below"
    );
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
            &WarningKind::BelowDname {
                first: dns("d.d.example."),
            }
        )]
    );
}

#[test]
fn s2_4_a_dname_at_the_apex_occludes_all_below() {
    let loaded = load_extra("@ DNAME \\# 15 056f74686572076578616d706c6500\n").expect("a zone");
    assert_eq!(kind(&loaded, "example."), Kind::Authoritative);
    assert_eq!(kind(&loaded, "ns.example."), Kind::Occluded);
    assert_eq!(loaded.report.warnings.len(), 1);
}

// --- the shape of the zone ---

#[test]
fn the_nodes_are_in_canonical_order() {
    let loaded = signed();
    let names: Vec<Name<'static>> = loaded.zone.nodes().map(|(n, _)| n.clone()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    assert_eq!(names.first(), Some(&dns("example.")));
    assert_eq!(loaded.zone.nodes().len(), names.len());
}

#[test]
fn s2_2_2_a_name_between_a_record_and_the_apex_is_an_empty_non_terminal() {
    // RFC 4035 appendix A: `x.y.w.example.` holds a record, `y.w.example.` and `w.example.` none.
    let loaded = signed();
    assert_eq!(kind(&loaded, "y.w.example."), Kind::EmptyNonTerminal);
    assert_eq!(kind(&loaded, "w.example."), Kind::EmptyNonTerminal);
    let w = loaded.zone.node(&dns("w.example.")).expect("w");
    assert_eq!(w.rrsets().len(), 0);
    assert_eq!(loaded.zone.node(&dns("nothing.example.")), None);
}

#[test]
fn s2_1_1_a_wildcard_owner_is_marked() {
    let loaded = signed();
    let wildcard = loaded
        .zone
        .node(&dns("*.w.example."))
        .expect("the wildcard");
    assert!(wildcard.is_wildcard());
    let x = loaded.zone.node(&dns("x.w.example.")).expect("x.w");
    assert!(!x.is_wildcard());
    // `*` is a wildcard only as the whole first label.
    let loaded = load_extra("a*.b A 192.0.2.9\n*a A 192.0.2.10\n").expect("a zone");
    assert!(
        !loaded
            .zone
            .node(&dns("a*.b.example."))
            .expect("a*.b")
            .is_wildcard()
    );
    assert!(
        !loaded
            .zone
            .node(&dns("*a.example."))
            .expect("*a")
            .is_wildcard()
    );
}

#[test]
fn a_name_is_found_whatever_its_case() {
    let loaded = signed();
    assert!(loaded.zone.node(&dns("NS1.A.Example.")).is_some());
}

#[test]
fn a_duplicate_is_one_record() {
    let loaded = load_extra("x A 192.0.2.9\nx A 192.0.2.9\nx A 192.0.2.10\n").expect("a zone");
    let x = loaded.zone.node(&dns("x.example.")).expect("x");
    assert_eq!(x.rrset(RecordType::A).expect("A").rdatas().len(), 2);
    assert_eq!(loaded.zone.record_count(), 3 + 2);
}
