//! The records of a zone transfer, the SOA aside (RFC 5936 §2.2, §3.5): each record of the zone once, occluded
//! names and glue included, and a walk that resumes from any place.

use dedens_proto::Record;
use dedens_zone::{At, Limits, Zone};

use crate::util::{load, load_files, zone_file};

fn example(file: &str) -> Zone {
    load_files("example.", &zone_file(file), None, &[], &Limits::default())
        .expect("the RFC's zone")
        .zone
}

/// The example zones of RFC 4035 and RFC 5155, and a zone with a delegation and a DNAME over names of its own.
fn zones() -> Vec<Zone> {
    let occluded = "$ORIGIN example.\n$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\n@ NS ns\nns A 192.0.2.1\n\
                    sub NS ns.sub\nns.sub A 192.0.2.2\nbelow.sub TXT \"occluded\"\n\
                    moved DNAME \\# 15 056f74686572076578616d706c6500\nx.moved A 192.0.2.3\n";
    vec![
        example("rfc4035_appendix_a.zone"),
        example("rfc5155_appendix_a.zone"),
        load(occluded).expect("a valid zone").zone,
    ]
}

/// The zone as text from its SOA and the walk: what a secondary loads from the transfer.
fn reloaded(zone: &Zone, records: &[Record<'_>]) -> Zone {
    let text: String = std::iter::once(zone.soa_record().to_string())
        .chain(records.iter().map(ToString::to_string))
        .map(|line| line + "\n")
        .collect();
    load_files(
        &zone.apex().to_string(),
        &text,
        None,
        &[],
        &Limits::default(),
    )
    .expect("the records of a zone")
    .zone
}

#[test]
fn s2_2_the_walk_and_the_soa_are_the_zone() {
    for zone in zones() {
        let records: Vec<_> = zone
            .transfer_records(At::default())
            .map(|(record, _)| record)
            .collect();
        assert_eq!(records.len() + 1, zone.record_count(), "{}", zone.apex());
        assert_eq!(reloaded(&zone, &records), zone, "{}", zone.apex());
    }
}

#[test]
fn s2_2_the_soa_is_not_in_the_walk_but_its_signatures_are() {
    let zone = example("rfc4035_appendix_a.zone");
    let apex = zone.apex();
    let types: Vec<_> = zone
        .transfer_records(At::default())
        .filter(|(record, _)| record.name == *apex)
        .map(|(record, _)| record.rdata.rtype())
        .collect();
    assert!(!types.contains(&dedens_proto::RecordType::SOA));
    assert!(types.contains(&dedens_proto::RecordType::RRSIG));
}

#[test]
fn s3_5_occluded_names_and_glue_are_transferred() {
    let zone = &zones()[2];
    let names: Vec<_> = zone
        .transfer_records(At::default())
        .map(|(record, _)| record.name.to_string())
        .collect();
    for name in ["ns.sub.example.", "below.sub.example.", "x.moved.example."] {
        assert!(names.iter().any(|n| n == name), "{name}");
    }
}

#[test]
fn a_walk_resumes_from_the_place_of_any_record() {
    for zone in zones() {
        let all: Vec<_> = zone.transfer_records(At::default()).collect();
        for (n, (_, at)) in all.iter().enumerate() {
            let rest: Vec<_> = zone
                .transfer_records(*at)
                .map(|(record, _)| record)
                .collect();
            let expected: Vec<_> = all[n + 1..]
                .iter()
                .map(|(record, _)| record.clone())
                .collect();
            assert_eq!(rest, expected, "{} after {n}", zone.apex());
        }
    }
}
