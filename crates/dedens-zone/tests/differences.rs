//! The difference of two versions of a zone and a changeset applied (RFC 1995 §4, §6, RFC 1982 §3.2, D207).
//!
//! The versions are the example zones of the RFCs and the small zone of `util::APEX`, each changed by text as a
//! person editing the zone file would: a record added, removed, retimed, a delegation cut in, the serial raised.

use dedens_proto::rdata::RData;
use dedens_proto::{Class, Question, Record, RecordType, Serial, Ttl};
use dedens_testkit::dns;
use dedens_zone::{Changeset, ChangesetError, End, ErrorKind, Kind, Limits, Node, RrSet, Zone};

use crate::util::{APEX, load, load_files, with_names_after_b, zone_file};

/// [`APEX`] at `serial`, then `extra`, loaded.
fn version(serial: u32, extra: &str) -> Zone {
    let apex = APEX.replace(" hostmaster 1 ", &format!(" hostmaster {serial} "));
    load(&format!("{apex}{extra}")).expect("a valid zone").zone
}

/// The zone of RFC 4035 appendix A, its serial and `edit` applied to the text.
fn signed(serial: u32, edit: impl Fn(String) -> String) -> Zone {
    let text = zone_file("rfc4035_appendix_a.zone").replace("1081539377", &serial.to_string());
    load_files("example.", &edit(text), None, &[], &Limits::default())
        .expect("a valid zone")
        .zone
}

/// A record as a line, to compare without ordering.
fn lines(records: &[Record<'static>]) -> Vec<String> {
    let mut lines: Vec<_> = records.iter().map(ToString::to_string).collect();
    lines.sort();
    lines
}

/// The record of one line of zone text, alone in a zone of its own.
fn record(text: &str) -> Record<'static> {
    let preamble = "$ORIGIN example.\n$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\n@ NS ns\n";
    let zone = load(&format!("{preamble}{text}")).expect("a zone").zone;
    let (name, _) = text.split_once(' ').expect("an owner");
    let node = zone.node(&dns(&format!("{name}.example."))).expect("owner");
    let (_, set) = node.rrsets().next().expect("one set");
    let rdata = set.rdatas().first().expect("a record");
    Record {
        name: dns(&format!("{name}.example.")),
        class: Class::IN,
        ttl: set.ttl(),
        rdata: rdata.clone(),
    }
}

fn soa(serial: u32) -> Record<'static> {
    let zone = version(serial, "");
    Record::new(
        zone.apex().clone(),
        zone.class(),
        zone.soa_ttl(),
        &RData::Soa(zone.soa().clone()),
    )
}

fn changeset(
    from: u32,
    to: u32,
    removed: &[&str],
    added: &[&str],
) -> Result<Changeset, ChangesetError> {
    Changeset::new(
        soa(from),
        soa(to),
        removed.iter().map(|r| record(r)).collect(),
        added.iter().map(|r| record(r)).collect(),
    )
}

// --- RFC 1995 §4: the differences between two versions ---

#[test]
fn s4_a_difference_lists_the_records_removed_and_those_added() {
    let old = version(1, "www A 192.0.2.10\nold TXT \"x\"\nkept MX 10 ns\n");
    let new = version(
        2,
        "www A 192.0.2.10\nnew A 192.0.2.20\nkept MX 10 ns\nwww AAAA 2001:db8::1\n",
    );
    let diff = Zone::diff(&old, &new).expect("serial 2 is ahead of 1");
    assert_eq!(diff.from_serial(), Serial::new(1));
    assert_eq!(diff.to_serial(), Serial::new(2));
    assert_eq!(lines(diff.removed()), lines(&[record("old TXT \"x\"")]));
    assert_eq!(
        lines(diff.added()),
        lines(&[record("new A 192.0.2.20"), record("www AAAA 2001:db8::1")])
    );
    assert_eq!(diff.from_soa().rtype(), RecordType::SOA);
    assert_eq!(diff.zone().0, &dns("example."));
}

#[test]
fn s4_the_difference_of_a_zone_with_its_next_serial_is_empty() {
    let old = version(1, "www A 192.0.2.10\n");
    let new = version(2, "www A 192.0.2.10\n");
    let diff = Zone::diff(&old, &new).expect("ahead");
    assert_eq!((diff.removed(), diff.added()), (&[][..], &[][..]));
    assert_eq!(
        old.apply(&diff, &Limits::default()).expect("applies").zone,
        new
    );
}

/// RFC 2181 §5.2: an `RRset` has one TTL, so a record whose TTL changed makes the whole set go and come again; a
/// set that kept its TTL sends only the records that changed.
#[test]
fn s4_a_changed_ttl_removes_the_set_and_adds_it_again() {
    let old = version(1, "www 300 A 192.0.2.10\nwww 300 A 192.0.2.11\n");
    let new = version(2, "www 600 A 192.0.2.10\nwww 600 A 192.0.2.11\n");
    let diff = Zone::diff(&old, &new).expect("ahead");
    assert_eq!(diff.removed().len(), 2);
    assert_eq!(diff.added().len(), 2);
    assert!(
        diff.removed()
            .iter()
            .all(|r| r.ttl == Ttl::new(300).expect("ttl"))
    );
    assert!(
        diff.added()
            .iter()
            .all(|r| r.ttl == Ttl::new(600).expect("ttl"))
    );
    assert_eq!(
        old.apply(&diff, &Limits::default()).expect("applies").zone,
        new
    );
}

#[test]
fn s4_signatures_are_records_like_the_others() {
    let old = signed(1_081_539_377, |t| t);
    let new = signed(1_081_539_378, |t| t.replace("38519", "38520"));
    let diff = Zone::diff(&old, &new).expect("ahead");
    assert!(
        diff.removed()
            .iter()
            .all(|r| r.rtype() == RecordType::RRSIG)
    );
    assert_eq!(diff.removed().len(), diff.added().len());
    assert!(
        diff.removed().len() > 5,
        "every signature carries the key tag"
    );
    assert_eq!(
        old.apply(&diff, &Limits::default()).expect("applies").zone,
        new
    );
}

/// RFC 4343 §3: a name's case is no change; RDATA compares as the zone does.
#[test]
fn s4_a_change_of_case_in_a_name_is_no_difference() {
    let old = version(1, "alias CNAME Target\n");
    let new = version(2, "alias CNAME TARGET\n");
    let diff = Zone::diff(&old, &new).expect("ahead");
    assert_eq!(diff.removed().len() + diff.added().len(), 0);
}

#[test]
fn s4_the_serial_must_be_ahead() {
    let (one, two) = (version(1, ""), version(2, ""));
    assert_eq!(
        Zone::diff(&two, &one),
        Err(ChangesetError::NotAhead {
            from: Serial::new(2),
            to: Serial::new(1)
        })
    );
    assert!(matches!(
        Zone::diff(&one, &one),
        Err(ChangesetError::NotAhead { .. })
    ));
}

/// RFC 1982 §3.2: ahead is by the circle, so 4294967295 to 1 is two steps forward.
#[test]
fn s4_a_serial_that_wrapped_is_ahead() {
    let (old, new) = (version(u32::MAX, "a A 192.0.2.1\n"), version(1, ""));
    let diff = Zone::diff(&old, &new).expect("1 is ahead of 4294967295");
    assert_eq!(
        old.apply(&diff, &Limits::default()).expect("applies").zone,
        new
    );
}

#[test]
fn s4_zones_of_two_apexes_have_no_difference() {
    let other = load_files(
        "other.",
        &APEX.replace("example.", "other.").replace(" 1 ", " 2 "),
        None,
        &[],
        &Limits::default(),
    )
    .expect("a zone")
    .zone;
    assert_eq!(
        Zone::diff(&version(1, ""), &other),
        Err(ChangesetError::DifferentZone)
    );
}

/// A zone of another class is another zone though its apex is the same.
#[test]
fn s4_zones_of_two_classes_have_no_difference() {
    let chaos = |serial: u32| {
        let text = format!(
            "$ORIGIN example.\n$TTL 1h\n@ CH SOA ns hostmaster {serial} 1d 2h 4w 1h\n@ CH NS ns\n"
        );
        load_files("example.", &text, None, &[], &Limits::default())
            .expect("a zone")
            .zone
    };
    assert_eq!(chaos(1).class(), Class::CH);
    assert_eq!(
        Zone::diff(&chaos(1), &chaos(2)).map(|c| Changeset::to_serial(&c)),
        Ok(Serial::new(2)),
        "two zones of one class"
    );
    assert_eq!(
        Zone::diff(&version(1, ""), &chaos(2)),
        Err(ChangesetError::DifferentZone)
    );
}

// --- A changeset, built by hand ---

#[test]
fn a_changeset_has_two_soa_ends_one_zone_and_a_serial_ahead() {
    let a = record("www A 192.0.2.1");
    let soa_with = |f: &dyn Fn(&mut Record<'static>)| {
        let mut r = soa(2);
        f(&mut r);
        r
    };
    let build = |from: Record<'static>, to: Record<'static>, body: Vec<Record<'static>>| {
        Changeset::new(from, to, body, Vec::new())
    };
    assert_eq!(
        build(a.clone(), soa(2), vec![]),
        Err(ChangesetError::NotSoa)
    );
    assert_eq!(
        build(soa(1), a.clone(), vec![]),
        Err(ChangesetError::NotSoa)
    );
    assert_eq!(
        build(soa(1), soa_with(&|r| r.class = Class::CH), vec![]),
        Err(ChangesetError::DifferentZone)
    );
    assert_eq!(
        build(
            soa(1),
            soa_with(&|r| r.name = dns("other.example.")),
            vec![]
        ),
        Err(ChangesetError::DifferentZone)
    );
    assert_eq!(
        build(soa(1), soa(1), vec![]),
        Err(ChangesetError::NotAhead {
            from: Serial::new(1),
            to: Serial::new(1)
        })
    );
    // RFC 1982 §3.2: 2^31 apart has no order.
    assert!(matches!(
        build(soa(1), soa(1 + (1 << 31)), vec![]),
        Err(ChangesetError::NotAhead { .. })
    ));
    assert_eq!(
        build(soa(1), soa(2), vec![soa(5)]),
        Err(ChangesetError::SoaInBody)
    );
    assert!(build(soa(1), soa(2), vec![a]).is_ok());
}

// --- Applying ---

/// The versions of the signed zone of RFC 4035 appendix A, each changed from the one before.
fn signed_versions() -> Vec<Zone> {
    let edits: [fn(String) -> String; 5] = [
        |t| t,
        |t| {
            let added = "new 3600 IN A 192.0.2.99\nnew 3600 NSEC ns1.example. A RRSIG NSEC\n";
            with_names_after_b(&t, "new.example.", added)
        },
        |t| {
            let added = "new 3600 IN A 192.0.2.99\nnew 600 IN TXT \"hi\"\n\
                         new 3600 NSEC ns1.example. A TXT RRSIG NSEC\n";
            with_names_after_b(
                &t.replace("3600 NS     ns2.example.\n", ""),
                "new.example.",
                added,
            )
        },
        |t| {
            let added = "new 3600 IN A 192.0.2.99\nnew 3600 NSEC sub.new.example. A RRSIG NSEC\n\
                         sub.new 3600 IN NS ns.sub.new\nsub.new 3600 NSEC ns1.example. NS RRSIG NSEC\n\
                         ns.sub.new 3600 IN A 192.0.2.7\n";
            let t = t.replace("3600 MX     1 xx.example.\n", "3600 MX     2 xx.example.\n");
            with_names_after_b(&t, "new.example.", added)
        },
        |t| {
            let added = "deep.er.est 3600 IN A 192.0.2.5\ndeep.er.est 3600 NSEC ns1.example. A RRSIG NSEC\n";
            with_names_after_b(&t, "deep.er.est.example.", added)
        },
    ];
    edits
        .iter()
        .enumerate()
        .map(|(n, edit)| signed(1_081_539_377 + u32::try_from(n).expect("small"), edit))
        .collect()
}

/// RFC 1995 §4: the old version and the differences give the new one, for every pair of versions.
#[test]
fn s4_the_difference_then_apply_gives_the_new_version_for_every_pair() {
    let versions = signed_versions();
    let limits = Limits::default();
    let mut pairs = 0;
    for (n, old) in versions.iter().enumerate() {
        for new in &versions[n + 1..] {
            let diff = Zone::diff(old, new).expect("ahead");
            let applied = old.apply(&diff, &limits).expect("applies").zone;
            assert_eq!(
                &applied,
                new,
                "{} to {}",
                diff.from_serial(),
                diff.to_serial()
            );
            assert_eq!(applied.record_count(), new.record_count());
            pairs += 1;
        }
    }
    assert_eq!(pairs, 10);
}

/// The other example zones, one record changed at a time.
#[test]
fn s4_the_difference_then_apply_gives_the_new_version_for_the_other_example_zones() {
    let nsec3 = zone_file("rfc5155_appendix_a.zone");
    let old = load_files("example.", &nsec3, None, &[], &Limits::default())
        .expect("zone")
        .zone;
    let edited = nsec3.replacen(
        "bugs.x.w.example. 1 3600 300 (",
        "bugs.x.w.example. 2 3600 300 (",
        1,
    );
    let new = load_files(
        "example.",
        &format!("{edited}extra.example. 3600 IN TXT \"x\"\n"),
        None,
        &[],
        &Limits::default(),
    )
    .expect("zone")
    .zone;
    let diff = Zone::diff(&old, &new).expect("ahead");
    assert_eq!(diff.added().len(), 1);
    assert_eq!(
        old.apply(&diff, &Limits::default()).expect("applies").zone,
        new
    );
}

#[test]
fn applying_leaves_the_old_version_as_it_was() {
    let old = version(1, "www A 192.0.2.10\n");
    let before = old.clone();
    let diff = Zone::diff(&old, &version(2, "")).expect("ahead");
    let new = old.apply(&diff, &Limits::default()).expect("applies").zone;
    assert_eq!(old, before);
    assert_eq!(new.record_count(), 3);
    assert!(new.node(&dns("www.example.")).is_none());
}

/// RFC 1034 §4.2.1: a delegation added by a change occludes the names below it, and a name's last record removed
/// takes its empty non-terminals with it: the kinds are found again, as a load finds them.
#[test]
fn applying_finds_the_kinds_and_the_empty_non_terminals_again() {
    let old = version(1, "a.b.c A 192.0.2.1\nx.y A 192.0.2.2\n");
    let new = version(2, "c NS ns.c\nns.c A 192.0.2.3\na.b.c A 192.0.2.1\n");
    let diff = Zone::diff(&old, &new).expect("ahead");
    let applied = old.apply(&diff, &Limits::default()).expect("applies").zone;
    assert_eq!(applied, new);
    let kind = |n: &str| applied.node(&dns(n)).map(Node::kind);
    assert_eq!(kind("c.example."), Some(Kind::Delegation));
    let Some(Kind::Occluded { cut }) = kind("b.c.example.") else {
        panic!("b.c is occluded");
    };
    assert_eq!(
        applied.nodes().nth(cut).map(|(name, _)| name.clone()),
        Some(dns("c.example.")),
        "the cut is found again"
    );
    assert_eq!(kind("y.example."), None, "x.y's removal took its parent");
    let back = version(3, "x.y A 192.0.2.2\n");
    let diff = Zone::diff(&applied, &back).expect("ahead");
    let again = applied
        .apply(&diff, &Limits::default())
        .expect("applies")
        .zone;
    assert_eq!(
        again.node(&dns("y.example.")).map(Node::kind),
        Some(Kind::EmptyNonTerminal)
    );
}

#[test]
fn an_rrset_is_equal_to_the_same_records_in_another_order() {
    let a = version(1, "www A 192.0.2.1\nwww A 192.0.2.2\n");
    let b = version(1, "www A 192.0.2.2\nwww A 192.0.2.1\n");
    assert_eq!(a, b);
    assert_ne!(a, version(1, "www A 192.0.2.2\nwww A 192.0.2.3\n"));
    assert_ne!(a, version(1, "www A 192.0.2.1\n"));
}

// --- Applying a changeset that is wrong ---

fn kinds(report: dedens_zone::Report) -> Vec<(Option<(usize, usize)>, ErrorKind)> {
    report
        .errors
        .into_iter()
        .map(|e| (e.at.map(|a| (a.file, a.line)), e.kind))
        .collect()
}

/// RFC 1995 §4: the differences are from one version; another is no use.
#[test]
fn s4_a_changeset_from_another_version_is_refused() {
    let zone = version(5, "");
    let changeset = changeset(1, 2, &[], &["www A 192.0.2.1"]).expect("valid");
    let report = zone
        .apply(&changeset, &Limits::default())
        .expect_err("wrong version");
    assert_eq!(
        kinds(report),
        [(
            Some((1, 1)),
            ErrorKind::WrongVersion {
                zone: Serial::new(5),
                changeset: Serial::new(1)
            }
        )]
    );
}

/// RFC 1995 §4: a deleted record is one of the old version.
#[test]
fn s4_a_record_to_remove_that_the_zone_lacks_is_refused_with_its_place() {
    let zone = version(1, "www A 192.0.2.1\n");
    let changeset = changeset(
        1,
        2,
        &["www A 192.0.2.1", "www A 192.0.2.77", "gone TXT \"x\""],
        &[],
    )
    .expect("valid");
    let report = zone
        .apply(&changeset, &Limits::default())
        .expect_err("absent");
    assert_eq!(
        kinds(report.clone()),
        [
            (
                Some((1, 3)),
                ErrorKind::RemoveAbsent {
                    owner: dns("www.example."),
                    rtype: RecordType::A
                }
            ),
            (
                Some((1, 4)),
                ErrorKind::RemoveAbsent {
                    owner: dns("gone.example."),
                    rtype: RecordType::TXT
                }
            ),
        ]
    );
    assert_eq!(
        report.to_string().lines().next(),
        Some(
            "changeset:3:1: error: www.example. A record to remove is not in the zone (RFC 1995 §4)"
        )
    );
}

/// RFC 1995 §4 deletes by data: the TTL of the record sent is what the sender had, and the zone's may be other.
#[test]
fn s4_a_record_is_removed_whatever_its_ttl() {
    let zone = version(1, "www 300 A 192.0.2.1\n");
    let changeset = changeset(1, 2, &["www 999 A 192.0.2.1"], &[]).expect("valid");
    let applied = zone
        .apply(&changeset, &Limits::default())
        .expect("applies")
        .zone;
    assert!(applied.node(&dns("www.example.")).is_none());
}

/// RFC 5155 §7.2.8: a node holding only NSEC3 records is no name unless a node is below it, which a change can add
/// or remove, so the mark of the applied zone is that of a load of it (D206).
#[test]
fn s7_2_8_the_proof_only_mark_follows_the_changes_applied() {
    let nsec3 = "hash NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX\n";
    let child = "child.hash A 192.0.2.5";
    let proof_only = |zone: &Zone| {
        zone.node(&dns("hash.example."))
            .expect("the hash")
            .is_proof_only()
    };
    let no_data = |zone: &Zone| {
        let question = Question::new(dns("hash.example."), RecordType::A);
        matches!(zone.answer(&question).end, End::NoData { .. })
    };
    let old = version(1, nsec3);
    assert!(proof_only(&old));
    assert!(!no_data(&old));

    let add = changeset(1, 2, &[], &[child]).expect("valid");
    let with_child = old.apply(&add, &Limits::default()).expect("applies").zone;
    assert!(!proof_only(&with_child));
    assert!(no_data(&with_child));
    assert_eq!(with_child, version(2, &format!("{nsec3}{child}\n")));

    let remove = changeset(2, 3, &[child], &[]).expect("valid");
    let without = with_child
        .apply(&remove, &Limits::default())
        .expect("applies")
        .zone;
    assert!(proof_only(&without));
    assert!(!no_data(&without));
}

/// The checks of a load run on the zone after the change: RFC 2181 §10.1, RFC 1035 §5.2.
#[test]
fn a_change_that_breaks_the_zone_is_refused_by_the_checks_of_a_load() {
    let zone = version(1, "www A 192.0.2.1\n");
    let cname = changeset(1, 2, &[], &["www CNAME ns"]).expect("valid");
    let report = zone
        .apply(&cname, &Limits::default())
        .expect_err("CNAME beside A");
    assert_eq!(
        kinds(report),
        [(
            Some((1, 3)),
            ErrorKind::CnameWithOtherData {
                other: RecordType::A
            }
        )]
    );
    let apex_ns = {
        let node = zone.node(&dns("example.")).expect("apex");
        let ns = node.rrset(RecordType::NS).expect("NS");
        Record {
            name: dns("example."),
            class: Class::IN,
            ttl: ns.ttl(),
            rdata: ns.rdatas()[0].clone(),
        }
    };
    let no_ns = Changeset::new(soa(1), soa(2), vec![apex_ns], vec![]).expect("valid");
    let report = zone.apply(&no_ns, &Limits::default()).expect_err("no NS");
    assert_eq!(kinds(report), [(None, ErrorKind::NoApexNs)]);
}

/// The RDATA bytes of every record of `zone`, as `Limits::rdata_bytes` counts them.
fn rdata_bytes(zone: &Zone) -> usize {
    zone.nodes()
        .flat_map(|(_, node)| {
            node.rrsets()
                .map(|(_, set)| set)
                .chain(node.signature_sets())
        })
        .flat_map(RrSet::rdatas)
        .map(|rdata| rdata.wire().len())
        .sum()
}

/// Removing counts: a change that takes out as many bytes as it puts in fits the limit that the zone fills, one that
/// puts in more does not.
#[test]
fn a_change_past_the_rdata_bytes_is_refused_and_removals_make_room() {
    let zone = version(1, "t TXT \"ab\"\n");
    let limits = Limits {
        rdata_bytes: rdata_bytes(&zone),
        ..Limits::default()
    };
    let same = changeset(1, 2, &["t TXT \"ab\""], &["t TXT \"cd\""]).expect("valid");
    assert!(zone.apply(&same, &limits).is_ok());
    let bigger = changeset(1, 2, &["t TXT \"ab\""], &["t TXT \"cdef\""]).expect("valid");
    let report = zone
        .apply(&bigger, &limits)
        .expect_err("two bytes too many");
    assert!(matches!(
        report.errors.first().map(|e| &e.kind),
        Some(ErrorKind::Limit { limit, .. }) if *limit == limits.rdata_bytes
    ));
    let room = Limits {
        rdata_bytes: limits.rdata_bytes + 2,
        ..limits
    };
    assert!(zone.apply(&bigger, &room).is_ok());
}

/// The line of a record in an error is its place in the sequence of RFC 1995 §4: after the old SOA, the removed
/// records, the new SOA, and the added ones before it.
#[test]
fn s4_an_added_record_has_its_place_in_the_sequence_as_its_line() {
    let zone = version(1, "www A 192.0.2.1\nold A 192.0.2.2\n");
    let change = changeset(
        1,
        2,
        &["old A 192.0.2.2"],
        &["a A 192.0.2.5", "b A 192.0.2.6", "www CNAME ns"],
    )
    .expect("valid");
    let report = zone
        .apply(&change, &Limits::default())
        .expect_err("CNAME beside A");
    // Old SOA 1, removed 2, new SOA 3, added 4, 5 and 6.
    assert_eq!(
        kinds(report),
        [(
            Some((1, 6)),
            ErrorKind::CnameWithOtherData {
                other: RecordType::A
            }
        )]
    );
}

#[test]
fn a_change_past_a_limit_is_refused() {
    let zone = version(1, "");
    let limits = Limits {
        records: zone.record_count(),
        ..Limits::default()
    };
    let more = changeset(1, 2, &[], &["www A 192.0.2.1"]).expect("valid");
    let report = zone.apply(&more, &limits).expect_err("one record too many");
    assert!(matches!(
        report.errors.first().map(|e| &e.kind),
        Some(ErrorKind::Limit { limit, .. }) if *limit == zone.record_count()
    ));
    // A change that removes as much as it adds fits, the SOA swap included.
    let swap = changeset(1, 2, &["ns A 192.0.2.1"], &["ns A 192.0.2.9"]).expect("valid");
    assert!(zone.apply(&swap, &limits).is_ok());
}

// --- RFC 1995 §6: condensed differences ---

/// RFC 1995 §6: the differences of several versions in one sequence give the same zone as the steps one by one,
/// and the same records as the difference of the first and the last version.
#[test]
fn s6_condensed_differences_equal_the_difference_of_the_ends() {
    let versions = signed_versions();
    let limits = Limits::default();
    for (n, first) in versions.iter().enumerate() {
        for last in 2..=versions.len() - n {
            let range = &versions[n..n + last];
            let steps: Vec<_> = range
                .windows(2)
                .map(|w| Zone::diff(&w[0], &w[1]).expect("ahead"))
                .collect();
            let condensed = steps
                .into_iter()
                .reduce(|a, b| a.condense(b).expect("consecutive"))
                .expect("a step");
            let end = range.last().expect("a version");
            let direct = Zone::diff(first, end).expect("ahead");
            assert_eq!(lines(condensed.removed()), lines(direct.removed()));
            assert_eq!(lines(condensed.added()), lines(direct.added()));
            assert_eq!(condensed.from_serial(), direct.from_serial());
            assert_eq!(condensed.to_serial(), direct.to_serial());
            assert_eq!(
                &first.apply(&condensed, &limits).expect("applies").zone,
                end
            );
        }
    }
}

/// RFC 1995 §6: a record added then removed is in neither; one removed then added again is in neither either.
#[test]
fn s6_a_record_added_then_removed_is_in_neither_list() {
    let a = version(1, "keep A 192.0.2.1\ngone A 192.0.2.2\n");
    let b = version(2, "keep A 192.0.2.1\ntemp A 192.0.2.3\n");
    let c = version(3, "keep A 192.0.2.1\ngone A 192.0.2.2\n");
    let ab = Zone::diff(&a, &b).expect("ahead");
    let bc = Zone::diff(&b, &c).expect("ahead");
    let condensed = ab.condense(bc).expect("consecutive");
    assert_eq!((condensed.removed(), condensed.added()), (&[][..], &[][..]));
    assert_eq!(condensed.from_serial(), Serial::new(1));
    assert_eq!(condensed.to_serial(), Serial::new(3));
}

/// A TTL changed twice leaves the first record removed and the last added.
#[test]
fn s6_a_ttl_changed_twice_keeps_the_first_removal_and_the_last_addition() {
    let a = version(1, "www 100 A 192.0.2.1\n");
    let b = version(2, "www 200 A 192.0.2.1\n");
    let c = version(3, "www 300 A 192.0.2.1\n");
    let condensed = Zone::diff(&a, &b)
        .expect("ahead")
        .condense(Zone::diff(&b, &c).expect("ahead"))
        .expect("consecutive");
    assert_eq!(condensed.removed().len(), 1);
    assert_eq!(condensed.removed()[0].ttl, Ttl::new(100).expect("ttl"));
    assert_eq!(condensed.added().len(), 1);
    assert_eq!(condensed.added()[0].ttl, Ttl::new(300).expect("ttl"));
}

#[test]
fn s6_changesets_that_do_not_follow_each_other_are_not_condensed() {
    let (a, b, c) = (version(1, ""), version(2, ""), version(3, ""));
    let ab = Zone::diff(&a, &b).expect("ahead");
    let ac = Zone::diff(&a, &c).expect("ahead");
    assert_eq!(ab.condense(ac), Err(ChangesetError::NotConsecutive));
}

/// Two steps of 2^30 are a step of 2^31, which RFC 1982 §3.2 leaves with no order: the changeset cannot exist.
#[test]
fn s6_condensing_past_half_the_circle_is_refused() {
    let first = changeset(1, 1 + (1 << 30), &[], &[]).expect("valid");
    let second =
        Changeset::new(soa(1 + (1 << 30)), soa(1 + (1 << 31)), vec![], vec![]).expect("valid");
    assert!(matches!(
        first.condense(second),
        Err(ChangesetError::NotAhead { .. })
    ));
}
