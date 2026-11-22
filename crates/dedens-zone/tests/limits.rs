//! Each bound of `Limits` (D204), reached: a record past it is an error naming it, once, and the load goes on to
//! report the rest.

use dedens_zone::{Bound, ErrorKind, Limits};

use crate::util::{APEX, NEXT_LINE, errors, load_files, load_with};

/// The errors of loading [`APEX`] and `extra` under `limits`.
fn refused(extra: &str, limits: &Limits) -> Vec<(Option<usize>, ErrorKind)> {
    errors(load_with(&format!("{APEX}{extra}"), limits).expect_err("a bound reached"))
}

fn limit(bound: Bound, limit: usize) -> ErrorKind {
    ErrorKind::Limit { bound, limit }
}

#[test]
fn the_defaults_are_the_ones_d204_documents() {
    let l = Limits::default();
    assert_eq!(
        (l.records, l.names, l.records_per_rrset, l.rrsets_per_name),
        (1 << 24, 1 << 24, 100, 100)
    );
    assert_eq!(
        (l.rdata_bytes, l.include_depth, l.errors),
        (1 << 30, 8, 100)
    );
}

#[test]
fn records_in_the_zone() {
    // The apex holds 3 records, one name more.
    let limits = Limits {
        records: 4,
        ..Limits::default()
    };
    assert_eq!(
        refused("x A 192.0.2.9\ny A 192.0.2.10\nz A 192.0.2.11\n", &limits),
        [(Some(NEXT_LINE + 1), limit(Bound::Records, 4))]
    );
    load_with(&format!("{APEX}x A 192.0.2.9\n"), &limits).expect("at the bound");
}

#[test]
fn names_in_the_zone() {
    let limits = Limits {
        names: 3,
        ..Limits::default()
    };
    assert_eq!(
        refused("x A 192.0.2.9\ny A 192.0.2.10\nz A 192.0.2.11\n", &limits),
        [(Some(NEXT_LINE + 1), limit(Bound::Names, 3))]
    );
}

#[test]
fn names_in_the_zone_count_the_empty_non_terminals() {
    // `a.b.c` makes `b.c` and `c`: the apex, ns, a.b.c, b.c, c.
    let limits = Limits {
        names: 4,
        ..Limits::default()
    };
    assert_eq!(
        refused("a.b.c A 192.0.2.9\n", &limits),
        [(None, limit(Bound::Names, 4))]
    );
    let limits = Limits {
        names: 5,
        ..Limits::default()
    };
    load_with(&format!("{APEX}a.b.c A 192.0.2.9\n"), &limits).expect("at the bound");
}

#[test]
fn records_in_an_rrset() {
    let limits = Limits {
        records_per_rrset: 2,
        ..Limits::default()
    };
    assert_eq!(
        refused(
            "x A 192.0.2.9\nx A 192.0.2.10\nx A 192.0.2.11\nx A 192.0.2.12\n",
            &limits
        ),
        [(Some(NEXT_LINE + 2), limit(Bound::RecordsPerRrset, 2))]
    );
    // A duplicate is no record.
    load_with(
        &format!("{APEX}x A 192.0.2.9\nx A 192.0.2.10\nx A 192.0.2.9\n"),
        &limits,
    )
    .expect("at the bound");
}

#[test]
fn rrsets_at_a_name() {
    let limits = Limits {
        rrsets_per_name: 2,
        ..Limits::default()
    };
    assert_eq!(
        refused(
            "x A 192.0.2.9\nx TXT \"a\"\nx MX 1 ns\nx AAAA 2001:db8::1\n",
            &limits
        ),
        [(Some(NEXT_LINE + 2), limit(Bound::RrsetsPerName, 2))]
    );
    // More records of a type already there do not count.
    load_with(
        &format!("{APEX}x A 192.0.2.9\nx TXT \"a\"\nx A 192.0.2.10\n"),
        &limits,
    )
    .expect("at the bound");
}

#[test]
fn rdata_bytes_in_the_zone() {
    // The SOA holds 12 + 20 + 20 bytes, the NS 12, the A record 4: the apex and `ns` come to 68.
    let at_bound = load_with(APEX, &Limits::default()).expect("a zone");
    assert_eq!(at_bound.zone.record_count(), 3);
    let limits = Limits {
        rdata_bytes: 68,
        ..Limits::default()
    };
    load_with(APEX, &limits).expect("the apex fits");
    assert_eq!(
        refused("x A 192.0.2.9\ny A 192.0.2.10\n", &limits),
        [(Some(NEXT_LINE), limit(Bound::RdataBytes, 68))]
    );
}

#[test]
fn levels_of_include() {
    let text = format!("{APEX}$INCLUDE again.db\n");
    let again = "$INCLUDE again.db\n";
    let limits = Limits {
        include_depth: 3,
        ..Limits::default()
    };
    let report = load_files("example.", &text, None, &[("again.db", again)], &limits)
        .expect_err("an endless include");
    assert_eq!(
        report.files,
        ["zone.db", "again.db", "again.db", "again.db"]
    );
    assert_eq!(errors(report), [(Some(1), limit(Bound::IncludeDepth, 3))]);
}

#[test]
fn errors_are_reported_up_to_the_limit() {
    let limits = Limits {
        errors: 2,
        ..Limits::default()
    };
    let found = refused(
        "a CH A 192.0.2.9\nb CH A 192.0.2.9\nc CH A 192.0.2.9\nd CH A 192.0.2.9\n",
        &limits,
    );
    assert_eq!(found.len(), 3);
    assert_eq!(found.last(), Some(&(None, ErrorKind::Stopped { limit: 2 })));
}
