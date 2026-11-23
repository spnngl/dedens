//! Finding a name in a zone: its closest encloser (RFC 1034 §4.3.2 step 3c) and the cut above it (step 3b, RFC 6672
//! §3.1), by a lookup of the name and its neighbour in the sorted nodes, against the search label by label that
//! the RFC describes (D206).

use std::collections::BTreeMap;
use std::fmt::Write;

use dedens_proto::{Name, Question, RecordType};
use dedens_testkit::dns;
use dedens_zone::{End, Limits, Link};
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

use crate::util::load_files;

/// The labels of a name below the apex, the one next to the apex first: each is `a`, `b` or `c`.
type Path = Vec<u8>;

/// What a name of the zone holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holds {
    Address,
    Delegation,
    Dname,
}

/// The name of `path` in the zone `example.`.
fn name(path: &[u8]) -> Name<'static> {
    let labels: String = path
        .iter()
        .rev()
        .flat_map(|label| [char::from(b'a' + label), '.'])
        .collect();
    dns(&format!("{labels}example."))
}

/// The zone text of the names: the SOA and NS of the apex, then one record each. A DNAME leads to `other.`.
fn text(names: &BTreeMap<Path, Holds>) -> String {
    let mut text = String::from(
        "$ORIGIN example.\n$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\n@ NS ns\nns A 192.0.2.1\n",
    );
    for (path, holds) in names {
        let owner = name(path);
        let record = match holds {
            Holds::Address => "A 192.0.2.9",
            Holds::Delegation => "NS ns.other.",
            Holds::Dname => "DNAME \\# 7 056f7468657200",
        };
        writeln!(text, "{owner} {record}").expect("writes");
    }
    text
}

/// Where the RFC's search ends for the name of `path`, asked for A.
#[derive(Debug, PartialEq, Eq)]
enum Expected {
    Data,
    NoData,
    /// A delegation point refers: its name.
    Referral(Path),
    /// A DNAME owner redirects: its name.
    Redirect(Path),
    /// The closest encloser.
    NxDomain(Path),
}

/// A name of the zone, an empty non-terminal included, is one with a name of `names` at or below it.
fn exists(names: &BTreeMap<Path, Holds>, path: &[u8]) -> bool {
    path.is_empty() || names.keys().any(|key| key.starts_with(path))
}

/// The search of RFC 1034 §4.3.2, one label at a time from the apex.
fn expected(names: &BTreeMap<Path, Holds>, path: &[u8]) -> Expected {
    for above in 1..path.len() {
        match names.get(&path[..above]) {
            Some(Holds::Delegation) => return Expected::Referral(path[..above].to_vec()),
            Some(Holds::Dname) => return Expected::Redirect(path[..above].to_vec()),
            _ => {}
        }
    }
    match names.get(path) {
        Some(Holds::Address) => Expected::Data,
        Some(Holds::Delegation) => Expected::Referral(path.to_vec()),
        Some(Holds::Dname) => Expected::NoData,
        None if exists(names, path) => Expected::NoData,
        None => {
            let encloser = (0..path.len())
                .rev()
                .find(|depth| exists(names, &path[..*depth]))
                .unwrap_or_default();
            Expected::NxDomain(path[..encloser].to_vec())
        }
    }
}

/// Every name of up to `depth` labels with the labels `a`, `b` and `c`.
fn paths(depth: usize) -> Vec<Path> {
    let mut all = vec![Vec::new()];
    let mut level = vec![Vec::new()];
    for _ in 0..depth {
        level = level
            .iter()
            .flat_map(|path: &Path| {
                (0..3).map(|label| {
                    let mut next = path.clone();
                    next.push(label);
                    next
                })
            })
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

proptest! {
    /// Whatever the zone holds, the answer for each name of five labels or fewer is what the search from the
    /// apex finds: the closest encloser of a name that is not there, the first cut above one that is hidden, and
    /// the name itself otherwise.
    #[test]
    fn s4_3_2_a_lookup_ends_where_the_search_from_the_apex_does(
        names in btree_map(
            vec(0_u8..3, 1..=3),
            prop_oneof![
                3 => Just(Holds::Address),
                1 => Just(Holds::Delegation),
                1 => Just(Holds::Dname),
            ],
            0..12,
        )
    ) {
        let zone = load_files("example.", &text(&names), None, &[], &Limits::default())
            .expect("a zone")
            .zone;
        for path in paths(5).into_iter().filter(|path| !path.is_empty()) {
            let question = Question::new(name(&path), RecordType::A);
            let answer = zone.answer(&question);
            let found = match (&answer.end, answer.chain.as_slice()) {
                (End::Data { .. }, []) => Expected::Data,
                (End::NoData { .. }, []) => Expected::NoData,
                (End::Referral { cut }, []) => Expected::Referral(
                    paths(3).into_iter().find(|p| name(p) == *cut.name).unwrap_or_default(),
                ),
                (End::NxDomain { encloser, .. }, []) => Expected::NxDomain(
                    paths(3).into_iter().find(|p| name(p) == *encloser.name).unwrap_or_default(),
                ),
                (End::Open { .. }, [Link::Dname { at, .. }]) => Expected::Redirect(
                    paths(3).into_iter().find(|p| name(p) == *at.name).unwrap_or_default(),
                ),
                (end, chain) => panic!("{}: {end:?} after {chain:?}", name(&path)),
            };
            prop_assert_eq!(found, expected(&names, &path), "{}", name(&path));
        }
    }
}
