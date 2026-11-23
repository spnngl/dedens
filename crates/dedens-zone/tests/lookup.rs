//! Finding a name in a zone: its closest encloser (RFC 1034 §4.3.2 step 3c, RFC 4592 §2.2.1 for a wildcard) and the
//! cut above it (step 3b, RFC 6672 §3.1), by a lookup of the name and its neighbour in the sorted nodes, against the
//! search label by label that the RFC describes (D206). Names with NSEC3 records only are not names (RFC 5155
//! §7.2.8), as in Knot, whose main tree has none.

use std::collections::BTreeMap;
use std::fmt::Write;

use dedens_proto::{Name, Question, RecordType};
use dedens_zone::{End, Limits, Link, Match};
use proptest::collection::vec;
use proptest::prelude::*;

use crate::util::load_files;

/// The labels of the names: `a`, `b`, `c`, a wildcard, and the first hash of RFC 5155 appendix A.
const LABELS: [&str; 5] = ["a", "b", "c", "*", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"];

/// The index in [`LABELS`] of the wildcard.
const WILDCARD: u8 = 3;

/// The index in [`LABELS`] of the hash.
const HASH: u8 = 4;

/// The apexes: one label, two, and the root.
const APEXES: [&str; 3] = ["example.", "x.y.example.", "."];

/// The longest a name of the zone is below the apex, made of a shared prefix and a tail.
const TRUNK: usize = 9;

/// The labels of a name below the apex as indexes in [`LABELS`], the one next to the apex first.
type Path = Vec<u8>;

/// What a name of the zone holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holds {
    Address,
    Delegation,
    Dname,
    /// NSEC3 records only.
    Nsec3,
}

/// The text of the name of `path` below `apex`, the labels in the case `seed` gives, if there is one.
fn text_name(path: &[u8], apex: &str, seed: Option<u64>) -> String {
    let mut text = String::new();
    let mut at = 0;
    for label in path.iter().rev() {
        for c in LABELS[usize::from(*label)].chars() {
            text.push(if seed.is_some_and(|seed| seed >> (at % 64) & 1 == 1) {
                c.to_ascii_uppercase()
            } else {
                c
            });
            at += 1;
        }
        text.push('.');
    }
    if apex == "." && !path.is_empty() {
        text
    } else {
        text + apex
    }
}

/// The zone text of the names: the SOA and NS of the apex, then one record each. A DNAME leads to `other.`.
fn zone_text(apex: &str, names: &BTreeMap<Path, Holds>) -> String {
    let mut text = format!(
        "$ORIGIN {apex}\n$TTL 1h\n@ SOA ns.example. h.example. 1 1d 2h 4w 1h\n@ NS ns.example.\n"
    );
    for (path, holds) in names {
        let owner = text_name(path, apex, None);
        let record = match holds {
            Holds::Address => "A 192.0.2.9",
            Holds::Delegation => "NS ns.other.",
            Holds::Dname => "DNAME \\# 7 056f7468657200",
            Holds::Nsec3 => "NSEC3 1 0 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A",
        };
        writeln!(text, "{owner} {record}").expect("writes");
    }
    text
}

/// Where the search ends: the names in lower case.
#[derive(Debug, PartialEq, Eq)]
enum Ends {
    Data(String),
    NoData(String),
    /// The wildcard that answers.
    Wildcard(String),
    NxDomain(String),
    Referral(String),
    Redirect(String),
    /// What no name can end in, for the assertion to show.
    Other(String),
}

/// What the answer for `name`, asked for A, is, in the form of [`Ends`].
fn found(zone: &dedens_zone::Zone, name: Name<'static>) -> Ends {
    let question = Question::new(name, RecordType::A);
    let answer = zone.answer(&question);
    let lower = |name: &Name<'_>| name.to_string().to_ascii_lowercase();
    // A DNAME ends the search; what its target leads to is another search, in the root zone too.
    if let Some(Link::Dname { at, .. }) = answer.chain.first() {
        return Ends::Redirect(lower(at.name));
    }
    match (&answer.end, answer.chain.as_slice()) {
        (
            End::Data {
                at: Match::Exact(at),
                ..
            },
            [],
        ) => Ends::Data(lower(at.name)),
        (
            End::NoData {
                at: Match::Exact(at),
                ..
            },
            [],
        ) => Ends::NoData(lower(at.name)),
        (
            End::Data {
                at: Match::Wildcard { source, .. },
                ..
            }
            | End::NoData {
                at: Match::Wildcard { source, .. },
                ..
            },
            [],
        ) => Ends::Wildcard(lower(source.name)),
        (End::NxDomain { encloser, .. }, []) => Ends::NxDomain(lower(encloser.name)),
        (End::Referral { cut }, []) => Ends::Referral(lower(cut.name)),
        (end, chain) => Ends::Other(format!("{end:?} after {chain:?}")),
    }
}

/// The search of RFC 1034 §4.3.2, one label at a time from the apex, with Knot's rules for the names with NSEC3
/// records only: such a name does not exist, but names below it do, so it is an empty non-terminal then.
fn expected(names: &BTreeMap<Path, Holds>, path: &[u8], apex: &str) -> Ends {
    let real = |at: &[u8]| {
        names
            .get(at)
            .copied()
            .filter(|holds| *holds != Holds::Nsec3)
    };
    let exists = |at: &[u8]| {
        at.is_empty()
            || names
                .iter()
                .any(|(key, holds)| key.starts_with(at) && *holds != Holds::Nsec3)
    };
    let name = |at: &[u8]| text_name(at, apex, None).to_ascii_lowercase();
    for above in 1..path.len() {
        match real(&path[..above]) {
            Some(Holds::Delegation) => return Ends::Referral(name(&path[..above])),
            Some(Holds::Dname) => return Ends::Redirect(name(&path[..above])),
            _ => {}
        }
    }
    if exists(path) {
        return match real(path) {
            Some(Holds::Address) => Ends::Data(name(path)),
            Some(Holds::Delegation) => Ends::Referral(name(path)),
            _ => Ends::NoData(name(path)),
        };
    }
    let encloser = (0..path.len())
        .rev()
        .find(|depth| exists(&path[..*depth]))
        .expect("the apex exists");
    let mut star = path[..encloser].to_vec();
    star.push(WILDCARD);
    if exists(&star) {
        return match real(&star) {
            // RFC 4592 §4.2 leaves it open; Knot refers, D206.
            Some(Holds::Delegation) => Ends::Referral(name(&star)),
            _ => Ends::Wildcard(name(&star)),
        };
    }
    Ends::NxDomain(name(&path[..encloser]))
}

/// A zone and the names to ask it about.
#[derive(Debug)]
struct Shape {
    apex: &'static str,
    names: BTreeMap<Path, Holds>,
    queries: Vec<Path>,
    /// The bits of the case of the names asked.
    case: u64,
}

prop_compose! {
    /// Up to 13 names of up to 12 labels, many starting with a shared trunk of up to 9, so that long names share
    /// long prefixes; with the NSEC3 name of a hash, alone or with a name below it; and the questions: each
    /// name, its ancestors, a child of each with any label, longer names below each, and some at random.
    fn shapes()(
        apex in 0..APEXES.len(),
        trunk in vec(0..HASH, 0..=TRUNK),
        picks in vec((0..=2 * TRUNK, vec(0..HASH, 1..=3), 0_u8..10), 1..14),
        nsec3 in 0_u8..3,
        below in vec(0..WILDCARD, 1..=10),
        extra in vec(vec(0..=HASH, 1..=14), 0..20),
        case in any::<u64>(),
    ) -> Shape {
        let mut names = BTreeMap::new();
        for (cut, tail, holds) in picks {
            let mut path: Path = trunk.iter().take(cut).copied().collect();
            path.extend(tail);
            // A wildcard is no zone cut or alias: the labels of a name are the owner's, whatever it is.
            let holds = match holds {
                0 if path.last() != Some(&WILDCARD) => Holds::Delegation,
                1 if path.last() != Some(&WILDCARD) => Holds::Dname,
                _ => Holds::Address,
            };
            names.insert(path, holds);
        }
        if nsec3 > 0 {
            names.insert(vec![HASH], Holds::Nsec3);
        }
        if nsec3 == 2 {
            let mut path = vec![HASH];
            path.extend(below);
            names.insert(path, Holds::Address);
        }
        let mut queries = extra.clone();
        for (at, path) in names.keys().enumerate() {
            let tail = extra.get(at % extra.len().max(1)).cloned().unwrap_or_default();
            for depth in 0..=path.len() {
                for label in 0..=HASH {
                    let mut child = path[..depth].to_vec();
                    child.push(label);
                    queries.push(child);
                }
            }
            let mut longer = path.clone();
            longer.extend(tail.into_iter().take(12));
            queries.push(longer);
        }
        Shape { apex: APEXES[apex], names, queries, case }
    }
}

proptest! {
    /// Whatever the zone holds, the answer for each name asked is what the search from the apex finds: the closest
    /// encloser of a name that is not there, with the wildcard that answers for it if there is one, the first cut
    /// above one that is hidden, and the name itself otherwise.
    #[test]
    fn s4_3_2_a_lookup_ends_where_the_search_from_the_apex_does(shape in shapes()) {
        let Shape { apex, names, queries, case } = shape;
        let zone = load_files(apex, &zone_text(apex, &names), None, &[], &Limits::default())
            .expect("a zone")
            .zone;
        for path in queries {
            // The apex is not asked about here, and a name of more than 255 bytes is no question.
            let Ok(name) = text_name(&path, apex, Some(case)).parse::<Name<'static>>() else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            let asked = name.to_string();
            prop_assert_eq!(found(&zone, name), expected(&names, &path, apex), "{}", asked);
        }
    }
}
