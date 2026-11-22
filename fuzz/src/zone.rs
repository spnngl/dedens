//! Targets of dedens-zone: zone text on its way into a checked zone.

use dedens_proto::{Name, RecordType, Ttl};
use dedens_zone::{Kind, Limits, Source, Zone};

/// How many `$INCLUDE`s the callback gives the text of: each one reads the same bytes again, so a file that
/// includes itself must end.
const INCLUDES: usize = 4;

/// Arbitrary bytes as the zone `example.`, `$INCLUDE` answered with the same bytes a few times: the load never
/// panics, and a zone it returns is whole. Its apex has the SOA, the nodes are in canonical order inside the apex,
/// every name has its parents up to the apex, the record count is that of the `RRset`s, and what is below a
/// delegation or a DNAME is occluded. A refusal has an error, each placed in a file it read, from line 1.
///
/// # Panics
///
/// On a zone that is not whole, or a bug in the loader.
pub fn load_zone(data: &[u8]) {
    let apex = Name::from_labels([b"example".as_slice()]).expect("a valid name");
    let mut given = 0_usize;
    let mut include = |_: &str| {
        given += 1;
        if given > INCLUDES {
            Err("too many".to_owned())
        } else {
            Ok(data.to_vec())
        }
    };
    let source = Source {
        name: "fuzz.db",
        text: data,
        default_ttl: Some(Ttl::ZERO),
    };
    // Small bounds, so that the limits are reached too.
    let limits = Limits {
        records: 64,
        names: 64,
        records_per_rrset: 8,
        rrsets_per_name: 8,
        rdata_bytes: 4096,
        include_depth: 2,
        errors: 16,
    };
    match Zone::load(apex.clone(), source, &mut include, &limits) {
        Ok(loaded) => whole(&loaded.zone, &apex),
        Err(report) => {
            assert!(!report.errors.is_empty(), "a refusal without an error");
            for e in &report.errors {
                if let Some(at) = e.at {
                    assert!(at.file < report.files.len(), "{e:?} in no file");
                    assert!(at.line >= 1 && at.column >= 1, "{e:?} before line 1");
                }
            }
        }
    }
}

/// The invariants of a loaded `zone` of `apex`.
fn whole(zone: &Zone, apex: &Name<'static>) {
    assert_eq!(zone.apex(), apex);
    let root = zone.node(apex).expect("the apex is a node");
    assert!(root.rrset(RecordType::SOA).is_some());
    assert!(root.rrset(RecordType::NS).is_some());
    let mut previous: Option<&Name<'static>> = None;
    let mut records = 0;
    for (name, node) in zone.nodes() {
        assert!(name.is_within(apex), "{name} outside {apex}");
        assert!(previous.is_none_or(|p| p < name), "{name} out of order");
        previous = Some(name);
        let sets = node.rrsets().map(|(_, set)| set).chain(node.signature_sets());
        let mut held = 0;
        for set in sets {
            assert!(!set.rdatas().is_empty(), "an empty RRset at {name}");
            held += set.rdatas().len();
        }
        records += held;
        assert!(
            node.kind() != Kind::EmptyNonTerminal || held == 0,
            "{name} holds records"
        );
        let mut cut = false;
        let mut parent = name.parent();
        while let Some(p) = parent.filter(|_| name != apex) {
            let up = zone.node(&p).expect("every parent is a node");
            cut |= up.kind() == Kind::Delegation || up.is_dname_owner();
            if &p == apex {
                break;
            }
            parent = p.parent();
        }
        assert_eq!(node.kind() == Kind::Occluded, cut, "{name} is {:?}", node.kind());
    }
    assert_eq!(records, zone.record_count());
}
