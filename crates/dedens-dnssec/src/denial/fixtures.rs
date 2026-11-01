//! Test fixtures shared by the proptests of `nsec` and `nsec3`: the example zones of RFC 4035 and RFC 5155
//! Appendix A, and names around theirs.

use std::path::Path;

use dedens_proto::name::Name;
use dedens_proto::record::Record;
use dedens_proto::text::{Entry, ZoneReader};
use proptest::prelude::*;

/// The records of the zone file at `path`, relative to the crate.
pub(super) fn zone(path: &str) -> Vec<Record<'static>> {
    let text = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).expect("zone file");
    ZoneReader::new(&text, None)
        .filter_map(|e| match e.expect("a zone") {
            Entry::Record(decoded) => Some(decoded.record),
            _ => None,
        })
        .collect()
}

/// The labels of both example zones, and others that sort around them: a capital, `*`, and the lowest and a high
/// byte.
const LABELS: [&str; 15] = [
    "a", "ai", "b", "c", "ns1", "ns2", "w", "x", "y", "xx", "z", "*", "A", "\\001", "\\200",
];

/// A name of at most five labels under `example.`.
pub(super) fn names() -> impl Strategy<Value = Name<'static>> {
    prop::collection::vec(prop::sample::select(LABELS.to_vec()), 0..5).prop_map(|labels| {
        let labels: Vec<Vec<u8>> = labels
            .iter()
            .copied()
            .chain(["example"])
            .map(|label| match label {
                "\\001" => vec![1],
                "\\200" => vec![0x80],
                other => other.as_bytes().to_vec(),
            })
            .collect();
        Name::from_labels(labels.iter().map(Vec::as_slice)).expect("a name")
    })
}
