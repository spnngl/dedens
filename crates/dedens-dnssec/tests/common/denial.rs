//! Helpers of the denial tests: records read from an example zone or a capture, and a proof asked of them.
//! Included with `#[path = "common/denial.rs"] mod support;`.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses a subset of a shared module"
)]

use std::fs;
use std::path::PathBuf;

use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{self, MaxIterations, Proof, Unproven};
use dedens_proto::rdata::{Nsec, Nsec3, TypeBitmap};
use dedens_proto::text::{Entry, ZoneReader};
use dedens_proto::{Class, Message, Nsec3HashAlgorithm, Question, RData, Record, RecordType, Ttl};

use crate::common::name;

/// The records of the zone file at `path`, relative to the crate.
pub fn zone(path: &str) -> Vec<Record<'static>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    let text = fs::read(path).expect("zone file");
    ZoneReader::new(&text, None)
        .filter_map(|entry| match entry.expect("a valid zone") {
            Entry::Record(decoded) => Some(decoded.record),
            _ => None,
        })
        .collect()
}

/// The records of type `rtype` owned by one of `owners`: what a response would carry.
pub fn pick(
    records: &[Record<'static>],
    rtype: RecordType,
    owners: &[&str],
) -> Vec<Record<'static>> {
    let owners: Vec<_> = owners.iter().map(|o| name(o)).collect();
    records
        .iter()
        .filter(|r| r.rtype() == rtype && owners.contains(&r.name))
        .cloned()
        .collect()
}

/// The captured response `testdata/<id>.bin`.
pub fn capture(id: &str) -> Message<'static> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/testdata/{id}.bin"));
    let wire = fs::read(path).expect("captured file");
    Message::decode(&wire)
        .expect("decodes")
        .message
        .into_owned()
}

/// Asks for the proof of `qname` and `qtype` in the zone `apex` with the default limit and budget.
pub fn prove(
    apex: &str,
    qname: &str,
    qtype: RecordType,
    records: &[Record<'static>],
) -> Result<Proof, Unproven> {
    denial::prove(
        &name(apex),
        &Question::new(name(qname), qtype),
        records,
        MaxIterations::default(),
        &mut Budget::default(),
    )
}

/// Asks for the proof that `qname`, answered with an RRSIG of `labels` labels, came from a wildcard.
pub fn prove_wildcard(
    apex: &str,
    qname: &str,
    labels: u8,
    records: &[Record<'static>],
) -> Result<Proof, Unproven> {
    denial::prove_wildcard_answer(
        &name(apex),
        &name(qname),
        labels,
        records,
        MaxIterations::default(),
        &mut Budget::default(),
    )
}

/// An NSEC record of the example zone, `owner` to `next`, with the types of `types`.
pub fn nsec(owner: &str, next: &str, types: &[RecordType]) -> Record<'static> {
    let data = Nsec {
        next: name(next),
        types: TypeBitmap::from_types(types.iter().copied()),
    };
    Record::new(
        name(owner),
        Class::IN,
        Ttl::from_wire(3600),
        &RData::Nsec(data),
    )
}

/// `record`, an NSEC3, with another hash algorithm, flags and iterations.
pub fn nsec3_with(
    record: &Record<'static>,
    algorithm: Nsec3HashAlgorithm,
    flags: u8,
    iterations: u16,
) -> Record<'static> {
    let n = nsec3(record);
    let n = Nsec3::new(
        algorithm,
        flags,
        iterations,
        n.salt(),
        n.next_hashed_owner(),
        n.types.clone(),
    )
    .expect("valid");
    Record::new(
        record.name.clone(),
        record.class,
        record.ttl,
        &RData::Nsec3(n),
    )
}

/// The NSEC3 RDATA of `record`.
pub fn nsec3(record: &Record<'static>) -> Nsec3<'static> {
    match record.data() {
        RData::Nsec3(n) => Some(n.into_owned()),
        _ => None,
    }
    .expect("an NSEC3 record")
}
