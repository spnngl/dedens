//! Helpers of the denial tests: records picked from an example zone or a capture, and a proof asked of them.
//! Included with `#[path = "common/denial.rs"] mod support;`.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each test crate uses a subset of a shared module"
)]

use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{self, MaxIterations, Proof, Unproven};
use dedens_proto::rdata::{Nsec, Nsec3, RData, TypeBitmap};
use dedens_proto::{Class, Message, Nsec3HashAlgorithm, Question, Record, RecordType, Ttl};
use dedens_testkit::dnssec;

use crate::common::name;

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

/// The captured response `testdata/dnssec/<id>.bin`.
pub fn capture(id: &str) -> Message<'static> {
    let wire = dnssec::capture(id);
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

/// `record`, an NSEC3, made with another salt.
pub fn nsec3_salted(record: &Record<'static>, salt: &[u8]) -> Record<'static> {
    let n = nsec3(record);
    let n = Nsec3::new(
        n.hash_algorithm,
        n.flags,
        n.iterations,
        salt,
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
