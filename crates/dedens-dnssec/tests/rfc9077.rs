//! RFC 9077 §3: a negative proof is cached as long as the shortest of the records it used. The records are those
//! of the RFC 4035 and RFC 5155 example zones, with their TTLs changed (derived: the RFCs give one TTL to all).

mod common;

use common::denial::{pick, prove, prove_wildcard};
use dedens_dnssec::denial::Fact;
use dedens_proto::{Record, RecordType, Ttl};
use dedens_testkit::zone;

const APEX: &str = "example.";

fn with_ttls(mut records: Vec<Record<'static>>, ttls: &[u32]) -> Vec<Record<'static>> {
    for (record, ttl) in records.iter_mut().zip(ttls) {
        record.ttl = Ttl::from_wire(*ttl);
    }
    records
}

fn nsecs(owners: &[&str]) -> Vec<Record<'static>> {
    pick(&zone("rfc4035_appendix_a.zone"), RecordType::NSEC, owners)
}

fn nsec3s(hashes: &[&str]) -> Vec<Record<'static>> {
    let owners: Vec<String> = hashes.iter().map(|h| format!("{h}.example.")).collect();
    let owners: Vec<&str> = owners.iter().map(String::as_str).collect();
    pick(&zone("rfc5155_appendix_a.zone"), RecordType::NSEC3, &owners)
}

#[test]
fn nsec_proof_lasts_as_long_as_its_shortest_record() {
    let mut records = with_ttls(nsecs(&["b.example.", "example."]), &[300, 60]);
    // A record the proof does not use does not count.
    records.extend(with_ttls(nsecs(&["xx.example."]), &[0]));
    let proof = prove(APEX, "ml.example.", RecordType::A, &records).expect("a proof");
    assert_eq!(proof.fact, Fact::NameError { compact: false });
    assert_eq!(proof.ttl, Ttl::from_wire(60));
}

#[test]
fn nsec3_proof_lasts_as_long_as_its_shortest_record() {
    // The closest encloser, the next closer name's record and the wildcard's.
    let records = with_ttls(
        nsec3s(&[
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
            "b4um86eghhds6nea196smvmlo4ors995",
            "35mthgpgcu1qg68fab165klnsnk3dpvl",
        ]),
        &[300, 60, 600],
    );
    let proof = prove(APEX, "a.c.x.w.example.", RecordType::A, &records).expect("a proof");
    assert_eq!(proof.ttl, Ttl::from_wire(60));
}

#[test]
fn a_wildcard_answer_lasts_as_long_as_its_covering_record() {
    let records = with_ttls(nsec3s(&["q04jkcevqvmu85r014c7dkba38o0ji5r"]), &[120]);
    let proof = prove_wildcard(APEX, "a.z.w.example.", 2, &records).expect("a proof");
    assert_eq!(proof.fact, Fact::WildcardAnswer);
    assert_eq!(proof.ttl, Ttl::from_wire(120));
}
