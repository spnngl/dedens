//! RFC 9824 (compact denial of existence): an NSEC or NSEC3 with NXNAME in its bitmap, under NOERROR, proves a
//! name error; one with the types of the name proves no data. The Cloudflare captures of `testdata/` are the
//! responses.

mod common;
#[path = "common/denial.rs"]
mod support;

use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{self, Fact, MaxIterations, Unproven};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::{Nsec3, RData, TypeBitmap};
use dedens_proto::{Class, Message, Rcode, Record, RecordType};
use support::{capture, pick, prove, zone};

fn denials(message: &Message<'static>) -> Vec<Record<'static>> {
    message
        .authority
        .iter()
        .filter(|r| r.rtype() == RecordType::NSEC)
        .cloned()
        .collect()
}

/// §3.1, §3.3: the NOERROR response of `nonexistent.cloudflare.com.` has an NSEC at the name that lists NXNAME:
/// the name does not exist, and 06 sees it was not an NXDOMAIN.
#[test]
fn nxname_is_a_name_error() {
    let message = capture("nxname_cloudflare");
    assert_eq!(message.rcode(), Rcode::NOERROR);
    let proof = prove(
        "cloudflare.com.",
        "nonexistent.cloudflare.com.",
        RecordType::A,
        &denials(&message),
    )
    .expect("a proof");
    assert_eq!(proof.fact, Fact::NameError { compact: true });
    // Any type of the name gets the same: the name is not there.
    let proof = prove(
        "cloudflare.com.",
        "nonexistent.cloudflare.com.",
        RecordType::MX,
        &denials(&message),
    )
    .expect("a proof");
    assert_eq!(proof.fact, Fact::NameError { compact: true });
}

/// §3.2: the NSEC at `cloudflare.com.` lists its types, and no SRV: no data.
#[test]
fn compact_no_data_is_no_data() {
    let message = capture("nodata_compact");
    let records = denials(&message);
    let proof = prove(
        "cloudflare.com.",
        "cloudflare.com.",
        RecordType::SRV,
        &records,
    )
    .expect("a proof");
    assert_eq!(proof.fact, Fact::NoData);
    assert_eq!(
        prove(
            "cloudflare.com.",
            "cloudflare.com.",
            RecordType::MX,
            &records
        ),
        Err(Unproven::TypePresent)
    );
}

/// §3.5, §9: NXNAME is not a type to answer: the question is refused with EDE 30 before any record is read.
#[test]
fn nxname_is_not_a_question() {
    let message = capture("nxname_cloudflare");
    let refused = prove(
        "cloudflare.com.",
        "nonexistent.cloudflare.com.",
        RecordType::NXNAME,
        &denials(&message),
    );
    assert_eq!(refused, Err(Unproven::NxnameQuery));
    assert_eq!(
        refused.expect_err("refused").info_code(),
        Some(InfoCode::INVALID_QUERY_TYPE)
    );
}

/// Derived: §4: an NSEC3 at the hash of the name with NXNAME in its bitmap says the same as the NSEC. The record
/// is the real one of `ns1.example.` in RFC 5155 Appendix A with its bitmap replaced; no capture has compact
/// denial by NSEC3.
#[test]
fn nsec3_nxname_is_a_name_error() {
    let zone = zone("../dedens-proto/tests/zones/rfc5155_appendix_a.zone");
    let records: Vec<_> = pick(
        &zone,
        RecordType::NSEC3,
        &["2t7b4g4vsa5smi47k61mv5bv1a22bojr.example."],
    )
    .iter()
    .map(|r| {
        let RData::Nsec3(n) = r.data() else {
            panic!("an NSEC3 record");
        };
        let types = TypeBitmap::from_types([RecordType::NXNAME, RecordType::RRSIG]);
        let n = Nsec3::new(
            n.hash_algorithm,
            n.flags,
            n.iterations,
            n.salt(),
            n.next_hashed_owner(),
            types,
        )
        .expect("valid");
        Record::new(r.name.clone(), Class::IN, r.ttl, &RData::Nsec3(n))
    })
    .collect();
    let proof = denial::prove(
        &"example.".parse().expect("a name"),
        &dedens_proto::Question::new("ns1.example.".parse().expect("a name"), RecordType::A),
        &records,
        MaxIterations::default(),
        &mut Budget::default(),
    )
    .expect("a proof");
    assert_eq!(proof.fact, Fact::NameError { compact: true });
}
