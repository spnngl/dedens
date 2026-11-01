//! Every negative response of `testdata/capture.yaml` (described in `testdata/README.md`) proves what its rcode
//! and question say: a name error, no data, a wildcard no data or an unsigned delegation, by NSEC or NSEC3 of
//! any parameters, opt-out or not. The records are those of the response, whose signatures `captured.rs` and
//! the validator check; here they are trusted.

mod common;
#[path = "common/denial.rs"]
mod support;

use std::fs;
use std::path::PathBuf;

use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{self, Fact, MaxIterations};
use dedens_proto::{Message, Name, RData, Rcode, Record, RecordType};
use support::{capture, prove, prove_wildcard};

const NAME_ERROR: Fact = Fact::NameError { compact: false };
const COMPACT_NAME_ERROR: Fact = Fact::NameError { compact: true };

/// What each capture proves, by id.
const EXPECTED: [(&str, Fact); 20] = [
    ("nxdomain_root_nsec", NAME_ERROR),
    ("nxdomain_nsec", NAME_ERROR),
    ("nxdomain_nsec3", NAME_ERROR),
    ("nxdomain_nsec3_optout", NAME_ERROR),
    ("nxdomain_nsec3_salt", NAME_ERROR),
    ("nxdomain_nsec3_iterations", NAME_ERROR),
    ("nxname_cloudflare", COMPACT_NAME_ERROR),
    ("nodata_compact", Fact::NoData),
    ("nodata_root_nsec", Fact::NoData),
    ("nodata_nsec", Fact::NoData),
    ("nodata_nsec3", Fact::NoData),
    ("nodata_nsec3_optout", Fact::NoData),
    ("nodata_nsec3_iterations", Fact::NoData),
    ("ent_nsec", Fact::NoData),
    ("ent_nsec3", Fact::NoData),
    ("wildcard_nodata", Fact::WildcardNoData),
    ("google_com_ds", Fact::InsecureDelegation),
    ("jm_ds", Fact::InsecureDelegation),
    ("edgekey_net_ds", Fact::InsecureDelegation),
    ("akamaiedge_net_ds", Fact::InsecureDelegation),
];

/// The captured responses that are not in [`EXPECTED`]: the wildcard expansion is tested below.
const OTHERS: [&str; 1] = ["wildcard_answer"];

fn is_denial(record: &Record<'_>) -> bool {
    matches!(record.rtype(), RecordType::NSEC | RecordType::NSEC3)
}

/// The zone that signed the denial: the signer of the RRSIGs over its NSEC or NSEC3 records.
fn apex(message: &Message<'static>) -> Name<'static> {
    message
        .authority
        .iter()
        .find_map(|r| match r.data() {
            RData::Rrsig(rrsig)
                if matches!(rrsig.type_covered, RecordType::NSEC | RecordType::NSEC3) =>
            {
                Some(rrsig.signer.into_owned())
            }
            _ => None,
        })
        .expect("a signed denial")
}

#[test]
fn every_negative_capture_proves_what_it_says() {
    for (id, fact) in EXPECTED {
        let message = capture(id);
        let question = &message.questions[0];
        let proof = prove(
            &apex(&message).to_string(),
            &question.name.to_string(),
            question.qtype,
            &message.authority,
        )
        .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(proof.fact, fact, "{id}");
        let rcode = if fact == NAME_ERROR {
            Rcode::NXDOMAIN
        } else {
            Rcode::NOERROR
        };
        assert_eq!(message.rcode(), rcode, "{id}");
        let ttls = message
            .authority
            .iter()
            .filter(|r| is_denial(r))
            .map(|r| r.ttl);
        assert!(proof.ttl >= ttls.min().expect("denial records"), "{id}");
    }
}

/// A new capture with a denial in it has to be added to the tables above.
#[test]
fn every_capture_with_a_denial_is_listed() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
    for entry in fs::read_dir(dir).expect("testdata directory") {
        let path = entry.expect("entry").path();
        let Some(id) = path.extension().is_some_and(|e| e == "bin").then(|| {
            path.file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned()
        }) else {
            continue;
        };
        let message = capture(&id);
        let negative = message.rcode() == Rcode::NXDOMAIN || message.answer.is_empty();
        if negative && message.authority.iter().any(is_denial) {
            assert!(
                EXPECTED.iter().any(|(listed, _)| *listed == id) || OTHERS.contains(&id.as_str()),
                "{id} has a denial and is not listed"
            );
        }
    }
}

/// The answer's RRSIG has fewer labels than its owner, and the NSEC3 of the response covers the next closer name.
#[test]
fn wildcard_expansion_is_proven() {
    let message = capture("wildcard_answer");
    let question = &message.questions[0];
    let labels = message
        .answer
        .iter()
        .find_map(|r| match r.data() {
            RData::Rrsig(rrsig) if rrsig.type_covered == question.qtype => Some(rrsig.labels),
            _ => None,
        })
        .expect("an RRSIG over the answer");
    let apex = apex(&message).to_string();
    let proof = prove_wildcard(
        &apex,
        &question.name.to_string(),
        labels,
        &message.authority,
    )
    .expect("a proof");
    assert_eq!(proof.fact, Fact::WildcardAnswer);
}

/// The proof of one capture needs about one hash per label of the name, three at most beside the question's.
#[test]
fn proofs_cost_a_few_hashes() {
    let message = capture("nxdomain_nsec3_iterations");
    let question = &message.questions[0];
    let mut budget = Budget::default();
    let before = budget.nsec3_hashes_left();
    denial::prove(
        &apex(&message),
        question,
        &message.authority,
        MaxIterations::default(),
        &mut budget,
    )
    .expect("a proof");
    let spent = before.0 - budget.nsec3_hashes_left().0;
    // One iteration: two rounds per hash; the name, its parent, the closest encloser's wildcard.
    assert!(spent > 0 && spent <= 3 * 2 * 3, "{spent}");
}
