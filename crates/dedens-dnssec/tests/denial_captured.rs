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
use dedens_proto::rdata::RData;
use dedens_proto::{Message, Name, Rcode, Record, RecordType, Ttl};
use support::{capture, prove, prove_wildcard};

const NAME_ERROR: Fact = Fact::NameError { compact: false };
const COMPACT_NAME_ERROR: Fact = Fact::NameError { compact: true };

/// What each capture proves, by id, and whether the NSEC3 over its next closer name has the opt-out flag.
const EXPECTED: [(&str, Fact, bool); 43] = [
    ("nxdomain_root_nsec", NAME_ERROR, false),
    ("nxdomain_nsec", NAME_ERROR, false),
    ("nxdomain_nsec3", NAME_ERROR, false),
    ("nxdomain_nsec3_optout", NAME_ERROR, true),
    ("nxdomain_nsec3_salt", NAME_ERROR, true),
    ("nxdomain_nsec3_iterations", NAME_ERROR, false),
    ("nxname_cloudflare", COMPACT_NAME_ERROR, false),
    ("nodata_compact", Fact::NoData, false),
    ("nodata_root_nsec", Fact::NoData, false),
    ("nodata_nsec", Fact::NoData, false),
    ("nodata_nsec3", Fact::NoData, false),
    ("nodata_nsec3_optout", Fact::NoData, false),
    ("nodata_nsec3_iterations", Fact::NoData, false),
    ("ent_nsec", Fact::NoData, false),
    ("ent_nsec3", Fact::NoData, false),
    ("wildcard_nodata", Fact::WildcardNoData, false),
    ("wildcard_nodata_nsec", Fact::WildcardNoData, false),
    ("wildcard_nodata_optout", Fact::WildcardNoData, true),
    ("google_com_ds", Fact::InsecureDelegation, true),
    ("jm_ds", Fact::InsecureDelegation, false),
    ("edgekey_net_ds", Fact::InsecureDelegation, true),
    ("akamaiedge_net_ds", Fact::InsecureDelegation, true),
    // The DS of each owner of an answer, which the chain of trust asks for.
    ("leaf_xyzzy_ds", NAME_ERROR, false),
    ("leaf_nxdomain_nlnetlabs_ds", NAME_ERROR, false),
    ("leaf_nxdomain_debian_ds", NAME_ERROR, false),
    ("leaf_nxdomain_dev_ds", NAME_ERROR, false),
    ("leaf_nxname_cloudflare_ds", COMPACT_NAME_ERROR, false),
    ("leaf_ent_nlnetlabs_ds", Fact::NoData, false),
    ("leaf_ent_sidnlabs_ds", Fact::NoData, false),
    ("leaf_wildcard_sidnlabs_ds", Fact::WildcardNoData, false),
    ("leaf_wildcard_internet_nl_ds", Fact::WildcardNoData, false),
    ("leaf_synthesized_nist_gov_ds", Fact::NoData, false),
    ("leaf_wildcard_ph_ds", Fact::InsecureDelegation, true),
    ("leaf_wildcard_ws_ds", Fact::InsecureDelegation, true),
    ("leaf_dname_sidnlabs_ds", Fact::NoData, false),
    ("leaf_www_example_nl_ds", Fact::NoData, false),
    ("leaf_cdn_cloudflare_net_ds", Fact::NoData, false),
    ("leaf_org_cdn_ds", Fact::NoData, false),
    ("leaf_www_nlnetlabs_ds", Fact::NoData, false),
    ("leaf_icann_cdn_ds", Fact::NoData, false),
    ("leaf_icann_cdn_mid_ds", Fact::NoData, false),
    ("leaf_sigok_ippacket_ds", Fact::NoData, false),
    ("leaf_sigfail_ippacket_ds", Fact::NoData, false),
];

/// The captured responses that are not in [`EXPECTED`]: the wildcard expansion is tested below; the DS of a name
/// under an opt-out span is an NXDOMAIN with the proof of an insecure delegation, and a referral's DS is proven for
/// the child, not for the name asked.
const OTHERS: [&str; 4] = [
    "wildcard_answer",
    "leaf_nxdomain_com_ds",
    "leaf_nxdomain_org_ds",
    "referral_unsigned",
];

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

/// The least TTL of the NSEC and NSEC3 records of the response: each capture's proof uses them all, and every
/// record the proof reads has one of them or more.
fn least_ttl(message: &Message<'_>) -> Ttl {
    message
        .authority
        .iter()
        .filter(|r| is_denial(r))
        .map(|r| r.ttl)
        .min()
        .expect("denial records")
}

#[test]
fn every_negative_capture_proves_what_it_says() {
    for (id, fact, opt_out) in EXPECTED {
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
        assert_eq!(proof.opt_out, opt_out, "{id}: opt-out");
        let rcode = if fact == NAME_ERROR {
            Rcode::NXDOMAIN
        } else {
            Rcode::NOERROR
        };
        assert_eq!(message.rcode(), rcode, "{id}");
        assert_eq!(proof.ttl, least_ttl(&message), "{id}");
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
                EXPECTED.iter().any(|(listed, ..)| *listed == id)
                    || OTHERS.contains(&id.as_str())
                    || id.starts_with("ip6_ds_"),
                "{id} has a denial and is not listed"
            );
        }
    }
}

/// The DS of each label of an IPv6 reverse name, below `arpa`: a DS where a zone starts, else no data.
#[test]
fn the_ds_of_each_label_of_a_reverse_name_is_there_or_proven_absent() {
    for n in 1..=34 {
        let id = format!("ip6_ds_{n}");
        let message = capture(&id);
        if !message.answer.is_empty() {
            continue;
        }
        let question = &message.questions[0];
        let proof = prove(
            &apex(&message).to_string(),
            &question.name.to_string(),
            question.qtype,
            &message.authority,
        )
        .unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(proof.fact, Fact::NoData, "{id}");
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
    assert_eq!(proof.ttl, least_ttl(&message));
    assert!(!proof.opt_out);
}

/// The proof of one capture needs about one hash per label of the name, three at most beside the question's: a few
/// SHA-1 blocks, as many as the iterations make of each.
#[test]
fn proofs_cost_a_few_hashes() {
    let message = capture("nxdomain_nsec3_iterations");
    let question = &message.questions[0];
    let mut budget = Budget::default();
    let before = budget.nsec3_blocks_left();
    denial::prove(
        &apex(&message),
        question,
        &message.authority,
        MaxIterations::default(),
        &mut budget,
    )
    .expect("a proof");
    let spent = before.0 - budget.nsec3_blocks_left().0;
    // One iteration: two blocks per hash; the name, its parent, the closest encloser's wildcard.
    assert!(spent > 0 && spent <= 3 * 2 * 3, "{spent}");
}
