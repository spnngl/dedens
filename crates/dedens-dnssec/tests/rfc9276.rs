//! RFC 9276 §3.2: NSEC3 records above the iteration limit prove nothing and the response is insecure, with EDE 27;
//! the hashing they ask for is counted by the `Budget`.

mod common;
#[path = "common/denial.rs"]
mod support;

use dedens_dnssec::crypto::{Budget, BudgetExhausted, Nsec3Blocks, Verifications};
use dedens_dnssec::denial::{self, MaxIterations, Unproven};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Nsec3HashAlgorithm, Question, RecordType};
use dedens_testkit::zone;
use support::{capture, nsec3_with, pick, prove};

/// The captured NSEC3 name error of `nonexistent-xyz123.dev.`: 1 iteration.
fn iterating() -> (Question<'static>, Vec<dedens_proto::Record<'static>>) {
    let message = capture("nxdomain_nsec3_iterations");
    let question = message.questions[0].clone();
    let records = message
        .authority
        .into_iter()
        .filter(|r| r.rtype() == RecordType::NSEC3)
        .collect();
    (question, records)
}

fn apex() -> dedens_proto::Name<'static> {
    "dev.".parse().expect("a name")
}

fn prove_with(max: MaxIterations, budget: &mut Budget) -> Result<denial::Proof, Unproven> {
    let (question, records) = iterating();
    denial::prove(&apex(), &question, &records, max, budget)
}

/// The capture has 1 iteration: a limit of 1 accepts it, a limit of 0 does not.
#[test]
fn the_limit_is_inclusive() {
    let accepted = prove_with(MaxIterations(1), &mut Budget::default()).expect("a proof");
    assert_eq!(accepted.fact, denial::Fact::NameError { compact: false });
    assert_eq!(
        prove_with(MaxIterations(0), &mut Budget::default()),
        Err(Unproven::IterationsAboveLimit {
            iterations: 1,
            limit: 0
        })
    );
}

/// The default limit is 150, as in Unbound and BIND (D74): the NSEC3 records of RFC 5155 with 150 iterations are
/// looked at, and with 151 they are not. Derived: the iteration count of a real record of RFC 5155 Appendix A
/// (`2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.`) is rewritten; no capture has more than one iteration.
#[test]
fn the_default_limit_is_150() {
    assert_eq!(MaxIterations::default(), MaxIterations(150));
    let zone = zone("rfc5155_appendix_a.zone");
    let nsec3 = pick(
        &zone,
        RecordType::NSEC3,
        &["2t7b4g4vsa5smi47k61mv5bv1a22bojr.example."],
    );
    let with = |iterations| -> Vec<_> {
        nsec3
            .iter()
            .map(|r| nsec3_with(r, Nsec3HashAlgorithm::SHA1, 1, iterations))
            .collect()
    };
    // The hash no longer matches: the records are used, and prove nothing of this name.
    assert_eq!(
        prove("example.", "ns1.example.", RecordType::MX, &with(150)),
        Err(Unproven::NoClosestEncloser)
    );
    let above = prove("example.", "ns1.example.", RecordType::MX, &with(151));
    assert_eq!(
        above,
        Err(Unproven::IterationsAboveLimit {
            iterations: 151,
            limit: 150
        })
    );
    assert_eq!(
        above.expect_err("above").info_code(),
        Some(InfoCode::UNSUPPORTED_NSEC3_ITERATIONS)
    );
    // The maximum a record can say is refused all the same.
    assert!(matches!(
        prove("example.", "ns1.example.", RecordType::MX, &with(u16::MAX)),
        Err(Unproven::IterationsAboveLimit { .. })
    ));
}

/// §3.2: a response whose hashing does not fit the budget is refused, and the budget says which counter ran out;
/// the verdict, insecure or SERVFAIL, is the caller's (D71). The budget counts SHA-1 blocks (D106).
#[test]
fn hashing_is_counted_by_the_budget() {
    // One hash of 1 iteration, of a short name and a short salt, is 2 computations of one block: it costs 2.
    let mut budget = Budget::new(Verifications(0), Nsec3Blocks(1));
    assert_eq!(
        prove_with(MaxIterations(1), &mut budget),
        Err(Unproven::Budget(BudgetExhausted::Nsec3Blocks))
    );
    assert_eq!(budget.nsec3_blocks_left(), Nsec3Blocks(0));
    // The budget the proof leaves is the one it did not spend.
    let mut budget = Budget::default();
    let before = budget.nsec3_blocks_left().0;
    prove_with(MaxIterations(1), &mut budget).expect("a proof");
    let spent = before - budget.nsec3_blocks_left().0;
    assert!(spent > 0 && spent % 2 == 0, "{spent}");
}

/// RFC 5155 B.1 (`a.c.x.w.example.`, 12 iterations, so 13 blocks a hash) takes four hashes: the name, its parent,
/// the closest encloser and its wildcard. The budget runs out in the loop that looks for the closest encloser,
/// or at the wildcard, and a budget of the whole cost, 52 blocks, is enough.
#[test]
fn the_budget_runs_out_in_the_middle_of_a_proof() {
    let records = pick(
        &zone("rfc5155_appendix_a.zone"),
        RecordType::NSEC3,
        &[
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
            "b4um86eghhds6nea196smvmlo4ors995.example.",
            "35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
        ],
    );
    let question = Question::new("a.c.x.w.example.".parse().expect("a name"), RecordType::A);
    let apex = "example.".parse().expect("a name");
    let run = |blocks| {
        let mut budget = Budget::new(Verifications(0), Nsec3Blocks(blocks));
        denial::prove(
            &apex,
            &question,
            &records,
            MaxIterations::default(),
            &mut budget,
        )
    };
    for short in [0, 12, 13, 26, 38, 39, 51] {
        assert_eq!(
            run(short),
            Err(Unproven::Budget(BudgetExhausted::Nsec3Blocks)),
            "{short}"
        );
    }
    assert!(run(52).is_ok());
}

/// The limit holds for every set of parameters in the response, not only the first one read.
/// Derived: the iterations of real records of RFC 5155 Appendix A are rewritten.
#[test]
fn the_limit_applies_to_every_set_of_parameters() {
    let zone = zone("rfc5155_appendix_a.zone");
    let owners = [
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
        "35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
    ];
    let nsec3 = pick(&zone, RecordType::NSEC3, &owners);
    let records = vec![
        nsec3_with(&nsec3[0], Nsec3HashAlgorithm::SHA1, 1, 12),
        nsec3_with(&nsec3[1], Nsec3HashAlgorithm::SHA1, 1, 151),
    ];
    assert_eq!(
        prove("example.", "ns1.example.", RecordType::MX, &records),
        Err(Unproven::IterationsAboveLimit {
            iterations: 151,
            limit: 150
        })
    );
}
