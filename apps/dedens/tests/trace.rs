//! `+trace`: the referrals followed from the roots without recursion (RFC 1034 §4.3.2).

use dedens_proto::Flags;
use dedens_testkit::responder::Responder;
use predicates::prelude::*;
use predicates::str::contains;

use crate::util::{dedens, queries};

#[test]
fn trace_starts_from_the_roots_without_recursion() {
    let root = Responder::start(&["a"]);
    let out = dedens()
        .args(["+trace", "example.com", "--color=never"])
        .env("DEDENS_ROOTS", root.addr.to_string())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).expect("UTF-8");
    assert!(out.contains("example.com. A  NOERROR"), "{out}");
    let asked = queries(&root);
    assert_eq!(asked.len(), 1);
    assert!(!asked[0].1.header.flags.contains(Flags::RD));
}

#[test]
fn trace_exits_9_when_no_root_replies() {
    let (first, second) = (Responder::start(&[]), Responder::start(&[]));
    dedens()
        .args(["+trace", "example.com", "+tries=1", "+time=100ms"])
        .env("DEDENS_ROOTS", format!("{},{}", first.addr, second.addr))
        .assert()
        .code(9)
        .stdout("")
        .stderr(contains("example.com_A"));
    assert_eq!((first.queries().len(), second.queries().len()), (1, 1));
}

/// A `+trace` run with `roots` as the root servers.
fn trace(roots: &[&Responder], args: &[&str]) -> assert_cmd::assert::Assert {
    let roots: Vec<String> = roots.iter().map(|root| root.addr.to_string()).collect();
    dedens()
        .args(["+trace", "--color=never"])
        .args(args)
        .env("DEDENS_ROOTS", roots.join(","))
        .assert()
}

#[test]
fn trace_ends_on_nxdomain() {
    let root = Responder::start(&["nxdomain_soa"]);
    trace(&[&root], &["nonexistent.invalid"])
        .success()
        .stdout(contains("NXDOMAIN"));
    assert_eq!(root.queries().len(), 1);
}

#[test]
fn trace_moves_past_a_broken_server() {
    let (failing, answering) = (Responder::start(&["ede"]), Responder::start(&["ede_cd"]));
    trace(&[&failing, &answering], &["dnssec-failed.org"])
        .success()
        .stdout(contains("SERVFAIL").and(contains("NOERROR")));
    assert_eq!((failing.queries().len(), answering.queries().len()), (1, 1));
}

#[test]
fn trace_fails_on_a_response_that_leads_nowhere() {
    // NOERROR without answer, AA, referral or SOA: lame.
    let root = Responder::start(&["truncated"]);
    let out = trace(&[&root], &["google.com", "TXT", "+ignore"])
        .code(10)
        .stderr(contains("neither an answer nor a referral"))
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8_lossy(&out).matches("NOERROR").count(), 1);
}
