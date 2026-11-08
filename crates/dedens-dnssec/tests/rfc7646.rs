//! RFC 7646 (negative trust anchors) §1.1: a name at or below one is not validated, unless a positive anchor
//! lies between it and the name.

mod common;

use std::fmt::Write as _;

use common::name;
use dedens_dnssec::TrustAnchors;

const DS: &str = "2BB183AF5F22588179A53B0A98631FAD1A292118";

fn anchors(zones: &[&str], negative: &[&str]) -> TrustAnchors {
    let mut text = String::new();
    for zone in zones {
        writeln!(text, "{zone} IN DS 60485 5 1 {DS}").expect("a string");
    }
    let mut anchors = TrustAnchors::read(&text).expect("anchors");
    for n in negative {
        anchors.add_negative(name(n));
    }
    anchors
}

#[test]
fn s1_1_no_negative_anchor_validates_everything() {
    let anchors = anchors(&["."], &[]);
    assert!(!anchors.negative(&name("example.com.")));
    assert!(!anchors.negative(&name(".")));
}

#[test]
fn s1_1_the_name_and_everything_below_it_are_insecure() {
    let anchors = anchors(&["."], &["example.com."]);
    assert!(anchors.negative(&name("example.com.")));
    assert!(anchors.negative(&name("www.example.com.")));
    assert!(anchors.negative(&name("a.b.c.example.com.")));
    assert!(anchors.negative(&name("WWW.Example.COM.")));
}

#[test]
fn s1_1_names_not_below_it_are_validated() {
    let anchors = anchors(&["."], &["example.com."]);
    assert!(!anchors.negative(&name("com.")));
    assert!(!anchors.negative(&name(".")));
    assert!(!anchors.negative(&name("example.net.")));
    // A sibling whose name only ends in the same letters.
    assert!(!anchors.negative(&name("badexample.com.")));
}

#[test]
fn s1_1_a_negative_anchor_at_the_root_covers_every_name() {
    let anchors = anchors(&["."], &["."]);
    assert!(anchors.negative(&name(".")));
    assert!(anchors.negative(&name("example.com.")));
}

#[test]
fn s1_1_several_negative_anchors_are_independent() {
    let anchors = anchors(&["."], &["example.com.", "example.org."]);
    assert!(anchors.negative(&name("a.example.com.")));
    assert!(anchors.negative(&name("a.example.org.")));
    assert!(!anchors.negative(&name("a.example.net.")));
}

#[test]
fn s1_1_a_deeper_positive_anchor_resumes_validation() {
    // The RFC's example: a negative anchor at `example.com` and a positive one at `foo.bar.example.com`.
    let anchors = anchors(&[".", "foo.bar.example.com."], &["example.com."]);
    assert!(anchors.negative(&name("example.com.")));
    assert!(anchors.negative(&name("bar.example.com.")));
    assert!(anchors.negative(&name("baz.bar.example.com.")));
    assert!(!anchors.negative(&name("foo.bar.example.com.")));
    assert!(!anchors.negative(&name("www.foo.bar.example.com.")));
}

#[test]
fn s1_1_a_positive_anchor_above_changes_nothing() {
    let anchors = anchors(&[".", "com."], &["example.com."]);
    assert!(anchors.negative(&name("www.example.com.")));
    assert!(!anchors.negative(&name("other.com.")));
}

#[test]
fn s1_1_the_negative_anchor_wins_at_the_same_name() {
    let anchors = anchors(&[".", "example.com."], &["example.com."]);
    assert!(anchors.negative(&name("example.com.")));
    assert!(anchors.negative(&name("www.example.com.")));
}

#[test]
fn s1_1_a_negative_anchor_below_a_positive_one_still_applies() {
    let anchors = anchors(&[".", "example.com."], &["www.example.com."]);
    assert!(!anchors.negative(&name("example.com.")));
    assert!(!anchors.negative(&name("mail.example.com.")));
    assert!(anchors.negative(&name("a.www.example.com.")));
}
