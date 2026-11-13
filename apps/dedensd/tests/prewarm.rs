//! `dedensd` keeping the names of a cache stage's `prewarm` answered (D96; RFC 9520 §3.2 for the failures it does not
//! hold): each asked of the upstream once at the start, before any client; a client then hits the cache, and still
//! does once the TTL has passed, the entry having been asked again before it expired. The upstream is a loopback
//! server of captured responses that counts what it is asked (D89).

use std::time::{Duration, Instant};

use dedens_proto::{Flags, Message, Rcode, RecordType};
use dedens_testkit::responder::Responder;

use crate::util::{Server, ask_udp, query_for, validate};

/// How long a condition that should come is waited for.
const WAIT: Duration = Duration::from_secs(20);

/// Waits until `condition` holds.
///
/// # Panics
///
/// When it does not within [`WAIT`].
#[track_caller]
fn until(what: &str, condition: impl Fn() -> bool) {
    let end = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < end, "never came: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A caching forwarder of `upstream` whose cache stage has the settings `cache` and prewarms `prewarm`, each as
/// lines of `"    key: value\n"`.
fn text(listen: &str, upstream: &str, cache: &str, prewarm: &str) -> String {
    format!(
        "listen: ['{listen}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n{cache}    prewarm:\n{prewarm}  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 1000\n    tries: 1\n"
    )
}

/// The reply of `server` to the captured query `case`, whose ID is `id`.
fn reply(server: &Server, case: &str, id: u16) -> Message<'static> {
    ask_udp(server.addr, &query_for(case, id))
}

/// Whether the cache of `server` answers the captured query `case` with data. The query has RD clear: it gets the fresh
/// cached data or REFUSED, and never goes upstream (D46), so that it neither asks nor hides what the task asked.
fn kept(server: &Server, case: &str) -> bool {
    let mut query = dedens_testkit::query(case, 0x5a5a);
    query.header.flags = Flags::NONE;
    let answer = ask_udp(server.addr, &query.to_vec().expect("a query fits"));
    answer.rcode() == Rcode::NOERROR && !answer.answer.is_empty()
}

#[test]
fn every_listed_name_and_type_is_asked_once_before_any_client_and_answers_from_the_cache() {
    let upstream = Responder::start(&["a", "aaaa"]);
    let at = upstream.addr.to_string();
    let server = Server::configured(|listen| {
        text(
            listen,
            &at,
            "",
            "      entries: [example.com, cloudflare.com]\n      types: [A, AAAA]\n",
        )
    });
    // Kept: not merely asked, which the upstream counts before the answer is stored.
    until("the name kept", || kept(&server, "a"));
    let answer = reply(&server, "a", 0x5a5b);
    assert!(!answer.answer.is_empty(), "{answer:?}");
    until("the last name asked", || upstream.queries().len() == 4);
    for (name, qtype) in [
        ("example.com", RecordType::A),
        ("example.com", RecordType::AAAA),
        ("cloudflare.com", RecordType::A),
        ("cloudflare.com", RecordType::AAAA),
    ] {
        assert_eq!(upstream.asked(name, qtype), 1, "{name} {qtype:?}");
    }
}

#[test]
fn a_short_lived_name_is_kept_across_its_expiry_with_no_client() {
    // A TTL of 4 s, asked again 2 s before it expires, the margin, whatever the 50% of it.
    let upstream = Responder::ttl("a", 4);
    let at = upstream.addr.to_string();
    let server = Server::configured(|listen| {
        text(
            listen,
            &at,
            "    min_ttl: 0\n    prefetch_percent: 50\n",
            "      entries: [example.com]\n      types: [A]\n",
        )
    });
    until("the name kept", || kept(&server, "a"));
    // Across two expiries the cache answers every time: a refresh that came late would find REFUSED.
    let end = Instant::now() + Duration::from_secs(9);
    while Instant::now() < end {
        assert!(kept(&server, "a"), "expired before it was asked again");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(upstream.asked("example.com", RecordType::A) >= 3);
}

#[test]
fn a_reload_asks_the_names_added_alone() {
    let upstream = Responder::start(&["a", "aaaa"]);
    let at = upstream.addr.to_string();
    let mut server = Server::configured(|listen| {
        text(
            listen,
            &at,
            "",
            "      entries: [example.com]\n      types: [A]\n",
        )
    });
    until("the name kept", || kept(&server, "a"));
    let listen = server.addr.to_string();
    let wider = text(
        &listen,
        &at,
        "",
        "      entries: [example.com, cloudflare.com]\n      types: [A, AAAA]\n",
    );
    std::fs::write(&server.config, wider).expect("rewritten");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    until("the new questions asked", || {
        [
            ("example.com", RecordType::AAAA),
            ("cloudflare.com", RecordType::A),
            ("cloudflare.com", RecordType::AAAA),
        ]
        .iter()
        .all(|&(name, qtype)| upstream.asked(name, qtype) == 1)
    });
    // The entry the cache kept is not asked again.
    assert_eq!(upstream.asked("example.com", RecordType::A), 1);
}

/// D96, D117: a question the validator's allowance sheds is asked again once it admits, not left until a reload. The
/// share of prewarm's address is one unit: the first of the two questions of the name (without DO, with it) goes into
/// debt and the other is shed until it is paid. The answers are bogus, the signatures of the captures being long
/// expired, which is no matter: what counts is the upstream is asked twice.
#[test]
fn a_question_the_allowance_sheds_is_asked_again() {
    let upstream = Responder::start(&["alg8_a", "root_dnskey"]);
    let at = upstream.addr.to_string();
    let _server = Server::configured(|listen| {
        format!(
            "listen: ['{listen}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n    prewarm:\n      entries: [nlnetlabs.nl]\n      types: [A]\n  up:\n    type: forward\n    servers: ['{at}']\n    timeout_ms: 1000\n    tries: 1\n    dnssec: validate\n    client_share: {{rate: 1, burst: 1}}\n"
        )
    });
    until("both questions asked", || {
        upstream.asked("nlnetlabs.nl.", RecordType::A) >= 2
    });
}

#[test]
fn a_name_a_stage_before_the_cache_answers_is_not_asked_upstream() {
    let upstream = Responder::start(&["a", "aaaa"]);
    let at = upstream.addr.to_string();
    let server = Server::configured(|listen| {
        format!(
            "listen: ['{listen}']\npipeline: [block, cache, up]\nstages:\n  block:\n    type: blocklist\n    entries: [example.com]\n  cache:\n    type: cache\n    prewarm:\n      entries: [example.com, cloudflare.com]\n      types: [AAAA]\n  up:\n    type: forward\n    servers: ['{at}']\n    timeout_ms: 1000\n    tries: 1\n"
        )
    });
    until("the name left asked", || {
        upstream.asked("cloudflare.com", RecordType::AAAA) == 1
    });
    assert_eq!(upstream.asked("example.com", RecordType::A), 0);
    assert_eq!(upstream.asked("example.com", RecordType::AAAA), 0);
    drop(server);
}

#[test]
fn a_prewarm_without_a_forward_stage_after_the_cache_is_refused() {
    let (code, stderr) = validate(
        "listen: ['127.0.0.1:0']\npipeline: [cache]\nstages:\n  cache:\n    type: cache\n    prewarm:\n      entries: [example.com]\n",
    );
    assert_ne!(code, Some(0), "{stderr}");
    assert!(stderr.contains("no forward stage"), "{stderr}");
}
