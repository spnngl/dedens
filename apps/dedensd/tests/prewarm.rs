//! `dedensd` keeping the names of a cache stage's `prewarm` answered (D96; RFC 9520 §3.2 for the failures it does not
//! hold): each asked of the upstream once at the start, before any client; a client then hits the cache, and still
//! does once the TTL has passed, the entry having been asked again before it expired. The upstream is a loopback
//! server of captured responses that counts what it is asked (D89).

use std::time::{Duration, Instant};

use dedens_proto::{Message, RecordType};
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

/// Whether the upstream was sent a query with `id`.
fn saw(upstream: &Responder, id: u16) -> bool {
    upstream
        .queries()
        .iter()
        .any(|(_, query)| query.get(..2) == Some(&id.to_be_bytes()))
}

#[test]
fn a_listed_name_is_asked_once_before_any_client_and_answers_from_the_cache() {
    let upstream = Responder::start(&["a"]);
    let at = upstream.addr.to_string();
    let server = Server::configured(|listen| {
        text(
            listen,
            &at,
            "",
            "      entries: [example.com]\n      types: [A]\n",
        )
    });
    until("the name asked", || {
        upstream.asked("example.com", RecordType::A) == 1
    });
    let answer = reply(&server, "a", 0x5a5a);
    assert!(!answer.answer.is_empty(), "{answer:?}");
    assert!(!saw(&upstream, 0x5a5a), "the client's query went upstream");
    assert_eq!(upstream.asked("example.com", RecordType::A), 1);
    // Nothing else is asked: the type that is not listed.
    assert_eq!(upstream.queries().len(), 1);
}

#[test]
fn a_short_lived_name_is_asked_again_before_it_expires_with_no_client() {
    // A TTL of 4 s, kept as it is, and refreshed at the half of it.
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
    until("the name asked three times", || {
        upstream.asked("example.com", RecordType::A) >= 3
    });
    // Past the TTL, still a hit: the client's query is not the one the upstream saw.
    let answer = reply(&server, "a", 0x5a5b);
    assert!(!answer.answer.is_empty(), "{answer:?}");
    assert!(!saw(&upstream, 0x5a5b), "the client's query went upstream");
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
    until("the name asked", || {
        upstream.asked("example.com", RecordType::A) == 1
    });
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
    until("the new name asked", || {
        upstream.asked("cloudflare.com", RecordType::AAAA) == 1
    });
    // The entry the cache kept is not asked again, nor is a name that is no longer listed.
    assert_eq!(upstream.asked("example.com", RecordType::A), 1);
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
