//! RFC 9018 in the server cookies (D113): the interoperable Server Cookie of version 1, SipHash-2-4, checked against
//! the examples of Appendix A, whose secrets, addresses and timestamps are used as written, and the timestamp
//! window of §4.3 and the secret rollover of §5.

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::hex;
use dedens_proto::edns::Cookie;
use dedens_server::{Clock, Cookies, Secret, Secrets, Standing};

const SECRET: &str = "e5e973e5a6b2a43f48e7dc849e37bfcf";
const OLD: &str = "dd3bdf9344b678b185a6f5cb60fca715";
const NEW: &str = "445536bcd2513298075a5d379663c962";
const CLIENT: &str = "2464c4abcf10c957";

fn secret(text: &str) -> Secret {
    text.parse().expect("a secret")
}

fn addr(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// A clock a test sets.
fn clock(start: u64) -> (Arc<AtomicU64>, Clock) {
    let time = Arc::new(AtomicU64::new(start));
    let reading = Arc::clone(&time);
    (time, Arc::new(move || reading.load(Ordering::Relaxed)))
}

fn cookies(secrets: Secrets, now: u64) -> Cookies {
    Cookies::new(secrets, clock(now).1)
}

fn fixed(current: &str, accepted: &[&str]) -> Secrets {
    Secrets::new(
        secret(current),
        accepted.iter().map(|text| secret(text)).collect(),
    )
}

/// The cookie of the hexadecimal `text`: 8 bytes of client cookie, the rest the server's.
fn cookie(text: &str) -> Cookie {
    let bytes = hex(text);
    let (client, server) = bytes.split_at(8);
    Cookie::new(
        client.try_into().expect("8 bytes"),
        (!server.is_empty()).then_some(server),
    )
    .expect("a cookie")
}

fn client_cookie(text: &str) -> [u8; 8] {
    hex(text).try_into().expect("8 bytes")
}

/// The examples of Appendix A: a cookie the server issues for a client cookie at a time.
#[test]
fn the_examples_of_appendix_a_are_issued() {
    for (secrets, client, from, now, expected) in [
        // A.1: a client cookie only.
        (
            fixed(SECRET, &[]),
            CLIENT,
            "198.51.100.100",
            1_559_731_985,
            "2464c4abcf10c957010000005cf79f111f8130c3eee29480",
        ),
        // A.2: the client uses the cookie of A.1 later: a new timestamp, a new hash.
        (
            fixed(SECRET, &[]),
            CLIENT,
            "198.51.100.100",
            1_559_734_385,
            "2464c4abcf10c957010000005cf7a871d4a564a1442aca77",
        ),
        // A.3: another client; its request had reserved bytes of abcdef, the reply has zeros.
        (
            fixed(SECRET, &[]),
            "fc93fc62807ddb86",
            "203.0.113.203",
            1_559_734_700,
            "fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e",
        ),
        // A.4: an IPv6 client, the new secret of a rollover.
        (
            fixed(NEW, &[OLD]),
            "22681ab97d52c298",
            "2001:db8:220:1:59de:d0f4:8769:82b8",
            1_559_741_961,
            "22681ab97d52c298010000005cf7c609a6bb79d16625507a",
        ),
    ] {
        let issued = cookies(secrets, now).issue(client_cookie(client), addr(from));
        assert_eq!(issued, cookie(expected), "{from} at {now}");
    }
}

/// The requests of A.3 and A.4 verify, reserved bytes and all (§4.2: they are not required to be zero).
#[test]
fn the_requests_of_appendix_a_verify() {
    for (secrets, from, now, request) in [
        (
            fixed(SECRET, &[]),
            "203.0.113.203",
            // A.3's request is a few seconds old, not the hours of its reply.
            1_559_727_985 + 10,
            "fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5",
        ),
        (
            // A.4: the request has the old secret; the server is at stage 2 of §5: new secret, old accepted.
            fixed(NEW, &[OLD]),
            "2001:db8:220:1:59de:d0f4:8769:82b8",
            1_559_741_961,
            "22681ab97d52c298010000005cf7c57926556bd0934c72f8",
        ),
        (
            // The reply of A.4, to a server of stage 1: old secret, new accepted.
            fixed(OLD, &[NEW]),
            "2001:db8:220:1:59de:d0f4:8769:82b8",
            1_559_741_961,
            "22681ab97d52c298010000005cf7c609a6bb79d16625507a",
        ),
    ] {
        let standing = cookies(secrets, now).verify(Some(&cookie(request)), addr(from));
        assert_eq!(standing, Standing::Valid, "{request}");
    }
}

#[test]
fn a_secret_the_server_does_not_have_does_not_verify() {
    let request = cookie("22681ab97d52c298010000005cf7c57926556bd0934c72f8");
    let from = addr("2001:db8:220:1:59de:d0f4:8769:82b8");
    // Stage 3 of §5: the old secret is gone.
    let after = cookies(fixed(NEW, &[]), 1_559_741_961);
    assert_eq!(after.verify(Some(&request), from), Standing::Invalid);
    let before = cookies(fixed(OLD, &[]), 1_559_741_961);
    assert_eq!(before.verify(Some(&request), from), Standing::Valid);
}

/// §4.4: the hash covers the client's address and the client cookie.
#[test]
fn a_cookie_is_for_one_address_and_one_client_cookie() {
    let cookies = cookies(fixed(SECRET, &[]), 1_559_731_985);
    let issued = cookies.issue(client_cookie(CLIENT), addr("198.51.100.100"));
    assert_eq!(
        cookies.verify(Some(&issued), addr("198.51.100.100")),
        Standing::Valid
    );
    assert_eq!(
        cookies.verify(Some(&issued), addr("198.51.100.101")),
        Standing::Invalid
    );
    // An IPv4-mapped address is the IPv4 one (D91).
    assert_eq!(
        cookies.verify(Some(&issued), addr("::ffff:198.51.100.100")),
        Standing::Valid
    );
    let other = Cookie::new(client_cookie("2464c4abcf10c958"), issued.server()).expect("a cookie");
    assert_eq!(
        cookies.verify(Some(&other), addr("198.51.100.100")),
        Standing::Invalid
    );
}

/// §4.3: a cookie is good for an hour from its timestamp, and a timestamp may be five minutes ahead of the clock
/// (the skew of an anycast set).
#[test]
fn a_timestamp_must_be_within_an_hour_past_and_five_minutes_ahead() {
    let from = addr("198.51.100.100");
    let (time, reading) = clock(1_559_731_985);
    let cookies = Cookies::new(fixed(SECRET, &[]), reading);
    let issued = cookies.issue(client_cookie(CLIENT), from);
    for (now, expected) in [
        (1_559_731_985 - 300, Standing::Valid),
        (1_559_731_985 - 301, Standing::Invalid),
        (1_559_731_985 + 3600, Standing::Valid),
        (1_559_731_985 + 3601, Standing::Invalid),
    ] {
        time.store(now, Ordering::Relaxed);
        assert_eq!(cookies.verify(Some(&issued), from), expected, "at {now}");
    }
}

/// §4.3: timestamps are 32 bits compared as serial numbers (RFC 1982), so that they wrap.
#[test]
fn timestamps_wrap_at_2_pow_32() {
    let from = addr("198.51.100.100");
    let before_wrap = u64::from(u32::MAX) - 10;
    let (time, reading) = clock(before_wrap);
    let cookies = Cookies::new(fixed(SECRET, &[]), reading);
    let issued = cookies.issue(client_cookie(CLIENT), from);
    // 100 seconds on, the clock is past 2^32 and the timestamp small again.
    time.store(before_wrap + 100, Ordering::Relaxed);
    assert_eq!(cookies.verify(Some(&issued), from), Standing::Valid);
}

/// §4.1: only version 1 is checked here; a version 1 cookie is 16 bytes.
#[test]
fn another_version_or_length_is_invalid() {
    let from = addr("198.51.100.100");
    let cookies = cookies(fixed(SECRET, &[]), 1_559_731_985);
    for server in [
        "020000005cf79f111f8130c3eee29480",
        "010000005cf79f111f8130c3eee294",
        "010000005cf79f111f8130c3eee29480ff",
        "0100000000000000",
    ] {
        let sent = cookie(&format!("{CLIENT}{server}"));
        assert_eq!(
            cookies.verify(Some(&sent), from),
            Standing::Invalid,
            "{server}"
        );
    }
}

#[test]
fn what_the_query_carries_is_its_standing() {
    let from = addr("198.51.100.100");
    let cookies = cookies(fixed(SECRET, &[]), 1_559_731_985);
    assert_eq!(cookies.verify(None, from), Standing::NoCookie);
    assert_eq!(
        cookies.verify(Some(&cookie(CLIENT)), from),
        Standing::ClientOnly
    );
}

#[test]
fn a_secret_is_32_hexadecimal_digits_and_never_printed() {
    for bad in ["", "e5e973", &"zz".repeat(16), &format!("{SECRET}00")] {
        assert!(bad.parse::<Secret>().is_err(), "{bad}");
    }
    let shown = format!("{:?}", fixed(SECRET, &[OLD]));
    assert!(
        !shown.contains("e5e9") && !shown.contains("dd3b"),
        "{shown}"
    );
}
