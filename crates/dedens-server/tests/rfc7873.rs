//! RFC 7873 §5.2 and §5.4 in the server core (D113): a query with a Client Cookie is answered with a Server Cookie
//! (made as RFC 9018 says, `tests/rfc9018.rs`), on every transport and from the cache; an invalid Server Cookie is
//! treated as none, so the query is answered; a query without a question but with a cookie is a request for one.

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use common::{caching, decode, forwarder, query_for, reply, run, wire};
use dedens_proto::edns::{Cookie, Edns, EdnsOption};
use dedens_proto::{Message, Rcode, Transport};
use dedens_server::{Clock, Cookies, Secret, Secrets, Standing};
use dedens_testkit::{captured, hex};

const CLIENT: [u8; 8] = [0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57];
const NOW: u64 = 1_559_731_985;
const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

fn cookies() -> Cookies {
    let clock: Clock = Arc::new(|| NOW);
    let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
        .parse()
        .expect("a secret");
    Cookies::new(Secrets::new(secret, vec![]), clock)
}

/// `query` asking with `cookie`.
fn with_cookie(mut query: Message<'static>, cookie: &Cookie) -> Vec<u8> {
    query.edns = Some(Edns {
        options: vec![EdnsOption::Cookie(*cookie)],
        ..Edns::default()
    });
    wire(&query)
}

fn client_only() -> Cookie {
    Cookie::new(CLIENT, None).expect("a client cookie")
}

/// The cookie of the reply's OPT record, if any.
fn cookie_of(reply: &[u8]) -> Option<Cookie> {
    decode(reply)
        .edns?
        .options
        .into_iter()
        .find_map(|option| match option {
            EdnsOption::Cookie(cookie) => Some(cookie),
            _ => None,
        })
}

/// A query with a Client Cookie alone gets its own Client Cookie back and a Server Cookie of RFC 9018 §4: 16 bytes,
/// version 1, the timestamp of now.
#[test]
fn a_client_cookie_is_answered_with_a_server_cookie() {
    let pipeline = forwarder().with_cookies(cookies());
    let query = query_for(&captured("a"));
    let sent = with_cookie(query, &client_only());
    for transport in [Transport::Udp, Transport::Tcp, Transport::Https] {
        let answer = reply(&pipeline, &sent, transport, Some(&captured("a")));
        let cookie = cookie_of(&answer).expect("a cookie");
        assert_eq!(cookie.client(), CLIENT);
        let server = cookie.server().expect("a Server Cookie");
        assert_eq!(&server[..4], [1, 0, 0, 0]);
        assert_eq!(
            server[4..8],
            u32::try_from(NOW).expect("a timestamp").to_be_bytes()
        );
        assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
    }
}

/// §5.2.1: a query without a cookie is answered without one; so is any query to a pipeline without cookies.
#[test]
fn no_cookie_asked_none_given() {
    let query = wire(&query_for(&captured("a")));
    let pipeline = forwarder().with_cookies(cookies());
    assert_eq!(
        cookie_of(&reply(
            &pipeline,
            &query,
            Transport::Udp,
            Some(&captured("a"))
        )),
        None
    );
    let sent = with_cookie(query_for(&captured("a")), &client_only());
    let bare = forwarder();
    assert_eq!(
        cookie_of(&reply(&bare, &sent, Transport::Udp, Some(&captured("a")))),
        None
    );
}

/// §5.2.5: the reply to a query with a valid Server Cookie has one, fresh, from the cache or upstream alike.
#[test]
fn a_valid_server_cookie_is_answered_and_renewed_from_the_cache_too() {
    let pipeline = caching().with_cookies(cookies());
    let issued = cookies().issue(CLIENT, LOOPBACK);
    let sent = with_cookie(query_for(&captured("a")), &issued);
    let first = run(&pipeline, &sent, Transport::Udp, &[Some(&captured("a"))]);
    assert_eq!(first.asked.len(), 1);
    let cached = run(&pipeline, &sent, Transport::Udp, &[]);
    assert_eq!(cached.asked.len(), 0, "the cache answers");
    for answer in [first.reply, cached.reply] {
        let answer = answer.expect("a reply");
        assert_eq!(
            cookie_of(&answer),
            Some(issued),
            "the same time, the same cookie"
        );
        assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
    }
}

/// §5.2.3, §5.2.4: our policy answers a query whose Server Cookie is invalid as one with a Client Cookie alone: the
/// answer is the real one, with a valid Server Cookie to use next, not BADCOOKIE (D113).
#[test]
fn an_invalid_server_cookie_is_answered_with_a_fresh_one() {
    let pipeline = forwarder().with_cookies(cookies());
    let stale =
        Cookie::new(CLIENT, Some(&hex("010000005cf79f11ffffffffffffffff"))).expect("a cookie");
    let sent = with_cookie(query_for(&captured("a")), &stale);
    let answer = reply(&pipeline, &sent, Transport::Udp, Some(&captured("a")));
    assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
    assert!(!decode(&answer).answer.is_empty(), "the real answer");
    let fresh = cookie_of(&answer).expect("a cookie");
    let verified = pipeline
        .cookies()
        .map(|cookies| cookies.verify(Some(&fresh), LOOPBACK));
    assert_eq!(verified, Some(Standing::Valid));
}

/// §5.2.2: a query that breaks a rule, here two questions (RFC 9619 §4), is FORMERR with no cookie, though its
/// own is well-formed.
#[test]
fn a_query_breaking_a_rule_is_formerr_without_a_cookie() {
    let pipeline = forwarder().with_cookies(cookies());
    let mut query = query_for(&captured("a"));
    query.questions.push(query.questions[0].clone());
    let answer = reply(
        &pipeline,
        &with_cookie(query, &client_only()),
        Transport::Udp,
        None,
    );
    assert_eq!(decode(&answer).rcode(), Rcode::FORMERR);
    assert_eq!(cookie_of(&answer), None);
}

/// The request sent upstream carries no cookie of ours or the client's: they are for the hop they were made for.
#[test]
fn the_cookie_is_not_forwarded() {
    let pipeline = forwarder().with_cookies(cookies());
    let sent = with_cookie(query_for(&captured("a")), &client_only());
    let ran = run(&pipeline, &sent, Transport::Udp, &[Some(&captured("a"))]);
    let request = ran.requests.first().expect("a request");
    let options = request.edns.as_ref().map(|edns| edns.options.clone());
    assert!(
        options
            .unwrap_or_default()
            .iter()
            .all(|option| !matches!(option, EdnsOption::Cookie(_)))
    );
}

/// §5.4: a query with no question and a cookie asks for a cookie: NOERROR with one, BADCOOKIE when the Server
/// Cookie it sent is invalid, with a valid one to retry with. Without a cookie it is FORMERR (RFC 9619).
#[test]
fn a_query_without_a_question_asks_for_a_cookie() {
    let pipeline = forwarder().with_cookies(cookies());
    let empty = || {
        let mut query = Message::default();
        query.header.id = 9;
        query
    };
    let bad = Cookie::new(CLIENT, Some(&hex("010000005cf79f11ffffffffffffffff"))).expect("cookie");
    let good = cookies().issue(CLIENT, LOOPBACK);
    for (cookie, rcode) in [
        (client_only(), Rcode::NOERROR),
        (good, Rcode::NOERROR),
        (bad, Rcode::BADCOOKIE),
    ] {
        let answer = reply(
            &pipeline,
            &with_cookie(empty(), &cookie),
            Transport::Udp,
            None,
        );
        assert_eq!(decode(&answer).rcode(), rcode, "{cookie:?}");
        let fresh = cookie_of(&answer).expect("a cookie");
        assert_eq!(cookies().verify(Some(&fresh), LOOPBACK), Standing::Valid);
    }
    let mut bare = empty();
    bare.edns = Some(Edns::default());
    let answer = reply(&pipeline, &wire(&bare), Transport::Udp, None);
    assert_eq!(decode(&answer).rcode(), Rcode::FORMERR);
}

/// A query with an empty OPT record followed by COOKIE options of `lengths` bytes of data each.
fn with_cookie_options(lengths: &[usize]) -> Vec<u8> {
    let mut sent = wire(&{
        let mut query = query_for(&captured("a"));
        query.edns = Some(Edns::default());
        query
    });
    // The OPT record is last: its RDLENGTH, the two bytes before the end, now holds the options.
    let options: usize = lengths.iter().map(|length| 4 + length).sum();
    let rdlength = sent.len() - 2;
    sent[rdlength..].copy_from_slice(&u16::try_from(options).expect("fits").to_be_bytes());
    for &length in lengths {
        sent.extend_from_slice(&10_u16.to_be_bytes());
        sent.extend_from_slice(&u16::try_from(length).expect("fits").to_be_bytes());
        sent.extend_from_slice(&vec![7; length]);
    }
    sent
}

/// §5.2.2: a COOKIE option of a length other than 8, or 16 to 40, is FORMERR, with no cookie in the reply; those
/// lengths are answered, with a Server Cookie.
#[test]
fn a_cookie_of_the_wrong_length_is_formerr() {
    let pipeline = forwarder().with_cookies(cookies());
    for length in [0, 7, 9, 12, 15, 41] {
        let answer = reply(
            &pipeline,
            &with_cookie_options(&[length]),
            Transport::Udp,
            None,
        );
        assert_eq!(decode(&answer).rcode(), Rcode::FORMERR, "{length} bytes");
        assert_eq!(cookie_of(&answer), None, "{length} bytes");
    }
    for length in [8, 16, 24, 40] {
        let sent = with_cookie_options(&[length]);
        let answer = reply(&pipeline, &sent, Transport::Udp, Some(&captured("a")));
        assert_eq!(decode(&answer).rcode(), Rcode::NOERROR, "{length} bytes");
        let fresh = cookie_of(&answer).expect("a cookie");
        assert_eq!(fresh.client(), [7; 8], "{length} bytes");
        assert_eq!(cookies().verify(Some(&fresh), LOOPBACK), Standing::Valid);
    }
}

/// §5.2: a COOKIE option after the first is ignored, a malformed one too.
#[test]
fn the_cookie_options_after_the_first_are_ignored() {
    let pipeline = forwarder().with_cookies(cookies());
    let sent = with_cookie_options(&[8, 12, 41]);
    let answer = reply(&pipeline, &sent, Transport::Udp, Some(&captured("a")));
    assert_eq!(decode(&answer).rcode(), Rcode::NOERROR);
    assert_eq!(cookie_of(&answer).expect("a cookie").client(), [7; 8]);
}
