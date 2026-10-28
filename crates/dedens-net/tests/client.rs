//! The client end to end, against scripted servers on the loopback address (D27).

mod common;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use common::loopback::{answer, id, responders, udp_responder};
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::{Failure, Options, Transport};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{Message, Rcode};

/// The cookie a message carries.
fn cookie(wire: &[u8]) -> Option<Cookie> {
    let edns = Message::decode(wire).expect("a message").message.edns?;
    edns.options.into_iter().find_map(|option| match option {
        EdnsOption::Cookie(cookie) => Some(cookie),
        _ => None,
    })
}

fn answer_plainly(query: &[u8]) -> Vec<u8> {
    answer(query, Vec::new())
}

#[compio::test]
async fn a_query_gets_its_response_over_udp() {
    let server = udp_responder(|query| Some(answer_plainly(query))).await;
    let response = Client::new()
        .exchange(&common::query(), server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Udp);
    assert_eq!(response.sends, 1);
    assert_eq!(id(&response.wire), id(&response.query));
}

/// RFC 7766 §5, RFC 1123 §6.1.3.2.
#[compio::test]
async fn a_truncated_response_is_asked_again_over_tcp() {
    let server = responders(
        |query| {
            let mut truncated = answer_plainly(query);
            truncated[2] |= 0x02;
            Some(truncated)
        },
        answer_plainly,
    )
    .await;
    let response = Client::new()
        .exchange(&common::query(), server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Tcp);
    assert_eq!(response.sends, 2);
}

/// RFC 7873 §5.1, §5.3: the client cookie stays for the server, its server cookie comes back to it.
#[compio::test]
async fn the_server_cookie_goes_back_to_its_server() {
    const SERVER_COOKIE: &[u8] = b"server-cookie-16";
    let queries = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&queries);
    let server = udp_responder(move |query| {
        seen.borrow_mut().push(query.to_vec());
        let client = cookie(query).expect("a cookie").client();
        let returned = Cookie::new(client, Some(SERVER_COOKIE)).expect("a valid cookie");
        Some(answer(query, vec![EdnsOption::Cookie(returned)]))
    })
    .await;
    let client = Client::new();
    for _ in 0..2 {
        let response = client
            .exchange(&common::query(), server, &Options::default())
            .await
            .expect("a response");
        assert!(cookie(&response.wire).is_some());
    }
    let queries = queries.borrow();
    let (first, second) = (
        cookie(&queries[0]).expect("a cookie"),
        cookie(&queries[1]).expect("a cookie"),
    );
    assert_eq!(first.server(), None);
    assert_eq!(second.client(), first.client());
    assert_eq!(second.server(), Some(SERVER_COOKIE));
}

#[compio::test]
async fn no_response_times_out_after_every_try() {
    let server = udp_responder(|_| None).await;
    let mut options = Options::default();
    options.timeout = Duration::from_millis(20);
    options.tries = 2.try_into().expect("not zero");
    let result = Client::new()
        .exchange(&common::query(), server, &options)
        .await;
    assert!(
        matches!(
            result,
            Err(ClientError::Exchange(Failure::TimedOut { sends: 2 }))
        ),
        "{result:?}"
    );
}

#[compio::test]
async fn a_query_without_edns_goes_without_a_cookie() {
    let server = udp_responder(|query| Some(answer_plainly(query))).await;
    let mut query = common::query();
    query.edns = None;
    let response = Client::new()
        .exchange(&query, server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(cookie(&response.query), None);
}

/// RFC 7873 §5.3: a response with the client cookie alone leaves the server cookie known.
#[compio::test]
async fn a_response_without_a_server_cookie_keeps_the_known_one() {
    const SERVER_COOKIE: &[u8] = b"server-cookie-16";
    let queries = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&queries);
    let server = udp_responder(move |query| {
        let mut seen = seen.borrow_mut();
        // Only the first response carries a server cookie.
        let server_cookie = seen.is_empty().then_some(SERVER_COOKIE);
        seen.push(query.to_vec());
        let client = cookie(query).expect("a cookie").client();
        let returned = Cookie::new(client, server_cookie).expect("a valid cookie");
        Some(answer(query, vec![EdnsOption::Cookie(returned)]))
    })
    .await;
    let client = Client::new();
    for _ in 0..3 {
        client
            .exchange(&common::query(), server, &Options::default())
            .await
            .expect("a response");
    }
    let third = cookie(&queries.borrow()[2]).expect("a cookie");
    assert_eq!(third.server(), Some(SERVER_COOKIE));
}

/// RFC 7873 §5.3: the fresh server cookie of a BADCOOKIE is kept, though the exchange then fails.
#[compio::test]
async fn the_fresh_cookie_of_a_badcookie_is_kept_when_the_exchange_fails() {
    const FRESH: &[u8] = b"fresh-cookie-016";
    let queries = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&queries);
    // BADCOOKIE with a fresh cookie to the first query, then no response.
    let server = udp_responder(move |query| {
        let mut seen = seen.borrow_mut();
        seen.push(query.to_vec());
        (seen.len() == 1).then(|| {
            let client = cookie(query).expect("a cookie").client();
            let fresh = Cookie::new(client, Some(FRESH)).expect("a valid cookie");
            let query = Message::decode(query).expect("a query").message;
            let mut response = common::response(&query, Rcode::BADCOOKIE);
            response.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Cookie(fresh)];
            common::wire(&response)
        })
    })
    .await;
    let client = Client::new();
    let mut options = Options::default();
    options.timeout = Duration::from_millis(20);
    options.tries = 1.try_into().expect("not zero");
    let failed = client.exchange(&common::query(), server, &options).await;
    assert!(failed.is_err(), "{failed:?}");
    let _ = client.exchange(&common::query(), server, &options).await;
    // The first query of the second exchange, after the BADCOOKIE retry.
    let next = cookie(&queries.borrow()[2]).expect("a cookie");
    assert_eq!(next.server(), Some(FRESH));
}
