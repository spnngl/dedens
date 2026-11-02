//! `dedensd` giving Server Cookies (RFC 7873 §5.2, RFC 9018, D113) and leaving loopback out of the rate limit: the
//! source of every client here is `127.0.0.1`, which cannot be spoofed from outside, so it is not limited however
//! low `rrl` sets the rate. The limit itself is tested on the pipeline, `crates/dedens-server/tests/rrl.rs`.

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use common::{Server, ask_tcp, ask_udp};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{Edns, Message, Question, RecordType};
use dedens_server::{Cookies, Secret, Secrets, Standing};

fn config(extra: &str) -> impl Fn(&str) -> String {
    let extra = extra.to_owned();
    move |listen| {
        format!(
            "listen: ['{listen}']\n{extra}pipeline: [hosts]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 www.example']\n"
        )
    }
}

fn query(cookie: Option<Cookie>) -> Vec<u8> {
    let name = "www.example.".parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, RecordType::A));
    query.edns = Some(Edns {
        options: cookie.map(EdnsOption::Cookie).into_iter().collect(),
        ..Edns::default()
    });
    query.to_vec().expect("a query fits")
}

fn cookie_of(reply: &Message<'_>) -> Option<Cookie> {
    reply
        .edns
        .iter()
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            EdnsOption::Cookie(cookie) => Some(*cookie),
            _ => None,
        })
}

/// A Client Cookie is answered with a Server Cookie over UDP and TCP, and the Server Cookie, sent back, is
/// answered with the same Client Cookie and a Server Cookie again.
#[test]
fn a_client_cookie_gets_a_server_cookie() {
    let server = Server::configured(config(""));
    let client = Cookie::new([9; 8], None).expect("a cookie");
    for ask in [ask_udp, ask_tcp] {
        let first = cookie_of(&ask(server.addr, &query(Some(client)))).expect("a cookie");
        assert_eq!(first.client(), [9; 8]);
        assert_eq!(first.server().map(<[u8]>::len), Some(16));
        let again = ask(server.addr, &query(Some(first)));
        assert_eq!(again.answer.len(), 1);
        assert_eq!(cookie_of(&again).map(|c| c.client()), Some([9; 8]));
    }
    assert_eq!(cookie_of(&ask_udp(server.addr, &query(None))), None);
}

/// `cookies: {enabled: false}` gives none.
#[test]
fn cookies_can_be_turned_off() {
    let server = Server::configured(config("cookies: {enabled: false}\n"));
    let client = Cookie::new([9; 8], None).expect("a cookie");
    assert_eq!(cookie_of(&ask_udp(server.addr, &query(Some(client)))), None);
}

/// A server with a `secret` makes cookies of RFC 9018 under it: a verifier holding that secret, as another server of an
/// anycast set does, finds them valid for the client's address.
#[test]
fn a_configured_secret_makes_cookies_others_holding_it_verify() {
    let secret = "e5e973e5a6b2a43f48e7dc849e37bfcf";
    let server = Server::configured(config(&format!("cookies:\n  secret: {secret}\n")));
    let client = Cookie::new([9; 8], None).expect("a cookie");
    let given = cookie_of(&ask_udp(server.addr, &query(Some(client)))).expect("a cookie");
    let clock = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs()
    };
    let verifier = Cookies::new(
        Secrets::new(secret.parse().expect("a secret"), vec![]),
        Arc::new(clock),
    );
    let from = "127.0.0.1".parse().expect("an address");
    assert_eq!(verifier.verify(Some(&given), from), Standing::Valid);
    let other = Cookies::new(Secrets::new(Secret::new([0; 16]), vec![]), Arc::new(clock));
    assert_eq!(other.verify(Some(&given), from), Standing::Invalid);
}

/// Loopback is not rate limited, even at one query a second.
#[test]
fn loopback_is_not_rate_limited() {
    let server = Server::configured(config(
        "rrl: {slip: 0, ipv4: {rate: 1, burst: 1}, ipv6: {rate: 1, burst: 1}}\n",
    ));
    for _ in 0..20 {
        assert_eq!(ask_udp(server.addr, &query(None)).answer.len(), 1);
    }
}
