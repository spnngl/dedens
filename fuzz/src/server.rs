//! Targets of dedens-server, and of the dedens-cache it serves from: the pipeline's replies to any query and
//! response, under access lists, a rate limit and cookies; networks of access lists; the cache's hits.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_proto::edns::{Cookie, Edns, EdnsOption as CookieOption};
use dedens_proto::{Flags, Header, MAX_MESSAGE_LEN, Message, Query, Rcode, Transport};
use dedens_server::{
    Access, Cookies, Denial, Forward, Network, Pipeline, Rate, RateLimit, RateLimitConfig, Secret,
    Secrets, Stage, Standing, Step,
};

/// A response off the wire, stored in the cache as the answer to a query for its question, then served again into
/// a buffer whose size comes from the response's ID (at least [`Cache::MIN_OUT`]): the hit must decode without
/// violations and carry the ID and question of the query it answers.
///
/// # Panics
///
/// On a bug in the cache, or in the encoder or decoder it relies on.
pub fn cache_insert(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let Some(question) = decoded.message.questions.first() else {
        return;
    };
    let cache = Cache::new(Config {
        capacity: 1 << 20,
        shards: 1,
        ..Config::default()
    })
    .expect("a valid config");
    // Asked with the response's RD, CD and AD bits, under an ID of its own.
    let id = !decoded.message.header.id;
    let mut query = Message::query(id, question.clone());
    query.header.flags = decoded.message.header.flags.without(Flags::QR);
    let query = query.to_vec().expect("a query fits");
    let query = Query::read(&query).expect("an encoded query reads");
    if cache.insert(&query, &decoded, 0, 0).is_err() {
        return;
    }
    let size = usize::from(decoded.message.header.id).max(Cache::MIN_OUT);
    let mut out = vec![0; size];
    let Lookup::Hit(hit) = cache.lookup(&query, 0, StalePolicy::Never, &mut out) else {
        panic!("a response just stored is served");
    };
    let served = out.get(..hit.len).expect("the hit is within the buffer");
    let served = Message::decode(served).expect("a hit decodes");
    assert_eq!(served.violations, [], "a hit is conforming");
    assert_eq!(served.message.header.id, id, "a hit carries the query's ID");
    assert_eq!(
        served.message.questions,
        std::slice::from_ref(question),
        "a hit answers the question asked"
    );
    // A hit cut to the buffer is the whole response encoded into it (D116).
    let mut whole = vec![0; MAX_MESSAGE_LEN];
    let Lookup::Hit(all) = cache.lookup(&query, 0, StalePolicy::Never, &mut whole) else {
        panic!("a response just stored is served whole");
    };
    let whole_len = all.len;
    let all = Message::decode(
        whole
            .get(..whole_len)
            .expect("the hit is within the buffer"),
    )
    .expect("a hit decodes");
    let mut cut = vec![0; size];
    let encoded = all
        .message
        .encode_truncated(&mut cut)
        .expect("the whole response encodes into the buffer");
    // `Hit::truncated` is any cut; TC is set only by a cut in the answer or authority section.
    assert_eq!(
        (cut.get(..encoded.len), encoded.len < whole_len),
        (out.get(..hit.len), hit.truncated),
        "a cut hit is the whole one encoded into the buffer"
    );
}

/// Arbitrary bytes as a client's query, and as the upstream response to a query for their question, then that query
/// again, from the cache: whatever the server sends back is a conforming reply under the query's ID, within the
/// client's UDP payload. A server whose access lists hold no network answers the first input with nothing or REFUSED
/// under its ID (D91). A server limiting rates and giving cookies (D113) answers the input, sent over UDP from a
/// source over its rate, with nothing or a conforming reply (TC=1, BADCOOKIE), and a query for the input's question
/// with a Client Cookie from the bytes of the input gets a Server Cookie that verifies and lets the next through.
///
/// # Panics
///
/// On a reply that breaks this.
pub fn serve_query(data: &[u8]) {
    let server = SocketAddr::from(([192, 0, 2, 1], 53));
    let mut out = vec![0; MAX_MESSAGE_LEN];
    limited_cookied(data, &mut out);
    let denying = Pipeline::default().with_access(Access::new([], [], Denial::Refuse));
    for transport in [Transport::Udp, Transport::Tcp] {
        match denying.query(data, transport, Ipv4Addr::LOCALHOST.into(), 0, &mut out) {
            Step::Drop => {}
            Step::Reply(len) => {
                let id = Header::peek(data).expect("a reply goes to a header").id;
                check_reply(&out[..len], id, transport);
                let reply = Message::decode(&out[..len]).expect("a reply decodes");
                assert_eq!(
                    reply.message.rcode(),
                    Rcode::REFUSED,
                    "a denied client is refused"
                );
            }
            Step::Upstream(_) | Step::Refresh(..) => {
                panic!("a denied client's query goes upstream")
            }
        }
        let pipeline = Pipeline::new(vec![
            Stage::Cache(Arc::new(
                Cache::new(Config::default()).expect("the default settings"),
            )),
            Stage::Forward(Forward::new([server]).expect("one server")),
        ]);
        if let Step::Reply(len) =
            pipeline.query(data, transport, Ipv4Addr::LOCALHOST.into(), 0, &mut out)
        {
            let id = Header::peek(data).expect("a reply goes to a header").id;
            check_reply(&out[..len], id, transport);
        }
        let Ok(decoded) = Message::decode(data) else {
            continue;
        };
        let Some(question) = decoded.message.questions.first() else {
            continue;
        };
        let id = !decoded.message.header.id;
        let query = Message::query(id, question.clone())
            .to_vec()
            .expect("a query fits");
        let Step::Upstream(upstream) =
            pipeline.query(&query, transport, Ipv4Addr::LOCALHOST.into(), 0, &mut out)
        else {
            continue;
        };
        let Step::Reply(len) = pipeline.receive(upstream, Some(data), 0, &mut out) else {
            panic!("the only server's response is answered");
        };
        check_reply(&out[..len], id, transport);
        // Asked again, from the cache when it stored the response.
        if let Step::Reply(len) =
            pipeline.query(&query, transport, Ipv4Addr::LOCALHOST.into(), 1, &mut out)
        {
            check_reply(&out[..len], id, transport);
        }
    }
}

/// The checks of `serve_query` on a pipeline with a rate limit of one query, slip 1, and cookies.
fn limited_cookied(data: &[u8], out: &mut [u8]) {
    let rate = Rate {
        prefix: 24,
        per_second: 1,
        burst: 1,
    };
    let limit = RateLimit::new(RateLimitConfig {
        ipv4: rate,
        ipv6: Rate { prefix: 56, ..rate },
        slip: 1,
        table: 16,
        ..RateLimitConfig::default()
    })
    .expect("a valid limit");
    let cookies = Cookies::new(
        Secrets::new(Secret::new([7; 16]), Vec::new()),
        Arc::new(|| 0),
    );
    let pipeline = Pipeline::default()
        .with_rate_limit(limit)
        .with_cookies(cookies);
    let from = IpAddr::from([198, 51, 100, 7]);
    for _ in 0..3 {
        if let Step::Reply(len) = pipeline.query(data, Transport::Udp, from, 0, out) {
            let id = Header::peek(data).expect("a reply goes to a header").id;
            check_reply(&out[..len], id, Transport::Udp);
        }
    }
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let Some(question) = decoded.message.questions.first() else {
        return;
    };
    let mut client = [0; 8];
    for (byte, input) in client.iter_mut().zip(data) {
        *byte = *input;
    }
    let ask = |cookie: Cookie| {
        let mut query = Message::query(9, question.clone());
        query.edns = Some(Edns {
            options: vec![CookieOption::Cookie(cookie)],
            ..Edns::default()
        });
        query.to_vec().expect("a query fits")
    };
    // Another network than the one the input spent, so the bucket holds its one query.
    let from = IpAddr::from([203, 0, 113, 7]);
    let Ok(client_cookie) = Cookie::new(client, None) else {
        return;
    };
    let Step::Reply(len) = pipeline.query(&ask(client_cookie), Transport::Udp, from, 0, out) else {
        return;
    };
    check_reply(&out[..len], 9, Transport::Udp);
    let reply = Message::decode(&out[..len])
        .expect("a reply decodes")
        .message;
    let given = reply
        .edns
        .iter()
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            CookieOption::Cookie(cookie) => Some(*cookie),
            _ => None,
        })
        .expect("a Client Cookie is answered with a cookie");
    let cookies = pipeline.cookies().expect("cookies");
    assert_eq!(cookies.verify(Some(&given), from), Standing::Valid);
    // A valid Server Cookie is not limited: the bucket is spent, and the reply is not TC or BADCOOKIE.
    if let Step::Reply(len) = pipeline.query(&ask(given), Transport::Udp, from, 0, out) {
        let reply = Message::decode(&out[..len])
            .expect("a reply decodes")
            .message;
        assert_ne!(reply.rcode(), Rcode::BADCOOKIE, "a valid cookie passes");
        assert!(
            !reply.header.flags.contains(Flags::TC),
            "a valid cookie passes"
        );
    }
}

/// Checks a reply of `serve_query`.
fn check_reply(reply: &[u8], id: u16, transport: Transport) {
    let decoded = Message::decode(reply).expect("a reply decodes");
    assert_eq!(decoded.violations, [], "a reply is conforming");
    assert_eq!(
        decoded.message.header.id, id,
        "a reply carries the query's ID"
    );
    if transport == Transport::Udp {
        assert!(reply.len() <= 1232, "a UDP reply fits the largest payload");
    }
}

/// A network of an access list (D91): what reads displays as text that reads back to the same network, with
/// no bit past its length, and a list holding it permits its own address.
///
/// # Panics
///
/// On a disagreement, or a bug in the reader or display.
pub fn parse_network(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(network) = text.parse::<Network>() else {
        return;
    };
    let shown = network.to_string();
    let again: Network = shown
        .parse()
        .unwrap_or_else(|e| panic!("`{shown}` from `{text}` reads back: {e}"));
    assert_eq!(again, network, "`{shown}` from `{text}`");
    let access = Access::new([network], [], Denial::Refuse);
    // The address of a network with no host bits is its first one.
    let address = shown
        .split_once('/')
        .and_then(|(address, _)| address.parse::<IpAddr>().ok());
    let address = address.unwrap_or_else(|| panic!("`{shown}` from `{text}` has an address"));
    assert!(access.permits(address), "`{shown}` from `{text}`");
}
