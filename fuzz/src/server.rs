//! Targets of dedens-server, and of the dedens-cache it serves from: the pipeline's replies to any query and
//! response, under access lists, a rate limit and cookies; networks of access lists; the cache's hits.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_plugins::TopLevel;
use dedens_proto::edns::{Cookie, Edns, EdnsOption as CookieOption};
use dedens_proto::{Flags, Header, MAX_MESSAGE_LEN, Message, Query, Rcode, Transport, Ttl};
use dedens_resolver::{Caches, DEFAULT_CAPACITY, InfraCache, Marks, Reply, RrsetCache};
use dedens_roots::{RootHints, Tlds};
use dedens_server::{
    Access, Action, Authoritative, Cookies, Denial, Forward, Grant, Network, Next, Pipeline, Rate,
    RateLimit, RateLimitConfig, Recurse, Secret, Secrets, Stage, Standing, Step, Turn, ZoneAccess,
};
use dedens_zone::{Limits, Source, Zone};

use crate::odoh::Fixed;

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

/// The bundled TLD list, parsed and copied once: `serve_query` runs per input.
static BUNDLED: LazyLock<Arc<Tlds>> = LazyLock::new(|| Arc::new(Tlds::bundled().clone()));

/// Arbitrary bytes as a client's query, and as the upstream response to a query for their question, then that query
/// again, from the cache: whatever the server sends back is a conforming reply under the query's ID, within the
/// client's UDP payload. A server whose access lists hold no network answers the first input with nothing or REFUSED
/// under its ID (D91). A server limiting rates and giving cookies (D113) answers the input, sent over UDP from a
/// source over its rate, with nothing or a conforming reply (TC=1, BADCOOKIE), and a query for the input's question
/// with a Client Cookie from the bytes of the input gets a Server Cookie that verifies and lets the next through.
/// A `tlds` stage (D128) answers the input, any class, with a conforming reply or passes it on. A `recurse` stage
/// (D195) answers it, or resolves it with the input as each authoritative server's response, into a conforming reply.
/// An `authoritative` stage (D208) before a forward stage answers a client the access lists deny with a conforming
/// reply or nothing, never upstream.
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
        recursing(data, transport, &mut out);
        authoritative(data, transport, &mut out);
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
            Step::Upstream(_)
            | Step::Refresh(..)
            | Step::Park(_)
            | Step::Resolve(_)
            | Step::Transfer(_) => panic!("a denied client's query goes on"),
        }
        let top_level = Pipeline::new(vec![Stage::Plugin(Box::new(TopLevel::new(
            Arc::clone(&BUNDLED),
            Ttl::ZERO,
            Arc::new(|| 0),
        )))]);
        if let Step::Reply(len) =
            top_level.query(data, transport, Ipv4Addr::LOCALHOST.into(), 0, &mut out)
        {
            let id = Header::peek(data).expect("a reply goes to a header").id;
            check_reply(&out[..len], id, transport);
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

/// The zone of RFC 4035 Appendix A, `example.`, loaded once: `serve_query` runs per input.
static EXAMPLE: LazyLock<Arc<Zone>> = LazyLock::new(|| {
    let source = Source {
        name: "rfc4035_appendix_a.zone",
        text: include_bytes!("../../testdata/zones/rfc4035_appendix_a.zone"),
        default_ttl: None,
    };
    let mut include = |_: &str| Err("no include".to_owned());
    let example = dedens_proto::Name::from_labels([b"example".as_slice()]).expect("a valid name");
    Arc::new(
        Zone::load(example, source, &mut include, &Limits::default())
            .expect("the zone loads")
            .zone,
    )
});

/// The checks of `serve_query` on a pipeline of an authoritative stage then a forward stage, from a client the
/// access lists deny but the zone's `transfer` list permits: its names are answered, the others refused, none goes
/// upstream; a transfer (D214), over TCP alone, is a stream of conforming messages under the query's ID that ends.
fn authoritative(data: &[u8], transport: Transport, out: &mut [u8]) {
    let server = SocketAddr::from(([192, 0, 2, 1], 53));
    let local: Network = "127.0.0.1/32".parse().expect("a network");
    let access = ZoneAccess::default().with(Action::Transfer, [Grant::new([local], None)]);
    let zones = Authoritative::guarded([(Arc::clone(&EXAMPLE), access)]).expect("one zone");
    let pipeline = Pipeline::new(vec![
        Stage::Authoritative(zones),
        Stage::Forward(Forward::new([server]).expect("one server")),
    ])
    .with_access(Access::new([], [], Denial::Refuse));
    let id = || Header::peek(data).expect("a reply goes to a header").id;
    match pipeline.query(data, transport, Ipv4Addr::LOCALHOST.into(), 0, out) {
        Step::Drop => {}
        Step::Reply(len) => check_reply(&out[..len], id(), transport),
        Step::Transfer(mut transfer) => {
            assert_eq!(
                transport,
                Transport::Tcp,
                "a transfer is made over TCP alone"
            );
            // The zone's records, each a message at most, and its two SOAs.
            for _ in 0..=EXAMPLE.record_count() + 2 {
                match transfer.next(&pipeline, out) {
                    Next::Message(len) => check_reply(&out[..len], id(), transport),
                    Next::Ended => return,
                    Next::Cut => panic!("an unsigned transfer of a served zone is cut"),
                }
            }
            panic!("a transfer does not end");
        }
        Step::Upstream(_) | Step::Refresh(..) | Step::Park(_) | Step::Resolve(_) => {
            panic!("a denied client's query goes upstream")
        }
    }
}

/// The most queries `recursing` answers with the input: the resolution's own limit, 32, is reached long after.
const RESPONSES: usize = 8;

/// The checks of `serve_query` on a pipeline of a cache stage and a recurse stage, whose servers all respond with
/// `data`.
fn recursing(data: &[u8], transport: Transport, out: &mut [u8]) {
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let caches = Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, config.clone()).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 1).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: None,
    };
    let pipeline = Pipeline::new(vec![
        Stage::Cache(Arc::new(Cache::new(config).expect("valid settings"))),
        Stage::Recurse(Recurse::new(Arc::new(caches))),
    ]);
    let Some(id) = Header::peek(data).map(|header| header.id) else {
        return;
    };
    let mut resolving = match pipeline.query(data, transport, Ipv4Addr::LOCALHOST.into(), 0, out) {
        Step::Reply(len) => return check_reply(&out[..len], id, transport),
        Step::Resolve(resolving) => resolving,
        _ => return,
    };
    let response = Message::decode(data).ok();
    let mut now = Duration::ZERO;
    for _ in 0..RESPONSES {
        let Turn::Send(query) = resolving.step(now, &mut Fixed(1)) else {
            break;
        };
        now += query.timeout / 2;
        let reply = match &response {
            Some(decoded) => Reply::Response {
                message: &decoded.message,
                seen: Marks::default(),
                rtt: Some(Duration::from_millis(20)),
            },
            None => Reply::Undecodable,
        };
        resolving.receive(reply, now);
    }
    if let Step::Reply(len) = pipeline.resolved(&resolving, 0, out) {
        check_reply(&out[..len], id, transport);
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
