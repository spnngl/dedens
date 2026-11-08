//! What response rate limiting and Server Cookies add to a UDP query (D113), on the path of a cache hit, the cheapest
//! a query takes: `Pipeline::query` from a source outside loopback with neither, with the limit, with a Client Cookie
//! (a fresh Server Cookie is made and added to the reply), with a valid Server Cookie (checked, made again, and the
//! limit skipped), and with both on; and the query of a source over its rate, dropped or slipped (truncated, or
//! BADCOOKIE with a cookie), which costs the flood the least. The allocation counts show only a slipped reply allocates.

use std::hint::black_box;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_cache::{Cache, Config};
use dedens_proto::edns::{Cookie, Edns, EdnsOption};
use dedens_proto::{Message, Transport};
use dedens_server::{
    Cookies, Forward, Pipeline, Rate, RateLimit, RateLimitConfig, Secret, Secrets, Stage, Step,
};
use dedens_testkit::captured;
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

/// A source outside loopback, which the limit does not exempt.
fn source() -> IpAddr {
    IpAddr::from([198, 51, 100, 7])
}

/// The query for the captured response `a`, with `cookie` in its EDNS.
fn query(cookie: Option<Cookie>) -> Vec<u8> {
    let response = captured("a");
    let message = Message::decode(&response).expect("decodes").message;
    let mut query = Message::query(7, message.questions[0].clone());
    query.edns = Some(Edns {
        options: cookie.map(EdnsOption::Cookie).into_iter().collect(),
        ..Edns::default()
    });
    query.to_vec().expect("a query fits")
}

/// A limit no query reaches: the burst is the largest, the rate one a second, and the time stays at 0.
fn lax() -> RateLimit {
    let rate = Rate {
        prefix: 24,
        per_second: 1,
        burst: 0x00FF_FFFF,
    };
    limit(rate, 2)
}

fn limit(rate: Rate, slip: u8) -> RateLimit {
    RateLimit::new(RateLimitConfig {
        ipv4: rate,
        slip,
        ..RateLimitConfig::default()
    })
    .expect("a valid limit")
}

fn cookies() -> Cookies {
    let clock = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    };
    Cookies::new(
        Secrets::new(Secret::new([7; 16]), Vec::new()),
        Arc::new(clock),
    )
}

/// A caching forwarder holding the response `a`, with `limit` and `cookies` if given.
fn pipeline(limit: Option<RateLimit>, cookies: Option<Cookies>) -> Pipeline {
    let server = SocketAddr::from(([192, 0, 2, 53], 53));
    let mut pipeline = Pipeline::new(vec![
        Stage::Cache(Arc::new(
            Cache::new(Config::default()).expect("the default config is valid"),
        )),
        Stage::Forward(Forward::new([server]).expect("a server")),
    ]);
    if let Some(limit) = limit {
        pipeline = pipeline.with_rate_limit(limit);
    }
    if let Some(cookies) = cookies {
        pipeline = pipeline.with_cookies(cookies);
    }
    let mut out = vec![0; 65535];
    let Step::Upstream(upstream) =
        pipeline.query(&query(None), Transport::Udp, source(), 0, &mut out)
    else {
        unreachable!("an empty cache sends the query upstream");
    };
    let step = pipeline.receive(upstream, Some(&captured("a")), 0, &mut out);
    assert!(matches!(step, Step::Reply(_)), "{step:?}");
    pipeline
}

fn hit(bencher: Bencher<'_, '_>, pipeline: &Pipeline, query: &[u8]) {
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(black_box(query), Transport::Udp, source(), 0, &mut out);
        assert!(matches!(step, Step::Reply(_)));
    });
}

/// The path of a cache hit as before D113: no limit, no cookies.
#[divan::bench]
fn baseline(bencher: Bencher<'_, '_>) {
    hit(bencher, &pipeline(None, None), &query(None));
}

/// The limit alone, the source within its rate.
#[divan::bench]
fn limited(bencher: Bencher<'_, '_>) {
    hit(bencher, &pipeline(Some(lax()), None), &query(None));
}

/// A Client Cookie: a Server Cookie is made (SipHash-2-4, the clock) and written in the reply.
#[divan::bench]
fn client_cookie(bencher: Bencher<'_, '_>) {
    let cookie = Cookie::new([1; 8], None).expect("a cookie");
    hit(
        bencher,
        &pipeline(None, Some(cookies())),
        &query(Some(cookie)),
    );
}

/// A valid Server Cookie: checked, and a fresh one made.
#[divan::bench]
fn valid_cookie(bencher: Bencher<'_, '_>) {
    let cookies = cookies();
    let valid = cookies.issue([1; 8], source());
    hit(
        bencher,
        &pipeline(Some(lax()), Some(cookies)),
        &query(Some(valid)),
    );
}

/// Both on, a query with a Client Cookie alone: the limit is checked, the cookie made.
#[divan::bench]
fn limit_and_client_cookie(bencher: Bencher<'_, '_>) {
    let cookie = Cookie::new([1; 8], None).expect("a cookie");
    hit(
        bencher,
        &pipeline(Some(lax()), Some(cookies())),
        &query(Some(cookie)),
    );
}

/// A query of a source over its rate, the slip 0 or 2: dropped, or every second truncated.
#[divan::bench(args = [0, 2])]
fn over_the_rate(bencher: Bencher<'_, '_>, slip: u8) {
    exhausted(bencher, slip, None);
}

/// As [`over_the_rate`] with a Client Cookie and cookies on: the cookie is checked first, and the slip is BADCOOKIE
/// with a fresh Server Cookie, 16 bytes more than the query.
#[divan::bench(args = [0, 2])]
fn over_the_rate_with_client_cookie(bencher: Bencher<'_, '_>, slip: u8) {
    exhausted(
        bencher,
        slip,
        Some(Cookie::new([1; 8], None).expect("a cookie")),
    );
}

fn exhausted(bencher: Bencher<'_, '_>, slip: u8, cookie: Option<Cookie>) {
    let rate = Rate {
        prefix: 24,
        per_second: 1,
        burst: 1,
    };
    let cookies = cookie.is_some().then(cookies);
    let pipeline = pipeline(Some(limit(rate, slip)), cookies);
    let query = query(cookie);
    let mut out = vec![0; 1232];
    // The bucket's one query.
    let _ = pipeline.query(&query, Transport::Udp, source(), 0, &mut out);
    bencher.bench_local(|| {
        let step = pipeline.query(black_box(&query), Transport::Udp, source(), 0, &mut out);
        assert!(matches!(step, Step::Drop | Step::Reply(_)));
    });
}
