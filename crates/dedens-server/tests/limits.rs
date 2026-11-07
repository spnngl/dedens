//! What a client's queries may cost a validating forward stage (D77): the work of one query, an allowance all the
//! queries share, and the share of it each client network has, past which an uncached query is answered SERVFAIL
//! without being validated. Upstream answers from the captures of `dedens-dnssec`, the validation at the time of
//! their run; the buckets count in the `now` of the queries.

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use common::{
    Captures, captured_at, client_query, decode, run_captured, run_captured_from, run_together,
    validating_under, wire,
};
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::validator::{Limits, Validator};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Flags, Rcode, RecordType, Transport};
use dedens_server::{
    Allowance, Budget, Budgets, Clock, Cookies, Pipeline, RateLimit, RateLimitConfig, Secret,
    Secrets, Validating,
};

/// The second the queries start at, far from 0 so that a clock gone back can be tried.
const START: u32 = 1_000_000;

/// Validation with no key cache, so that each query walks the chain from the root: each costs the same.
fn validating(allowance: Allowance) -> Validating {
    let limits = Limits {
        key_cache: 0,
        ..Limits::default()
    };
    Validating::new(
        Validator::new(TrustAnchors::root(), limits),
        Arc::new(captured_at),
    )
    .allowing(allowance)
}

/// What a query came to: the questions upstream, and the reply.
fn ask(pipeline: &Pipeline, name: &str, now: u32) -> (usize, dedens_proto::Message<'static>) {
    let done = run_captured(
        pipeline,
        &client_query(name, RecordType::A, Flags::NONE, true),
        now,
        &Captures::new(),
    );
    (
        done.requests.len(),
        decode(&done.reply.expect("a reply")).into_owned(),
    )
}

fn error(reply: &dedens_proto::Message<'_>) -> Option<InfoCode> {
    reply
        .edns
        .as_ref()?
        .options
        .iter()
        .find_map(|option| match option {
            EdnsOption::Ede(ede) => Some(ede.code),
            _ => None,
        })
}

/// An allowance of `burst` units that refills fast: a second makes it whole.
fn allowance(burst: u32) -> Allowance {
    Allowance {
        per_second: 1_000_000,
        burst,
        ..Allowance::default()
    }
}

/// D77, D106: the allowance is spent by the questions and the work of the queries validated; one that finds it spent
/// is answered SERVFAIL, with no question upstream, and nothing of it is held or cached. One that runs it into debt
/// asks no more questions: it is answered the same, after the step that did.
#[test]
fn a_query_past_the_allowance_is_shed_without_being_validated() {
    // One unit left admits a query; its first question takes it, and the debt stops the query there.
    let pipeline = validating_under(validating(allowance(1)));
    let (questions, reply) = ask(&pipeline, "cloudflare.com.", START);
    assert_eq!(questions, 1, "the client's question only");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    // The next finds the allowance in debt.
    let (questions, reply) = ask(&pipeline, "nlnetlabs.nl.", START);
    assert_eq!(questions, 0, "nothing is asked upstream");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    // Shed, not failed: no failure is held, so once the debt is paid the same query is asked upstream again.
    let (questions, reply) = ask(&pipeline, "cloudflare.com.", START + 1);
    assert_eq!(questions, 1, "{questions}");
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
}

/// D77: the allowance refills at its rate, up to its burst, by the `now` of the queries, and never goes back with
/// it.
#[test]
fn the_allowance_refills_at_its_rate_up_to_its_burst() {
    let validating = validating(Allowance {
        per_second: 1,
        burst: 1,
        ..Allowance::default()
    });
    // One query goes into debt of one unit, the most the burst keeps: one second repays it, and leaves none.
    drop(ask(
        &validating_under(validating.clone()),
        "cloudflare.com.",
        START,
    ));
    let (questions, reply) = ask(
        &validating_under(validating.clone()),
        "nlnetlabs.nl.",
        START + 1,
    );
    assert_eq!(questions, 0);
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    // A clock gone back repays nothing.
    let (questions, _) = ask(&validating_under(validating.clone()), "nlnetlabs.nl.", 0);
    assert_eq!(questions, 0);
    // A long while later the burst is all that is back, and admits one query.
    let (questions, _) = ask(
        &validating_under(validating),
        "nlnetlabs.nl.",
        START + 10_000,
    );
    assert_eq!(questions, 1, "{questions}");
}

/// A validator that has the keys of `www.icann.org.` and of the name its CNAME goes on at already, so that a query
/// for it takes no question upstream but the client's and the chasing of the chain: the step that validates the
/// first response costs a verification and the question that chases, two units or a few more.
fn keyed() -> Validating {
    let keyed = Validating::new(
        Validator::new(TrustAnchors::root(), Limits::default()),
        Arc::new(captured_at),
    );
    let (questions, reply) = ask(&validating_under(keyed.clone()), "www.icann.org.", START);
    assert!(questions > 2, "{questions}");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    keyed
}

/// D106: the debt stops at one burst: validation is back `burst / per_second + 1` seconds after queries that cost
/// several times the burst, and not a second before the burst is repaid. Ten queries in flight take the 10 units
/// of the burst, then cost at least 2 each as they are answered; without the floor the debt of 20 takes 21 s to
/// repay.
#[test]
fn the_debt_of_queries_in_flight_is_at_most_a_burst() {
    let allowing = Allowance {
        per_second: 1,
        burst: 10,
        ..Allowance::default()
    };
    let validating = keyed().allowing(allowing);
    let pipeline = validating_under(validating.clone());
    let (_, replies) = run_together(&pipeline, "www.icann.org.", 10, START, &Captures::new());
    assert_eq!(
        replies.len(),
        10,
        "all were admitted before any was charged"
    );
    let (questions, reply) = ask(
        &validating_under(validating.clone()),
        "nlnetlabs.nl.",
        START + 10,
    );
    assert_eq!(questions, 0, "the debt is not yet repaid");
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    let (questions, _) = ask(&validating_under(validating), "nlnetlabs.nl.", START + 11);
    assert_eq!(questions, 1, "admitted again");
}

/// D106: a flood of queries in flight, all admitted before any is charged, asks no more than its units allow: a query
/// that finds the allowance in debt stops after the step it is in, so that the work past the burst is one step of
/// each, not the whole chain. 40 queries take 40 of the 60 units at admission; each next question is asked only
/// after a step that cost a unit and left none owed, so at most 20 are asked. Run to the end, they ask ten times that.
#[test]
fn a_flood_in_flight_asks_no_more_than_the_burst_allows() {
    let allowing = Allowance {
        per_second: 1,
        burst: 60,
        ..Allowance::default()
    };
    let pipeline = validating_under(validating(allowing));
    let (requests, replies) =
        run_together(&pipeline, "cloudflare.com.", 40, START, &Captures::new());
    assert!(requests <= 40 + 20, "{requests}");
    assert_eq!(replies.len(), 40);
    for reply in replies.iter().flatten() {
        let reply = decode(reply);
        assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    }
}

/// D77: one query costs at most `per_query` units, the questions it asks upstream and the signatures it checks,
/// the chasing of a CNAME chain included: past it, no verdict (indeterminate: it was validated in part, so the
/// failure is held as any other, RFC 9520).
#[test]
fn a_query_that_costs_more_than_its_limit_has_no_verdict() {
    let few = Allowance {
        per_query: 3,
        ..allowance(1_000_000)
    };
    let pipeline = validating_under(validating(few));
    let (questions, reply) = ask(&pipeline, "cloudflare.com.", START);
    assert!(questions <= 4, "{questions}");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(error(&reply), Some(InfoCode::DNSSEC_INDETERMINATE));
    // Held: the same query asks nothing upstream now.
    let (questions, reply) = ask(&pipeline, "cloudflare.com.", START);
    assert_eq!(questions, 0, "the failure is held");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
}

/// D77: `per_query` is the most a query may spend, not a bound it must stay under: a cold validation of
/// `cloudflare.com.` has spent 8 units when it asks its last question, and a limit of 8 lets it ask; at 2, the
/// query that has spent 3 by its second question asks no more.
#[test]
fn a_query_may_spend_its_limit_and_no_more() {
    let limited = |per_query| {
        validating_under(validating(Allowance {
            per_query,
            ..allowance(1_000_000)
        }))
    };
    let (_, reply) = ask(&limited(8), "cloudflare.com.", START);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
    let (questions, reply) = ask(&limited(2), "cloudflare.com.", START);
    assert_eq!(questions, 2, "the client's question and one more");
    assert_eq!(error(&reply), Some(InfoCode::DNSSEC_INDETERMINATE));
}

/// The clients of D117's tests, one /24 apart or together.
fn address(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// Cold validations of `name` for the client at `from` over `transport` under `validating`, with `limit` on the
/// pipeline if any: the questions asked and the reply, a fresh cache each time so that only the buckets differ
/// between asks.
fn ask_from(
    validating: &Validating,
    limit: Option<&Arc<RateLimit>>,
    (from, transport): (IpAddr, Transport),
    name: &str,
    now: u32,
) -> (usize, dedens_proto::Message<'static>) {
    let pipeline = validating_under(validating.clone());
    let pipeline = match limit {
        Some(limit) => pipeline.with_rate_limit(Arc::clone(limit)),
        None => pipeline,
    };
    let done = run_captured_from(
        &pipeline,
        (from, transport),
        &client_query(name, RecordType::A, Flags::NONE, true),
        now,
        &Captures::new(),
        None,
    );
    (
        done.requests.len(),
        decode(&done.reply.expect("a reply")).into_owned(),
    )
}

/// A validation under an allowance of `burst` units, and a share of 20 units that does not refill within a
/// test, in a million buckets keyed at random: two networks of a test share one once in a million runs, not once in
/// 256.
fn sharing(burst: u32) -> Validating {
    validating(Allowance {
        per_second: 1,
        burst,
        ..Allowance::default()
    })
    .sharing(
        Budgets::new(Budget {
            per_second: 1,
            burst: 20,
            table: 1 << 20,
        })
        .expect("a share in bounds"),
    )
}

/// Asks cold validations for `from` until one is shed, which the share of 20 units does within 20.
fn spend_the_share(validating: &Validating, limit: Option<&Arc<RateLimit>>, from: IpAddr) -> bool {
    (0..20).any(|_| {
        let (_, reply) = ask_from(
            validating,
            limit,
            (from, Transport::Udp),
            "cloudflare.com.",
            START,
        );
        error(&reply) == Some(InfoCode::NOT_READY)
    })
}

/// D117: the allowance is global, but each client network spends it only up to its share, so one client cannot
/// shed the others (the trigger of audit S3: one client with cold validations shed everyone). The greedy client
/// runs out of its share and is shed with EDE 14, nothing held; its neighbour in the same /24 is shed with it; a
/// client of another network is still validated, and so is the greedy one once the share is paid down.
#[test]
fn a_client_over_its_share_cannot_shed_another_client() {
    let validating = sharing(200);
    let (greedy, neighbour, other) = (
        address("198.51.100.7"),
        address("198.51.100.200"),
        address("203.0.113.9"),
    );
    assert!(
        spend_the_share(&validating, None, greedy),
        "the share is spent within 20 cold validations"
    );
    let (questions, reply) = ask_from(
        &validating,
        None,
        (greedy, Transport::Udp),
        "cloudflare.com.",
        START,
    );
    assert_eq!(questions, 0, "nothing is asked upstream");
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    let (questions, reply) = ask_from(
        &validating,
        None,
        (neighbour, Transport::Udp),
        "nlnetlabs.nl.",
        START,
    );
    assert_eq!(questions, 0, "the /24 shares one budget");
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    let (questions, reply) = ask_from(
        &validating,
        None,
        (other, Transport::Udp),
        "nlnetlabs.nl.",
        START,
    );
    assert!(questions > 0, "another network is validated");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
    // Shed, not failed: once the share is paid down the greedy client is validated again.
    let (questions, _) = ask_from(
        &validating,
        None,
        (greedy, Transport::Udp),
        "cloudflare.com.",
        START + 100,
    );
    assert!(questions > 0, "admitted again");
}

/// D117: a UDP source can be spoofed, so a flood from spoofed addresses of a network spends the share of the
/// network's unproven queries; a client of the network over TCP, whose address is proven, has a share of its own and
/// is still validated.
#[test]
fn a_proven_client_is_not_shed_by_the_unproven_ones_of_its_network() {
    let validating = sharing(200);
    let victim = address("198.51.100.7");
    assert!(spend_the_share(&validating, None, victim));
    let (questions, reply) = ask_from(
        &validating,
        None,
        (address("198.51.100.8"), Transport::Tcp),
        "nlnetlabs.nl.",
        START,
    );
    assert!(questions > 0, "the connection is validated");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
}

/// D117, RFC 7873 §5.2.5: a valid Server Cookie proves a UDP source as a connection does, so the client has the
/// proven share of its network, which a flood without cookies does not spend.
#[test]
fn a_udp_client_with_a_valid_cookie_is_not_shed_by_the_unproven_ones() {
    let validating = sharing(200);
    assert!(spend_the_share(&validating, None, address("198.51.100.7")));
    let client = address("198.51.100.8");
    let clock: Clock = Arc::new(|| u64::from(START));
    let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
        .parse()
        .expect("a secret");
    let cookies = Cookies::new(Secrets::new(secret, vec![]), clock);
    let cookie = cookies.issue([7; 8], client);
    let mut query = decode(&client_query(
        "nlnetlabs.nl.",
        RecordType::A,
        Flags::NONE,
        true,
    ))
    .into_owned();
    let edns = query.edns.as_mut().expect("EDNS");
    edns.options.push(EdnsOption::Cookie(cookie));
    let done = run_captured_from(
        &validating_under(validating).with_cookies(cookies),
        (client, Transport::Udp),
        &wire(&query),
        START,
        &Captures::new(),
        None,
    );
    assert!(!done.requests.is_empty(), "the proven client is validated");
    let reply = decode(&done.reply.expect("a reply")).into_owned();
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
}

/// D117: a source on the rate limit's exempt list (D113), which may be a proxy hiding its clients, has no share,
/// and the global allowance still bounds it.
#[test]
fn an_exempt_source_has_no_share() {
    let validating = sharing(10_000);
    let limit = Arc::new(
        RateLimit::new(RateLimitConfig {
            exempt: vec!["198.51.100.0/24".parse().expect("a network")],
            ..RateLimitConfig::default()
        })
        .expect("a limit in bounds"),
    );
    let proxy = address("198.51.100.7");
    assert!(
        !spend_the_share(&validating, Some(&limit), proxy),
        "20 cold validations are over its share, and are not shed"
    );
    // Not exempt: the same asks are shed by the share.
    assert!(spend_the_share(&validating, None, proxy));
}

/// D77: a client that disabled checking costs no validation, so the allowance never sheds it.
#[test]
fn a_query_that_is_not_validated_is_never_shed() {
    let validating = validating(allowance(0));
    let pipeline = validating_under(validating);
    let query = client_query("cloudflare.com.", RecordType::A, Flags::CD, true);
    let done = run_captured(&pipeline, &query, START, &Captures::new());
    let reply = decode(&done.reply.expect("a reply")).into_owned();
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(!reply.header.flags.contains(Flags::AD));
}
