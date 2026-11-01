//! What a client's queries may cost a validating forward stage (D77): the work of one query, and an allowance
//! all the queries share, past which an uncached query is answered SERVFAIL without being validated. Upstream
//! answers from the captures of `dedens-dnssec`, the validation at the time of their run.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{Captures, captured_at, client_query, decode, run_captured, validating_under};
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::validator::{Limits, Validator};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Flags, Rcode, RecordType};
use dedens_server::{Allowance, Pipeline, Validating};

/// Validation with no key cache, so that each query walks the chain from the root: each costs the same.
fn validating(allowance: Allowance, clock: &Arc<AtomicU64>) -> Validating {
    let limits = Limits {
        key_cache: 0,
        ..Limits::default()
    };
    let clock = Arc::clone(clock);
    Validating::new(
        Validator::new(TrustAnchors::root(), limits),
        Arc::new(move || clock.load(Ordering::Relaxed)),
    )
    .allowing(allowance)
}

/// What a query came to: the questions upstream, and the reply.
fn ask(pipeline: &Pipeline, name: &str) -> (usize, dedens_proto::Message<'static>) {
    let done = run_captured(
        pipeline,
        &client_query(name, RecordType::A, Flags::NONE, true),
        0,
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

/// An allowance of `burst` units that does not refill unless the clock moves a second.
fn allowance(burst: u32) -> Allowance {
    Allowance {
        per_second: 1_000_000,
        burst,
        ..Allowance::default()
    }
}

/// D77: the allowance is spent by the questions and the work of the queries validated; one that finds it spent is
/// answered SERVFAIL, with no question upstream, and nothing of it is held or cached.
#[test]
fn a_query_past_the_allowance_is_shed_without_being_validated() {
    let clock = Arc::new(AtomicU64::new(captured_at()));
    let validating = validating(allowance(1), &clock);
    // One unit left admits a query, which goes into debt as far as it costs.
    let (questions, reply) = ask(&validating_under(validating.clone()), "cloudflare.com.");
    assert!(questions > 1, "{questions}");
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
    // The next finds the allowance in debt.
    let pipeline = validating_under(validating);
    let (questions, reply) = ask(&pipeline, "nlnetlabs.nl.");
    assert_eq!(questions, 0, "nothing is asked upstream");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    // Shed, not failed: no failure is held, so once the debt is paid the same query is validated.
    clock.fetch_add(1, Ordering::Relaxed);
    let (questions, reply) = ask(&pipeline, "nlnetlabs.nl.");
    assert!(questions > 1, "{questions}");
    assert!(reply.header.flags.contains(Flags::AD));
}

/// D77: the allowance refills at its rate, up to its burst, by the clock the validator reads, and never goes
/// back with it.
#[test]
fn the_allowance_refills_at_its_rate_up_to_its_burst() {
    let clock = Arc::new(AtomicU64::new(captured_at()));
    let validating = validating(
        Allowance {
            per_second: 1,
            burst: 1,
            ..Allowance::default()
        },
        &clock,
    );
    // One query goes into debt of dozens of units: one second repays one.
    drop(ask(
        &validating_under(validating.clone()),
        "cloudflare.com.",
    ));
    clock.fetch_add(1, Ordering::Relaxed);
    let (questions, reply) = ask(&validating_under(validating.clone()), "nlnetlabs.nl.");
    assert_eq!(questions, 0);
    assert_eq!(error(&reply), Some(InfoCode::NOT_READY));
    // A clock gone back repays nothing.
    clock.store(0, Ordering::Relaxed);
    let (questions, _) = ask(&validating_under(validating.clone()), "nlnetlabs.nl.");
    assert_eq!(questions, 0);
    // A long while later the burst is all that is back, and admits one query.
    clock.store(captured_at() + 10_000, Ordering::Relaxed);
    let (questions, _) = ask(&validating_under(validating), "nlnetlabs.nl.");
    assert!(questions > 1, "{questions}");
}

/// D77: one query costs at most `per_query` units, the questions it asks upstream and the signatures it checks,
/// the chasing of a CNAME chain included: past it, no verdict (indeterminate: it was validated in part, so the
/// failure is held as any other, RFC 9520).
#[test]
fn a_query_that_costs_more_than_its_limit_has_no_verdict() {
    let clock = Arc::new(AtomicU64::new(captured_at()));
    let few = Allowance {
        per_query: 3,
        ..allowance(1_000_000)
    };
    let pipeline = validating_under(validating(few, &clock));
    let (questions, reply) = ask(&pipeline, "cloudflare.com.");
    assert!(questions <= 4, "{questions}");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(error(&reply), Some(InfoCode::DNSSEC_INDETERMINATE));
    // Held: the same query asks nothing upstream now.
    let (questions, reply) = ask(&pipeline, "cloudflare.com.");
    assert_eq!(questions, 0, "the failure is held");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
}

/// D77: a client that disabled checking costs no validation, so the allowance never sheds it.
#[test]
fn a_query_that_is_not_validated_is_never_shed() {
    let clock = Arc::new(AtomicU64::new(captured_at()));
    let validating = validating(allowance(0), &clock);
    let pipeline = validating_under(validating);
    let query = client_query("cloudflare.com.", RecordType::A, Flags::CD, true);
    let done = run_captured(&pipeline, &query, 0, &Captures::new());
    let reply = decode(&done.reply.expect("a reply")).into_owned();
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(!reply.header.flags.contains(Flags::AD));
}
