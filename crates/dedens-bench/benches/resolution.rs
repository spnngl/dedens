//! One resolution step of the recursive resolver (D201): what a miss costs it once its caches hold the delegations,
//! as they do under a load of names that never repeat, on the capture of `testdata/recursion/signed-com.yaml`
//! (D188), RFC 1034 §5.3.3.
//!
//! `warm` resolves `example.com.` A with the caches that resolved it once, the answer expired (RFC 1035 §3.2.1: its
//! TTL has run out, the delegations' have not): the resolution sends one query, to the zone's server, reads its
//! response and ends; the clock is on the three calls of that exchange, the transport being the caller's. `cold` is
//! the same from empty caches: priming, the root's referral, `com.`'s referral and the answer, the delegations
//! the other one starts from. `warm_wire` is `warm` with the response decoded from its wire inside the clock.

use std::collections::HashMap;
use std::convert::Infallible;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::Config;
use dedens_proto::{Message, Name, Question, RecordType};
use dedens_resolver::{
    Caches, DEFAULT_CAPACITY, InfraCache, Limits, Marks, Minimisation, Next, Reply, Resolution,
    RrsetCache,
};
use dedens_roots::RootHints;
use dedens_testkit::recursion::Resolution as Capture;
use divan::Bencher;
use rand_core::{TryCryptoRng, TryRng};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

/// A fixed draw: the servers drawn from do not change what a step costs.
struct Fixed;

impl TryRng for Fixed {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0x0707_0707)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0x0707_0707_0707_0707)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(7);
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

/// How much later the answer has expired, the delegations not: `example.com.`'s A is cached for 300 s at most in
/// the capture, the NS of `com.` and `example.com.` for a day or more.
const LATER: Duration = Duration::from_secs(3600);

/// The captured responses, as the authorities answer: by the zone asked, the name and the type, whatever the server.
struct Authorities(HashMap<(Name<'static>, Name<'static>, RecordType), Message<'static>>);

impl Authorities {
    fn new(capture: &Capture) -> Self {
        Self(
            capture
                .exchanges
                .iter()
                .map(|e| {
                    let key = (e.zone.clone(), e.name.clone(), e.rtype);
                    (key, dedens_testkit::message(&e.response))
                })
                .collect(),
        )
    }

    /// Resolves the capture's question on `caches` at `now`, each query answered as captured; the queries sent.
    fn resolve(&self, capture: &Capture, caches: &Arc<Caches>, now: Duration) -> usize {
        let mut resolution = start(capture, caches, now);
        loop {
            let message = match resolution.step(now, &mut Fixed) {
                Next::Done(_) => return resolution.sent(),
                Next::Send(query) => {
                    let key = (
                        query.zone.clone(),
                        query.question.name.clone(),
                        query.question.qtype,
                    );
                    self.0.get(&key).expect("a captured question").clone()
                }
            };
            resolution.receive(reply(&message), now);
        }
    }
}

fn reply<'a>(message: &'a Message<'a>) -> Reply<'a> {
    Reply::Response {
        message,
        seen: Marks::default(),
        rtt: Some(Duration::from_millis(20)),
    }
}

fn caches() -> Arc<Caches> {
    Arc::new(Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, Config::default()).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 64).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: None,
    })
}

fn start(capture: &Capture, caches: &Arc<Caches>, now: Duration) -> Resolution {
    let question = Question::new(capture.name.clone(), capture.rtype);
    Resolution::start(
        question,
        Arc::clone(caches),
        now,
        Limits::default(),
        Minimisation::Off,
    )
    .expect("an IN question")
}

fn capture() -> (Capture, Authorities, Duration) {
    let capture = Capture::read("signed-com");
    let authorities = Authorities::new(&capture);
    let at = Duration::from_secs(capture.captured_at);
    (capture, authorities, at)
}

/// A miss under warm delegations: one query, its response, the end.
#[divan::bench]
fn warm(bencher: Bencher<'_, '_>) {
    let (capture, authorities, at) = capture();
    let response = authorities
        .0
        .get(&(capture.name.clone(), capture.name.clone(), capture.rtype))
        .expect("the zone's answer")
        .clone();
    let zone = capture.name.clone();
    bencher
        .with_inputs(|| {
            let caches = caches();
            authorities.resolve(&capture, &caches, at);
            start(&capture, &caches, at + LATER)
        })
        .bench_local_values(|mut resolution| {
            let now = at + LATER;
            // The one query goes to the zone's own server: the delegations are warm.
            assert!(matches!(
                black_box(&mut resolution).step(now, &mut Fixed),
                Next::Send(query) if query.zone == zone
            ));
            resolution.receive(reply(black_box(&response)), now);
            assert!(matches!(resolution.step(now, &mut Fixed), Next::Done(_)));
            resolution
        });
}

/// A miss as `dedensd` takes it from the transport: [`warm`] with the response decoded from its wire first, as the
/// recurse stage's `hand` does.
#[divan::bench]
fn warm_wire(bencher: Bencher<'_, '_>) {
    let capture = Capture::read("signed-com");
    let authorities = Authorities::new(&capture);
    let at = Duration::from_secs(capture.captured_at);
    let wire = capture
        .exchanges
        .iter()
        .find(|e| e.zone == capture.name && e.name == capture.name && e.rtype == capture.rtype)
        .expect("the zone's answer")
        .response
        .clone();
    bencher
        .with_inputs(|| {
            let caches = caches();
            authorities.resolve(&capture, &caches, at);
            start(&capture, &caches, at + LATER)
        })
        .bench_local_values(|mut resolution| {
            let now = at + LATER;
            assert!(matches!(
                black_box(&mut resolution).step(now, &mut Fixed),
                Next::Send(_)
            ));
            let decoded = Message::decode(black_box(&wire)).expect("a message");
            resolution.receive(reply(&decoded.message), now);
            assert!(matches!(resolution.step(now, &mut Fixed), Next::Done(_)));
            resolution
        });
}

/// The same from empty caches: the whole walk from the root's hints.
#[divan::bench]
fn cold(bencher: Bencher<'_, '_>) {
    let (capture, authorities, at) = capture();
    bencher.with_inputs(caches).bench_local_values(|caches| {
        black_box(authorities.resolve(&capture, &caches, at));
        caches
    });
}
