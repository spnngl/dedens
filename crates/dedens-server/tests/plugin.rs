//! Plugin stages (D54): an answer is written after the client's question, with AA when the plugin is
//! authoritative; a query the plugin passes on goes to the next stage.

mod common;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{decode, dns, run, servers, wire};
use dedens_cache::{Cache, Config};
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::validator::{Limits, Validator};
use dedens_proto::edns::{Edns, EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, Flags, Message, Name, Opcode, Query, Question, Rcode, Record, RecordType, Transport, Ttl,
};
use dedens_server::{Answer, Forward, Pipeline, Plugin, Records, Reviewer, Stage, Validating};

/// Answers A queries for `local.test.` with `count` addresses, and blocks `blocked.test.`.
#[derive(Debug)]
struct Local {
    records: Records,
}

impl Local {
    fn new(count: u8) -> Self {
        let name = dns("local.test");
        let records: Vec<_> = (0..count)
            .map(|i| {
                let data = RData::A(Ipv4Addr::new(192, 0, 2, i));
                Record::new(name.clone(), Class::IN, Ttl::from_wire(60), &data)
            })
            .collect();
        Self {
            records: Records::new(&name, &records).expect("the records fit"),
        }
    }
}

impl Plugin for Local {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        if question.name == dns("blocked.test") {
            return Some(Answer {
                rcode: Rcode::NXDOMAIN,
                records: None,
                authoritative: false,
                error: Some(InfoCode::BLOCKED),
            });
        }
        (question.name == dns("local.test")).then_some(Answer {
            rcode: Rcode::NOERROR,
            records: (question.qtype == RecordType::A).then_some(&self.records),
            authoritative: true,
            error: None,
        })
    }
}

fn pipeline(count: u8) -> Pipeline {
    Pipeline::new(vec![
        Stage::Plugin(Box::new(Local::new(count))),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ])
}

fn query(name: &str, qtype: RecordType, edns: bool) -> Vec<u8> {
    let name: Name<'static> = name.parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, qtype));
    if !edns {
        query.edns = None;
    }
    wire(&query)
}

/// RFC 1035 §4.1.1: AA, the plugin holding the name; the answer owned by the question's name, in its case
/// (RFC 4343 §4), the OPT record after the records (RFC 6891 §7).
#[test]
fn an_answer_follows_the_question_in_its_case() {
    let done = run(
        &pipeline(2),
        &query("LoCaL.TeSt.", RecordType::A, true),
        Transport::Udp,
        &[],
    );
    assert_eq!(done.asked, []);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!((reply.header.id, reply.header.opcode), (7, Opcode::QUERY));
    assert_eq!(
        reply.header.flags,
        Flags::QR | Flags::AA | Flags::RD | Flags::RA
    );
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.questions[0].name.to_string(), "LoCaL.TeSt.");
    let owners: Vec<_> = reply.answer.iter().map(|r| r.name.to_string()).collect();
    assert_eq!(owners, ["LoCaL.TeSt.", "LoCaL.TeSt."]);
    let data: Vec<_> = reply.answer.iter().map(Record::data).collect();
    assert_eq!(
        data,
        [
            RData::A(Ipv4Addr::new(192, 0, 2, 0)),
            RData::A(Ipv4Addr::new(192, 0, 2, 1))
        ]
    );
    assert_eq!(reply.edns, Some(Edns::default()));
}

/// RFC 2308 §2.2: no data, NOERROR with an empty answer.
#[test]
fn a_name_without_records_of_the_type_has_no_data() {
    let wire = run(
        &pipeline(1),
        &query("local.test.", RecordType::MX, false),
        Transport::Udp,
        &[],
    )
    .reply
    .expect("a reply");
    let reply = decode(&wire);
    assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NOERROR, 0));
    assert!(reply.header.flags.contains(Flags::AA));
}

/// RFC 8914 §4.16: Blocked; AA clear, the plugin being no authority.
#[test]
fn an_error_goes_in_our_opt_record() {
    let wire = run(
        &pipeline(1),
        &query("blocked.test.", RecordType::A, true),
        Transport::Udp,
        &[],
    )
    .reply
    .expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
    assert!(!reply.header.flags.contains(Flags::AA));
    let options = reply.edns.expect("our OPT record").options;
    assert!(
        matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
        "{options:?}"
    );
}

/// RFC 2181 §9: records that do not fit 512 bytes are left out, with TC.
#[test]
fn records_too_large_for_the_client_set_tc() {
    let wire = run(
        &pipeline(40),
        &query("local.test.", RecordType::A, false),
        Transport::Udp,
        &[],
    )
    .reply
    .expect("a reply");
    let reply = decode(&wire);
    assert!(reply.header.flags.contains(Flags::TC));
    assert_eq!(reply.answer.len(), 0);
    let tcp = run(
        &pipeline(40),
        &query("local.test.", RecordType::A, false),
        Transport::Tcp,
        &[],
    )
    .reply
    .expect("a reply");
    assert_eq!(decode(&tcp).answer.len(), 40);
}

#[test]
fn a_query_passed_on_goes_upstream() {
    let done = run(
        &pipeline(1),
        &query("example.com.", RecordType::A, true),
        Transport::Udp,
        &[],
    );
    assert_eq!(done.asked, servers());
}

/// A plugin answers without RD: its data is local, no recursion (RFC 1034 §4.3.1).
#[test]
fn a_plugin_answers_without_recursion_desired() {
    let mut message = Message::query(
        7,
        Question::new("local.test.".parse().expect("a name"), RecordType::A),
    );
    message.header.flags = Flags::default();
    let wire = run(&pipeline(1), &common::wire(&message), Transport::Udp, &[])
        .reply
        .expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.answer.len(), 1);
    assert_eq!(reply.header.flags, Flags::QR | Flags::AA | Flags::RA);
}

/// Answers every query with its fields.
#[derive(Debug)]
struct Fixed {
    rcode: Rcode,
    records: Option<Records>,
    error: Option<InfoCode>,
}

impl Fixed {
    /// A pipeline of this plugin alone, answering `records` of `local.test.`, none when empty.
    fn pipeline(rcode: Rcode, records: &[&str], error: Option<InfoCode>) -> Pipeline {
        let records: Vec<Record<'static>> = records
            .iter()
            .map(|text| text.parse().expect("a record"))
            .collect();
        let records = (!records.is_empty())
            .then(|| Records::new(&dns("local.test"), &records).expect("the records fit"));
        Pipeline::new(vec![Stage::Plugin(Box::new(Self {
            rcode,
            records,
            error,
        }))])
    }
}

impl Plugin for Fixed {
    fn answer(&self, _: &Query<'_>) -> Option<Answer<'_>> {
        Some(Answer {
            rcode: self.rcode,
            records: self.records.as_ref(),
            authoritative: true,
            error: self.error,
        })
    }
}

/// RFC 6891 §6.1.3: an RCODE past 4 bits needs an OPT record; a client without one gets SERVFAIL. RCODE 15 fits.
#[test]
fn an_extended_rcode_goes_to_edns_clients_only() {
    for (rcode, edns, sent) in [(16_u16, true, 16_u16), (16, false, 2), (15, false, 15)] {
        let pipeline = Fixed::pipeline(Rcode::from(rcode), &[], None);
        let wire = run(
            &pipeline,
            &query("local.test.", RecordType::A, edns),
            Transport::Udp,
            &[],
        )
        .reply
        .expect("a reply");
        assert_eq!(decode(&wire).rcode(), Rcode::from(sent), "{rcode} {edns}");
    }
}

/// RFC 2181 §9: records filling the client's UDP size to the byte go out whole, with an extended error (RFC 8914);
/// a byte less, they are left out with TC.
#[test]
fn records_that_just_fit_go_out_whole() {
    let records: Vec<String> = (0..40)
        .map(|i| format!("local.test. 60 IN A 192.0.2.{i}"))
        .collect();
    let records: Vec<&str> = records.iter().map(String::as_str).collect();
    let pipeline = Fixed::pipeline(Rcode::NOERROR, &records, Some(InfoCode::BLOCKED));
    let mut query = Message::query(7, Question::new(dns("local.test"), RecordType::A));
    let whole = run(&pipeline, &wire(&query), Transport::Tcp, &[])
        .reply
        .expect("a reply");
    let size = u16::try_from(whole.len()).expect("a UDP size");
    assert!(size > 512, "{size}");
    for (payload, count) in [(size, 40), (size - 1, 0)] {
        query.edns.as_mut().expect("EDNS").udp_payload = payload;
        let wire = run(&pipeline, &wire(&query), Transport::Udp, &[])
            .reply
            .expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.answer.len(), count, "{payload}");
        assert_eq!(
            reply.header.flags.contains(Flags::TC),
            count == 0,
            "{payload}"
        );
        let options = reply.edns.expect("our OPT record").options;
        assert!(matches!(&options[..], [EdnsOption::Ede(_)]), "{options:?}");
    }
}

/// RFC 8467 §4.1: an answer to a padded query over TLS is padded to the next multiple of 468 bytes, whatever its
/// length.
#[test]
fn answers_are_padded_to_the_next_block() {
    let long = "a".repeat(255);
    for n in 150..=170 {
        let record = format!("local.test. 60 IN TXT \"{long}\" \"{}\"", "b".repeat(n));
        let pipeline = Fixed::pipeline(Rcode::NOERROR, &[&record], None);
        let len = |padded: bool| {
            let mut query = Message::query(7, Question::new(dns("local.test"), RecordType::TXT));
            if padded {
                query.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Padding(0)];
            }
            let reply = run(&pipeline, &wire(&query), Transport::Tls, &[]).reply;
            reply.expect("a reply").len()
        };
        let plain = len(false);
        assert_eq!(len(true), (plain + 4).next_multiple_of(468), "{n}");
    }
}

/// Blocks, in review, a response whose answer has a CNAME to `target` (D118); answers `own.test.` itself, with no
/// records. Counts the responses it reviews.
#[derive(Debug)]
struct Gate {
    target: Name<'static>,
    reviews: Arc<AtomicUsize>,
}

impl Gate {
    fn new(target: &str) -> (Self, Arc<AtomicUsize>) {
        let reviews = Arc::new(AtomicUsize::new(0));
        let gate = Self {
            target: dns(target),
            reviews: Arc::clone(&reviews),
        };
        (gate, reviews)
    }
}

impl Plugin for Gate {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let own = query.question()?.name == dns("own.test");
        own.then_some(Answer {
            rcode: Rcode::NOERROR,
            records: None,
            authoritative: true,
            error: None,
        })
    }

    fn reviewer(&self) -> Option<&dyn Reviewer> {
        Some(self)
    }
}

impl Reviewer for Gate {
    fn review(&self, _query: &Query<'_>, response: &Message<'_>) -> Option<Answer<'_>> {
        self.reviews.fetch_add(1, Ordering::Relaxed);
        response
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Cname(target) if target == self.target))
            .then_some(Answer {
                rcode: Rcode::NXDOMAIN,
                records: None,
                authoritative: false,
                error: Some(InfoCode::BLOCKED),
            })
    }
}

/// The captured response to `www.ripe.net. A`: a CNAME to `www.ripe.net.edgekey.net.`, to
/// `e337066.dscb.akamaiedge.net.`, and its addresses.
fn ripe() -> Vec<u8> {
    common::Captures::get("cname_to_insecure")
}

/// A pipeline of the gate, a cache and a forward stage; `cache` is shared to be kept across pipelines.
fn gated(target: &str, cache: &Arc<Cache>) -> (Pipeline, Arc<AtomicUsize>) {
    let (gate, reviews) = Gate::new(target);
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(gate)),
        Stage::Cache(Arc::clone(cache)),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ]);
    (pipeline, reviews)
}

fn cache() -> Arc<Cache> {
    Arc::new(Cache::new(Config::default()).expect("the default settings"))
}

fn assert_blocked(wire: &[u8]) {
    let reply = decode(wire);
    assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NXDOMAIN, 0));
    assert!(!reply.header.flags.contains(Flags::AA));
    assert!(!reply.header.flags.contains(Flags::AD));
    let options = reply.edns.expect("our OPT record").options;
    assert!(
        matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
        "{options:?}"
    );
}

/// D118: a response from upstream whose chain a plugin refuses is answered as that plugin answers. It is stored, not
/// its replacement, and refused again by the hit: a repeat does not go upstream.
#[test]
fn a_response_a_plugin_replaces_is_stored_and_refused_on_a_hit() {
    let (pipeline, reviews) = gated("e337066.dscb.akamaiedge.net", &cache());
    let query = query("www.ripe.net.", RecordType::A, true);
    let response = ripe();
    let first = run(&pipeline, &query, Transport::Udp, &[Some(&response)]);
    assert_eq!(first.asked.len(), 1);
    assert_blocked(&first.reply.expect("a reply"));
    let second = run(&pipeline, &query, Transport::Udp, &[]);
    assert_eq!(second.asked, []);
    assert_blocked(&second.reply.expect("a reply"));
    assert_eq!(reviews.load(Ordering::Relaxed), 2);
}

/// A plugin after the cache stage cannot refuse what the cache serves: its refusal is not stored.
#[test]
fn a_response_a_plugin_after_the_cache_replaces_is_not_stored() {
    let (gate, _) = Gate::new("e337066.dscb.akamaiedge.net");
    let pipeline = Pipeline::new(vec![
        Stage::Cache(cache()),
        Stage::Plugin(Box::new(gate)),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ]);
    let query = query("www.ripe.net.", RecordType::A, true);
    let response = ripe();
    for _ in 0..2 {
        let done = run(&pipeline, &query, Transport::Udp, &[Some(&response)]);
        assert_eq!(done.asked.len(), 1, "upstream is asked again");
        assert_blocked(&done.reply.expect("a reply"));
    }
}

/// The same response, its chain accepted, is stored and served: the first reply is the response, the second a hit.
/// The pipeline reviewed it when it came, and does not decode the hit: one review.
#[test]
fn a_response_no_plugin_replaces_is_cached_and_reviewed_once() {
    let (pipeline, reviews) = gated("nothing.example", &cache());
    let query = query("www.ripe.net.", RecordType::A, true);
    let response = ripe();
    let first = run(&pipeline, &query, Transport::Udp, &[Some(&response)]);
    assert_eq!(decode(&first.reply.expect("a reply")).answer.len(), 5);
    for _ in 0..2 {
        let hit = run(&pipeline, &query, Transport::Udp, &[]);
        assert_eq!(hit.asked, []);
        assert_eq!(decode(&hit.reply.expect("a reply")).answer.len(), 5);
    }
    assert_eq!(reviews.load(Ordering::Relaxed), 1);
}

/// D118: a pipeline built on reload reviews an entry of the old one, once: the mark of the old is not its own.
#[test]
fn a_reload_reviews_an_entry_again_once() {
    let cache = cache();
    let query = query("www.ripe.net.", RecordType::A, true);
    let (old, _) = gated("nothing.example", &cache);
    let _ = run(&old, &query, Transport::Udp, &[Some(&ripe())]);
    let (new, reviews) = gated("nothing.example", &cache);
    for _ in 0..3 {
        let hit = run(&new, &query, Transport::Udp, &[]);
        assert_eq!(decode(&hit.reply.expect("a reply")).answer.len(), 5);
    }
    assert_eq!(reviews.load(Ordering::Relaxed), 1);
}

/// D55: a reload keeps the cache, so a response stored before a name was listed must not be served: a hit is
/// reviewed by the plugins before the cache stage.
#[test]
fn a_cached_response_is_reviewed_on_a_hit() {
    let cache = cache();
    let query = query("www.ripe.net.", RecordType::A, true);
    let before = Pipeline::new(vec![
        Stage::Cache(Arc::clone(&cache)),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ]);
    let stored = run(&before, &query, Transport::Udp, &[Some(&ripe())]);
    assert_eq!(decode(&stored.reply.expect("a reply")).answer.len(), 5);
    let (after, _) = gated("e337066.dscb.akamaiedge.net", &cache);
    let done = run(&after, &query, Transport::Udp, &[]);
    assert_eq!(done.asked, []);
    assert_blocked(&done.reply.expect("a reply"));
}

/// D54, D118: what a plugin answers itself is its own data, not reviewed; a response from upstream is.
#[test]
fn a_plugin_does_not_review_its_own_answers() {
    let (pipeline, reviews) = gated("nothing.example", &cache());
    let done = run(
        &pipeline,
        &query("own.test.", RecordType::A, true),
        Transport::Udp,
        &[],
    );
    assert_eq!(done.asked, []);
    assert_eq!(
        decode(&done.reply.expect("a reply")).rcode(),
        Rcode::NOERROR
    );
    assert_eq!(reviews.load(Ordering::Relaxed), 0);
    let _ = run(
        &pipeline,
        &query("www.ripe.net.", RecordType::A, true),
        Transport::Udp,
        &[Some(&ripe())],
    );
    assert_eq!(reviews.load(Ordering::Relaxed), 1);
}

/// A plugin after the stage that produced the response does not review it: plugins review for the stages after
/// them, as they answer queries for them (D23).
#[test]
fn a_plugin_after_the_forward_stage_is_not_asked() {
    let (gate, reviews) = Gate::new("e337066.dscb.akamaiedge.net");
    let pipeline = Pipeline::new(vec![
        Stage::Forward(Forward::new(servers()).expect("servers")),
        Stage::Plugin(Box::new(gate)),
    ]);
    let done = run(
        &pipeline,
        &query("www.ripe.net.", RecordType::A, true),
        Transport::Udp,
        &[Some(&ripe())],
    );
    assert_eq!(decode(&done.reply.expect("a reply")).answer.len(), 5);
    assert_eq!(reviews.load(Ordering::Relaxed), 0);
}

/// A validating stage reviews the first response before it asks a question of the validation, and stores nothing
/// when it is replaced (D118): the chain of the captured `www.icann.org. A` crosses zones, `org` to `cloudflare.net`.
#[test]
fn a_validated_response_is_reviewed() {
    let (gate, reviews) = Gate::new("www.icann.org.cdn.cloudflare.net");
    let validator = Validator::new(TrustAnchors::root(), Limits::default());
    let validating = Validating::new(validator, Arc::new(common::captured_at));
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(gate)),
        Stage::Cache(cache()),
        Stage::Forward(
            Forward::new(servers())
                .expect("servers")
                .validating(validating),
        ),
    ]);
    let query = common::client_query("www.icann.org.", RecordType::A, Flags::NONE, true);
    let captures = common::Captures::new();
    for _ in 0..2 {
        let done = common::run_captured(&pipeline, &query, 0, &captures);
        assert_eq!(
            done.asked.len(),
            1,
            "no question of the validation, nothing stored"
        );
        assert_blocked(&done.reply.expect("a reply"));
    }
    assert_eq!(reviews.load(Ordering::Relaxed), 2);
}
