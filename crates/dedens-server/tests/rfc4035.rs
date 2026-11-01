//! RFC 4035 in the validating forward stage (D77): what a validating resolver answers (§3.2), caches (§4.5, §4.7)
//! and sends (§4.6, §4.8). Upstream answers from the captures of `dedens-dnssec` (`testdata/README.md`), the
//! validation at the time of their run.

mod common;

use common::{Captures, client_query, decode, run_captured, validating, with_flags};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Flags, Message, Rcode, RecordType};

/// The reply to a query, the requests upstream, and what the pipeline replied.
fn ask(
    name: &str,
    qtype: RecordType,
    flags: Flags,
    dnssec: bool,
) -> (Vec<Message<'static>>, Vec<u8>) {
    let pipeline = validating();
    let done = run_captured(
        &pipeline,
        &client_query(name, qtype, flags, dnssec),
        0,
        &Captures::new(),
    );
    (done.requests, done.reply.expect("a reply"))
}

/// Whether `items` has one: `is_empty` and `first` are both linted in an assertion.
fn some<T>(items: &[T]) -> bool {
    matches!(items, [_, ..])
}

fn signed(reply: &Message<'_>) -> bool {
    reply
        .answer
        .iter()
        .chain(&reply.authority)
        .any(|record| record.rtype() == RecordType::RRSIG)
}

fn error(reply: &Message<'_>) -> Option<InfoCode> {
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

/// §3.2.3: the answer of a secure zone checked up to the trust anchor is authentic, and says so. §3.2.1: the
/// signatures come with it for a client that set DO.
#[test]
fn a_secure_answer_has_ad_and_its_signatures_for_clients_with_do() {
    let (requests, wire) = ask("cloudflare.com.", RecordType::A, Flags::NONE, true);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
    assert!(signed(&reply));
    assert!(requests.len() > 1, "the chain of trust is asked for");
}

/// §3.2.1: a client that did not set DO gets no DNSSEC record, §3.2.3 and RFC 6840 §5.8: AD when it asked with AD.
#[test]
fn signatures_are_left_out_for_clients_without_do() {
    let (_, wire) = ask("cloudflare.com.", RecordType::A, Flags::AD, false);
    let reply = decode(&wire);
    assert!(reply.header.flags.contains(Flags::AD));
    assert!(!signed(&reply));
    assert!(some(&reply.answer));
}

/// §3.2.3: an answer of an unsigned zone is insecure: no AD.
#[test]
fn an_insecure_answer_has_no_ad() {
    let (_, wire) = ask("google.com.", RecordType::A, Flags::AD, true);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(!reply.header.flags.contains(Flags::AD));
    assert!(some(&reply.answer));
}

/// §5.5, RFC 8914 §4.7: an answer that fails validation is SERVFAIL, with the reason.
#[test]
fn a_bogus_answer_is_servfail_with_an_extended_error() {
    for (name, code) in [
        ("dnssec-failed.org.", InfoCode::DNSKEY_MISSING),
        ("sigfail.verteiltesysteme.net.", InfoCode::DNSSEC_BOGUS),
    ] {
        let (_, wire) = ask(name, RecordType::A, Flags::NONE, true);
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::SERVFAIL, "{name}");
        assert!(reply.answer.is_empty(), "{name}");
        assert!(!reply.header.flags.contains(Flags::AD));
        assert_eq!(error(&reply), Some(code), "{name}");
    }
}

/// §3.2.2: a client that set CD gets the data whatever its signatures, as it came, AD clear, and no validation
/// was asked for.
#[test]
fn a_client_with_cd_gets_bogus_data_unvalidated() {
    let (requests, wire) = ask("dnssec-failed.org.", RecordType::A, Flags::CD, true);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(some(&reply.answer));
    assert!(!reply.header.flags.contains(Flags::AD));
    assert!(reply.header.flags.contains(Flags::CD));
    assert_eq!(requests.len(), 1);
}

/// §4.7: bad data is kept for a short time that the resolver sets, 60 seconds; a client that did not disable
/// checking gets SERVFAIL from it, one that did gets the data (§3.2.2); then it is validated again.
#[test]
fn bogus_data_is_cached_for_sixty_seconds() {
    let pipeline = validating();
    let captures = Captures::new();
    let query = client_query("dnssec-failed.org.", RecordType::A, Flags::NONE, true);
    let first = run_captured(&pipeline, &query, 100, &captures);
    assert!(some(&first.requests));
    let cached = run_captured(&pipeline, &query, 159, &captures);
    assert_eq!(cached.requests.len(), 0, "answered from the cache");
    let wire = cached.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(error(&reply), Some(InfoCode::DNSKEY_MISSING));

    let disabled = client_query("dnssec-failed.org.", RecordType::A, Flags::CD, true);
    let served = run_captured(&pipeline, &disabled, 159, &captures);
    assert_eq!(served.requests.len(), 0, "the data comes from the cache");
    let wire = served.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(some(&reply.answer));

    let again = run_captured(&pipeline, &query, 161, &captures);
    assert!(some(&again.requests), "validated again");
}

/// §4.5: a validated response is one entry with its signatures: a client's next query is answered from it, AD
/// following the client's query and the verdict.
#[test]
fn a_validated_answer_is_cached_whole() {
    let pipeline = validating();
    let captures = Captures::new();
    let asked = |flags, dnssec| {
        let query = client_query("cloudflare.com.", RecordType::A, flags, dnssec);
        let done = run_captured(&pipeline, &query, 1, &captures);
        (
            done.requests.len(),
            decode(&done.reply.expect("a reply")).into_owned(),
        )
    };
    let (first, _) = asked(Flags::NONE, true);
    assert!(first > 1);
    let (hit, reply) = asked(Flags::NONE, true);
    assert_eq!(hit, 0);
    assert!(reply.header.flags.contains(Flags::AD));
    assert!(signed(&reply));
    let (hit, reply) = asked(Flags::NONE, false);
    assert_eq!(
        hit, 1,
        "another key: the answer for a client without DO, its chain from the key cache (D86)"
    );
    assert!(!reply.header.flags.contains(Flags::AD));
    let (hit, reply) = asked(Flags::AD, false);
    assert_eq!(hit, 0);
    assert!(reply.header.flags.contains(Flags::AD));
    assert!(!signed(&reply));
}

/// §4.6: queries clear AD; RFC 6840 §5.9: and set CD, with DO, and none of the client's options, for the client's
/// question and for each of the validator's.
#[test]
fn every_query_upstream_has_do_and_cd_and_no_ad() {
    let pipeline = validating();
    let query = client_query("cloudflare.com.", RecordType::A, Flags::AD, false);
    let done = run_captured(&pipeline, &query, 0, &Captures::new());
    assert!(done.requests.len() > 1);
    for request in &done.requests {
        assert_eq!(request.header.flags, Flags::RD | Flags::CD);
        let edns = request.edns.as_ref().expect("EDNS");
        assert!(edns.flags.contains(dedens_proto::EdnsFlags::DO));
        assert_eq!(edns.options, []);
    }
}

/// §4.8: the CNAME a DNAME makes is covered by the DNAME's signature, and the answer keeps it.
#[test]
fn the_cname_a_dname_makes_stays_in_the_secure_answer() {
    let (_, wire) = ask(
        "www.dname.sidnlabs.nl.",
        RecordType::AAAA,
        Flags::NONE,
        true,
    );
    let reply = decode(&wire);
    assert!(reply.header.flags.contains(Flags::AD));
    let types: Vec<RecordType> = reply
        .answer
        .iter()
        .map(dedens_proto::Record::rtype)
        .collect();
    assert!(types.contains(&RecordType::DNAME), "{types:?}");
    assert!(types.contains(&RecordType::CNAME), "{types:?}");
    assert!(types.contains(&RecordType::AAAA), "{types:?}");
}

/// §3.2.3 and RFC 6840 §5.8: AD says all of the answer is authentic: a chain that goes on in an unsigned zone
/// is delivered without it, whatever the CNAMEs signed.
#[test]
fn an_answer_that_leaves_the_secure_zone_has_no_ad() {
    let (_, wire) = ask("www.ripe.net.", RecordType::A, Flags::AD, true);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(some(&reply.answer));
    assert!(!reply.header.flags.contains(Flags::AD));
}

/// §4.6: the AD bit of an upstream response means nothing without a secure channel: only the verdict sets it.
#[test]
fn the_ad_bit_of_upstream_is_ignored() {
    let pipeline = validating();
    let lying = with_flags(Captures::get("google_com_a"), Flags::AD);
    let captures = Captures::new().with(lying);
    let query = client_query("google.com.", RecordType::A, Flags::AD, true);
    let done = run_captured(&pipeline, &query, 0, &captures);
    let wire = done.reply.expect("a reply");
    assert!(!decode(&wire).header.flags.contains(Flags::AD));
}

/// §3.2.3: the verdict covers the answer and authority sections, not the additional one: what upstream put there
/// is not handed out.
#[test]
fn a_secure_answer_loses_its_additional_section() {
    let mut message = decode(&Captures::get("alg13_a")).into_owned();
    let mut extra = message.answer[0].clone();
    extra.name = common::dns("unsigned.example.");
    message.additional.push(extra);
    let captures = Captures::new().with(common::wire(&message));
    let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
    let done = run_captured(&validating(), &query, 0, &captures);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert!(reply.header.flags.contains(Flags::AD));
    assert!(some(&reply.answer));
    assert_eq!(reply.additional, []);
}

/// A record of class IN owned by `owner` with `data`.
fn record(owner: &str, ttl: u32, data: &dedens_proto::RData<'_>) -> dedens_proto::Record<'static> {
    dedens_proto::Record {
        name: common::dns(owner),
        class: dedens_proto::Class::IN,
        ttl: dedens_proto::Ttl::from_wire(ttl),
        rdata: dedens_proto::WireRdata::new(data),
    }
}

/// D77, D75: the validator ignores what is not on the name path of the answer; a record the verdict says nothing
/// of is neither served under AD nor cached as secure: unrelated sets, signatures that sign nothing, authority
/// sets that are not at or above the answer, other classes.
#[test]
fn a_secure_answer_is_cut_to_what_was_verified() {
    let mut message = decode(&Captures::get("alg13_a")).into_owned();
    let a = message.answer[0].clone();
    let foreign = |owner: &str| dedens_proto::Record {
        name: common::dns(owner),
        ..a.clone()
    };
    let signature = message
        .answer
        .iter()
        .find(|record| record.rtype() == RecordType::RRSIG)
        .expect("a signature")
        .clone();
    let ns = record(
        "unrelated.example.",
        300,
        &dedens_proto::RData::Cname(common::dns("evil.example.")),
    );
    let genuine = message.answer.len();
    message.answer.push(foreign("other.example."));
    message.answer.push(dedens_proto::Record {
        name: common::dns("other.example."),
        ..signature.clone()
    });
    message.answer.push(dedens_proto::Record {
        name: common::dns("orphan.cloudflare.com."),
        ..signature
    });
    message.answer.push(dedens_proto::Record {
        class: dedens_proto::Class::CH,
        ..a.clone()
    });
    message.authority.push(ns);
    message.authority.push(foreign("cloudflare.net."));
    let captures = Captures::new().with(common::wire(&message));
    let pipeline = validating();
    for round in 0..2 {
        let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
        let done = run_captured(&pipeline, &query, round, &captures);
        assert_eq!(done.requests.is_empty(), round == 1, "the second is a hit");
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert!(reply.header.flags.contains(Flags::AD));
        assert_eq!(reply.answer.len(), genuine, "{:?}", reply.answer);
        assert_eq!(reply.authority, [], "round {round}");
        assert!(
            reply
                .answer
                .iter()
                .all(|record| record.name == common::dns("cloudflare.com."))
        );
    }
}

/// RFC 6672 §3.1, D75: only the CNAME a DNAME makes goes unverified, so a set of it with another record is
/// checked as any CNAME, unsigned in a secure zone: bogus, never served under AD.
#[test]
fn a_second_record_in_the_cname_a_dname_makes_is_bogus() {
    let mut message = decode(&Captures::get("dname_answer")).into_owned();
    let at = message
        .answer
        .iter()
        .position(|record| record.rtype() == RecordType::CNAME)
        .expect("the synthesized CNAME");
    let evil = dedens_proto::Record {
        rdata: dedens_proto::WireRdata::new(&dedens_proto::RData::Cname(common::dns(
            "evil.example.",
        ))),
        ..message.answer[at].clone()
    };
    message.answer.insert(at + 1, evil);
    let captures = Captures::new().with(common::wire(&message));
    let query = client_query(
        "www.dname.sidnlabs.nl.",
        RecordType::AAAA,
        Flags::NONE,
        true,
    );
    let done = run_captured(&validating(), &query, 0, &captures);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert!(!reply.header.flags.contains(Flags::AD));
    assert_eq!(reply.answer, []);
    assert_eq!(error(&reply), Some(InfoCode::RRSIGS_MISSING));
}

/// §4.3: no verdict, for lack of an answer to a question of the validator's: SERVFAIL, held for the next query.
#[test]
fn no_verdict_is_servfail_and_held() {
    let pipeline = validating();
    let captures = Captures::new().without("com.", RecordType::DS);
    let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
    let first = run_captured(&pipeline, &query, 0, &captures);
    assert!(
        first.asked.len() > 2,
        "every server was tried: {:?}",
        first.asked
    );
    let wire = first.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert!(!reply.header.flags.contains(Flags::AD));
    assert!(error(&reply).is_some());
    let held = run_captured(&pipeline, &query, 1, &captures);
    assert_eq!(held.requests.len(), 0, "the failure is held");
}

/// `genuine` as the response to the question for `name`, its records replaced by `answer`.
fn response_for(
    genuine: &Message<'static>,
    name: &str,
    answer: Vec<dedens_proto::Record<'static>>,
) -> Vec<u8> {
    let mut message = genuine.clone();
    message.questions[0].name = common::dns(name);
    message.answer = answer;
    message.authority.clear();
    message.additional.clear();
    common::wire(&message)
}

/// The signed CNAME of `www.ripe.net.` alone, and the rest of its chain: what two responses of upstream are, to
/// the question for the name and to the one for the CNAME's target.
fn split_chain() -> (Vec<u8>, Vec<u8>) {
    let genuine = decode(&Captures::get("cname_to_insecure")).into_owned();
    let (head, tail): (Vec<_>, Vec<_>) = genuine
        .answer
        .iter()
        .cloned()
        .partition(|record| record.name == common::dns("www.ripe.net."));
    (
        response_for(&genuine, "www.ripe.net.", head),
        response_for(&genuine, "www.ripe.net.edgekey.net.", tail),
    )
}

/// RFC 6840 §5.8, D77: a CNAME chain that stops short is chased, the name it goes on at asked and its response
/// validated as one of its own; the answer is never secure, whatever the verdicts.
#[test]
fn a_chain_that_stops_short_is_chased_and_not_secure() {
    let (head, tail) = split_chain();
    let captures = Captures::new().with(head).with(tail);
    let query = client_query("www.ripe.net.", RecordType::A, Flags::AD, true);
    let done = run_captured(&validating(), &query, 0, &captures);
    let chased = done
        .requests
        .iter()
        .any(|request| request.questions[0].name == common::dns("www.ripe.net.edgekey.net."));
    assert!(chased);
    let reply = decode(&done.reply.expect("a reply")).into_owned();
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(!reply.header.flags.contains(Flags::AD));
    assert!(some(&reply.answer));
}

/// D77: a chased name upstream does not answer leaves no verdict: SERVFAIL, not the first response as if it were
/// the whole answer.
#[test]
fn a_chased_name_without_an_answer_is_indeterminate() {
    let (head, _) = split_chain();
    let captures = Captures::new()
        .with(head)
        .without("www.ripe.net.edgekey.net.", RecordType::A);
    let query = client_query("www.ripe.net.", RecordType::A, Flags::AD, true);
    let done = run_captured(&validating(), &query, 0, &captures);
    let reply = decode(&done.reply.expect("a reply")).into_owned();
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert!(!reply.header.flags.contains(Flags::AD));
    assert!(!some(&reply.answer));
}

/// D77: a server that did not answer is not asked again for the next question of the same query: one dead server
/// costs the patience of one question, not of each.
#[test]
fn a_dead_server_is_asked_once_by_a_query() {
    let dead = common::servers()[0];
    let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
    let done = common::run_captured_without(&validating(), &query, 0, &Captures::new(), Some(dead));
    let reply = decode(&done.reply.expect("a reply")).into_owned();
    assert!(reply.header.flags.contains(Flags::AD));
    assert!(done.requests.len() > 2);
    assert_eq!(
        done.asked.iter().filter(|&&server| server == dead).count(),
        1
    );
}

/// §4.7, D77: a refresh whose answer fails validation leaves the entry it refreshes: bad data does not replace data
/// that is still good.
#[test]
fn a_refresh_that_turns_bogus_keeps_the_entry() {
    let pipeline = validating();
    let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
    let first = run_captured(&pipeline, &query, 0, &Captures::new());
    let ttl = decode(&first.reply.expect("a reply")).answer[0].ttl.get();
    assert!(ttl >= 20, "{ttl}");

    let mut forged = decode(&Captures::get("alg13_a")).into_owned();
    for record in &mut forged.answer {
        if record.rtype() == RecordType::A {
            record.rdata = dedens_proto::WireRdata::new(&dedens_proto::RData::A(
                std::net::Ipv4Addr::new(192, 0, 2, 66),
            ));
        }
    }
    let captures = Captures::new().with(common::wire(&forged));
    let late = ttl - 1;
    let refresh = run_captured(&pipeline, &query, late, &captures);
    assert!(some(&refresh.requests), "the entry was refreshed");

    let served = run_captured(&pipeline, &query, late, &captures);
    assert_eq!(served.requests.len(), 0, "answered from the cache");
    let reply = decode(&served.reply.expect("a reply")).into_owned();
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
    assert!(reply.answer.iter().all(|record| {
        !matches!(record.data(), dedens_proto::RData::A(address) if address == std::net::Ipv4Addr::new(192, 0, 2, 66))
    }));
}
