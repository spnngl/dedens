//! `scrub` on the captured resolutions of `testdata/recursion` (D188), as captured and changed the way an attacker
//! would change them (D192): RFC 1034 §4.3.2, RFC 2181 §5.4.1/§6.1, RFC 2308 §2, RFC 4697 §2.2, RFC 5452 §6,
//! RFC 6672 §2.2/§3.4. Each change is written next to it; a test of a bound reaches it.

use std::fmt::Write as _;

use dedens_proto::rdata::{Opaque, RData};
use dedens_proto::{
    Class, Flags, MAX_NAME_LEN, Message, Name, Question, Rcode, Record, RecordType, Section, Ttl,
    ZoneEntry, ZoneReader,
};
use dedens_resolver::{
    MAX_CHAIN, MAX_GLUE, MAX_NS, MAX_SIGNATURES, Outcome, Rank, Reason, Scrubbed, Unusable, scrub,
};
use dedens_testkit::recursion::Resolution;

/// The first captured response of resolution `id` from a server of `zone` to `name` and `rtype`, with its question
/// and zone.
fn captured(
    id: &str,
    zone: &str,
    name: &str,
    rtype: RecordType,
) -> (Vec<u8>, Question<'static>, Name<'static>) {
    let zone: Name<'static> = zone.parse().expect("a name");
    let name: Name<'static> = name.parse().expect("a name");
    let e = Resolution::read(id)
        .exchanges
        .into_iter()
        .find(|e| e.zone == zone && e.name == name && e.rtype == rtype)
        .expect("a captured exchange");
    (e.response, Question::new(name, rtype), zone)
}

fn decode(bytes: &[u8]) -> Message<'_> {
    Message::decode(bytes).expect("a captured response").message
}

/// A record written in zone text, its owner absolute.
fn rr(line: &str) -> Record<'static> {
    match ZoneReader::new(line.as_bytes(), Some(Name::root())).next() {
        Some(Ok(ZoneEntry::Record(decoded))) => Some(decoded.record),
        _ => None,
    }
    .expect("a record")
}

/// A DNAME record from `owner` to `target` (RFC 6672 §2.1).
fn dname(owner: &str, target: &str) -> Record<'static> {
    let target: Name<'static> = target.parse().expect("a name");
    let mut buf = [0; MAX_NAME_LEN];
    let wire = target.to_wire(&mut buf);
    let data = Opaque::new(RecordType::DNAME, wire).expect("a DNAME");
    Record::new(
        owner.parse().expect("a name"),
        Class::IN,
        Ttl::from_wire(300),
        &RData::Opaque(data),
    )
}

/// Why the record at `index` of `section` was dropped, if it was.
fn reason(scrubbed: &Scrubbed<'_>, section: Section, index: usize) -> Option<Reason> {
    scrubbed
        .dropped
        .iter()
        .find(|d| d.section == section && d.index == index)
        .map(|d| d.reason)
}

fn names(records: &[Record<'_>]) -> Vec<String> {
    records
        .iter()
        .map(|r| format!("{} {}", r.name, r.rtype()))
        .collect()
}

/// One line of what `scrub` makes of a response: the outcome, the owner and type of each record kept, by field,
/// and the records dropped.
fn describe(scrubbed: &Scrubbed<'_>) -> String {
    let list = |records: &[Record<'_>]| names(records).join(", ");
    let mut line = match &scrubbed.outcome {
        Outcome::Answer {
            chain,
            records,
            authority,
            additional,
        } => format!(
            "Answer chain=[{}] records=[{}] authority=[{}] additional={}",
            list(chain),
            list(records),
            list(authority),
            additional.len()
        ),
        Outcome::Cname {
            chain,
            target,
            authority,
        } => format!(
            "Cname chain=[{}] target={target} authority=[{}]",
            list(chain),
            list(authority)
        ),
        Outcome::Referral {
            child,
            ns,
            proof,
            glue,
        } => format!(
            "Referral child={child} ns={} proof=[{}] glue={}",
            ns.len(),
            list(proof),
            glue.len()
        ),
        Outcome::NoData { authority } => format!("NoData authority=[{}]", list(authority)),
        Outcome::NxDomain { chain, authority } => {
            format!(
                "NxDomain chain=[{}] authority=[{}]",
                list(chain),
                list(authority)
            )
        }
        Outcome::Lame => "Lame".to_owned(),
        Outcome::Unusable(why) => format!("Unusable {why:?}"),
    };
    for d in &scrubbed.dropped {
        write!(line, " drop={:?}[{}]:{:?}", d.section, d.index, d.reason).expect("a String");
    }
    line
}

/// Every response of every capture scrubs to what it holds (RFC 2181 §6.1): nothing of its answer section is
/// dropped; what goes is the zone's own NS `RRset` beside an answer (Unbound's `iter-scrub-promiscuous`) and the
/// addresses of its servers. The snapshot has the outcome of each.
#[test]
fn rfc2181_6_1_every_capture_scrubs_to_what_it_holds() {
    let mut out = String::new();
    for (id, resolution) in Resolution::all() {
        for e in &resolution.exchanges {
            let response = decode(&e.response);
            let question = Question::new(e.name.clone(), e.rtype);
            let scrubbed = scrub(&response, &question, &e.zone);
            for d in &scrubbed.dropped {
                let record = match d.section {
                    Section::Answer => panic!("{id} {}: answer {} dropped", e.name, d.index),
                    Section::Authority => &response.authority[d.index],
                    Section::Additional => &response.additional[d.index],
                };
                let covered = match record.data() {
                    RData::Rrsig(sig) => sig.type_covered,
                    _ => record.rtype(),
                };
                assert!(
                    matches!(covered, RecordType::NS | RecordType::A | RecordType::AAAA),
                    "{id} {}: {} {} dropped",
                    e.name,
                    record.name,
                    record.rtype()
                );
            }
            let line = describe(&scrubbed);
            writeln!(
                out,
                "{id} {} {} {} @{}: {line}",
                e.zone, e.name, e.rtype, e.server
            )
            .expect("a String");
        }
    }
    insta::assert_snapshot!(out);
}

/// The `com.` servers' referral for google.com: glue for a name of another zone is the Kaminsky attack, dropped
/// whatever it names (RFC 2181 §6.1, RFC 5452 §6); an address in the zone that is no server's is not glue.
#[test]
fn rfc5452_6_out_of_zone_glue_is_dropped() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    let added = response.additional.len();
    // Changed: an address for a server of net., and one for www.google.com, appended to the additional section.
    response
        .additional
        .push(rr("a.gtld-servers.net. 172800 IN A 192.0.2.66"));
    response
        .additional
        .push(rr("www.google.com. 172800 IN A 192.0.2.66"));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Referral { glue, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(glue.len(), added);
    assert_eq!(
        reason(&scrubbed, Section::Additional, added),
        Some(Reason::OutsideZone)
    );
    assert_eq!(
        reason(&scrubbed, Section::Additional, added + 1),
        Some(Reason::NotGlue)
    );
}

/// The same referral with NS `RRset`s for a sibling, for the zone itself and for another zone: only the one at or
/// above the name asked and below the zone is a delegation (RFC 1034 §4.3.2 step 3b).
#[test]
fn rfc1034_4_3_2_ns_for_a_sibling_or_parent_is_dropped() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    let added = response.authority.len();
    // Changed: NS records for example.com (a sibling), com. (the zone asked) and net. (another zone) appended.
    response
        .authority
        .push(rr("example.com. 172800 IN NS ns.attacker.example."));
    response
        .authority
        .push(rr("com. 172800 IN NS ns.attacker.example."));
    response
        .authority
        .push(rr("net. 172800 IN NS ns.attacker.example."));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Referral { child, ns, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(child.to_string(), "google.com.");
    assert_eq!(ns.len(), 4);
    assert_eq!(
        reason(&scrubbed, Section::Authority, added),
        Some(Reason::NotDelegation)
    );
    assert_eq!(
        reason(&scrubbed, Section::Authority, added + 1),
        Some(Reason::NotDelegation)
    );
    assert_eq!(
        reason(&scrubbed, Section::Authority, added + 2),
        Some(Reason::OutsideZone)
    );
}

/// A referral to a sibling only leads nowhere: the server is lame for the name (RFC 4697 §2.2).
#[test]
fn rfc4697_2_2_a_referral_to_a_sibling_is_lame() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: the authority section replaced by a delegation of example.com.
    response.authority = vec![rr("example.com. 172800 IN NS ns.attacker.example.")];
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::Lame),
        "{}",
        describe(&scrubbed)
    );
}

/// example.com's answer for its apex, with records for another name of the zone and of another zone: neither is on
/// the way from the name asked (RFC 1034 §4.3.2 step 3a, RFC 2181 §6.1).
#[test]
fn rfc1034_4_3_2_an_answer_for_another_name_is_dropped() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    let added = response.answer.len();
    // Changed: A records for www.example.com and www.example.net appended to the answer section.
    response
        .answer
        .push(rr("www.example.com. 300 IN A 192.0.2.66"));
    response
        .answer
        .push(rr("www.example.net. 300 IN A 192.0.2.66"));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Answer { records, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert!(
        records.iter().all(|r| r.name == question.name),
        "{:?}",
        names(records)
    );
    assert_eq!(
        reason(&scrubbed, Section::Answer, added),
        Some(Reason::OffChain)
    );
    assert_eq!(
        reason(&scrubbed, Section::Answer, added + 1),
        Some(Reason::OutsideZone)
    );
    let mut response = decode(&bytes);
    // Changed: the answer replaced by a CNAME to www.example.com, which has no data here, then a CNAME at another
    // name of the zone.
    response.answer = vec![
        rr("example.com. 300 IN CNAME www.example.com."),
        rr("mail.example.com. 300 IN CNAME attacker.example.com."),
    ];
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Cname { target, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(target.to_string(), "www.example.com.");
    assert_eq!(
        reason(&scrubbed, Section::Answer, 1),
        Some(Reason::OffChain)
    );
}

/// A question for ANY is answered by every type at the name, but an RRSIG still only beside the set it covers.
#[test]
fn rfc2181_5_any_keeps_no_signature_without_its_set() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: the question made ANY, and an RRSIG over a TXT set the answer lacks appended to the answer section.
    response.questions = vec![Question::new(question.name.clone(), RecordType::ANY)];
    response.answer.push(rr(
        "example.com. 300 IN RRSIG TXT 13 2 300 20261201000000 20261101000000 12345 example.com. AAAA",
    ));
    let any = Question::new(question.name.clone(), RecordType::ANY);
    let scrubbed = scrub(&response, &any, &zone);
    let Outcome::Answer { records, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert!(records.iter().any(|r| r.rtype() == RecordType::A));
    let last = response.answer.len() - 1;
    assert!(reason(&scrubbed, Section::Answer, last).is_some());
}

/// A DNAME redirects the names below its owner only (RFC 6672 §2.3): one at the name asked, or below it, is off
/// the chain.
#[test]
fn rfc6672_2_3_a_dname_at_or_below_the_name_is_dropped() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    for owner in ["example.com.", "sub.example.com."] {
        let mut response = decode(&bytes);
        // Changed: a DNAME at `owner` to example.net put first in the answer section.
        response.answer.insert(0, dname(owner, "example.net."));
        let scrubbed = scrub(&response, &question, &zone);
        let Outcome::Answer { chain, records, .. } = &scrubbed.outcome else {
            panic!("{owner}: {}", describe(&scrubbed));
        };
        assert!(chain.is_empty(), "{owner}: {}", describe(&scrubbed));
        assert!(records.iter().all(|r| r.name == question.name));
        assert_eq!(
            reason(&scrubbed, Section::Answer, 0),
            Some(Reason::OffChain)
        );
    }
}

/// dns.netmeister.org's DNAME answer, the DNAME redirected to an unrelated zone: the resolver synthesises the CNAME
/// (RFC 6672 §3.4), so the server's, which no longer matches, goes; the chain stops at the zone's edge, and the
/// address the server adds for the new target is outside its zone.
#[test]
fn rfc6672_3_4_a_dname_to_an_unrelated_zone_stops_the_chain() {
    let (bytes, question, zone) = captured(
        "dname",
        "dns.netmeister.org.",
        "www.dname.dns.netmeister.org.",
        RecordType::A,
    );
    let mut response = decode(&bytes);
    let at = response
        .answer
        .iter()
        .position(|r| r.rtype() == RecordType::DNAME)
        .expect("a DNAME");
    // Changed: the DNAME's target, dns.netmeister.org, replaced by attacker.example; an A for its new name appended.
    response.answer[at] = dname("dname.dns.netmeister.org.", "attacker.example.");
    response
        .answer
        .push(rr("www.attacker.example. 300 IN A 192.0.2.66"));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Cname { chain, target, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(target.to_string(), "www.attacker.example.");
    let cname = chain
        .iter()
        .find_map(|r| match r.data() {
            RData::Cname(target) if r.name == question.name => Some(target.into_owned()),
            _ => None,
        })
        .expect("a synthesised CNAME");
    assert_eq!(cname.to_string(), "www.attacker.example.");
    let reasons: Vec<_> = scrubbed
        .dropped
        .iter()
        .map(|d| (d.section, d.reason))
        .collect();
    assert!(
        reasons.contains(&(Section::Answer, Reason::OutsideZone)),
        "{reasons:?}"
    );
    assert!(
        reasons.contains(&(Section::Answer, Reason::OffChain)),
        "{reasons:?}"
    );
}

/// A DNAME above the zone asked is not the server's to say (RFC 2181 §6.1).
#[test]
fn rfc2181_6_1_a_dname_above_the_zone_is_dropped() {
    let (bytes, question, zone) = captured(
        "dname",
        "dns.netmeister.org.",
        "www.dname.dns.netmeister.org.",
        RecordType::A,
    );
    let mut response = decode(&bytes);
    // Changed: a DNAME for netmeister.org, the parent, put first in the answer section.
    response
        .answer
        .insert(0, dname("netmeister.org.", "attacker.example."));
    let scrubbed = scrub(&response, &question, &zone);
    assert_eq!(
        reason(&scrubbed, Section::Answer, 0),
        Some(Reason::OutsideZone)
    );
    let Outcome::Cname { target, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(target.to_string(), "www.netmeister.org.");
}

/// An answer without AA is data the server holds from elsewhere (RFC 2181 §5.4.1): nothing of it is kept.
#[test]
fn rfc2181_5_4_1_an_answer_without_aa_is_lame() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: AA cleared.
    response.header.flags = response.header.flags.without(Flags::AA);
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::Lame),
        "{}",
        describe(&scrubbed)
    );
    assert_eq!(scrubbed.ranked().len(), 0);
    let (bytes, question, zone) = captured(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
        RecordType::A,
    );
    let mut response = decode(&bytes);
    // Changed: AA cleared from an NXDOMAIN.
    response.header.flags = response.header.flags.without(Flags::AA);
    assert!(matches!(
        scrub(&response, &question, &zone).outcome,
        Outcome::Lame
    ));
}

/// An AA answer is an answer, not a referral, though its authority section names a zone between the one asked and
/// the name: gandi.net's answer, as if from a server of net., keeps its address and drops gandi.net's NS.
#[test]
fn rfc1034_4_3_2_an_answer_with_ns_below_the_zone_is_no_referral() {
    let (bytes, question, _) =
        captured("dname", "gandi.net.", "ns-143-b.gandi.net.", RecordType::A);
    let response = decode(&bytes);
    // Changed: the zone asked is net., the parent of the one that answered.
    let net: Name<'static> = "net.".parse().expect("a name");
    let scrubbed = scrub(&response, &question, &net);
    let Outcome::Answer { records, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(names(records), ["ns-143-b.gandi.net. A"]);
    assert_eq!(
        reason(&scrubbed, Section::Authority, 0),
        Some(Reason::NotAllowed)
    );
}

/// A response that is not one to the question is not read at all.
#[test]
fn rfc1034_4_3_2_a_response_to_another_question_is_unusable() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let response = decode(&bytes);
    let other = Question::new("www.example.com.".parse().expect("a name"), RecordType::A);
    let outcome = |q: &Question<'_>, z: &Name<'_>| scrub(&response, q, z).outcome;
    assert!(matches!(
        outcome(&other, &zone),
        Outcome::Unusable(Unusable::QuestionMismatch)
    ));
    let aaaa = Question::new(question.name.clone(), RecordType::AAAA);
    assert!(matches!(
        outcome(&aaaa, &zone),
        Outcome::Unusable(Unusable::QuestionMismatch)
    ));
    let mut query = decode(&bytes);
    // Changed: QR cleared, a query.
    query.header.flags = query.header.flags.without(Flags::QR);
    assert!(matches!(
        scrub(&query, &question, &zone).outcome,
        Outcome::Unusable(Unusable::NotResponse)
    ));
    let org: Name<'static> = "org.".parse().expect("a name");
    assert!(matches!(
        outcome(&question, &org),
        Outcome::Unusable(Unusable::OutsideZone)
    ));
    let mut failed = decode(&bytes);
    // Changed: the response code set to SERVFAIL.
    failed.set_rcode(Rcode::SERVFAIL).expect("a code");
    assert!(matches!(
        scrub(&failed, &question, &zone).outcome,
        Outcome::Unusable(Unusable::Rcode(Rcode::SERVFAIL))
    ));
    let (bytes, question, zone) = captured(
        "truncated",
        "microsoft.com.",
        "microsoft.com.",
        RecordType::TXT,
    );
    let response = decode(&bytes);
    assert!(matches!(
        scrub(&response, &question, &zone).outcome,
        Outcome::Unusable(Unusable::Truncated)
    ));
}

/// sidn.nl's NXDOMAIN with an NSEC claiming a span past the zone (Unbound's `sanitize_nsec_is_overreach`) and a
/// record of another class.
#[test]
fn rfc2181_6_1_an_nsec_past_the_zone_and_another_class_are_dropped() {
    let (bytes, question, zone) = captured(
        "nxdomain-signed",
        "sidn.nl.",
        "dedens-nxdomain.sidn.nl.",
        RecordType::A,
    );
    let mut response = decode(&bytes);
    let added = response.authority.len();
    // Changed: an NSEC from sidn.nl to attacker.example, and an SOA of class CH, appended to the authority section.
    response.authority.push(rr(
        "dedens-nxdomain.sidn.nl. 300 IN NSEC attacker.example. A RRSIG NSEC",
    ));
    response.authority.push(rr(
        "sidn.nl. 300 CH SOA ns.sidn.nl. hostmaster.sidn.nl. 1 2 3 4 5",
    ));
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::NxDomain { .. }),
        "{}",
        describe(&scrubbed)
    );
    assert_eq!(
        reason(&scrubbed, Section::Authority, added),
        Some(Reason::Overreach)
    );
    assert_eq!(
        reason(&scrubbed, Section::Authority, added + 1),
        Some(Reason::OtherClass)
    );
}

/// [`MAX_NS`]: a referral of more name servers keeps the first ones.
#[test]
fn max_ns_bounds_a_referral() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    let before = response.authority.len();
    // Changed: name servers for google.com appended up to one past the bound.
    for i in 4..=MAX_NS {
        response.authority.push(rr(&format!(
            "google.com. 172800 IN NS ns{i}.attacker.example."
        )));
    }
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Referral { ns, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(ns.len(), MAX_NS);
    assert_eq!(
        reason(&scrubbed, Section::Authority, before + MAX_NS - 4),
        Some(Reason::TooManyNs)
    );
}

/// [`MAX_GLUE`]: a referral of more addresses keeps the first ones.
#[test]
fn max_glue_bounds_the_addresses() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    let glue = response.additional.len();
    // Changed: addresses for ns1.google.com appended up to one past the bound.
    for i in glue..=MAX_GLUE {
        response.additional.push(rr(&format!(
            "ns1.google.com. 172800 IN A 192.0.2.{}",
            i % 256
        )));
    }
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Referral { glue, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(glue.len(), MAX_GLUE);
    assert_eq!(
        reason(&scrubbed, Section::Additional, MAX_GLUE),
        Some(Reason::TooMuchGlue)
    );
}

/// [`MAX_SIGNATURES`]: an `RRset` of more signatures keeps the first ones.
#[test]
fn max_signatures_bounds_an_rrset() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    let sig = response
        .answer
        .iter()
        .position(|r| r.rtype() == RecordType::RRSIG)
        .expect("an RRSIG");
    // Changed: the answer's RRSIG repeated up to one past the bound.
    let copies = response.answer[sig].clone();
    let last = response.answer.len() + MAX_SIGNATURES - 1;
    for _ in 1..=MAX_SIGNATURES {
        response.answer.push(copies.clone());
    }
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Answer { records, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    let signatures = records
        .iter()
        .filter(|r| r.rtype() == RecordType::RRSIG)
        .count();
    assert_eq!(signatures, MAX_SIGNATURES);
    assert_eq!(
        reason(&scrubbed, Section::Answer, last),
        Some(Reason::TooManySignatures)
    );
}

/// [`MAX_CHAIN`]: a CNAME chain longer than the bound stops at it, its end the resolution's to ask again
/// (RFC 1034 §4.3.2 step 3a).
#[test]
fn max_chain_bounds_a_cname_chain() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: the answer section replaced by a chain from example.com, one CNAME past the bound.
    response.answer = (0..=MAX_CHAIN)
        .map(|i| {
            let owner = if i == 0 {
                "example.com.".to_owned()
            } else {
                format!("c{i}.example.com.")
            };
            rr(&format!("{owner} 300 IN CNAME c{}.example.com.", i + 1))
        })
        .collect();
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Cname { chain, target, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(chain.len(), MAX_CHAIN);
    assert_eq!(target.to_string(), format!("c{MAX_CHAIN}.example.com."));
    assert_eq!(
        reason(&scrubbed, Section::Answer, MAX_CHAIN),
        Some(Reason::ChainTooLong)
    );
}

/// [`MAX_CHAIN`] counts DNAME hops too: a CNAME into a run of DNAMEs stops at the bound.
#[test]
fn max_chain_bounds_a_dname_chain() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: the answer section replaced by a CNAME to y.x.d0.example.com, then a DNAME from each dN.example.com
    // to dN+1.example.com, the last one past the bound.
    response.answer = vec![rr("example.com. 300 IN CNAME y.x.d0.example.com.")];
    response.answer.extend((0..MAX_CHAIN).map(|i| {
        dname(
            &format!("d{i}.example.com."),
            &format!("d{}.example.com.", i + 1),
        )
    }));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Cname { target, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(
        target.to_string(),
        format!("y.x.d{}.example.com.", MAX_CHAIN - 1)
    );
    assert_eq!(
        reason(&scrubbed, Section::Answer, MAX_CHAIN),
        Some(Reason::ChainTooLong)
    );
}

/// An SOA is kept by a negative answer only (RFC 2308 §2): beside an answer, or beside a chain whose end the zone
/// is asked again for, it is dropped.
#[test]
fn rfc2308_2_an_soa_beside_an_answer_or_a_chain_is_dropped() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let soa = "example.com. 300 IN SOA ns.icann.org. noc.dns.icann.org. 1 7200 3600 1209600 3600";
    let mut response = decode(&bytes);
    // Changed: an SOA of example.com appended to the authority section.
    response.authority.push(rr(soa));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Answer { authority, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert!(names(authority).iter().all(|n| !n.ends_with(" SOA")));
    let last = response.authority.len() - 1;
    assert_eq!(
        reason(&scrubbed, Section::Authority, last),
        Some(Reason::NotAllowed)
    );
    let mut response = decode(&bytes);
    // Changed: the answer replaced by a CNAME to www.example.com, which has no data here, and the SOA appended.
    response.answer = vec![rr("example.com. 300 IN CNAME www.example.com.")];
    response.authority.push(rr(soa));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Cname {
        target, authority, ..
    } = &scrubbed.outcome
    else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(target.to_string(), "www.example.com.");
    assert!(names(authority).iter().all(|n| !n.ends_with(" SOA")));
    let last = response.authority.len() - 1;
    assert_eq!(
        reason(&scrubbed, Section::Authority, last),
        Some(Reason::NotAllowed)
    );
}

/// The ranks of RFC 2181 §5.4.1: a referral's records are the non-authoritative authority and additional data, an
/// answer's chain is authoritative at the name asked only.
#[test]
fn rfc2181_5_4_1_ranks_follow_section_and_aa() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let response = decode(&bytes);
    let ranks: Vec<_> = scrub(&response, &question, &zone)
        .ranked()
        .into_iter()
        .map(|(rank, r)| (rank, r.rtype()))
        .collect();
    assert!(
        ranks.contains(&(Rank::AuthorityNonAuthoritative, RecordType::NS)),
        "{ranks:?}"
    );
    assert!(
        ranks.contains(&(Rank::AdditionalNonAuthoritative, RecordType::A)),
        "{ranks:?}"
    );
    let (bytes, question, zone) = captured(
        "dname",
        "dns.netmeister.org.",
        "www.dname.dns.netmeister.org.",
        RecordType::A,
    );
    let response = decode(&bytes);
    let scrubbed = scrub(&response, &question, &zone);
    for (rank, r) in scrubbed.ranked() {
        let expected = if r.name == question.name {
            Rank::AnswerAuthoritative
        } else {
            Rank::AnswerNonAuthoritative
        };
        assert_eq!(rank, expected, "{} {}", r.name, r.rtype());
    }
}
