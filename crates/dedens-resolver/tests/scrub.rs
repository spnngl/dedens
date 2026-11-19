//! `scrub` on the captured resolutions of `testdata/recursion` (D188), as captured and changed the way an attacker
//! would change them (D192): RFC 1034 §4.3.2, RFC 1035 §4.1.1, RFC 2181 §5.4.1/§6.1, RFC 2308 §2/§5, RFC 4035
//! §2.2/§2.3/§3.1.4, RFC 4697 §2.2, RFC 5452 §6, RFC 6672 §2.2/§2.5/§3.4. Each change is written next to it; a
//! test of a bound reaches it.

use std::fmt::Write as _;

use dedens_proto::rdata::{Opaque, RData};
use dedens_proto::{
    Class, Flags, MAX_NAME_LEN, Message, Name, Question, Rcode, Record, RecordType, Section, Ttl,
    ZoneEntry, ZoneReader,
};
use dedens_resolver::{
    MAX_CHAIN, MAX_GLUE, MAX_NS, MAX_SIGNATURES, Negative, Outcome, Rank, Reason, Rrset, Scrubbed,
    Unusable, scrub,
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
pub(crate) fn dname(owner: &str, target: &str) -> Record<'static> {
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

/// A record of `rtype` at `owner` whose RDATA is `data`, valid for the type or not.
fn raw(owner: &str, rtype: RecordType, data: &[u8]) -> Record<'static> {
    let data = Opaque::new(rtype, data).expect("RDATA");
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

/// What `scrub` made of a response: the outcome and the owner and type of each record kept, by field.
fn outcome(scrubbed: &Scrubbed<'_>) -> String {
    let list = |records: &[Record<'_>]| names(records).join(", ");
    match &scrubbed.outcome {
        Outcome::Answer {
            chain,
            records,
            denials,
            additional,
        } => format!(
            "Answer chain=[{}] records=[{}] denials=[{}] additional={}",
            list(chain),
            list(records),
            list(denials),
            additional.len()
        ),
        Outcome::Signatures { chain, records } => format!(
            "Signatures chain=[{}] records=[{}]",
            list(chain),
            list(records)
        ),
        Outcome::Cname {
            chain,
            target,
            denials,
        } => format!(
            "Cname chain=[{}] target={target} denials=[{}]",
            list(chain),
            list(denials)
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
        Outcome::NoData { soa, denials } => {
            format!("NoData soa={} denials=[{}]", soa.name, list(denials))
        }
        Outcome::NxDomain {
            chain,
            soa,
            denials,
        } => format!(
            "NxDomain chain=[{}] soa={} denials=[{}]",
            list(chain),
            soa.name,
            list(denials)
        ),
        Outcome::YxDomain { chain } => format!("YxDomain chain=[{}]", list(chain)),
        Outcome::NoSoa(Negative::NoData) => "NoSoa NoData".to_owned(),
        Outcome::NoSoa(Negative::NxDomain { chain }) => {
            format!("NoSoa NxDomain chain=[{}]", list(chain))
        }
        Outcome::Lame => "Lame".to_owned(),
        Outcome::Unusable(why) => format!("Unusable {why:?}"),
    }
}

/// The outcome, and the place and reason of each record dropped.
fn describe(scrubbed: &Scrubbed<'_>) -> String {
    let mut line = outcome(scrubbed);
    for d in &scrubbed.dropped {
        write!(line, " drop={:?}[{}]:{:?}", d.section, d.index, d.reason).expect("a String");
    }
    line
}

/// Every response of every capture scrubs to what it holds (RFC 2181 §6.1): nothing of its answer section is
/// dropped. The snapshot has the outcome of each and every record dropped, by owner and type.
#[test]
fn rfc2181_6_1_every_capture_scrubs_to_what_it_holds() {
    let mut out = String::new();
    for (id, resolution) in Resolution::all() {
        for e in &resolution.exchanges {
            let response = decode(&e.response);
            let question = Question::new(e.name.clone(), e.rtype);
            let scrubbed = scrub(&response, &question, &e.zone);
            let mut line = outcome(&scrubbed);
            for d in &scrubbed.dropped {
                let record = match d.section {
                    Section::Answer => panic!("{id} {}: answer {} dropped", e.name, d.index),
                    Section::Authority => &response.authority[d.index],
                    Section::Additional => &response.additional[d.index],
                };
                write!(
                    line,
                    " drop={}:{} {}:{:?}",
                    if d.section == Section::Authority {
                        "authority"
                    } else {
                        "additional"
                    },
                    record.name,
                    record.rtype(),
                    d.reason
                )
                .expect("a String");
            }
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

/// Every capture's records kept come out as `RRsets` (RFC 2181 §5), none lost, each RRSIG kept with the `RRset` it
/// covers at the rank of its records (RFC 4034 §3): what the `RRset` cache takes.
#[test]
fn rfc4034_3_every_capture_groups_each_signature_with_its_rrset() {
    let mut signed = 0;
    for (id, resolution) in Resolution::all() {
        for e in &resolution.exchanges {
            let response = decode(&e.response);
            let question = Question::new(e.name.clone(), e.rtype);
            let scrubbed = scrub(&response, &question, &e.zone);
            let (records, ranked) = (scrubbed.records(), scrubbed.ranked());
            let (sigs, data): (Vec<_>, Vec<_>) = records
                .iter()
                .partition(|(_, r)| r.rtype() == RecordType::RRSIG);
            let set_of = |rank: Rank, r: &Record<'_>, rtype: RecordType| {
                ranked.iter().find(|(k, set)| {
                    *k == rank
                        && *set.owner() == r.name
                        && set.rtype() == rtype
                        && set.class() == r.class
                })
            };
            for (rank, r) in &data {
                assert!(
                    set_of(*rank, r, r.rtype()).is_some(),
                    "{id} {}: {rank:?} {} {} in no RRset",
                    e.name,
                    r.name,
                    r.rtype()
                );
            }
            for (rank, r) in &sigs {
                let RData::Rrsig(sig) = r.data() else {
                    panic!("{id} {}: an RRSIG that does not parse kept", e.name);
                };
                let set = set_of(*rank, r, sig.type_covered);
                assert!(
                    set.is_some_and(|(_, set)| !set.rrsigs().is_empty()),
                    "{id} {}: {rank:?} {} RRSIG {} with no RRset",
                    e.name,
                    r.name,
                    sig.type_covered
                );
            }
            let count = |f: fn(&Rrset) -> usize| ranked.iter().map(|(_, s)| f(s)).sum::<usize>();
            assert_eq!(count(|s| s.rdatas().len()), data.len(), "{id} {}", e.name);
            assert_eq!(count(|s| s.rrsigs().len()), sigs.len(), "{id} {}", e.name);
            signed += sigs.len();
        }
    }
    assert!(signed > 0, "the captures hold signatures");
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
    // Changed: the DNAME's target, dns.netmeister.org, replaced by attacker.example; an A for its new name appended;
    // the RRSIG of the server's CNAME copied as one of the name asked.
    response.answer[at] = dname("dname.dns.netmeister.org.", "attacker.example.");
    response
        .answer
        .push(rr("www.attacker.example. 300 IN A 192.0.2.66"));
    let sig = response
        .answer
        .iter()
        .find(|r| matches!(r.data(), RData::Rrsig(s) if s.type_covered == RecordType::CNAME))
        .expect("a CNAME's RRSIG");
    let sig = Record::new(question.name.clone(), sig.class, sig.ttl, &sig.data());
    response.answer.push(sig);
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Cname { chain, target, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(target.to_string(), "www.attacker.example.");
    assert!(
        !names(chain).contains(&format!("{} RRSIG", question.name)),
        "a synthesised CNAME is never signed: {}",
        describe(&scrubbed)
    );
    assert_eq!(
        reason(&scrubbed, Section::Answer, response.answer.len() - 1),
        Some(Reason::OffChain)
    );
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

/// A server CNAME that is not the DNAME's goes with the signatures at its name (RFC 6672 §3.4); the signatures of
/// the DNAME and of the chain past it stay.
#[test]
fn rfc6672_3_4_a_replaced_cname_loses_its_signatures_alone() {
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
        .position(|r| r.rtype() == RecordType::CNAME && r.name == question.name)
        .expect("the server's CNAME");
    // Changed: the server's CNAME pointed at evil.dns.netmeister.org; the RRSIG of www.dns.netmeister.org's CNAME
    // copied as one of the name asked.
    response.answer[at] = rr("www.dname.dns.netmeister.org. 300 IN CNAME evil.dns.netmeister.org.");
    let sig = response
        .answer
        .iter()
        .find(|r| matches!(r.data(), RData::Rrsig(s) if s.type_covered == RecordType::CNAME))
        .expect("a CNAME's RRSIG");
    let sig = Record::new(question.name.clone(), sig.class, sig.ttl, &sig.data());
    response.answer.push(sig);
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Cname { chain, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    let chain = names(chain);
    for kept in [
        "dname.dns.netmeister.org. RRSIG",
        "www.dns.netmeister.org. RRSIG",
    ] {
        assert!(chain.iter().any(|n| n == kept), "{kept}: {chain:?}");
    }
    assert!(
        !chain.contains(&format!("{} RRSIG", question.name)),
        "{chain:?}"
    );
    for i in [at, response.answer.len() - 1] {
        assert_eq!(
            reason(&scrubbed, Section::Answer, i),
            Some(Reason::OffChain)
        );
    }
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

/// Only authoritative data from the zone's servers is trusted (RFC 2181 §5.4.1): a response without AA that is not
/// a referral is lame, RA set or not, NXDOMAIN included, where Unbound keeps it unless RA is set (D192). RA beside
/// AA changes nothing.
#[test]
fn rfc2181_5_4_1_an_answer_without_aa_is_lame() {
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    for ra in [false, true] {
        let mut response = decode(&bytes);
        // Changed: AA cleared; RA set or not.
        response.header.flags = response.header.flags.without(Flags::AA);
        if ra {
            response.header.flags = response.header.flags.with(Flags::RA);
        }
        let scrubbed = scrub(&response, &question, &zone);
        assert!(
            matches!(scrubbed.outcome, Outcome::Lame),
            "ra={ra}: {}",
            describe(&scrubbed)
        );
        assert_eq!(scrubbed.ranked().len(), 0);
        assert_eq!(scrubbed.dropped.len(), 0);
    }
    let mut response = decode(&bytes);
    // Changed: RA set; AA still set.
    response.header.flags = response.header.flags.with(Flags::RA);
    assert!(matches!(
        scrub(&response, &question, &zone).outcome,
        Outcome::Answer { .. }
    ));
    let (bytes, question, zone) = captured(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
        RecordType::A,
    );
    let mut response = decode(&bytes);
    // Changed: AA cleared from an NXDOMAIN.
    response.header.flags = response.header.flags.without(Flags::AA);
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::Lame),
        "{}",
        describe(&scrubbed)
    );
}

/// The com. servers' referral for google.com, as an answer without AA to google.com NS: no referral, which the
/// authority section carries (RFC 1034 §4.3.2 step 3b), and no authoritative answer, so lame (D192).
#[test]
fn rfc2181_5_4_1_ns_without_aa_in_the_answer_section_is_lame() {
    let (bytes, _, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    let ns = Question::new("google.com.".parse().expect("a name"), RecordType::NS);
    // Changed: the question made NS, and the NS records moved from the authority section to the answer section.
    response.questions = vec![ns.clone()];
    let (records, rest) = response
        .authority
        .drain(..)
        .partition(|r| r.rtype() == RecordType::NS);
    response.answer = records;
    response.authority = rest;
    let scrubbed = scrub(&response, &ns, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::Lame),
        "{}",
        describe(&scrubbed)
    );
}

/// A referral to the zone itself or above it leads nowhere, whatever AA says (RFC 4697 §2.2); with neither SOA nor
/// NS, a negative answer is not cached (RFC 2308 §5).
#[test]
fn rfc4697_2_2_a_referral_to_the_zone_or_above_is_lame_whatever_aa() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    for ns in [
        "com. 172800 IN NS a.gtld-servers.net.",
        ". 518400 IN NS a.root-servers.net.",
    ] {
        for aa in [false, true] {
            let mut response = decode(&bytes);
            // Changed: the authority section replaced by an NS record at com. or the root; AA set or not.
            response.authority = vec![rr(ns)];
            if aa {
                response.header.flags = response.header.flags.with(Flags::AA);
            }
            let scrubbed = scrub(&response, &question, &zone);
            assert!(
                matches!(scrubbed.outcome, Outcome::Lame),
                "{ns} aa={aa}: {}",
                describe(&scrubbed)
            );
        }
    }
    let mut response = decode(&bytes);
    // Changed: the authority section emptied, AA set.
    response.authority.clear();
    response.header.flags = response.header.flags.with(Flags::AA);
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::NoSoa(Negative::NoData)),
        "{}",
        describe(&scrubbed)
    );
}

/// A referral read from the records kept: an SOA outside the zone, or an answer outside it, makes no answer of it.
#[test]
fn rfc2181_6_1_records_outside_the_zone_do_not_change_a_referral() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: an SOA of example.net appended to the authority section, an A of www.example.net to the answer.
    response.authority.push(rr(
        "example.net. 300 IN SOA ns.example.net. hostmaster.example.net. 1 2 3 4 5",
    ));
    response
        .answer
        .push(rr("www.example.net. 300 IN A 192.0.2.66"));
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::Referral { .. }),
        "{}",
        describe(&scrubbed)
    );
}

/// The NS records of a zone beside its negative answer are dropped: they would replace the delegation the
/// resolver holds (CVE-2025-11411, Unbound's `iter-scrub-promiscuous`).
#[test]
fn rfc2308_2_ns_beside_a_negative_answer_is_dropped() {
    let ns = "google.com. 300 IN NS ns.attacker.example.";
    for (id, name, rtype) in [
        (
            "nxdomain-unsigned",
            "dedens-nxdomain.google.com.",
            RecordType::A,
        ),
        ("nodata-unsigned", "google.com.", RecordType::SRV),
    ] {
        let (bytes, question, zone) = captured(id, "google.com.", name, rtype);
        let mut response = decode(&bytes);
        // Changed: an NS record of google.com appended to the authority section.
        response.authority.push(rr(ns));
        let scrubbed = scrub(&response, &question, &zone);
        let (Outcome::NxDomain { soa, .. } | Outcome::NoData { soa, .. }) = &scrubbed.outcome
        else {
            panic!("{id}: {}", describe(&scrubbed));
        };
        assert_eq!(soa.rtype(), RecordType::SOA);
        assert_eq!(
            reason(&scrubbed, Section::Authority, response.authority.len() - 1),
            Some(Reason::NotAllowed)
        );
    }
}

/// The same negative answers without their SOA: their TTL is unknown, so nothing caches them (RFC 2308 §5).
#[test]
fn rfc2308_5_a_negative_answer_without_its_soa_is_not_cached() {
    for (id, name, rtype) in [
        (
            "nxdomain-unsigned",
            "dedens-nxdomain.google.com.",
            RecordType::A,
        ),
        ("nodata-unsigned", "google.com.", RecordType::SRV),
    ] {
        let (bytes, question, zone) = captured(id, "google.com.", name, rtype);
        let below: Name<'static> = format!("below.{name}").parse().expect("a name");
        for moved in [false, true] {
            let mut response = decode(&bytes);
            if moved {
                // Changed: the SOA's owner made a name below the name asked, not its zone's apex.
                for r in &mut response.authority {
                    if r.rtype() == RecordType::SOA {
                        r.name = below.clone();
                    }
                }
            } else {
                // Changed: the SOA removed from the authority section.
                response.authority.retain(|r| r.rtype() != RecordType::SOA);
            }
            let scrubbed = scrub(&response, &question, &zone);
            assert!(
                matches!(
                    scrubbed.outcome,
                    Outcome::NoSoa(Negative::NoData | Negative::NxDomain { .. })
                ),
                "{id} moved={moved}: {}",
                describe(&scrubbed)
            );
            assert_eq!(scrubbed.ranked().len(), 0);
        }
    }
}

/// RDATA that does not parse for its type is dropped (Unbound dfc00271d): a 3-byte address is no glue and no
/// answer.
#[test]
fn d9_malformed_rdata_is_dropped() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    let glue = response.additional.len();
    // Changed: a 3-byte A record for ns1.google.com appended to the additional section.
    response
        .additional
        .push(raw("ns1.google.com.", RecordType::A, &[192, 0, 2]));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Referral { glue: kept, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(kept.len(), glue);
    assert_eq!(
        reason(&scrubbed, Section::Additional, glue),
        Some(Reason::Malformed)
    );
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: a 3-byte A record for example.com put first in the answer section.
    response
        .answer
        .insert(0, raw("example.com.", RecordType::A, &[192, 0, 2]));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Answer { records, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert!(
        records
            .iter()
            .all(|r| !matches!(r.data(), RData::Opaque(_)))
    );
    assert_eq!(
        reason(&scrubbed, Section::Answer, 0),
        Some(Reason::Malformed)
    );
}

/// A DNAME's target is never compressed (RFC 6672 §2.5): one that is, and the CNAME the server made of it, which
/// nothing can check, are dropped.
#[test]
fn rfc6672_2_5_a_compressed_dname_is_dropped_with_its_cname() {
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
    let cname = response
        .answer
        .iter()
        .position(|r| r.rtype() == RecordType::CNAME && r.name == question.name)
        .expect("the server's CNAME");
    // Changed: the DNAME's target, dns.netmeister.org, written as `dns` and a pointer to offset 12, the question.
    response.answer[at] = raw(
        "dname.dns.netmeister.org.",
        RecordType::DNAME,
        &[3, b'd', b'n', b's', 0xC0, 12],
    );
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::NoSoa(Negative::NoData)),
        "{}",
        describe(&scrubbed)
    );
    assert_eq!(
        reason(&scrubbed, Section::Answer, at),
        Some(Reason::Malformed)
    );
    assert_eq!(
        reason(&scrubbed, Section::Answer, cname),
        Some(Reason::Malformed)
    );
}

/// The same DNAME to a target that makes the name asked longer than 255 bytes: the answer is YXDOMAIN with the
/// DNAME (RFC 6672 §2.2), whether the server says so or not; a YXDOMAIN without such a DNAME says nothing.
#[test]
fn rfc6672_2_2_an_over_long_synthesis_is_yxdomain() {
    let (bytes, question, zone) = captured(
        "dname",
        "dns.netmeister.org.",
        "www.dname.dns.netmeister.org.",
        RecordType::A,
    );
    let at = decode(&bytes)
        .answer
        .iter()
        .position(|r| r.rtype() == RecordType::DNAME)
        .expect("a DNAME");
    // A 253-byte target: www. makes 257.
    let long = format!("{0}.{0}.{0}.{1}.", "a".repeat(63), "b".repeat(59));
    for rcode in [Rcode::YXDOMAIN, Rcode::NOERROR] {
        let mut response = decode(&bytes);
        // Changed: the DNAME's target replaced by the long name; the response code set to `rcode`.
        response.answer[at] = dname("dname.dns.netmeister.org.", &long);
        response.set_rcode(rcode).expect("a code");
        let scrubbed = scrub(&response, &question, &zone);
        let Outcome::YxDomain { chain } = &scrubbed.outcome else {
            panic!("{rcode}: {}", describe(&scrubbed));
        };
        assert_eq!(
            names(chain),
            [
                "dname.dns.netmeister.org. DNAME",
                "dname.dns.netmeister.org. RRSIG"
            ]
        );
    }
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: the response code set to YXDOMAIN.
    response.set_rcode(Rcode::YXDOMAIN).expect("a code");
    assert!(matches!(
        scrub(&response, &question, &zone).outcome,
        Outcome::Unusable(Unusable::Rcode(Rcode::YXDOMAIN))
    ));
}

/// The com. servers' referral for example.com, as the answer to example.com DS: the DS records are the parent's
/// (RFC 4035 §3.1.4.1), so they are the answer, as in Unbound (6cb75924d); the child would deny them.
#[test]
fn rfc4035_3_1_4_1_a_referral_to_the_name_asked_for_its_ds_is_the_answer() {
    let (bytes, _, zone) = captured("signed-com", "com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    let ds = Question::new("example.com.".parse().expect("a name"), RecordType::DS);
    // Changed: the question made DS.
    response.questions = vec![ds.clone()];
    let scrubbed = scrub(&response, &ds, &zone);
    let Outcome::Answer { records, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(names(records), ["example.com. DS", "example.com. RRSIG"]);
    // The parent's authoritative data (RFC 4035 §2.3), though the referral is without AA.
    assert!(!response.header.flags.contains(Flags::AA));
    let ranked = scrubbed.ranked();
    let [(rank, set)] = ranked.as_slice() else {
        panic!("{ranked:?}");
    };
    assert_eq!(*rank, Rank::AnswerAuthoritative);
    assert_eq!((set.rtype(), set.rrsigs().len()), (RecordType::DS, 1));
}

/// sidn.nl's answer to sidn.nl RRSIG: signatures alone, which are not signed (RFC 4035 §2.2) and no `RRset` of
/// their own (D176), so the answer is `Signatures`, for the resolver to answer with and for no cache: grouping
/// them would lose them. Without them, the answer is a negative one, as for any type.
#[test]
fn rfc4035_2_2_an_rrsig_answer_is_answered_not_cached() {
    let (bytes, question, zone) = captured("rrsig", "sidn.nl.", "sidn.nl.", RecordType::RRSIG);
    let response = decode(&bytes);
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Signatures { chain, records } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert!(chain.is_empty(), "{}", describe(&scrubbed));
    assert_eq!(names(records), ["sidn.nl. RRSIG"]);
    assert!(scrubbed.dropped.is_empty(), "{}", describe(&scrubbed));
    // Nothing for the cache: grouping would lose the signatures.
    assert!(scrubbed.records().is_empty(), "{}", describe(&scrubbed));
    assert!(scrubbed.ranked().is_empty(), "{}", describe(&scrubbed));
    let mut response = decode(&bytes);
    // Changed: the answer section emptied.
    response.answer.clear();
    assert!(matches!(
        scrub(&response, &question, &zone).outcome,
        Outcome::NoSoa(Negative::NoData)
    ));
}

/// dns.netmeister.org's answer through its DNAME, as to www.dname.dns.netmeister.org RRSIG: the signatures at the
/// chain's end are the answer, the chain is for the cache at its ranks. A signed CNAME has an RRSIG at its own name,
/// which a server answers with, so only a DNAME's synthesised CNAME, unsigned, leads an RRSIG question on. No
/// capture holds one: netmeister.org's servers (Gandi) refuse RRSIG questions, so the resolution cannot reach
/// dns.netmeister.org's; its server answered one so on 2026-11-19 (`dig +norec +dnssec`, with an NSEC's RRSIG too).
#[test]
fn rfc4035_2_2_an_rrsig_answer_through_a_dname_is_answered_at_the_chain_end() {
    let (bytes, _, zone) = captured(
        "dname",
        "dns.netmeister.org.",
        "www.dname.dns.netmeister.org.",
        RecordType::A,
    );
    let mut response = decode(&bytes);
    let question = Question::new(
        "www.dname.dns.netmeister.org.".parse().expect("a name"),
        RecordType::RRSIG,
    );
    let end: Name<'static> = "www.dns.netmeister.org.".parse().expect("a name");
    // Changed: the question made RRSIG; the CNAME at www.dns.netmeister.org removed, its RRSIG kept: the server
    // answers an RRSIG question there with the RRSIGs, without following the CNAME.
    response.questions = vec![question.clone()];
    response
        .answer
        .retain(|r| !(r.rtype() == RecordType::CNAME && r.name == end));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Signatures { chain, records } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert!(scrubbed.dropped.is_empty(), "{}", describe(&scrubbed));
    assert_eq!(
        names(chain),
        [
            "dname.dns.netmeister.org. DNAME",
            "www.dname.dns.netmeister.org. CNAME",
            "dname.dns.netmeister.org. RRSIG",
        ]
    );
    assert_eq!(names(records), ["www.dns.netmeister.org. RRSIG"]);
    let ranked: Vec<_> = scrubbed
        .ranked()
        .into_iter()
        .map(|(rank, set)| (rank, set.rtype(), set.rrsigs().len()))
        .collect();
    assert_eq!(
        ranked,
        [
            (Rank::AnswerAuthoritative, RecordType::DNAME, 1),
            (Rank::AnswerAuthoritative, RecordType::CNAME, 0),
        ]
    );
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

/// A record of a QTYPE or meta type is no data (RFC 6895 §3.1): no `RRset` holds it, so the scrubber drops it rather
/// than rank what the cache would not take.
#[test]
fn rfc6895_3_1_a_qtype_or_meta_type_is_dropped() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let mut response = decode(&bytes);
    let added = response.additional.len();
    // Changed: a TKEY (249, meta) and an ANY (255, QTYPE) at ns1.google.com, appended.
    response
        .additional
        .push(raw("ns1.google.com.", RecordType::from(249), b""));
    response
        .additional
        .push(raw("ns1.google.com.", RecordType::ANY, b""));
    let scrubbed = scrub(&response, &question, &zone);
    assert!(
        matches!(scrubbed.outcome, Outcome::Referral { .. }),
        "{}",
        describe(&scrubbed)
    );
    for i in added..added + 2 {
        assert_eq!(
            reason(&scrubbed, Section::Additional, i),
            Some(Reason::NotData),
            "{i}"
        );
    }
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
        Some(Reason::TooManyRecords)
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
    let Outcome::Answer { denials, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert!(names(denials).iter().all(|n| !n.ends_with(" SOA")));
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
        target, denials, ..
    } = &scrubbed.outcome
    else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(target.to_string(), "www.example.com.");
    assert!(names(denials).iter().all(|n| !n.ends_with(" SOA")));
    let last = response.authority.len() - 1;
    assert_eq!(
        reason(&scrubbed, Section::Authority, last),
        Some(Reason::NotAllowed)
    );
}

/// The ranks of RFC 2181 §5.4.1: a referral's records are the non-authoritative authority and additional data; an
/// answer's chain is authoritative at the name asked and at the owner of its first record, a DNAME, as Unbound ranks
/// it (RFC 1035 §4.1.1); an authoritative answer's additional data is ranked authoritative additional data, its
/// authority data (a negative answer's SOA and denials, an answer's wildcard proof) authoritative authority data.
#[test]
fn rfc2181_5_4_1_ranks_follow_section_and_aa() {
    let (bytes, question, zone) = captured("unsigned", "com.", "google.com.", RecordType::A);
    let response = decode(&bytes);
    let ranks: Vec<_> = scrub(&response, &question, &zone)
        .ranked()
        .into_iter()
        .map(|(rank, set)| (rank, set.rtype()))
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
    let dname: Name<'_> = "dname.dns.netmeister.org.".parse().expect("a name");
    for (rank, set) in scrubbed.ranked() {
        let expected = if *set.owner() == question.name || *set.owner() == dname {
            Rank::AnswerAuthoritative
        } else {
            Rank::AnswerNonAuthoritative
        };
        assert_eq!(rank, expected, "{} {}", set.owner(), set.rtype());
    }
    let (bytes, question, zone) = captured("priming", ".", ".", RecordType::NS);
    let response = decode(&bytes);
    let ranks: Vec<_> = scrub(&response, &question, &zone)
        .ranked()
        .into_iter()
        .map(|(rank, set)| (rank, set.rtype()))
        .collect();
    assert!(
        ranks.contains(&(Rank::AnswerAuthoritative, RecordType::NS)),
        "{ranks:?}"
    );
    assert!(
        ranks.contains(&(Rank::AdditionalAuthoritative, RecordType::AAAA)),
        "{ranks:?}"
    );
    // An authoritative response's authority section: a negative answer's SOA and denials.
    for (id, name, rtype) in [
        ("nxdomain-signed", "dedens-nxdomain.sidn.nl.", RecordType::A),
        ("nodata-signed", "sidn.nl.", RecordType::SRV),
    ] {
        let (bytes, question, zone) = captured(id, "sidn.nl.", name, rtype);
        let response = decode(&bytes);
        let ranks: Vec<_> = scrub(&response, &question, &zone)
            .ranked()
            .into_iter()
            .map(|(rank, set)| (rank, set.rtype()))
            .collect();
        for rtype in [RecordType::SOA, RecordType::NSEC] {
            assert!(
                ranks.contains(&(Rank::AuthorityAuthoritative, rtype)),
                "{id}: {ranks:?}"
            );
        }
        assert!(
            ranks
                .iter()
                .all(|(rank, _)| *rank == Rank::AuthorityAuthoritative),
            "{id}: {ranks:?}"
        );
    }
    // And an answer's: its wildcard proof.
    let (bytes, question, zone) =
        captured("signed-com", "example.com.", "example.com.", RecordType::A);
    let mut response = decode(&bytes);
    // Changed: an NSEC of example.com appended to the authority section, as a wildcard expansion's proof.
    response.authority.push(rr(
        "example.com. 300 IN NSEC www.example.com. A NS SOA RRSIG NSEC DNSKEY",
    ));
    let scrubbed = scrub(&response, &question, &zone);
    let Outcome::Answer { denials, .. } = &scrubbed.outcome else {
        panic!("{}", describe(&scrubbed));
    };
    assert_eq!(names(denials), ["example.com. NSEC"]);
    let ranks: Vec<_> = scrubbed
        .ranked()
        .into_iter()
        .map(|(rank, set)| (rank, set.rtype()))
        .collect();
    assert_eq!(
        ranks,
        [
            (Rank::AnswerAuthoritative, RecordType::A),
            (Rank::AuthorityAuthoritative, RecordType::NSEC)
        ]
    );
}
