//! The answers of pre-signed zones with DO (D209): the example responses of RFC 4035 Appendix B and RFC 5155
//! Appendix B, from the zones of their Appendix A (RFC 4035 §3.1, RFC 5155 §7.2); every answer to the captured
//! questions of `testdata/authoritative/` accepted by the validator of `dedens-dnssec` (RFC 4035 §5), among them the
//! NSEC3 zone Knot signed with ECDSA P-256 (RFC 5155 §7.2); the proof of every negative or wildcard answer checked by
//! `denial::prove` (RFC 4035 §5.4, RFC 5155 §8); and two properties of every answer: without DO it is the answer with
//! DO less the DNSSEC records, and with DO each `RRset` has its signature (RFC 4035 §3.1.1).

use std::collections::BTreeSet;
use std::fs;

use dedens_dnssec::crypto::{Budget, Nsec3Blocks, Verifications};
use dedens_dnssec::denial::{self, Fact, MaxIterations};
use dedens_dnssec::{
    Delegation, InsecureReason, Limits as ValidatorLimits, Next, TrustAnchors, Validator, Verdict,
};
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Flags, Header, MAX_MESSAGE_LEN, Message, Name, Question, Rcode, Record, RecordType, Ttl,
    ZoneEntry, ZoneReader,
};
use dedens_testkit::authoritative::Answers;
use dedens_testkit::{dns, message};
use dedens_zone::{Dnssec, End, Limits, Zone};
use proptest::prelude::*;

use crate::util::{load_files, zone_file};

/// A zone of `testdata/zones/`.
fn zone(origin: &str, file: &str) -> Zone {
    load_files(origin, &zone_file(file), None, &[], &Limits::default())
        .expect("a valid zone")
        .zone
}

/// The zone of RFC 4035 Appendix A, signed with RSA/SHA-1 keys of 1024 bits.
fn rfc4035() -> Zone {
    zone("example.", "rfc4035_appendix_a.zone")
}

/// The zone of RFC 5155 Appendix A, whose keys of 512 bits no validator takes (D71): its proofs are checked by
/// `denial::prove` alone.
fn rfc5155() -> Zone {
    zone("example.", "rfc5155_appendix_a.zone")
}

/// The response to `question` with DO, through the wire.
fn respond(zone: &Zone, question: &Question<'_>) -> Message<'static> {
    respond_as(zone, question, Dnssec::With)
}

/// The response to `question` with or without DO, through the wire.
fn respond_as(zone: &Zone, question: &Question<'_>, dnssec: Dnssec) -> Message<'static> {
    let answer = zone.answer(question);
    let mut response = Message {
        header: Header {
            flags: Flags::QR,
            ..Header::default()
        },
        questions: vec![question.clone()],
        edns: Some(Edns {
            flags: if dnssec == Dnssec::With {
                EdnsFlags::DO
            } else {
                EdnsFlags::default()
            },
            ..Edns::default()
        }),
        ..Message::default()
    };
    let glue = answer.fill(zone, &mut response, MAX_MESSAGE_LEN, dnssec);
    let mut buf = vec![0; MAX_MESSAGE_LEN];
    let len = glue.encode(&response, &mut buf).expect("encodes");
    message(&buf[..len])
}

/// A response as an RFC prints it: its header, question and sections, each record as zone text.
#[derive(Debug)]
struct Printed {
    aa: bool,
    rcode: Rcode,
    question: Question<'static>,
    sections: [BTreeSet<String>; 3],
}

/// The text of RFC `number` from `docs/rfc/archive/`.
fn rfc_text(number: u16) -> String {
    fs::read_to_string(format!(
        "{}/../../docs/rfc/archive/rfc{number}.txt",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("an RFC of the archive")
}

/// The example response under `heading` of RFC `number`'s Appendix B, without the page breaks.
fn printed(number: u16, heading: &str) -> Printed {
    // RFC 5155 B.6 leaves out the parenthesis its RRSIG continues in.
    let text = rfc_text(number).replace("RRSIG NSEC3 7 2 3600\n", "RRSIG NSEC3 7 2 3600 (\n");
    let start = text.find(&format!("\n{heading}\n")).expect("the heading") + heading.len() + 2;
    let rest = &text[start..];
    let end = ["\nB.", "\nAppendix "]
        .iter()
        .filter_map(|next| rest.find(next))
        .min()
        .unwrap_or(rest.len());
    let lines: Vec<&str> = rest[..end]
        .lines()
        .filter(|line| {
            !(line.contains("[Page ") || line.starts_with("RFC ") || line.contains('\u{c}'))
        })
        .collect();
    let header = lines
        .iter()
        .find(|line| line.contains(";; Header:"))
        .expect("a header");
    let rcode = if header.ends_with("RCODE=3") {
        Rcode::NXDOMAIN
    } else {
        assert!(header.ends_with("RCODE=0"), "{header}");
        Rcode::NOERROR
    };
    let asked = lines
        .iter()
        .skip_while(|line| !line.contains(";; Question"))
        .nth(1)
        .expect("a question");
    let fields: Vec<&str> = asked.split_whitespace().collect();
    let question = Question::new(dns(fields[0]), fields[2].parse().expect("a type"));
    // The lines of each section, from the marker before them, without the indent of the RFC's text: up to three
    // spaces before a record, more before the lines a parenthesis continues. The response ends at the prose that
    // explains it: outside parentheses, an unindented line neither a comment nor a record of an owner.
    let mut texts: [Vec<&str>; 3] = Default::default();
    let mut current = None;
    let mut depth = 0_usize;
    for line in &lines {
        let indent = line.len() - line.trim_start().len();
        let first = line.split_whitespace().next().unwrap_or(";");
        let record = first.starts_with(';') || first.ends_with('.') || indent > 3;
        if current.is_some() && depth == 0 && !record {
            break;
        }
        depth = (depth + line.matches('(').count()).saturating_sub(line.matches(')').count());
        for (at, marker) in [";; Answer", ";; Authority", ";; Additional"]
            .iter()
            .enumerate()
        {
            if line.trim_start().starts_with(marker) {
                current = Some(at);
            }
        }
        if let Some(at) = current {
            texts[at].push(if indent < 4 { line.trim_start() } else { line });
        }
    }
    let sections = texts.map(|text| {
        records(&text.join("\n"))
            .iter()
            .map(ToString::to_string)
            .collect()
    });
    Printed {
        aa: header.split_whitespace().any(|flag| flag == "AA"),
        rcode,
        question,
        sections,
    }
}

/// The records of zone `text`, at the `$TTL` of the RFCs' zones where it has none, as RFC 5155 prints them.
fn records(text: &str) -> Vec<Record<'static>> {
    ZoneReader::new(text.as_bytes(), None)
        .with_ttl(Ttl::new(3600).expect("a TTL"))
        .filter_map(|entry| match entry.expect("records of the RFC") {
            ZoneEntry::Record(decoded) => Some(decoded.record.into_owned()),
            _ => None,
        })
        .collect()
}

/// The records of `message`'s sections as zone text.
fn sections(message: &Message<'_>) -> [BTreeSet<String>; 3] {
    [&message.answer, &message.authority, &message.additional]
        .map(|section| section.iter().map(ToString::to_string).collect())
}

/// Leaves out of a positive `printed` response the apex NS its authority section has, with its signatures and
/// the addresses of its servers that only it asks for: D203's first difference, dedens answering as Knot.
fn without_apex_ns(printed: &mut Printed, apex: &str) {
    if printed.sections[0].is_empty() {
        return;
    }
    let records = |text: &BTreeSet<String>| {
        records(
            &text
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };
    let hosts = |records: &[Record<'static>]| -> Vec<Name<'static>> {
        records
            .iter()
            .filter_map(|record| match record.data() {
                RData::Ns(name) => Some(name.into_owned()),
                RData::Mx(mx) => Some(mx.exchange.into_owned()),
                _ => None,
            })
            .collect()
    };
    let authority = records(&printed.sections[1]);
    let answered = hosts(&records(&printed.sections[0]));
    let apex = dns(apex);
    let apex_ns = |record: &Record<'_>| {
        record.name == apex
            && match record.data() {
                RData::Ns(_) => true,
                RData::Rrsig(rrsig) => rrsig.type_covered == RecordType::NS,
                _ => false,
            }
    };
    let servers: Vec<Name<'static>> = hosts(&authority)
        .into_iter()
        .filter(|server| !answered.contains(server))
        .collect();
    printed.sections[1] = authority
        .iter()
        .filter(|record| !apex_ns(record))
        .map(ToString::to_string)
        .collect();
    printed.sections[2] = records(&printed.sections[2])
        .iter()
        .filter(|record| !servers.contains(&record.name))
        .map(ToString::to_string)
        .collect();
}

/// Asks `zone` the question of the example under `heading` of RFC `number` and compares the response with it.
fn reproduces(zone: &Zone, number: u16, heading: &str) {
    let mut printed = printed(number, heading);
    without_apex_ns(&mut printed, "example.");
    let ours = respond(zone, &printed.question);
    let key = format!("RFC {number} {heading}");
    assert_eq!(ours.rcode(), printed.rcode, "{key}");
    assert_eq!(ours.header.flags.contains(Flags::AA), printed.aa, "{key}");
    let ours = sections(&ours);
    for (at, name) in ["answer", "authority", "additional"].iter().enumerate() {
        assert_eq!(ours[at], printed.sections[at], "{key}: {name}");
    }
}

#[test]
fn rfc4035_b_1_an_answer_has_the_signatures_of_its_rrsets_and_of_its_addresses() {
    reproduces(&rfc4035(), 4035, "B.1.  Answer");
}

#[test]
fn rfc4035_b_2_a_name_error_proves_the_name_and_its_wildcard_absent() {
    reproduces(&rfc4035(), 4035, "B.2.  Name Error");
}

#[test]
fn rfc4035_b_3_no_data_has_the_nsec_of_the_name() {
    reproduces(&rfc4035(), 4035, "B.3.  No Data Error");
}

#[test]
fn rfc4035_b_4_a_referral_to_a_signed_zone_has_its_ds() {
    reproduces(&rfc4035(), 4035, "B.4.  Referral to Signed Zone");
}

#[test]
fn rfc4035_b_5_a_referral_to_an_unsigned_zone_has_the_nsec_of_the_delegation() {
    reproduces(&rfc4035(), 4035, "B.5.  Referral to Unsigned Zone");
}

#[test]
fn rfc4035_b_6_a_wildcard_answer_proves_the_name_absent() {
    reproduces(&rfc4035(), 4035, "B.6.  Wildcard Expansion");
}

#[test]
fn rfc4035_b_7_wildcard_no_data_proves_the_name_absent_and_the_type_at_the_wildcard() {
    reproduces(&rfc4035(), 4035, "B.7.  Wildcard No Data Error");
}

#[test]
fn rfc4035_b_8_ds_at_the_apex_is_no_data() {
    reproduces(&rfc4035(), 4035, "B.8.  DS Child Zone No Data Error");
}

#[test]
fn rfc5155_b_1_a_name_error_has_the_closest_encloser_proof_and_the_wildcard_s() {
    reproduces(&rfc5155(), 5155, "B.1.  Name Error");
}

#[test]
fn rfc5155_b_2_no_data_has_the_nsec3_of_the_name() {
    reproduces(&rfc5155(), 5155, "B.2.  No Data Error");
}

#[test]
fn rfc5155_b_2_1_no_data_at_an_empty_non_terminal_has_its_nsec3() {
    reproduces(
        &rfc5155(),
        5155,
        "B.2.1.  No Data Error, Empty Non-Terminal",
    );
}

#[test]
fn rfc5155_b_3_a_referral_under_opt_out_has_the_closest_provable_encloser_proof() {
    reproduces(
        &rfc5155(),
        5155,
        "B.3.  Referral to an Opt-Out Unsigned Zone",
    );
}

#[test]
fn rfc5155_b_4_a_wildcard_answer_covers_the_next_closer_name() {
    reproduces(&rfc5155(), 5155, "B.4.  Wildcard Expansion");
}

#[test]
fn rfc5155_b_5_wildcard_no_data_has_the_nsec3_of_the_wildcard() {
    reproduces(&rfc5155(), 5155, "B.5.  Wildcard No Data Error");
}

#[test]
fn rfc5155_b_6_ds_at_the_apex_is_no_data() {
    reproduces(&rfc5155(), 5155, "B.6.  DS Child Zone No Data Error");
}

#[test]
fn rfc5155_s4_the_records_of_another_chain_prove_nothing() {
    // A chain being made beside the served one: same algorithm and salt, other iterations. Its record sorts
    // between 0p9mhaveq…, the cover of B.1's next closer name, and that name's hash 0va5bpr2…; the NSEC3PARAM
    // names the chain to serve (RFC 5155 §4): the load checks that one alone, and B.1 is still the answer.
    let text = zone_file("rfc5155_appendix_a.zone")
        + "0q000000000000000000000000000000.example. 3600 IN NSEC3 1 1 5 aabbccdd \
           0q000000000000000000000000000000\n";
    let zone = load_files("example.", &text, None, &[], &Limits::default())
        .expect("the served chain closed")
        .zone;
    reproduces(&zone, 5155, "B.1.  Name Error");
}

/// What the NSEC or NSEC3 records of `response` prove about it, from `denial::prove`; `None` for a response that
/// needs no proof: a positive answer of no wildcard, or a referral to a signed child.
fn proven(apex: &Name<'_>, response: &Message<'_>) -> Option<Result<Fact, denial::Unproven>> {
    let question = response.questions.first().expect("a question");
    let mut budget = Budget::new(Verifications(u32::MAX), Nsec3Blocks(u32::MAX));
    let max = MaxIterations::default();
    let records = &response.authority;
    // The name the answer ends at: past the CNAMEs of its chain.
    let mut name = question.name.clone();
    for record in &response.answer {
        if let (true, RData::Cname(target)) = (record.name == name, record.data()) {
            name = target.into_owned();
        }
    }
    let referral = !response.header.flags.contains(Flags::AA);
    if referral {
        let cut = response.referral()?;
        let signed = records
            .iter()
            .any(|record| record.rtype() == RecordType::DS);
        let ds = Question::new(cut.clone(), RecordType::DS);
        return (!signed)
            .then(|| denial::prove(apex, &ds, records, max, &mut budget).map(|p| p.fact));
    }
    let expanded = response
        .answer
        .iter()
        .find_map(|record| match record.data() {
            // The labels of a wildcard's own signature leave out its `*` (RFC 4034 §3.1.3).
            RData::Rrsig(rrsig)
                if usize::from(rrsig.labels) < record.name.label_count()
                    && record.name.labels().next() != Some(b"*".as_slice()) =>
            {
                Some((record.name.clone(), rrsig.labels))
            }
            _ => None,
        });
    let negative = !response.answer.iter().any(|record| {
        record.name == name
            && record.rtype() != RecordType::RRSIG
            && record.rtype() != RecordType::CNAME
    }) && response
        .authority
        .iter()
        .any(|record| record.rtype() == RecordType::SOA);
    // DS at the apex is denied by the zone itself, which only the parent's records can prove (RFC 4035 §3.1.4.1).
    let apex_ds = question.qtype == RecordType::DS && name == *apex;
    if negative && name.is_within(apex) && !apex_ds {
        let question = Question::new(name, question.qtype);
        return Some(denial::prove(apex, &question, records, max, &mut budget).map(|p| p.fact));
    }
    let (owner, labels) = expanded?;
    Some(
        denial::prove_wildcard_answer(apex, &owner, labels, records, max, &mut budget)
            .map(|p| p.fact),
    )
}

/// Every name of `zone` and names below them that it lacks, with each type a zone of the RFCs has: the questions
/// a property test draws from.
fn names(zone: &Zone) -> Vec<Name<'static>> {
    zone.nodes().map(|(name, _)| name.clone()).collect()
}

const TYPES: [RecordType; 9] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::MX,
    RecordType::NS,
    RecordType::DS,
    RecordType::NSEC,
    RecordType::NSEC3,
    RecordType::SOA,
    RecordType::TXT,
];

/// Whether a record of `response`, in the answer section or not, is one DO adds: a signature, an NSEC or NSEC3 of a
/// proof, the DS of a referral. The type the question asked for is its data, in the answer.
fn is_dnssec(
    record: &Record<'_>,
    in_answer: bool,
    data: Option<RecordType>,
    referral: bool,
) -> bool {
    let rtype = record.rtype();
    let added = matches!(
        rtype,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    ) || (referral && !in_answer && rtype == RecordType::DS);
    added && !(in_answer && data == Some(rtype))
}

/// D209, the first property: the response without DO is the one with DO less the records DO adds, section by
/// section, in order.
fn check_do_off(zone: &Zone, question: &Question<'_>) -> Result<(), TestCaseError> {
    let with = respond(zone, question);
    let without = respond_as(zone, question, Dnssec::Without);
    let answer = zone.answer(question);
    let data = match answer.end {
        End::Data { rtype, .. } => Some(rtype),
        _ => None,
    };
    let referral = matches!(answer.end, End::Referral { .. });
    let kept = |records: &[Record<'static>], in_answer| -> Vec<Record<'static>> {
        let kept = records.iter();
        kept.filter(|r| !is_dnssec(r, in_answer, data, referral))
            .cloned()
            .collect()
    };
    prop_assert_eq!(without.header.flags, with.header.flags, "{:?}", question);
    prop_assert_eq!(without.rcode(), with.rcode(), "{:?}", question);
    prop_assert_eq!(&without.answer, &kept(&with.answer, true), "{:?}", question);
    prop_assert_eq!(
        &without.authority,
        &kept(&with.authority, false),
        "{:?}",
        question
    );
    prop_assert_eq!(
        &without.additional,
        &kept(&with.additional, false),
        "{:?}",
        question
    );
    Ok(())
}

/// D209, the second property: under DO every `RRset` of the answer and authority sections has its signatures,
/// but the NS of a referral, which is the child's to sign, and the CNAME a DNAME makes up, whose signature is the
/// DNAME's (RFC 4035 §3.1.1, §3.1.4, RFC 6672 §5.3.1). Glue is in the additional section, signed or not.
fn check_signed_sets(response: &Message<'_>) -> Result<(), TestCaseError> {
    let referral = !response.header.flags.contains(Flags::AA);
    for (records, in_answer) in [(&response.answer, true), (&response.authority, false)] {
        for record in records {
            let rtype = record.rtype();
            if rtype == RecordType::RRSIG {
                continue;
            }
            let made_up = rtype == RecordType::CNAME
                && in_answer
                && response.answer.iter().any(|d| {
                    d.rtype() == RecordType::DNAME
                        && record.name != d.name
                        && record.name.is_within(&d.name)
                });
            let child_ns = referral && !in_answer && rtype == RecordType::NS;
            let signed = records.iter().any(|s| {
                matches!(s.data(), RData::Rrsig(sig) if sig.type_covered == rtype)
                    && s.name == record.name
            });
            prop_assert!(
                signed || made_up || child_ns,
                "{record:?} has no RRSIG\n{response:?}"
            );
        }
    }
    Ok(())
}

/// Checks the proof and the two DO properties of the response of `zone` to `name` and `rtype`.
fn check_proof(zone: &Zone, name: Name<'static>, rtype: RecordType) -> Result<(), TestCaseError> {
    let question = Question::new(name, rtype);
    let response = respond(zone, &question);
    if let Some(proof) = proven(zone.apex(), &response) {
        prop_assert!(proof.is_ok(), "{question:?}: {proof:?}\n{response:?}");
    }
    check_do_off(zone, &question)?;
    check_signed_sets(&response)
}

proptest! {
    #[test]
    fn rfc4035_s3_1_3_every_negative_and_wildcard_answer_of_nsec_is_proven(
        owner in any::<prop::sample::Index>(),
        below in prop::collection::vec(prop::sample::select(vec!["a", "z", "w", "dedens-wild"]), 0..3),
        rtype in prop::sample::select(TYPES.to_vec()),
    ) {
        let zone = rfc4035();
        check_proof(&zone, below_of(&names(&zone), owner, &below), rtype)?;
    }

    #[test]
    fn rfc5155_s7_2_every_negative_and_wildcard_answer_of_nsec3_is_proven(
        owner in any::<prop::sample::Index>(),
        below in prop::collection::vec(prop::sample::select(vec!["a", "z", "w", "dedens-wild"]), 0..3),
        rtype in prop::sample::select(TYPES.to_vec()),
    ) {
        let zone = rfc5155();
        check_proof(&zone, below_of(&names(&zone), owner, &below), rtype)?;
    }
}

/// The name of `names` at `owner` with `below` before it.
fn below_of(names: &[Name<'static>], owner: prop::sample::Index, below: &[&str]) -> Name<'static> {
    let name = owner.get(names);
    let prefix = below
        .iter()
        .fold(String::new(), |prefix, label| prefix + label + ".");
    dns(&format!("{prefix}{name}"))
}

/// The verdict of the validator on `response`, the zone's own answers to what it asks, at `now`.
fn verdict(validator: &Validator, zone: &Zone, response: &Message<'_>, now: u64) -> Verdict {
    let question = response.questions.first().expect("a question");
    let referral = !response.header.flags.contains(Flags::AA) && response.referral().is_some();
    let mut validation = if referral {
        validator.start_referral(question, response, now)
    } else {
        validator.start(question, response, now)
    };
    let mut asks = 0;
    loop {
        match validation.step() {
            Next::Ask(ask) => {
                asks += 1;
                assert!(asks < 64, "asks without end");
                let asked = ask.name.is_within(zone.apex()).then(|| respond(zone, &ask));
                validation.answer(asked.as_ref());
            }
            Next::Done(verdict) => return verdict,
        }
    }
}

/// Whether `verdict` accepts the response: secure, a referral to a child signed as its DS says, an answer of
/// RRSIG records, which are not signed (RFC 4035 §3.1.5), or a proof by an opt-out NSEC3 span whose signatures the
/// validator checked: it can only call the name insecure (RFC 5155 §6, §9.2).
fn accepted(verdict: &Verdict, response: &Message<'_>) -> bool {
    let signed = response
        .authority
        .iter()
        .any(|record| record.rtype() == RecordType::DS);
    match verdict {
        Verdict::Secure { .. }
        | Verdict::Insecure {
            reason: InsecureReason::RrsigQuery | InsecureReason::OptOut,
        } => true,
        Verdict::Referral { delegation, .. } => (*delegation == Delegation::Signed) == signed,
        _ => false,
    }
}

/// The validator of a zone whose anchor is its own DNSKEY `RRset`.
fn anchored(zone: &Zone) -> Validator {
    let apex = zone.node(zone.apex()).expect("the apex");
    let keys = apex.rrset(RecordType::DNSKEY).expect("the keys");
    let text: Vec<String> = keys
        .rdatas()
        .iter()
        .map(|rdata| format!("{} DNSKEY {}", zone.apex(), rdata))
        .collect();
    let anchors = TrustAnchors::read(&text.join("\n")).expect("anchor text");
    Validator::new(anchors, ValidatorLimits::default())
}

/// 2004-04-20, when the signatures of RFC 4035 Appendix A are valid (2004-04-09 to 2004-05-09).
const RFC4035_SIGNED: u64 = 1_082_419_200;

#[test]
fn rfc4035_s5_the_validator_accepts_every_answer_to_the_captured_questions() {
    let answers = Answers::read("rfc4035_appendix_a");
    let zone = rfc4035();
    let validator = anchored(&zone);
    let mut checked = 0;
    for reference in answers.answers.iter().filter(|r| r.dnssec_ok) {
        let question = &reference.query().questions[0];
        if !question.name.is_within(zone.apex()) {
            continue;
        }
        let response = respond(&zone, question);
        let verdict = verdict(&validator, &zone, &response, RFC4035_SIGNED);
        assert!(accepted(&verdict, &response), "{verdict:?}\n{response:?}");
        checked += 1;
    }
    assert!(checked > 50, "{checked}");
}

#[test]
fn rfc4035_s5_the_validator_accepts_every_answer_of_the_root_zone_to_the_captured_questions() {
    let answers = Answers::read("root");
    let zone = zone(".", "../authoritative/zones/root.zone");
    let validator = Validator::new(TrustAnchors::root(), ValidatorLimits::default());
    let mut checked = 0;
    for reference in answers.answers.iter().filter(|r| r.dnssec_ok) {
        let question = &reference.query().questions[0];
        if !question.name.is_within(zone.apex()) {
            continue;
        }
        let response = respond(&zone, question);
        let verdict = verdict(&validator, &zone, &response, answers.captured_at);
        assert!(accepted(&verdict, &response), "{verdict:?}\n{response:?}");
        checked += 1;
    }
    assert!(checked > 20, "{checked}");
}

/// 2026-05-28 20:26:40 UTC, the time `just capture-signed` told Knot's signer it was: the signatures of
/// `nsec3_signed.zone` start 90 minutes before and end 14 days after it.
const NSEC3_SIGNED: u64 = 1_780_000_000;

#[test]
fn rfc5155_s7_2_the_validator_accepts_every_answer_of_an_nsec3_zone_signed_by_knot_to_the_captured_questions()
 {
    let answers = Answers::read("nsec3_signed");
    let zone = zone("example.", "../authoritative/zones/nsec3_signed.zone");
    let validator = anchored(&zone);
    let (mut checked, mut secure) = (0, 0);
    for reference in answers.answers.iter().filter(|r| r.dnssec_ok) {
        let question = &reference.query().questions[0];
        if !question.name.is_within(zone.apex()) {
            continue;
        }
        let response = respond(&zone, question);
        let verdict = verdict(&validator, &zone, &response, NSEC3_SIGNED);
        assert!(accepted(&verdict, &response), "{verdict:?}\n{response:?}");
        checked += 1;
        secure += usize::from(matches!(verdict, Verdict::Secure { .. }));
    }
    assert!(checked > 50, "{checked}");
    assert!(secure > 30, "{secure} of {checked}");
}

#[test]
fn rfc5155_s7_2_every_answer_to_the_captured_questions_is_proven() {
    for id in [
        "rfc4035_appendix_a",
        "rfc5155_appendix_a",
        "root",
        "nsec3_signed",
    ] {
        let answers = Answers::read(id);
        let file = answers
            .file
            .strip_prefix("zones/")
            .map_or_else(|| format!("../{}", answers.file), str::to_owned);
        let zone = zone(&answers.zone.to_string(), &file);
        for reference in answers.answers.iter().filter(|r| r.dnssec_ok) {
            let response = respond(&zone, &reference.query().questions[0]);
            if let Some(proof) = proven(zone.apex(), &response) {
                assert!(proof.is_ok(), "{id}: {proof:?}\n{response:?}");
            }
        }
    }
}
