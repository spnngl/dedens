//! The captures of `testdata/authoritative/` (D203): each recording and reference answer decodes with
//! `dedens-proto`, and the transfers and answers show what their READMEs say. The captures implement no RFC: the
//! rows of `docs/rfc/coverage.md` name the tests of the later steps that check the server against them.

use std::collections::BTreeSet;

use dedens_proto::rdata::RData;
use dedens_proto::{
    DecodeErrorKind, Flags, Message, Opcode, Record, RecordType, Section, Violation,
};
use dedens_testkit::authoritative::{
    Answers, Peer, QUERY_ID, Recording, Reference, Server, Transport, zone,
};
use dedens_testkit::message;

/// `wire` decoded. An UPDATE (RFC 2136 §2) has records of class ANY or NONE with no RDATA in its prerequisite and
/// update sections, which `dedens-proto` reads as invalid RDATA of their type, or, for a type whose RDATA is a name
/// (NS), not at all: `None`. Nothing else may be wrong. Step 14 reads UPDATE with its own parser.
fn decode(wire: &[u8]) -> Option<Message<'static>> {
    let decoded = match Message::decode(wire) {
        Ok(decoded) => decoded,
        Err(error) => {
            let update = wire.get(2).is_some_and(|byte| (byte >> 3) & 0xF == 5);
            assert!(
                update && matches!(error.kind, DecodeErrorKind::RdataLength),
                "{error}"
            );
            return None;
        }
    };
    let update = decoded.message.header.opcode == Opcode::UPDATE;
    for violation in &decoded.violations {
        assert!(
            update
                && matches!(
                    violation,
                    Violation::InvalidRdata {
                        section: Section::Answer | Section::Authority,
                        ..
                    }
                ),
            "{violation}"
        );
    }
    Some(decoded.message.into_owned())
}

/// The messages the server sent, in order.
fn responses(recording: &Recording) -> Vec<Message<'static>> {
    recording
        .messages
        .iter()
        .filter(|packet| packet.from == Peer::Server)
        .filter_map(|packet| decode(&packet.message))
        .collect()
}

/// The answer records of the response messages, in order.
fn transferred(responses: &[Message<'static>]) -> Vec<Record<'static>> {
    responses
        .iter()
        .flat_map(|response| response.answer.iter().cloned())
        .collect()
}

/// The serial of an SOA record.
fn serial(record: &Record<'_>) -> Option<u32> {
    match record.data() {
        RData::Soa(soa) => Some(soa.serial),
        _ => None,
    }
}

#[test]
fn every_message_of_a_recording_decodes() {
    let ids = Recording::ids();
    assert!(ids.len() >= 40, "the scenarios of the README: {ids:?}");
    for id in ids {
        let recording = Recording::read(&id);
        assert!(!recording.messages.is_empty(), "{id}");
        for packet in &recording.messages {
            let _ = decode(&packet.message);
        }
    }
}

#[test]
fn the_axfr_of_the_root_zone_is_the_zone_file() {
    let recording = Recording::read("axfr-root");
    let answers = transferred(&responses(&recording));
    let (last, records) = answers.split_last().expect("records");
    assert_eq!(records.first().map(Record::rtype), Some(RecordType::SOA));
    assert_eq!(
        Some(last),
        records.first(),
        "ends where it began (RFC 5936 §2.2)"
    );
    assert_eq!(records, zone("root.zone").as_slice());
}

#[test]
fn the_axfr_of_zonetransfer_me_is_the_zone_file() {
    let recording = Recording::read("axfr-zonetransfer.me");
    let answers = transferred(&responses(&recording));
    let (_, records) = answers.split_last().expect("records");
    assert_eq!(records, zone("zonetransfer.me.zone").as_slice());
}

#[test]
fn the_ixfr_of_the_root_zone_goes_from_the_previous_zone_to_the_current_one() {
    let recording = Recording::read("root-ixfr");
    let answers = transferred(&responses(&recording));
    let serials: Vec<u32> = answers.iter().filter_map(serial).collect();
    let previous = serial(&zone("root-previous.zone")[0]).expect("an SOA");
    let current = serial(&zone("root.zone")[0]).expect("an SOA");
    // RFC 1995 §4: the new SOA, the old one, the deleted records, the new SOA, the added ones, the new SOA.
    assert_eq!(serials, [current, previous, current, current]);
}

#[test]
fn every_answer_decodes_and_answers_its_query() {
    let ids = Answers::ids();
    assert_eq!(ids.len(), 5, "{ids:?}");
    for id in ids {
        let answers = Answers::read(&id);
        assert!(!answers.versions.is_empty(), "{id}");
        for reference in &answers.answers {
            for (server, wire) in &reference.responses {
                let response = message(wire);
                assert!(response.header.flags.contains(Flags::QR), "{id} {server}");
                assert_eq!(response.header.id, QUERY_ID, "{id} {server}");
                let [question] = response.questions.as_slice() else {
                    unreachable!("{id}: one question");
                };
                assert_eq!(question.name, reference.name, "{id} {server}");
                assert_eq!(question.qtype, reference.rtype, "{id} {server}");
            }
        }
    }
}

/// How the responses of Knot and NSD to one query differ, as D203 lists: each difference is one of these, or the
/// test fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Difference {
    /// A response is truncated: what a server keeps of one that does not fit is its own (RFC 2181 §9).
    Truncation,
    /// NSD adds the apex NS `RRset` to the authority section of positive answers; Knot does not (RFC 1034 §4.3.2
    /// has no such step).
    ApexNsAuthority,
    /// The address records of the additional section differ: Knot adds A and AAAA of the targets, NSD some
    /// (RFC 2181 §10.3 leaves the choice to the server).
    AdditionalAddresses,
    /// A query for type `ANY`: each answers with one `RRset` (RFC 8482 §4.1), not the same one.
    AnyQuery,
    /// A query for type `RRSIG`: Knot answers with one `RRset`'s signatures, NSD with all of the name's (RFC 8482 §7).
    RrsigQuery,
    /// NSD adds an NSEC3 record to the proof of a NODATA answer for the wildcard's own name (RFC 5155 §7.2.3).
    ExtraNsec3,
    /// A query for type NSEC at a name a wildcard expands to: NSD adds the NSEC that proves the name does not exist,
    /// as RFC 4035 §3.1.3.3 requires of a wildcard answer; Knot leaves it out.
    WildcardNsecProof,
}

/// The records of a section, as lines, in a set: the order of a section is not compared (D203).
fn lines(section: &[Record<'static>]) -> BTreeSet<String> {
    section.iter().map(ToString::to_string).collect()
}

/// The owner and type of a line of [`lines`].
fn fields(line: &str) -> (&str, &str) {
    let mut fields = line.split('\t');
    (fields.next().unwrap_or(""), fields.nth(2).unwrap_or(""))
}

/// Whether a response of `wire` fits the limit of `reference`'s query (RFC 1035 §4.2.1: 512 without EDNS;
/// RFC 6891 §6.2.3).
fn fits(reference: &Reference, wire: &[u8]) -> bool {
    reference.transport == Transport::Tcp
        || wire.len() <= usize::from(reference.edns_size.unwrap_or(512))
}

/// Whether every line is of a type of `types`.
fn only(lines: impl IntoIterator<Item = String>, types: &[&str]) -> bool {
    lines
        .into_iter()
        .all(|line| types.contains(&fields(&line).1))
}

/// What differs between Knot's and NSD's responses to `reference`, from the zone `id`.
///
/// # Panics
///
/// When a difference is none of [`Difference`]'s: an unexplained one.
fn differences(id: &str, apex: &str, reference: &Reference) -> BTreeSet<Difference> {
    let key = || format!("{id} {} {}", reference.name, reference.rtype);
    let (Some(knot_wire), Some(nsd_wire)) = (
        reference.responses.get(&Server::Knot),
        reference.responses.get(&Server::Nsd),
    ) else {
        return BTreeSet::new();
    };
    let (knot, nsd) = (message(knot_wire), message(nsd_wire));
    let (mut knot_flags, mut nsd_flags) = (knot.header.flags, nsd.header.flags);
    let truncated = knot_flags.contains(Flags::TC) || nsd_flags.contains(Flags::TC);
    if truncated {
        // The one that did not truncate fits: the other's would not.
        for (flags, wire) in [(knot_flags, knot_wire), (nsd_flags, nsd_wire)] {
            assert!(
                flags.contains(Flags::TC) || fits(reference, wire),
                "{}",
                key()
            );
        }
        knot_flags = knot_flags.without(Flags::TC);
        nsd_flags = nsd_flags.without(Flags::TC);
    }
    assert_eq!(knot_flags, nsd_flags, "{}", key());
    assert_eq!(knot.rcode(), nsd.rcode(), "{}", key());
    assert_eq!(knot.edns.is_some(), nsd.edns.is_some(), "{}", key());
    if truncated {
        return BTreeSet::from([Difference::Truncation]);
    }
    let (ka, kn, kd) = (
        lines(&knot.answer),
        lines(&knot.authority),
        lines(&knot.additional),
    );
    let (na, mut nn, nd) = (
        lines(&nsd.answer),
        lines(&nsd.authority),
        lines(&nsd.additional),
    );
    let mut found = BTreeSet::new();
    if (&ka, &kn, &kd) == (&na, &nn, &nd) {
        return found;
    }
    if reference.rtype == RecordType::ANY {
        let one_rrset = |answer: &BTreeSet<String>| {
            let types: BTreeSet<&str> = answer
                .iter()
                .map(|line| fields(line).1)
                .filter(|rtype| *rtype != "RRSIG")
                .collect();
            types.len() <= 1
        };
        assert!(one_rrset(&ka) && one_rrset(&na), "{}", key());
        return BTreeSet::from([Difference::AnyQuery]);
    }
    if reference.rtype == RecordType::RRSIG {
        assert!(ka.is_subset(&na), "{}", key());
        found.insert(Difference::RrsigQuery);
    } else {
        assert_eq!(ka, na, "{}", key());
    }
    let before = nn.len();
    nn.retain(|line| {
        let (owner, rtype) = fields(line);
        let apex_ns = owner.eq_ignore_ascii_case(apex)
            && (rtype == "NS" || (rtype == "RRSIG" && line.contains("\tNS ")));
        !apex_ns
    });
    if nn.len() != before {
        found.insert(Difference::ApexNsAuthority);
    }
    if kn != nn {
        let (extra, proof) = if reference.rtype == RecordType::NSEC {
            (&["NSEC", "RRSIG"], Difference::WildcardNsecProof)
        } else {
            (&["NSEC3", "RRSIG"], Difference::ExtraNsec3)
        };
        assert!(
            nn.is_superset(&kn) && only(nn.difference(&kn).cloned(), extra),
            "unexplained {}: knot {kn:?} nsd {nn:?}",
            key()
        );
        found.insert(proof);
    }
    if kd != nd {
        assert!(
            only(
                kd.symmetric_difference(&nd).cloned(),
                &["A", "AAAA", "RRSIG"]
            ),
            "unexplained {}: knot {kd:?} nsd {nd:?}",
            key()
        );
        found.insert(Difference::AdditionalAddresses);
    }
    assert!(!found.is_empty(), "{}", key());
    found
}

#[test]
fn every_difference_between_knot_and_nsd_is_listed() {
    let mut seen = BTreeSet::new();
    for id in Answers::ids() {
        let answers = Answers::read(&id);
        let apex = answers.zone.to_string();
        for reference in &answers.answers {
            seen.extend(differences(&id, &apex, reference));
        }
    }
    assert_eq!(
        seen,
        BTreeSet::from([
            Difference::Truncation,
            Difference::ApexNsAuthority,
            Difference::AdditionalAddresses,
            Difference::AnyQuery,
            Difference::RrsigQuery,
            Difference::ExtraNsec3,
            Difference::WildcardNsecProof,
        ])
    );
}
