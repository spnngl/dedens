//! The answers of Knot 3.6.2 and NSD 4.15.4 to the questions of `testdata/authoritative/answers/`, which `dedens-zone`
//! answers from the same zone, by the comparison rules of D203 (RFC 1034 §4.3.2, RFC 2181 §9, RFC 8482 §4.2,
//! RFC 9471 §3.1): sections as sets of records with their TTLs, flags, response code and the presence of EDNS equal.
//!
//! Signed zones are compared without DO: the signatures and proofs of a DO answer are step 07's.

use std::collections::BTreeSet;
use std::fs;

use dedens_proto::{Flags, Header, Message, Opcode, Record, RecordType, Ttl};
use dedens_testkit::authoritative::{Answers, QUERY_ID, Reference, Server, Transport};
use dedens_testkit::{message, path};
use dedens_zone::{Include, Limits, Source, Zone};

/// The zones whose answers carry no DNSSEC records: with DO they are compared too.
const UNSIGNED: [&str; 2] = ["rfc1035_isi", "zonetransfer.me"];

/// The `$INCLUDE` of the ISI zone (RFC 1035 §5.3), and the file that holds it.
const ISI_INCLUDE: (&str, &str) = (
    "<SUBSYS>ISI-MAILBOXES.TXT",
    "zones/rfc1035_isi_mailboxes.zone",
);

/// The zone file `file`, as an answers file names it: relative to `testdata/`.
fn zone_text(file: &str) -> Vec<u8> {
    fs::read(path(file)).expect("a zone file")
}

/// The zone of `answers`, loaded as dedensd loads one.
fn load(answers: &Answers) -> Zone {
    let text = zone_text(&answers.file);
    let mut include: Box<Include<'_>> = Box::new(|name: &str| {
        if name == ISI_INCLUDE.0 {
            Ok(zone_text(ISI_INCLUDE.1))
        } else {
            Err("no such file".to_owned())
        }
    });
    let source = Source {
        name: &answers.file,
        text: &text,
        default_ttl: Ttl::new(3600),
    };
    Zone::load(
        answers.zone.clone(),
        source,
        &mut include,
        &Limits::default(),
    )
    .expect("the zone of the captures")
    .zone
}

/// The bytes the server sends in answer to `reference`'s query, within the limit of its transport and EDNS.
fn respond(zone: &Zone, reference: &Reference, limit: usize) -> Vec<u8> {
    let query = reference.query();
    let answer = zone.answer(&query.questions[0]);
    let mut response = Message {
        header: Header {
            id: QUERY_ID,
            flags: Flags::QR,
            opcode: Opcode::QUERY,
            ..Header::default()
        },
        questions: query.questions.clone(),
        edns: query.edns.clone(),
        ..Message::default()
    };
    let glue = answer.fill(zone, &mut response);
    let mut buf = vec![0; limit];
    let len = glue.encode(&response, &mut buf).expect("encodes");
    buf.truncate(len);
    buf
}

/// The records of a section as lines, in a set: the order of a section is not compared (D203).
fn lines(section: &[Record<'static>]) -> BTreeSet<String> {
    section.iter().map(ToString::to_string).collect()
}

/// The type of a line of [`lines`].
fn rtype(line: &str) -> &str {
    line.split('\t').nth(3).unwrap_or("")
}

fn fits(reference: &Reference, wire: &[u8]) -> bool {
    reference.transport == Transport::Tcp
        || wire.len() <= usize::from(reference.edns_size.unwrap_or(512))
}

/// Compares `ours` with what `server` sent, `theirs`, as D203 says.
fn compare(id: &str, server: Server, apex: &str, reference: &Reference, ours: &[u8], full: &[u8]) {
    let theirs = &reference.responses[&server];
    let key = format!(
        "{id} {server} {} {} {:?} DO={}",
        reference.name, reference.rtype, reference.edns_size, reference.dnssec_ok
    );
    let (mine, other) = (message(ours), message(theirs));
    let (mut a, mut b) = (mine.header.flags, other.header.flags);
    if a.contains(Flags::TC) || b.contains(Flags::TC) {
        // A response truncated on either side is compared on TC alone, and the other must fit (D203).
        assert!(
            a.contains(Flags::TC) || fits(reference, ours),
            "{key}: ours does not fit"
        );
        assert!(
            b.contains(Flags::TC) || fits(reference, theirs),
            "{key}: theirs does not fit"
        );
        a = a.without(Flags::TC);
        b = b.without(Flags::TC);
        assert_eq!(a, b, "{key}");
        return;
    }
    assert_eq!(a, b, "{key}");
    assert_eq!(mine.rcode(), other.rcode(), "{key}");
    assert_eq!(mine.edns.is_some(), other.edns.is_some(), "{key}");
    if reference.rtype == RecordType::ANY && server == Server::Nsd {
        // D203: which RRset answers ANY is the server's; ours is the lowest type, one of them (RFC 8482 §4.2).
        let types: BTreeSet<RecordType> = mine.answer.iter().map(Record::rtype).collect();
        assert!(types.len() <= 1, "{key}");
        return;
    }
    // Both servers write the names inside RDATA in lower case, NSD the owners too: the owners are compared as
    // each wrote them, so a name asked in another case than the zone's is answered in the case asked (RFC 4343
    // §4.1, D206).
    let fold = |set: BTreeSet<String>| -> BTreeSet<String> {
        set.into_iter()
            .map(|line| {
                let at = line.match_indices('\t').nth(3).map_or(0, |(at, _)| at);
                let (head, rdata) = line.split_at(at);
                let head = if server == Server::Nsd {
                    head.to_ascii_lowercase()
                } else {
                    head.to_owned()
                };
                head + &rdata.to_ascii_lowercase()
            })
            .collect()
    };
    assert_eq!(
        fold(lines(&mine.answer)),
        fold(lines(&other.answer)),
        "{key}: answer"
    );
    let (mut authority, mut extra) = (
        fold(lines(&other.authority)),
        fold(lines(&other.additional)),
    );
    if server == Server::Nsd {
        // NSD's own choices (D203): the apex NS in the authority of a positive answer, fewer addresses.
        let apex = apex.to_ascii_lowercase();
        authority.retain(|l| {
            !(rtype(l).eq_ignore_ascii_case("NS")
                && l.starts_with(&apex)
                && !mine.answer.is_empty())
        });
        extra = fold(lines(&mine.additional));
    }
    assert_eq!(fold(lines(&mine.authority)), authority, "{key}: authority");
    let additional = fold(lines(&mine.additional));
    if additional != fold(lines(&message(full).additional)) || extra != additional {
        // Past the limit the additional section is cut where the server decides (D203): what each keeps is
        // part of the whole.
        let whole = fold(lines(&message(full).additional));
        if additional != whole {
            assert!(
                additional.is_subset(&whole) && extra.is_subset(&whole),
                "{key}: additional"
            );
            return;
        }
    }
    assert_eq!(additional, extra, "{key}: additional");
}

#[test]
fn every_captured_answer_is_the_one_of_knot_by_the_rules_of_d203() {
    let mut compared = 0;
    for id in Answers::ids() {
        let answers = Answers::read(&id);
        let zone = load(&answers);
        let apex = answers.zone.to_string();
        let unsigned = UNSIGNED.contains(&id.as_str());
        for reference in &answers.answers {
            if reference.dnssec_ok && !unsigned {
                continue;
            }
            let server = if reference.responses.contains_key(&Server::Knot) {
                Server::Knot
            } else {
                Server::Nsd
            };
            let limit = match reference.transport {
                Transport::Tcp => usize::from(u16::MAX),
                Transport::Udp => usize::from(reference.edns_size.unwrap_or(512).max(512)),
            };
            let full = respond(&zone, reference, usize::from(u16::MAX));
            let ours = respond(&zone, reference, limit);
            compare(&id, server, &apex, reference, &ours, &full);
            compared += 1;
        }
    }
    assert!(compared > 500, "{compared}");
}
