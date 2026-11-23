//! The answers of Knot 3.6.2 and NSD 4.15.4 to the questions of `testdata/authoritative/answers/`, which `dedens-zone`
//! answers from the same zone, by the comparison rules of D203 (RFC 1034 §4.3.2, RFC 2181 §9, RFC 8482 §4.2,
//! RFC 9471 §3.1): sections as sets of records with their TTLs, flags, response code and the presence of EDNS equal.
//!
//! With DO, the answers of signed zones carry their signatures and proofs, compared the same way (D209).

use std::collections::BTreeSet;
use std::fs;

use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Header, Message, Name, Opcode, Record, RecordType, Ttl};
use dedens_testkit::authoritative::{Answers, QUERY_ID, Reference, Server, Transport};
use dedens_testkit::{message, path};
use dedens_zone::{Include, Kind, Limits, Source, Zone};

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
    let glue = answer.fill(zone, &mut response, limit);
    let mut buf = vec![0; limit];
    let len = glue.encode(&response, &mut buf).expect("encodes");
    buf.truncate(len);
    buf
}

/// The records of a section as compared (D203): each with its owner as the server wrote it, in lower case for
/// NSD. The record itself compares its names, in the owner and in RDATA, ASCII case-insensitively (RFC 4343),
/// and its strings as they are. Which are in a section is compared, not their order.
type Rows<'a> = Vec<(String, &'a Record<'static>)>;

fn rows<'a>(server: Server, records: impl IntoIterator<Item = &'a Record<'static>>) -> Rows<'a> {
    records
        .into_iter()
        .map(|record| {
            let owner = record.name.to_string();
            let owner = if server == Server::Nsd {
                owner.to_ascii_lowercase()
            } else {
                owner
            };
            (owner, record)
        })
        .collect()
}

/// Whether every row of `a` is in `b`.
fn subset(a: &Rows<'_>, b: &Rows<'_>) -> bool {
    a.iter().all(|row| b.contains(row))
}

/// Whether the two sections hold the same rows.
fn same(a: &Rows<'_>, b: &Rows<'_>) -> bool {
    subset(a, b) && subset(b, a)
}

/// The rows as lines, for the message of a failed assertion.
fn show(rows: &Rows<'_>) -> BTreeSet<String> {
    rows.iter()
        .map(|(owner, record)| format!("{owner} {record}"))
        .collect()
}

/// The size a response is held to: the limit of its transport and of the EDNS size it was asked with, 512
/// without (RFC 6891 §6.2.3, which takes a smaller size as 512).
fn limit(reference: &Reference) -> usize {
    match reference.transport {
        Transport::Tcp => usize::from(u16::MAX),
        Transport::Udp => usize::from(reference.edns_size.unwrap_or(512).max(512)),
    }
}

/// The least an address record takes: a compression pointer, type, class, TTL, length and four bytes of A.
const MIN_ADDRESS_LEN: usize = 2 + 10 + 4;

fn fits(reference: &Reference, wire: &[u8]) -> bool {
    wire.len() <= limit(reference)
}

/// Whether `name` is below a DNAME owner with no delegation point above that: the first cut on the way down from
/// the apex is a DNAME's, so the data there is occluded by it (RFC 6672 §2.4).
fn below_dname(zone: &Zone, name: &Name<'_>) -> bool {
    for depth in zone.apex().label_count()..name.label_count() {
        match zone.node(&name.ancestor(depth)) {
            Some(node) if node.kind() == Kind::Delegation => return false,
            Some(node) if node.is_dname_owner() => return true,
            _ => {}
        }
    }
    false
}

/// The records of `section` a response gives: not those of names below a DNAME owner in an answer, which dedens
/// leaves out where Knot gives them (D206); the glue below a delegation point is given, in a referral and in an
/// answer.
fn given<'a>(
    zone: &Zone,
    referral: bool,
    section: &'a [Record<'static>],
) -> impl Iterator<Item = &'a Record<'static>> {
    section
        .iter()
        .filter(move |record| referral || !below_dname(zone, &record.name))
}

/// Whether `response` answers NSEC from a wildcard: its signature counts fewer labels than its owner (RFC 4035
/// §5.3.2).
fn wildcard_nsec(response: &Message<'_>) -> bool {
    response.answer.iter().any(|record| match record.data() {
        RData::Rrsig(rrsig) => {
            rrsig.type_covered == RecordType::NSEC
                && usize::from(rrsig.labels) < record.name.label_count()
        }
        _ => false,
    })
}

/// Whether `record` is an NSEC or its signature.
fn proves(record: &Record<'_>) -> bool {
    match record.data() {
        RData::Nsec(_) => true,
        RData::Rrsig(rrsig) => rrsig.type_covered == RecordType::NSEC,
        _ => false,
    }
}

/// Compares `ours` with what `server` sent, `theirs`, as D203 says; `full` is ours without a limit.
fn compare(id: &str, server: Server, zone: &Zone, reference: &Reference, ours: &[u8], full: &[u8]) {
    let theirs = &reference.responses[&server];
    let key = format!(
        "{id} {server} {} {} {:?} DO={}",
        reference.name, reference.rtype, reference.edns_size, reference.dnssec_ok
    );
    let key = format!("{key} ours {} theirs {}", ours.len(), theirs.len());
    let (mine, other) = (message(ours), message(theirs));
    assert_eq!(mine.rcode(), other.rcode(), "{key}");
    assert_eq!(mine.edns.is_some(), other.edns.is_some(), "{key}");
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
    // An authority section with an NS record is a referral: ours has none else.
    let referral = mine.authority.iter().any(|r| r.rtype() == RecordType::NS);
    let (answer, mut authority) = (rows(server, &mine.answer), rows(server, &mine.authority));
    let (their_answer, mut their_authority) =
        (rows(server, &other.answer), rows(server, &other.authority));
    // The name servers of the apex NS NSD adds to a positive answer, whose addresses it adds too.
    let mut apex_servers = Vec::new();
    if server == Server::Nsd {
        // NSD's own choice (D203): the apex NS in the authority of a positive answer.
        their_authority.retain(|(owner, record)| {
            let apex_ns = record.rtype() == RecordType::NS
                && *owner == zone.apex().to_string().to_ascii_lowercase()
                && !mine.answer.is_empty();
            if let (true, RData::Ns(server)) = (apex_ns, record.data()) {
                apex_servers.push(server.into_owned());
            }
            !apex_ns
        });
    }
    if server == Server::Knot && wildcard_nsec(&mine) {
        // D203: the NSEC asked at a name a wildcard answers comes with the NSEC that proves the name absent, as
        // NSD gives it (RFC 4035 §3.1.3.3); Knot leaves it out.
        authority.retain(|(_, record)| !proves(record));
    }
    if reference.rtype == RecordType::ANY && server == Server::Nsd {
        // D203: which RRset answers ANY is the server's; ours is the lowest type, one of them (RFC 8482 §4.2).
        assert_eq!(answer.is_empty(), their_answer.is_empty(), "{key}: answer");
        if !their_answer.is_empty() {
            let types: BTreeSet<RecordType> = mine.answer.iter().map(Record::rtype).collect();
            assert_eq!(types.len(), 1, "{key}");
        }
        assert!(
            same(&authority, &their_authority),
            "{key}: authority {:?} {:?}",
            show(&authority),
            show(&their_authority)
        );
        return;
    }
    assert!(
        same(&answer, &their_answer),
        "{key}: answer {:?} {:?}",
        show(&answer),
        show(&their_answer)
    );
    assert!(
        same(&authority, &their_authority),
        "{key}: authority {:?} {:?}",
        show(&authority),
        show(&their_authority)
    );
    let additional = rows(server, &mine.additional);
    let whole_message = message(full);
    let whole = rows(server, &whole_message.additional);
    let their_additional = rows(
        server,
        given(zone, referral, &other.additional).filter(|r| !apex_servers.contains(&r.name)),
    );
    let outcome = if server == Server::Nsd {
        // NSD gives fewer addresses (D203): what it gives is part of the whole.
        subset(&their_additional, &whole)
    } else if same(&additional, &whole) {
        // Knot writes the names in the RDATA of NS uncompressed: its response may be full where ours is not, its
        // additional section cut short of one more address (D203).
        same(&additional, &their_additional)
            || (subset(&their_additional, &whole)
                && theirs.len() + MIN_ADDRESS_LEN > limit(reference))
    } else {
        // Past the limit the additional section is cut where the server decides (D203): what each keeps is
        // part of the whole.
        subset(&additional, &whole) && subset(&their_additional, &whole)
    };
    assert!(
        outcome,
        "{key}: additional {:?} {:?}",
        show(&additional),
        show(&their_additional)
    );
}

#[test]
fn every_captured_answer_is_the_one_of_knot_by_the_rules_of_d203() {
    let mut compared = 0;
    for id in Answers::ids() {
        let answers = Answers::read(&id);
        let zone = load(&answers);
        for reference in &answers.answers {
            let server = if reference.responses.contains_key(&Server::Knot) {
                Server::Knot
            } else {
                Server::Nsd
            };
            let full = respond(&zone, reference, usize::from(u16::MAX));
            let ours = respond(&zone, reference, limit(reference));
            compare(&id, server, &zone, reference, &ours, &full);
            compared += 1;
        }
    }
    assert!(compared > 500, "{compared}");
}

/// The priming answer, `. NS` of the root zone (RFC 8109 §3), has the addresses of the thirteen root servers,
/// which sit below the delegation of `net.`: glue, which Knot gives as optional additional data and dedens
/// does (D206).
#[test]
fn the_root_priming_answer_has_the_addresses_of_the_root_servers_as_knot_gives_them() {
    let answers = Answers::read("root");
    let zone = load(&answers);
    let reference = answers
        .answers
        .iter()
        .find(|r| {
            r.name == *zone.apex()
                && r.rtype == RecordType::NS
                && !r.dnssec_ok
                && r.edns_size == Some(1232)
                && r.transport == Transport::Udp
        })
        .expect("the priming query of the captures");
    let ours = message(&respond(&zone, reference, limit(reference)));
    let theirs = message(&reference.responses[&Server::Knot]);
    assert_eq!(ours.answer.len(), 13);
    let (additional, their_additional) = (
        rows(Server::Knot, &ours.additional),
        rows(Server::Knot, &theirs.additional),
    );
    assert!(
        same(&additional, &their_additional),
        "{:?} {:?}",
        show(&additional),
        show(&their_additional)
    );
    for rtype in [RecordType::A, RecordType::AAAA] {
        let count = ours
            .additional
            .iter()
            .filter(|r| r.rtype() == rtype)
            .count();
        assert_eq!(count, 13, "{rtype}");
    }
    assert_eq!(ours.additional.len(), 26);
}

