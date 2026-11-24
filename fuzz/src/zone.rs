//! Targets of dedens-zone: zone text on its way into a checked zone, a journal file into changesets, the
//! answers of a zone, and an UPDATE made to one.

use std::sync::LazyLock;

use dedens_proto::{
    Flags, Header, MAX_MESSAGE_LEN, Message, Name, Question, Rcode, Record, RecordType, Serial,
    Ttl, Update,
};
use dedens_zone::journal::format::{self, MAGIC, Tail};
use dedens_zone::{Answer, Dnssec, End, Kind, Limits, MAX_CHAIN, Source, Zone};

/// How many `$INCLUDE`s the callback gives the text of: each one reads the same bytes again, so a file that
/// includes itself must end.
const INCLUDES: usize = 4;

/// Arbitrary bytes as the zone `example.`, `$INCLUDE` answered with the same bytes a few times: the load never
/// panics, and a zone it returns is whole. Its apex has the SOA, the nodes are in canonical order inside the apex,
/// every name has its parents up to the apex, the record count is that of the `RRset`s, and what is below a
/// delegation or a DNAME is occluded. A refusal has an error, each placed in a file it read, from line 1.
///
/// # Panics
///
/// On a zone that is not whole, or a bug in the loader.
pub fn load_zone(data: &[u8]) {
    let apex = apex();
    match load(data, &apex) {
        Ok(zone) => whole(&zone, &apex),
        Err(report) => {
            assert!(!report.errors.is_empty(), "a refusal without an error");
            for e in &report.errors {
                if let Some(at) = e.at {
                    assert!(at.file < report.files.len(), "{e:?} in no file");
                    assert!(at.line >= 1 && at.column >= 1, "{e:?} before line 1");
                }
            }
        }
    }
}

fn apex() -> Name<'static> {
    Name::from_labels([b"example".as_slice()]).expect("a valid name")
}

/// `data` as the zone of `apex`, with small bounds so that the limits are reached too.
fn load(data: &[u8], apex: &Name<'static>) -> Result<Zone, dedens_zone::Report> {
    let mut given = 0_usize;
    let mut include = |_: &str| {
        given += 1;
        if given > INCLUDES {
            Err("too many".to_owned())
        } else {
            Ok(data.to_vec())
        }
    };
    let source = Source {
        name: "fuzz.db",
        text: data,
        default_ttl: Some(Ttl::ZERO),
    };
    let limits = Limits {
        records: 64,
        names: 64,
        records_per_rrset: 8,
        rrsets_per_name: 8,
        rdata_bytes: 4096,
        include_depth: 2,
        errors: 16,
        nsec3_iterations: 16,
    };
    Zone::load(apex.clone(), source, &mut include, &limits).map(|loaded| loaded.zone)
}

/// The types every name is asked for, with the one the input names.
const TYPES: [RecordType; 8] = [
    RecordType::A,
    RecordType::NS,
    RecordType::CNAME,
    RecordType::DNAME,
    RecordType::MX,
    RecordType::DS,
    RecordType::SOA,
    RecordType::ANY,
];

/// How many names of the zone are asked: each one with each type, itself and below, so a wildcard, a cut or a DNAME
/// is reached.
const ASKED: usize = 24;

/// A zone file, then (after a NUL, which no zone text holds) a question: 2 bytes of type and a name in text. Every
/// name of the zone, a name below it and the question's are asked of the zone `example.` the file loads into, with
/// and without DO (the proofs of a signed zone, D209): an answer never panics, ends a chain within [`MAX_CHAIN`],
/// and fills a message that encodes (in 512 bytes or 64 KiB)
/// and decodes with the `RCODE`, `AA` and sections the answer gave.
///
/// # Panics
///
/// On an answer that is not whole, or a bug in the answering.
pub fn zone_answer(data: &[u8]) {
    let (text, asked) = data
        .iter()
        .position(|&byte| byte == 0)
        .map_or((data, &[][..]), |at| (&data[..at], &data[at + 1..]));
    let apex = apex();
    let Ok(zone) = load(text, &apex) else {
        return;
    };
    let mut names: Vec<Name<'static>> = vec![apex.clone()];
    if let Some((qtype, name)) = asked.split_first_chunk::<2>()
        && let Some(name) = std::str::from_utf8(name)
            .ok()
            .and_then(|name| name.parse().ok())
    {
        ask(
            &zone,
            &name,
            RecordType(u16::from_be_bytes(*qtype)),
            Dnssec::With,
        );
        names.push(name);
    }
    for (name, _) in zone.nodes().take(ASKED) {
        names.push(name.clone());
        let below = format!("x.{name}");
        names.extend(below.parse());
    }
    for name in &names {
        for qtype in TYPES {
            for dnssec in [Dnssec::Without, Dnssec::With] {
                ask(&zone, name, qtype, dnssec);
            }
        }
    }
}

/// One question of `zone`, with DO or not: what the answer, and the reply made of it, must be.
fn ask(zone: &Zone, name: &Name<'static>, qtype: RecordType, dnssec: Dnssec) {
    let question = Question::new(name.clone(), qtype);
    let answer = zone.answer(&question);
    assert!(answer.chain.len() <= MAX_CHAIN, "{name}: a chain too long");
    assert_eq!(
        matches!(answer.end, End::NotAuth),
        !name.is_within(zone.apex()),
        "{name}: the zone is the authority for its names"
    );
    let mut message = Message {
        header: Header {
            flags: Flags::QR,
            ..Header::default()
        },
        questions: vec![question.clone()],
        ..Message::default()
    };
    // The larger size: what 512 bytes keep of it is cut by `encode`, whole `RRset`s at a time.
    let glue = answer.fill(zone, &mut message, MAX_MESSAGE_LEN, dnssec);
    if dnssec == Dnssec::With {
        without_dnssec_is_with_less_its_records(zone, &question, &answer, &message);
    }
    assert_eq!(message.rcode(), answer.rcode());
    assert_eq!(
        message.header.flags.contains(Flags::AA),
        answer.authoritative()
    );
    for size in [512, 65535] {
        let mut buf = vec![0; size];
        let len = glue.encode(&message, &mut buf).expect("a reply encodes");
        let decoded = Message::decode(&buf[..len])
            .expect("a reply decodes")
            .message;
        assert_eq!(decoded.rcode(), answer.rcode(), "{name} in {size}");
        let truncated = decoded.header.flags.contains(Flags::TC);
        // RFC 9471 §3.1: when the answer and authority fit, the glue the zone requires is in, or TC is set.
        let mut bare = message.clone();
        bare.additional.clear();
        if !bare
            .encode_truncated(&mut vec![0; size])
            .expect("a reply encodes")
            .truncated
        {
            assert!(
                truncated || decoded.additional.len() >= glue.required(),
                "{name} in {size}: required glue lost without TC"
            );
        }
        if size == 65535 {
            assert!(!truncated, "{name}: truncated in 64 KiB");
            assert_eq!(decoded.answer.len(), message.answer.len());
            assert_eq!(decoded.authority.len(), message.authority.len());
            assert_eq!(decoded.additional.len(), message.additional.len());
        }
    }
    assert!(
        answer.rcode() != Rcode::REFUSED || message.answer.is_empty(),
        "{name}: a refusal with an answer"
    );
}

/// D209: the answer without DO is the one with DO less its DNSSEC records: the signatures, the NSEC and NSEC3 of
/// proofs, and the DS of a referral. The records of the type the question asked for stay: they are its data.
fn without_dnssec_is_with_less_its_records<'a>(
    zone: &Zone,
    question: &Question<'static>,
    answer: &Answer<'_>,
    with: &Message<'a>,
) {
    let mut without = Message {
        header: Header {
            flags: Flags::QR,
            ..Header::default()
        },
        questions: with.questions.clone(),
        ..Message::default()
    };
    answer.fill(zone, &mut without, MAX_MESSAGE_LEN, Dnssec::Without);
    let data = match &answer.end {
        End::Data { rtype, .. } => Some(*rtype),
        _ => None,
    };
    let referral = matches!(answer.end, End::Referral { .. });
    let kept = |records: &[Record<'a>], in_answer: bool| -> Vec<Record<'a>> {
        records
            .iter()
            .filter(|record| {
                let rtype = record.rtype();
                let dnssec = matches!(
                    rtype,
                    RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                ) || (referral && !in_answer && rtype == RecordType::DS);
                !dnssec || (in_answer && data == Some(rtype))
            })
            .cloned()
            .collect()
    };
    let name = &question.name;
    assert_eq!(
        without.header, with.header,
        "{name}: the header changes with DO"
    );
    assert_eq!(without.answer, kept(&with.answer, true), "{name}: answer");
    assert_eq!(
        without.authority,
        kept(&with.authority, false),
        "{name}: authority"
    );
    assert_eq!(
        without.additional,
        kept(&with.additional, false),
        "{name}: additional"
    );
}

/// Arbitrary bytes as a journal file (D207): reading never panics, a journal it does not refuse is made of whole
/// changesets that each start where the one before ends, `valid` bytes of it are exactly those records, and the
/// changesets written again read back the same, to the last byte.
///
/// # Panics
///
/// On a file that reads as something else than its bytes say, or a bug in the reader.
pub fn journal_read(data: &[u8]) {
    let Ok(scan) = format::scan(data) else {
        return;
    };
    assert!(scan.valid <= data.len());
    assert_eq!(scan.changesets.len(), scan.sizes.len());
    assert_eq!(scan.tail == Tail::Clean, scan.valid == data.len());
    if scan.valid > 0 {
        assert_eq!(MAGIC.len() + scan.sizes.iter().sum::<usize>(), scan.valid);
    } else {
        assert_eq!(scan.changesets.len(), 0);
    }
    for pair in scan.changesets.windows(2) {
        assert_eq!(pair[0].to_serial(), pair[1].from_serial());
    }
    let mut again = MAGIC.to_vec();
    for changeset in &scan.changesets {
        format::encode(changeset, &mut again).expect("a changeset read from wire form fits it");
    }
    let read = format::scan(&again).expect("the header is ours");
    assert_eq!(read.changesets, scan.changesets);
    assert_eq!((read.valid, read.tail), (again.len(), Tail::Clean));
}

/// The invariants of a loaded `zone` of `apex`.
fn whole(zone: &Zone, apex: &Name<'static>) {
    assert_eq!(zone.apex(), apex);
    let root = zone.node(apex).expect("the apex is a node");
    assert!(root.rrset(RecordType::SOA).is_some());
    assert!(root.rrset(RecordType::NS).is_some());
    let mut previous: Option<&Name<'static>> = None;
    let mut records = 0;
    let nodes: Vec<_> = zone.nodes().collect();
    for (at, &(name, node)) in nodes.iter().enumerate() {
        assert!(name.is_within(apex), "{name} outside {apex}");
        assert!(previous.is_none_or(|p| p < name), "{name} out of order");
        previous = Some(name);
        // Proof-only: NSEC3 records and no other set, and no node below (RFC 5155 §7.2.8, D206).
        let only_nsec3 =
            node.rrsets().next().is_some() && node.rrsets().all(|(t, _)| t == RecordType::NSEC3);
        let below = nodes
            .get(at + 1)
            .is_some_and(|(next, _)| next.is_within(name));
        assert_eq!(
            node.is_proof_only(),
            only_nsec3 && !below,
            "{name} proof-only is wrong"
        );
        let sets = node
            .rrsets()
            .map(|(_, set)| set)
            .chain(node.signature_sets());
        let mut held = 0;
        for set in sets {
            assert!(!set.rdatas().is_empty(), "an empty RRset at {name}");
            held += set.rdatas().len();
        }
        records += held;
        assert!(
            node.kind() != Kind::EmptyNonTerminal || held == 0,
            "{name} holds records"
        );
        // The outermost cut above the name: the last one met going up.
        let mut cut = None;
        let mut parent = name.parent();
        while let Some(p) = parent.filter(|_| name != apex) {
            let up = zone.node(&p).expect("every parent is a node");
            if up.kind() == Kind::Delegation || up.is_dname_owner() {
                cut = Some(p.clone());
            }
            if &p == apex {
                break;
            }
            parent = p.parent();
        }
        let hidden_by = match node.kind() {
            Kind::Occluded { cut } => zone.nodes().nth(cut).map(|(cut, _)| cut.clone()),
            _ => None,
        };
        assert_eq!(
            matches!(node.kind(), Kind::Occluded { .. }),
            cut.is_some(),
            "{name} is {:?}",
            node.kind()
        );
        assert_eq!(hidden_by, cut, "{name} is hidden by another cut");
    }
    assert_eq!(records, zone.record_count());
}

/// The zone UPDATE requests are made to: RFC 5155 Appendix A's names, unsigned (`testdata/zones/nsec3_source.zone`,
/// D209), with a delegation, a wildcard, an empty non-terminal and a CNAME.
static UPDATED: LazyLock<Zone> = LazyLock::new(|| {
    let source = Source {
        name: "nsec3_source.zone",
        text: include_bytes!("../../testdata/zones/nsec3_source.zone"),
        default_ttl: None,
    };
    let mut include = |_: &str| Err("no include".to_owned());
    Zone::load(apex(), source, &mut include, &Limits::default())
        .expect("the zone loads")
        .zone
});

/// An UPDATE request made to [`UPDATED`] (D216): a refusal has the RCODE of a prerequisite or a policy; a change
/// moves the serial ahead, its changeset is the difference of the two versions, and the new version is whole; no
/// change leaves the version as it is.
///
/// # Panics
///
/// On an update breaking those rules, or a bug in the update.
pub(crate) fn update(update: &Update<'_>) {
    let zone = &*UPDATED;
    match zone.update(update, &Limits::default()) {
        Ok(None) => {}
        Ok(Some(updated)) => {
            let new = &updated.loaded.zone;
            whole(new, zone.apex());
            assert_eq!(
                updated.changeset.from_serial(),
                Serial::new(zone.soa().serial)
            );
            assert_eq!(updated.changeset.to_serial(), Serial::new(new.soa().serial));
            assert!(updated.changeset.to_serial() > updated.changeset.from_serial());
            assert_eq!(
                Zone::diff(zone, new).as_ref(),
                Ok(&updated.changeset),
                "the changeset is the difference"
            );
        }
        Err(rejection) => assert!(
            matches!(
                rejection.rcode(),
                Rcode::NOTAUTH
                    | Rcode::YXDOMAIN
                    | Rcode::NXDOMAIN
                    | Rcode::YXRRSET
                    | Rcode::NXRRSET
                    | Rcode::REFUSED
            ),
            "{rejection}"
        ),
    }
}
