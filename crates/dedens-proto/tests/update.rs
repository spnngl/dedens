//! UPDATE requests read whole (RFC 2136 §2.3 to §2.5, §3.1.1, §3.2.5, §3.4.1.3), from the requests knsupdate sent
//! Knot (`testdata/authoritative/recordings/update-*.yaml`, `just capture-authoritative`).

use std::fmt::Write as _;

use dedens_proto::{
    Change, Class, Fault, Message, Name, Prerequisite, Rcode, Record, RecordType, Section, Ttl,
    Update, UpdateError, WireRdata,
};
use dedens_testkit::authoritative::{Peer, Recording};

/// The first request of the recording `id`.
fn request(id: &str) -> Vec<u8> {
    (Recording::read(id).messages.into_iter())
        .find(|packet| packet.from == Peer::Client)
        .expect("a request")
        .message
}

/// `update` as lines: the zone, each prerequisite and each change.
fn describe(update: &Update<'_>) -> String {
    let mut out = format!("zone {} {}\n", update.zone(), update.class());
    for prerequisite in update.prerequisites() {
        let line = match prerequisite {
            Prerequisite::Exists(name, rtype) => format!("exists {name} {rtype}"),
            Prerequisite::Equals(name, rtype, rdatas) => {
                let rdatas = rdatas.iter().map(|rdata| rdata.data().to_string());
                format!(
                    "equals {name} {rtype} [{}]",
                    rdatas.collect::<Vec<_>>().join(", ")
                )
            }
            Prerequisite::Absent(name, rtype) => format!("absent {name} {rtype}"),
            Prerequisite::InUse(name) => format!("in use {name}"),
            Prerequisite::NotInUse(name) => format!("not in use {name}"),
        };
        writeln!(out, "{line}").expect("a String");
    }
    for change in update.changes() {
        let line = match change {
            Change::Add(record) => format!("add {record}"),
            Change::DeleteRrset(name, rtype) => format!("delete rrset {name} {rtype}"),
            Change::DeleteName(name) => format!("delete name {name}"),
            Change::Delete(name, rdata) => {
                format!("delete {name} {} {}", rdata.rtype(), rdata.data())
            }
        };
        writeln!(out, "{line}").expect("a String");
    }
    out
}

/// Each request knsupdate sent reads into the prerequisites and changes its scenario wrote, or, outside the zone,
/// into NOTZONE as Knot answered.
#[test]
fn rfc2136_s2_captured_requests() {
    let mut out = String::new();
    for id in Recording::ids()
        .into_iter()
        .filter(|id| id.starts_with("update-"))
    {
        let wire = request(&id);
        let message = Message::decode(&wire).expect("a message").message;
        writeln!(out, "# {id}").expect("a String");
        match Update::read(message) {
            Ok(update) => out.push_str(&describe(&update)),
            Err(e) => writeln!(out, "{} {e}", e.rcode()).expect("a String"),
        }
    }
    insta::assert_snapshot!(out);
}

/// The request of `update-add-name`, with `edit` made to its message.
fn edited(edit: impl FnOnce(&mut Message<'static>)) -> Result<Update<'static>, UpdateError> {
    let wire = request("update-add-name");
    let mut message = Message::decode(&wire)
        .expect("a message")
        .message
        .into_owned();
    edit(&mut message);
    Update::read(message)
}

fn fault(section: Section, fault: Fault) -> Result<Update<'static>, UpdateError> {
    Err(UpdateError::Record {
        section,
        index: 0,
        fault,
    })
}

/// No RDATA, of `rtype`: read from a record of class ANY, the one way to have it.
fn empty(rtype: RecordType) -> WireRdata<'static> {
    let wire = [
        &[0][..],
        &rtype.0.to_be_bytes(),
        &Class::ANY.0.to_be_bytes(),
        &[0; 6],
    ]
    .concat();
    let (decoded, _) = Record::from_wire(&wire).expect("a record");
    decoded.record.rdata.into_owned()
}

fn apex() -> Name<'static> {
    "example.".parse().expect("a name")
}

#[test]
fn rfc2136_s3_1_1_the_zone_section_holds_one_soa() {
    assert_eq!(
        edited(|m| m.questions.clear()),
        Err(UpdateError::ZoneCount(0))
    );
    assert_eq!(
        edited(|m| m.questions.push(m.questions[0].clone())),
        Err(UpdateError::ZoneCount(2))
    );
    assert_eq!(
        edited(|m| m.questions[0].qtype = RecordType::A),
        Err(UpdateError::ZoneType(RecordType::A))
    );
    assert_eq!(UpdateError::ZoneType(RecordType::A).rcode(), Rcode::FORMERR);
}

/// The prerequisite forms of §2.4 against the checks of §3.2.5, from the change of `update-add-name` moved to
/// the prerequisite section.
#[test]
fn rfc2136_s3_2_5_prerequisites() {
    let moved = |class: Class, ttl: u32, rdata: bool| {
        edited(|m| {
            let mut record = m.authority.remove(0);
            record.class = class;
            record.ttl = Ttl::from_wire(ttl);
            if !rdata {
                record.rdata = empty(record.rtype());
            }
            m.answer.push(record);
        })
    };
    let read = moved(Class::IN, 0, true).expect("an RRset that must exist");
    assert!(matches!(
        read.prerequisites(),
        [Prerequisite::Equals(_, RecordType::A, rdatas)] if rdatas.len() == 1
    ));
    assert_eq!(read.changes(), []);
    assert!(matches!(
        moved(Class::ANY, 0, false).expect("§2.4.1").prerequisites(),
        [Prerequisite::Exists(_, RecordType::A)]
    ));
    assert!(matches!(
        moved(Class::NONE, 0, false)
            .expect("§2.4.3")
            .prerequisites(),
        [Prerequisite::Absent(_, RecordType::A)]
    ));
    assert_eq!(
        moved(Class::IN, 300, true),
        fault(Section::Answer, Fault::Ttl)
    );
    assert_eq!(
        moved(Class::ANY, 0, true),
        fault(Section::Answer, Fault::Rdata)
    );
    assert_eq!(
        moved(Class::NONE, 0, true),
        fault(Section::Answer, Fault::Rdata)
    );
    assert_eq!(
        moved(Class::CH, 0, true),
        fault(Section::Answer, Fault::Class)
    );
}

/// Two records of one `RRset` make one value-dependent prerequisite (§2.4.2), once each RDATA, after the others;
/// a record of another name makes its own.
#[test]
fn rfc2136_s2_4_2_values_gather_into_one_rrset() {
    let wire = request("update-prereq-yxrrset-value");
    let mut message = Message::decode(&wire)
        .expect("a message")
        .message
        .into_owned();
    let first = message.answer[0].clone();
    let mut other = first.clone();
    other.name = "ns1.example.".parse().expect("a name");
    message.answer.extend([first, other]);
    let read = Update::read(message).expect("a request");
    let [
        Prerequisite::Equals(name, RecordType::NS, rdatas),
        Prerequisite::Equals(other, RecordType::NS, others),
    ] = read.prerequisites()
    else {
        panic!("{:?}", read.prerequisites());
    };
    assert_eq!(*name, apex());
    assert_eq!(rdatas.len(), 2);
    assert_eq!(other.to_string(), "ns1.example.");
    assert_eq!(others.len(), 1);
}

/// The prescan of §3.4.1.3 on the change of `update-add-name`.
#[test]
fn rfc2136_s3_4_1_3_prescan() {
    let change = |edit: fn(&mut Record<'static>)| edited(|m| edit(&mut m.authority[0]));
    assert_eq!(
        change(|r| r.name = "example.com.".parse().expect("a name")),
        fault(Section::Authority, Fault::OutsideZone)
    );
    assert_eq!(
        fault(Section::Authority, Fault::OutsideZone)
            .unwrap_err()
            .rcode(),
        Rcode::NOTZONE
    );
    assert_eq!(
        change(|r| r.class = Class::CH),
        fault(Section::Authority, Fault::Class)
    );
    assert_eq!(
        change(|r| r.class = Class::ANY),
        fault(Section::Authority, Fault::Ttl)
    );
    assert_eq!(
        change(|r| r.class = Class::NONE),
        fault(Section::Authority, Fault::Ttl)
    );
    assert_eq!(
        change(|r| {
            r.class = Class::ANY;
            r.ttl = Ttl::ZERO;
        }),
        fault(Section::Authority, Fault::Rdata)
    );
    let read = change(|r| {
        r.class = Class::NONE;
        r.ttl = Ttl::ZERO;
    })
    .expect("§2.5.4");
    assert!(matches!(read.changes(), [Change::Delete(_, rdata)] if rdata.rtype() == RecordType::A));
    for meta in [
        RecordType::ANY,
        RecordType::AXFR,
        RecordType::OPT,
        RecordType::TSIG,
    ] {
        assert_eq!(
            edited(|m| m.authority[0].rdata = empty(meta)),
            fault(Section::Authority, Fault::Type),
            "{meta}"
        );
    }
}
