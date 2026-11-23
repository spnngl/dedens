//! The authoritative stage in the pipeline (D208): a zone answers its names with AA whatever RD says (RFC 1034
//! §4.3.2), to every client, and passes the other names on to the stages after it for the clients the access lists
//! permit (D91, RFC 5358 §4), RA set only for them, and only when a forward or recurse stage follows (RFC 1035
//! §4.1.1).

use std::net::IpAddr;
use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Class, Flags, Message, Question, Rcode, RecordType, Transport, Ttl};
use dedens_server::{Access, Authoritative, Denial, Forward, Network, Pipeline, Stage, Step};
use dedens_testkit::dns;
use dedens_zone::{Limits, Source, Zone};

use crate::util::{decode, run, servers, wire};

/// The zone file `file` of `testdata/zones`, loaded with `origin` as its apex, records without a TTL at 3600
/// seconds, as dedensd loads them (D208), its `$INCLUDE` the mailboxes of RFC 1035 §5.3.
fn load(file: &str, origin: &str) -> Arc<Zone> {
    let text =
        std::fs::read(dedens_testkit::path(&format!("zones/{file}"))).expect("the zone file");
    let source = Source {
        name: file,
        text: &text,
        default_ttl: Some(Ttl::from_wire(3600)),
    };
    let mut include = |_: &str| {
        std::fs::read(dedens_testkit::path("zones/rfc1035_isi_mailboxes.zone"))
            .map_err(|e| e.to_string())
    };
    let loaded = Zone::load(dns(origin), source, &mut include, &Limits::default());
    Arc::new(loaded.expect("the zone loads").zone)
}

/// The zone of RFC 4035 Appendix A, `example.`.
pub(crate) fn example() -> Arc<Zone> {
    load("rfc4035_appendix_a.zone", "example")
}

/// The authoritative stage serving [`example`].
pub(crate) fn zones() -> Stage {
    Stage::Authoritative(Authoritative::new([example()]).expect("one zone"))
}

/// An authoritative server for `example.` alone.
fn authoritative() -> Pipeline {
    Pipeline::new(vec![zones()])
}

/// [`example`] first, then forwarding for the clients of 10.0.0.0/8, the others `denial`.
fn mixed(denial: Denial) -> Pipeline {
    let local: Network = "10.0.0.0/8".parse().expect("a network");
    Pipeline::new(vec![
        zones(),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ])
    .with_access(Access::new([local], [], denial))
}

/// A client the access lists of [`mixed`] permit.
const INSIDE: &str = "10.1.2.3";
/// A client they deny.
const OUTSIDE: &str = "192.0.2.1";

fn addr(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// What the query for `name` and `qtype`, with `flags` alone (RD or not), from `from` over UDP comes to, and what
/// was written: the reply, for [`Step::Reply`].
fn ask(
    pipeline: &Pipeline,
    (name, qtype): (&str, RecordType),
    flags: Flags,
    from: &str,
) -> (Step, Vec<u8>) {
    let mut query = Message::query(7, Question::new(dns(name), qtype));
    query.header.flags = flags;
    let mut out = vec![0; 65535];
    let step = pipeline.query(&wire(&query), Transport::Udp, addr(from), 0, &mut out);
    if let Step::Reply(len) = step {
        out.truncate(len);
    }
    (step, out)
}

/// The reply [`ask`] gets.
struct Replied {
    rcode: Rcode,
    flags: Flags,
    /// The records of every section, as text.
    records: Vec<String>,
    options: Vec<EdnsOption<'static>>,
}

fn replied(pipeline: &Pipeline, question: (&str, RecordType), flags: Flags, from: &str) -> Replied {
    let (step, out) = ask(pipeline, question, flags, from);
    assert!(matches!(step, Step::Reply(_)), "{step:?}");
    let reply = decode(&out).into_owned();
    Replied {
        rcode: reply.rcode(),
        flags: reply.header.flags,
        records: reply
            .answer
            .iter()
            .chain(&reply.authority)
            .chain(&reply.additional)
            .map(|record| record.to_string().replace('\t', " "))
            .collect(),
        options: reply.edns.map(|edns| edns.options).unwrap_or_default(),
    }
}

fn has(records: &[String], record: &str) -> bool {
    records.iter().any(|r| r == record)
}

#[test]
fn rfc1034_4_3_2_a_zone_answers_with_aa_whatever_rd() {
    for flags in [Flags::RD, Flags::NONE] {
        let reply = replied(
            &authoritative(),
            ("ns1.example", RecordType::A),
            flags,
            OUTSIDE,
        );
        assert_eq!(reply.rcode, Rcode::NOERROR);
        assert!(
            reply.flags.contains(Flags::AA | Flags::QR),
            "{:?}",
            reply.flags
        );
        assert_eq!(
            reply.flags.contains(Flags::RD),
            flags == Flags::RD,
            "RD copied"
        );
        // No stage forwards or recurses: no recursion is available (RFC 1035 §4.1.1).
        assert!(!reply.flags.contains(Flags::RA), "{:?}", reply.flags);
        assert_eq!(reply.records[0], "ns1.example. 3600 IN A 192.0.2.1");
    }
}

#[test]
fn rfc2308_2_1_a_name_the_zone_lacks_is_nxdomain_with_its_soa() {
    let reply = replied(
        &authoritative(),
        ("nothing.example", RecordType::A),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::NXDOMAIN);
    assert!(reply.flags.contains(Flags::AA));
    assert!(
        reply.records.iter().any(|record| record.contains(" SOA ")),
        "{:?}",
        reply.records
    );
}

#[test]
fn rfc1034_4_3_2_a_delegation_is_a_referral_without_aa() {
    let reply = replied(
        &authoritative(),
        ("www.a.example", RecordType::A),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::NOERROR);
    assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(has(&reply.records, "a.example. 3600 IN NS ns1.a.example."));
    assert!(has(&reply.records, "ns1.a.example. 3600 IN A 192.0.2.5"));
}

#[test]
fn a_name_outside_every_zone_is_refused_without_a_later_stage() {
    let reply = replied(
        &authoritative(),
        ("example.org", RecordType::A),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!((reply.rcode, reply.records.len()), (Rcode::REFUSED, 0));
    assert!(!reply.flags.contains(Flags::RA), "{:?}", reply.flags);
    assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
}

#[test]
fn a_zone_transfer_is_still_refused() {
    let reply = replied(
        &authoritative(),
        ("example", RecordType::AXFR),
        Flags::NONE,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::REFUSED);
}

#[test]
fn a_zone_answers_every_client_ra_only_for_those_recursion_serves() {
    for denial in [Denial::Refuse, Denial::Drop] {
        let pipeline = mixed(denial);
        assert_eq!(
            pipeline.denial(addr(OUTSIDE)),
            None,
            "the zones answer every client"
        );
        assert!(!pipeline.drops(addr(OUTSIDE)));
        assert!(
            !pipeline.silences(addr(OUTSIDE)),
            "sealed packets are opened"
        );
        assert!(
            pipeline.denies(addr(OUTSIDE)),
            "the ODoH proxy's requests are not"
        );
        for (from, ra) in [(INSIDE, true), (OUTSIDE, false)] {
            let reply = replied(&pipeline, ("ns1.example", RecordType::A), Flags::RD, from);
            assert_eq!(reply.rcode, Rcode::NOERROR);
            assert!(reply.flags.contains(Flags::AA));
            assert_eq!(reply.flags.contains(Flags::RA), ra, "{from}");
        }
    }
}

#[test]
fn rfc5358_4_a_name_outside_the_zones_goes_on_for_the_clients_the_access_lists_permit() {
    let question = ("example.org", RecordType::A);
    let pipeline = mixed(Denial::Refuse);
    let (step, _) = ask(&pipeline, question, Flags::RD, INSIDE);
    assert!(matches!(step, Step::Upstream(_)), "{step:?}");
    // The others get what the lists say: REFUSED with EDE 18 (RFC 8914 §4.19), or nothing.
    let reply = replied(&pipeline, question, Flags::RD, OUTSIDE);
    assert_eq!(reply.rcode, Rcode::REFUSED);
    assert!(!reply.flags.contains(Flags::RA), "{:?}", reply.flags);
    assert!(
        matches!(&reply.options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::PROHIBITED),
        "{:?}",
        reply.options
    );
    let (step, _) = ask(&mixed(Denial::Drop), question, Flags::RD, OUTSIDE);
    assert!(matches!(step, Step::Drop), "{step:?}");
}

#[test]
fn a_referral_is_never_passed_on_to_recursion() {
    // Recursion would start from the root, not from our cut, and so ignore the delegation: the referral is the
    // answer, as Knot and NSD give it, whatever RD and the client say (D208).
    let pipeline = mixed(Denial::Refuse);
    let question = ("www.a.example", RecordType::A);
    for (flags, from, ra) in [
        (Flags::RD, INSIDE, true),
        (Flags::NONE, INSIDE, true),
        (Flags::RD, OUTSIDE, false),
    ] {
        let reply = replied(&pipeline, question, flags, from);
        assert_eq!(reply.rcode, Rcode::NOERROR);
        assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
        assert_eq!(reply.flags.contains(Flags::RA), ra, "{from}");
        assert!(has(&reply.records, "a.example. 3600 IN NS ns1.a.example."));
    }
}

#[test]
fn rfc4035_3_1_4_1_a_ds_is_the_parent_zones_when_both_are_served() {
    // `a.example.` is a cut of `example.`, which holds its DS; the ISI zone file stands for the child.
    let child = load("rfc1035_isi.zone", "a.example");
    let both = Authoritative::new([example(), child]).expect("two apexes");
    let pipeline = Pipeline::new(vec![Stage::Authoritative(both)]);
    let reply = replied(&pipeline, ("a.example", RecordType::DS), Flags::RD, OUTSIDE);
    assert_eq!(reply.rcode, Rcode::NOERROR);
    assert!(reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(
        reply
            .records
            .iter()
            .any(|r| r.starts_with("a.example. 3600 IN DS 57855 5 1 ")),
        "{:?}",
        reply.records
    );
    // Any other type at the cut is the child's: its SOA, and not the parent's referral.
    let reply = replied(
        &pipeline,
        ("a.example", RecordType::SOA),
        Flags::RD,
        OUTSIDE,
    );
    assert!(reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(
        reply
            .records
            .iter()
            .any(|r| r.starts_with("a.example. 3600 IN SOA ")),
        "{:?}",
        reply.records
    );
    // The DS of a name that is no apex, or of the apex of the only zone, is that zone's.
    let alone = Pipeline::new(vec![Stage::Authoritative(
        Authoritative::new([example()]).expect("one zone"),
    )]);
    for name in ["example", "nothing.example"] {
        let reply = replied(&alone, (name, RecordType::DS), Flags::RD, OUTSIDE);
        assert!(reply.flags.contains(Flags::AA), "{name}: {:?}", reply.flags);
    }
}

/// The stage serving the zones `apexes`, each from the ISI zone file but for `example.`, the zone of RFC 4035
/// Appendix A: the SOA of each tells which of them answered.
fn nested(apexes: &[&str]) -> Pipeline {
    let zones = apexes.iter().map(|apex| match *apex {
        "example" => example(),
        apex => load("rfc1035_isi.zone", apex),
    });
    Pipeline::new(vec![Stage::Authoritative(
        Authoritative::new(zones).expect("no apex twice"),
    )])
}

/// The owners of the SOA records of `reply`, lowercased.
fn soa_owners(reply: &Replied) -> Vec<String> {
    (reply.records.iter())
        .filter(|record| record.contains(" IN SOA "))
        .filter_map(|record| record.split(' ').next())
        .map(str::to_lowercase)
        .collect()
}

#[test]
fn rfc4035_3_1_4_1_the_root_zone_answers_its_own_ds() {
    // The root has no parent: its DS is not another zone's.
    let reply = replied(&nested(&["."]), (".", RecordType::DS), Flags::RD, OUTSIDE);
    assert_eq!(reply.rcode, Rcode::NOERROR);
    assert!(reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert_eq!(soa_owners(&reply), ["."], "{:?}", reply.records);
}

#[test]
fn rfc4035_3_1_4_1_the_parent_of_a_ds_is_found_whatever_the_case() {
    let pipeline = nested(&["example", "a.example"]);
    let reply = replied(&pipeline, ("A.EXAMPLE", RecordType::DS), Flags::RD, OUTSIDE);
    assert!(reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(
        reply.records.iter().any(|r| r
            .to_lowercase()
            .starts_with("a.example. 3600 in ds 57855 5 1 ")),
        "{:?}",
        reply.records
    );
}

#[test]
fn rfc4035_3_1_4_1_the_parent_of_a_ds_is_found_past_a_zone_that_is_no_ancestor() {
    // `a.example.` sorts just before the parent `q.example.`, and shares only `example.` with it: the search for
    // the parent's zone goes on to `example.`, not to the zone of the name itself.
    let pipeline = nested(&["example", "a.example", "x.q.example"]);
    let reply = replied(
        &pipeline,
        ("x.q.example", RecordType::DS),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!(soa_owners(&reply), ["example."], "{:?}", reply.records);
}

#[test]
fn rfc4035_3_1_4_1_the_parent_zone_answers_a_ds_not_the_grandparent() {
    // `venera.a.example.` is no cut of `a.example.` but a name it holds: its DS is NODATA with the SOA of the
    // parent, not of the zone of that name, nor the referral the grandparent `example.` would give.
    let pipeline = nested(&["example", "a.example", "venera.a.example"]);
    let reply = replied(
        &pipeline,
        ("venera.a.example", RecordType::DS),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::NOERROR);
    assert!(reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert_eq!(soa_owners(&reply), ["a.example."], "{:?}", reply.records);
    // Any other type there is the zone of that name's.
    let reply = replied(
        &pipeline,
        ("venera.a.example", RecordType::SOA),
        Flags::RD,
        OUTSIDE,
    );
    assert!(
        reply
            .records
            .iter()
            .any(|r| r.starts_with("venera.a.example. 3600 IN SOA ")),
        "{:?}",
        reply.records
    );
}

#[test]
fn rfc4035_3_1_4_1_a_ds_below_a_cut_of_the_parent_is_a_referral() {
    // The parent of `x.a.example.` is `a.example.`, a cut of `example.`: no zone of its own is served.
    let reply = replied(
        &nested(&["example"]),
        ("x.a.example", RecordType::DS),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::NOERROR);
    assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(has(&reply.records, "a.example. 3600 IN NS ns1.a.example."));
}

#[test]
fn a_name_of_class_any_is_answered() {
    let mut question = Question::new(dns("ns1.example"), RecordType::A);
    question.qclass = Class::ANY;
    let mut query = Message::query(7, question);
    query.header.flags = Flags::RD;
    let mut out = vec![0; 65535];
    let step = authoritative().query(&wire(&query), Transport::Udp, addr(OUTSIDE), 0, &mut out);
    let Step::Reply(len) = step else {
        panic!("{step:?}")
    };
    let reply = decode(&out[..len]);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answer.len(), 1);
}

#[test]
fn a_cache_hit_has_ra_only_where_recursion_follows() {
    // The cache is shared by a pipeline that forwards, which fills it, and one that does not: its hits are no
    // recursion (RFC 1035 §4.1.1, D208).
    let cache = Arc::new(Cache::new(Config::default()).expect("valid settings"));
    let forwarding = Pipeline::new(vec![
        zones(),
        Stage::Cache(Arc::clone(&cache)),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ]);
    let query = wire(&dedens_testkit::query("a", 7));
    let response = dedens_testkit::captured("a");
    let done = run(&forwarding, &query, Transport::Udp, &[Some(&response)]);
    assert!(done.reply.is_some());
    let hit = |pipeline: &Pipeline| {
        let done = run(pipeline, &query, Transport::Udp, &[]);
        assert_eq!(done.asked, [], "a hit");
        decode(&done.reply.expect("a reply")).header.flags
    };
    assert!(hit(&forwarding).contains(Flags::RA));
    let cached = Pipeline::new(vec![zones(), Stage::Cache(cache)]);
    assert!(!hit(&cached).contains(Flags::RA));
}

#[test]
fn rfc1034_4_3_2_a_name_of_another_class_goes_on() {
    // Step 2 matches the class too: `example.` in CH is no zone of the stage, served or not by the stages after.
    let mut question = Question::new(dns("ns1.example"), RecordType::A);
    question.qclass = Class::CH;
    let mut query = Message::query(7, question);
    query.header.flags = Flags::RD;
    let mut out = vec![0; 65535];
    let pipeline = mixed(Denial::Refuse);
    let step = pipeline.query(&wire(&query), Transport::Udp, addr(INSIDE), 0, &mut out);
    assert!(matches!(step, Step::Upstream(_)), "{step:?}");
}
