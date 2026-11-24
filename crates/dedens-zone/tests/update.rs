//! UPDATE requests made to a zone (RFC 2136 §3.2, §3.4.2, §3.6, RFC 2181 §10.1, RFC 3007 §3.1.1, D216).
//!
//! Each `update-*` recording of `testdata/authoritative/recordings/` (D203) sent `knsupdate`'s request to Knot DNS
//! 3.6.2 serving `example.`, then took the zone by AXFR. The zone before is `axfr-open`'s transfer. `example.` is
//! signed there and Knot does not sign (`dnssec-signing: off`): its RRSIG and NSEC records are data to Knot and
//! out of reach of the requests, so both sides are compared without them, and the zone here is unsigned, which an
//! update may change (a signed one is refused, D216).

use dedens_proto::rdata::{RData, Soa};
use dedens_proto::{Class, Message, Rcode, Record, RecordType, Ttl, Update};
use dedens_testkit::authoritative::{Peer, Recording, Transport};
use dedens_testkit::dns;
use dedens_zone::{Limits, Rejection, Updated, Zone};

/// The messages of `recording` from `from` over `transport`, decoded.
fn messages(recording: &Recording, from: Peer, transport: Transport) -> Vec<Message<'static>> {
    recording
        .messages
        .iter()
        .filter(|packet| packet.from == from && packet.transport == transport)
        .map(|packet| {
            Message::decode(&packet.message)
                .expect("a message")
                .message
                .into_owned()
        })
        .collect()
}

/// The records of an AXFR's answers, without the closing SOA, and without what signing makes.
fn transferred(answers: &[Message<'static>]) -> Vec<Record<'static>> {
    let mut records: Vec<_> = answers
        .iter()
        .flat_map(|message| message.answer.iter().cloned())
        .collect();
    records.pop();
    unsigned(records)
}

fn unsigned(records: Vec<Record<'static>>) -> Vec<Record<'static>> {
    records
        .into_iter()
        .filter(|record| {
            !matches!(
                record.rtype(),
                RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM
            )
        })
        .collect()
}

fn zone(records: Vec<Record<'static>>) -> Zone {
    Zone::from_records(dns("example."), records, &Limits::default())
        .map_err(|report| report.to_string())
        .expect("example.")
        .zone
}

/// `example.` as `axfr-open` transferred it, unsigned.
fn before() -> Zone {
    let recording = Recording::read("axfr-open");
    zone(transferred(&messages(
        &recording,
        Peer::Server,
        Transport::Tcp,
    )))
}

/// What `request` does to `zone` here: the RCODE and the zone after.
fn made(zone: &Zone, request: Message<'static>) -> (Rcode, Zone) {
    let update = match Update::read(request) {
        Ok(update) => update,
        Err(error) => return (error.rcode(), zone.clone()),
    };
    match zone.update(&update, &Limits::default()) {
        Ok(Some(Updated { loaded, .. })) => (Rcode::NOERROR, loaded.zone),
        Ok(None) => (Rcode::NOERROR, zone.clone()),
        Err(rejection) => (rejection.rcode(), zone.clone()),
    }
}

/// Every unsigned request to `example.` gets Knot's RCODE and leaves the zone Knot's AXFR shows, its serial
/// included: one up for a change (§3.6), the same for none, as an update that only adds what is there or deletes
/// what is not, or that §3.4.2 ignores (the SOA, the apex's NS, a CNAME beside data).
#[test]
fn rfc2136_s3_every_captured_update_gives_knots_rcode_and_zone() {
    let before = before();
    let mut checked = 0;
    for id in Recording::ids()
        .into_iter()
        .filter(|id| id.starts_with("update-"))
    {
        let recording = Recording::read(&id);
        if recording.zone != dns("example.") || recording.key.is_some() {
            continue;
        }
        let request = messages(&recording, Peer::Client, Transport::Udp)
            .into_iter()
            .next()
            .expect("a request");
        let reply = messages(&recording, Peer::Server, Transport::Udp)
            .into_iter()
            .next()
            .expect("a reply");
        let knot = zone(transferred(&messages(
            &recording,
            Peer::Server,
            Transport::Tcp,
        )));
        let (rcode, after) = made(&before, request);
        assert_eq!(rcode, reply.rcode(), "{id}: the RCODE");
        assert_eq!(after, knot, "{id}: the zone after");
        checked += 1;
    }
    assert_eq!(checked, 21);
}

/// The SOA record of `zone`, its serial `serial`.
fn soa(zone: &Zone, serial: u32) -> Record<'static> {
    let soa = Soa {
        serial,
        ..zone.soa().clone()
    };
    Record::new(
        zone.apex().clone(),
        zone.class(),
        zone.soa_ttl(),
        &RData::Soa(soa),
    )
}

/// The UPDATE of `example.` that makes `changes`, a request built from `update-add-name`'s.
fn request(changes: Vec<Record<'static>>) -> Message<'static> {
    let recording = Recording::read("update-add-name");
    let mut message = messages(&recording, Peer::Client, Transport::Udp)
        .into_iter()
        .next()
        .expect("a request");
    message.authority = changes;
    message
}

/// RFC 2136 §3.4.2.2, §3.6: an SOA ahead replaces the apex's, its TTL too, and is the new version's, its serial
/// not raised again; one behind or level is ignored.
#[test]
fn rfc2136_s3_4_2_2_an_soa_ahead_replaces_the_apexs() {
    let before = before();
    let serial = before.soa().serial;
    let (rcode, after) = made(&before, request(vec![soa(&before, serial + 10)]));
    assert_eq!((rcode, after.soa().serial), (Rcode::NOERROR, serial + 10));
    let ttl = Ttl::new(60).expect("a TTL");
    let shorter = Record {
        ttl,
        ..soa(&before, serial + 1)
    };
    let (rcode, after) = made(&before, request(vec![shorter]));
    assert_eq!((rcode, after.soa_ttl()), (Rcode::NOERROR, ttl));
    let (rcode, after) = made(&before, request(vec![soa(&before, serial)]));
    assert_eq!((rcode, after.soa().serial), (Rcode::NOERROR, serial));
    let (rcode, after) = made(&before, request(vec![soa(&before, serial - 1)]));
    assert_eq!((rcode, after), (Rcode::NOERROR, before.clone()));
}

/// RFC 2136 §3.4.2.2, RFC 2181 §5.2: a record added to an `RRset` gives the set its TTL, as Knot's
/// `solve_add_different_ttl` does; a record already there with another TTL only changes the TTL.
#[test]
fn rfc2136_s3_4_2_2_an_added_record_sets_its_rrsets_ttl() {
    let before = before();
    let ns1 = before
        .node(&dns("ns1.example."))
        .and_then(|node| node.rrset(RecordType::A))
        .expect("an A RRset")
        .clone();
    let mut record = Record::new(
        dns("ns1.example."),
        before.class(),
        dedens_proto::Ttl::from_wire(60),
        &ns1.rdatas()[0].data(),
    );
    let (_, after) = made(&before, request(vec![record.clone()]));
    let set = after
        .node(&dns("ns1.example."))
        .and_then(|node| node.rrset(RecordType::A))
        .expect("an A RRset");
    assert_eq!((set.ttl().get(), set.rdatas().len()), (60, 1));
    assert_eq!(after.soa().serial, before.soa().serial + 1);
    record.name = dns("ns2.example.");
    let (_, after) = made(&before, request(vec![record]));
    let set = after
        .node(&dns("ns2.example."))
        .and_then(|node| node.rrset(RecordType::A))
        .expect("an A RRset");
    assert_eq!((set.ttl().get(), set.rdatas().len()), (60, 2));
}

/// RFC 3007 §3.1.1 (NXT, now NSEC and NSEC3) and D216: the records signing makes are refused, REFUSED.
#[test]
fn rfc3007_s3_1_1_the_records_of_signing_are_refused() {
    let signed = Zone::from_records(
        dns("example."),
        {
            let recording = Recording::read("axfr-open");
            let mut records: Vec<_> = messages(&recording, Peer::Server, Transport::Tcp)
                .iter()
                .flat_map(|message| message.answer.iter().cloned())
                .collect();
            records.pop();
            records
        },
        &Limits::default(),
    )
    .expect("example.")
    .zone;
    let before = before();
    let nsec = signed
        .node(&dns("example."))
        .and_then(|node| node.rrset(RecordType::NSEC))
        .expect("an NSEC")
        .rdatas()[0]
        .clone();
    let record = Record {
        name: dns("example."),
        class: before.class(),
        ttl: dedens_proto::Ttl::from_wire(3600),
        rdata: nsec,
    };
    let update = Update::read(request(vec![record])).expect("an update");
    assert_eq!(
        before.update(&update, &Limits::default()).err(),
        Some(Rejection::Dnssec(RecordType::NSEC))
    );
    let add = Update::read(request(Vec::new())).expect("an update");
    assert_eq!(
        signed.update(&add, &Limits::default()).err(),
        Some(Rejection::Signed)
    );

    // Signatures without a chain are a signed zone too: a change would leave them stale.
    let records: Vec<_> = {
        let recording = Recording::read("axfr-open");
        let mut records: Vec<_> = messages(&recording, Peer::Server, Transport::Tcp)
            .iter()
            .flat_map(|message| message.answer.iter().cloned())
            .filter(|record| record.rtype() != RecordType::NSEC)
            .collect();
        records.pop();
        records
    };
    let unchained = zone(records);
    assert_eq!(
        unchained.update(&add, &Limits::default()).err(),
        Some(Rejection::Signed)
    );
}

/// RFC 2136 §3.4.2.4: deleting every `RRset` of the apex keeps its SOA and NS.
#[test]
fn rfc2136_s3_4_2_4_the_apex_keeps_its_soa_and_ns() {
    let before = before();
    let any = Record::from_wire(&[0, 0, 255, 0, 255, 0, 0, 0, 0, 0, 0])
        .expect("ANY ANY at the root")
        .0
        .record
        .into_owned();
    let delete = Record {
        name: dns("example."),
        ..any
    };
    let (rcode, after) = made(&before, request(vec![delete]));
    assert_eq!(rcode, Rcode::NOERROR);
    let apex = after.node(&dns("example.")).expect("the apex");
    let kept: Vec<_> = apex.rrsets().map(|(rtype, _)| rtype).collect();
    assert_eq!(kept, [RecordType::NS, RecordType::SOA]);
}

/// RFC 2136 §3.4.2.4: deleting the apex's NS records one by one keeps the last, other `RRset`s of the apex go with
/// their last record.
#[test]
fn rfc2136_s3_4_2_4_the_apexs_last_ns_is_kept() {
    let before = before();
    let apex = dns("example.");
    let rdatas = |zone: &Zone, rtype| -> Vec<_> {
        zone.node(&apex)
            .and_then(|node| node.rrset(rtype))
            .map(|set| set.rdatas().to_vec())
            .unwrap_or_default()
    };
    let ns = rdatas(&before, RecordType::NS);
    let mx = rdatas(&before, RecordType::MX);
    assert_eq!((ns.len(), mx.len()), (2, 1));
    let delete = ns.iter().chain(&mx).map(|rdata| Record {
        name: apex.clone(),
        class: Class::NONE,
        ttl: Ttl::ZERO,
        rdata: rdata.clone(),
    });
    let (rcode, after) = made(&before, request(delete.collect()));
    assert_eq!(rcode, Rcode::NOERROR);
    assert_eq!(rdatas(&after, RecordType::NS), ns[1..]);
    assert_eq!(rdatas(&after, RecordType::MX), []);
}

/// RFC 2136 §3.4.2.3: the NS `RRset` of a delegation is deleted, by its type or with its name; only the apex's is
/// kept.
#[test]
fn rfc2136_s3_4_2_3_a_delegations_ns_is_deleted() {
    let before = before();
    let delete = |rtype: u8, name: &str| {
        let any = Record::from_wire(&[0, 0, rtype, 0, 255, 0, 0, 0, 0, 0, 0])
            .expect("a record of class ANY at the root")
            .0
            .record
            .into_owned();
        Record {
            name: dns(name),
            ..any
        }
    };
    // NS, then ANY.
    for (rtype, name) in [(2, "b.example."), (255, "a.example.")] {
        let has_ns = |zone: &Zone| {
            zone.node(&dns(name))
                .is_some_and(|node| node.rrset(RecordType::NS).is_some())
        };
        assert!(has_ns(&before), "{name}");
        let (rcode, after) = made(&before, request(vec![delete(rtype, name)]));
        assert_eq!(rcode, Rcode::NOERROR, "{name}");
        assert!(!has_ns(&after), "{name}");
    }
}

/// RFC 2136 §2.4.2, §3.2.3: an `RRset` exists with given values when its RDATAs are those, in any order: as many
/// others is NXRRSET.
#[test]
fn rfc2136_s3_2_3_values_compare_as_a_set() {
    let before = before();
    let ns = |host: &str| Record::new(dns("example."), Class::IN, Ttl::ZERO, &RData::Ns(dns(host)));
    for (hosts, expected) in [
        (["ns2.example.", "ns1.example."], Rcode::NOERROR),
        (["ns1.example.", "ns3.example."], Rcode::NXRRSET),
    ] {
        let mut message = request(Vec::new());
        message.answer = hosts.map(ns).to_vec();
        assert_eq!(made(&before, message).0, expected, "{hosts:?}");
    }
}

/// RFC 2136 §3.4.2.2: a CNAME added to a name without data is added, and another one then replaces it; other data
/// added beside it is ignored (RFC 2181 §10.1).
#[test]
fn rfc2136_s3_4_2_2_a_cname_replaces_a_cname() {
    let alias = dns("alias.example.");
    let cname = |target: &str| {
        let ttl = Ttl::new(300).expect("a TTL");
        Record::new(alias.clone(), Class::IN, ttl, &RData::Cname(dns(target)))
    };
    let targets = |zone: &Zone| -> Vec<String> {
        zone.node(&alias)
            .and_then(|node| node.rrset(RecordType::CNAME))
            .map(|set| set.rdatas().iter().map(|r| r.data().to_string()).collect())
            .unwrap_or_default()
    };
    let (rcode, first) = made(&before(), request(vec![cname("a.example.")]));
    assert_eq!(
        (rcode, targets(&first)),
        (Rcode::NOERROR, vec!["a.example.".to_owned()])
    );
    let (rcode, second) = made(&first, request(vec![cname("ai.example.")]));
    assert_eq!(
        (rcode, targets(&second)),
        (Rcode::NOERROR, vec!["ai.example.".to_owned()])
    );
    let a = Record::new(
        alias.clone(),
        Class::IN,
        Ttl::new(300).expect("a TTL"),
        &RData::A([192, 0, 2, 1].into()),
    );
    let (rcode, third) = made(&second, request(vec![a]));
    assert_eq!(rcode, Rcode::NOERROR);
    assert!(third == second, "the A beside the CNAME is ignored");
}

/// RFC 2136 §3.1.1: a request for another zone, or for the zone's name in another class, is not the zone's: NOTAUTH.
#[test]
fn rfc2136_s3_1_1_another_zone_is_notauth() {
    let before = before();
    let mut other = request(Vec::new());
    other.questions[0].name = dns("example.org.");
    let mut chaos = request(Vec::new());
    chaos.questions[0].qclass = Class::CH;
    for request in [other, chaos] {
        let update = Update::read(request).expect("a request");
        let rejection = before.update(&update, &Limits::default()).err();
        assert!(
            matches!(rejection, Some(Rejection::OtherZone)),
            "{rejection:?}"
        );
    }
}
