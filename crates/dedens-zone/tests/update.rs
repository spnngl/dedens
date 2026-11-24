//! UPDATE requests made to a zone (RFC 2136 §3.2, §3.4.2, §3.6, RFC 2181 §10.1, RFC 3007 §3.1.1, D216).
//!
//! Each `update-*` recording of `testdata/authoritative/recordings/` (D203) sent `knsupdate`'s request to Knot DNS
//! 3.6.2 serving `example.`, then took the zone by AXFR. The zone before is `axfr-open`'s transfer. `example.` is
//! signed there and Knot does not sign (`dnssec-signing: off`): its RRSIG and NSEC records are data to Knot and
//! out of reach of the requests, so both sides are compared without them, and the zone here is unsigned, which an
//! update may change (a signed one is refused, D216).

use dedens_proto::rdata::{RData, Soa};
use dedens_proto::{Message, Rcode, Record, RecordType, Update};
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

/// RFC 2136 §3.4.2.2, §3.6: an SOA ahead replaces the apex's and is the new version's, its serial not raised
/// again; one behind or level is ignored.
#[test]
fn rfc2136_s3_4_2_2_an_soa_ahead_replaces_the_apexs() {
    let before = before();
    let serial = before.soa().serial;
    let (rcode, after) = made(&before, request(vec![soa(&before, serial + 10)]));
    assert_eq!((rcode, after.soa().serial), (Rcode::NOERROR, serial + 10));
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
