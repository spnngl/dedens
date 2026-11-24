//! Zone transfers out (D214), read by `dedens-net`'s transfer client (D210): AXFR (RFC 5936 §2.2, §3) and IXFR
//! (RFC 1995 §2, §4, §6) of every test zone and the captured root zone, each message signed when the request was
//! (RFC 8945 §5.3.1), refused as the zone's access list (D211) and the transport (RFC 9103 §7.8) say.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use dedens_net::transfer::stream::{Asked, Reader, Step as Read, ixfr_soa};
use dedens_net::transfer::{self, Limits, Transfer as Received};
use dedens_proto::edns::{Edns, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Flags, MAX_MESSAGE_LEN, Message, Name, Rcode, Record, RecordType, Serial, Transport, Ttl,
};
use dedens_server::{
    Action, Authoritative, Grant, History, MESSAGE_LEN, Network, Next, Pipeline, Stage, Step,
    Transfer, ZoneAccess,
};
use dedens_testkit::authoritative::TSIG_KEY;
use dedens_testkit::dns;
use dedens_tsig::{Key, Keyring, ResponseVerifier, sign_request};
use dedens_zone::{At, Changeset, Limits as ZoneLimits, Source, Zone};

use crate::util::{decode, ede, wire};

/// The ID of every request.
const ID: u16 = 0x2a2a;

/// The server's clock, and the time requests are signed at.
const NOW: u64 = 1_750_000_000;

/// The secondary the zones are transferred to.
const SECONDARY: &str = "192.0.2.53";

/// A zone file: its directory under `testdata/`, its name, its apex, and the TTL of its records without one.
type File = (&'static str, &'static str, &'static str, Option<u32>);

/// The zones of the tests: those of `testdata/zones/` the server loads (not `every_type.zone`, of several classes),
/// the captured ones of `testdata/authoritative/zones/`.
const FILES: [File; 8] = [
    ("zones", "rfc1034_root.zone", ".", None),
    ("zones", "rfc1035_isi.zone", "isi.edu.", Some(3600)),
    ("zones", "rfc4035_appendix_a.zone", "example.", None),
    ("zones", "rfc5155_appendix_a.zone", "example.", None),
    ("zones", "nsec3_source.zone", "example.", None),
    ("authoritative/zones", "nsec3_signed.zone", "example.", None),
    (
        "authoritative/zones",
        "zonetransfer.me.zone",
        "zonetransfer.me.",
        None,
    ),
    ("authoritative/zones", "root.zone", ".", None),
];

/// The zone of `file`, its `$INCLUDE` the mailboxes of RFC 1035 §5.3.
fn load((dir, file, apex, ttl): File) -> Arc<Zone> {
    let text = std::fs::read(dedens_testkit::path(dir).join(file)).expect("the zone file");
    let source = Source {
        name: file,
        text: &text,
        default_ttl: ttl.map(Ttl::from_wire),
    };
    let mut include = |_: &str| {
        std::fs::read(dedens_testkit::path("zones/rfc1035_isi_mailboxes.zone"))
            .map_err(|e| e.to_string())
    };
    let loaded = Zone::load(dns(apex), source, &mut include, &ZoneLimits::default());
    Arc::new(loaded.expect(file).zone)
}

/// The captured root zone at serial 2026111401, then 2026112201, loaded once (a debug build takes seconds).
fn roots() -> (Arc<Zone>, Arc<Zone>) {
    static ROOTS: LazyLock<(Arc<Zone>, Arc<Zone>)> = LazyLock::new(|| {
        (
            load(("authoritative/zones", "root-previous.zone", ".", None)),
            load(FILES[7]),
        )
    });
    ROOTS.clone()
}

/// The captures' key.
fn key() -> Key {
    let algorithm = TSIG_KEY.algorithm.parse().expect("an algorithm");
    Key::from_base64(dns(TSIG_KEY.name), algorithm, TSIG_KEY.secret).expect("a secret")
}

/// The access lists of a zone that permits transfers to [`SECONDARY`], unsigned and signed with [`key`].
fn permitting() -> ZoneAccess {
    let network: Network = format!("{SECONDARY}/32").parse().expect("a network");
    let key = key();
    ZoneAccess::default().with(
        Action::Transfer,
        [
            Grant::new([network], None),
            Grant::new([network], Some(&key)),
        ],
    )
}

/// The server of `zone`, with its `history`, permitting transfers to [`SECONDARY`] and holding [`key`].
fn server(zone: Arc<Zone>, history: History) -> Pipeline {
    let apex = zone.apex().clone();
    let stage = Authoritative::guarded([(zone, permitting())]).expect("one zone");
    let keys = Keyring::new([key()]).expect("one key");
    Pipeline::new(vec![Stage::Authoritative(
        stage.with_history(&apex, history),
    )])
    .with_keys(keys, Arc::new(|| NOW))
}

/// The request for `asked` of `zone`, with an OPT record when `edns`, and signed with [`key`] when `signed`, and
/// the verifier of its responses.
fn request<'k>(
    zone: &Name<'static>,
    asked: Asked,
    edns: bool,
    key: Option<&'k Key>,
) -> (Vec<u8>, Option<ResponseVerifier<'k>>) {
    let authority = match asked {
        Asked::Ixfr(serial) => Some(ixfr_soa(zone, serial)),
        Asked::Axfr(_) => None,
    };
    let mut request = transfer::query(zone, asked.qtype(), authority, ID);
    if edns {
        let mut message = decode(&request);
        message.edns = Some(Edns::default());
        request = wire(&message);
    }
    let verifier = key.map(|key| sign_request(key, &mut request, NOW).expect("signed"));
    (request, verifier)
}

/// What `pipeline` answers `request` with, from [`SECONDARY`] over `transport`.
fn ask(pipeline: &Pipeline, request: &[u8], transport: Transport, out: &mut [u8]) -> Step {
    let from: IpAddr = SECONDARY.parse().expect("an address");
    pipeline.query(request, transport, from, 0, out)
}

/// The messages of the transfer `step`, each made with `pipeline`, until it ends.
fn messages(pipeline: &Pipeline, step: Step) -> Vec<Vec<u8>> {
    let Step::Transfer(mut transfer) = step else {
        unreachable!("not a transfer: {step:?}");
    };
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let mut messages = Vec::new();
    loop {
        match transfer.next(pipeline, &mut out) {
            Next::Message(len) => messages.push(out[..len].to_vec()),
            Next::Ended => return messages,
            Next::Cut => unreachable!("cut after {} messages", messages.len()),
        }
    }
}

/// What the client reads of `messages`, the stream of `asked` of `zone`, verified by `verifier` if any. Panics
/// when it refuses one, or when messages follow the end.
fn read(
    zone: &Name<'static>,
    asked: Asked,
    verifier: Option<ResponseVerifier<'_>>,
    messages: &[Vec<u8>],
) -> Received {
    let mut reader = Reader::new(zone.clone(), ID, asked, verifier, &Limits::default());
    for (n, message) in messages.iter().enumerate() {
        match reader.message(message, NOW).expect("a valid message") {
            Read::More(more) => reader = more,
            Read::Done(received) => {
                assert_eq!(n + 1, messages.len(), "messages after the end");
                return received;
            }
        }
    }
    unreachable!("the stream ends early")
}

/// The records of `zone`, its SOA first, as text, sorted.
fn records(zone: &Zone) -> Vec<String> {
    let mut records: Vec<_> = std::iter::once(zone.soa_record())
        .chain(
            zone.transfer_records(At::default())
                .map(|(r, _)| r.into_owned()),
        )
        .map(|record| record.to_string())
        .collect();
    records.sort_unstable();
    records
}

/// The zone of `received`, a whole one.
fn full(received: Received) -> Zone {
    let Received::Full(loaded) = received else {
        unreachable!("not a zone: {received:?}");
    };
    loaded.zone
}

/// The answer of a refused or one-message transfer: the reply step's message.
fn reply<'o>(step: &Step, out: &'o [u8]) -> Message<'o> {
    let Step::Reply(len) = step else {
        unreachable!("not a reply: {step:?}");
    };
    decode(&out[..*len])
}

// --- RFC 5936 §2.2, §3 ---

#[test]
fn s2_2_every_test_zone_is_transferred_whole() {
    for file in FILES {
        let zone = if file.1 == "root.zone" {
            roots().1
        } else {
            load(file)
        };
        let apex = zone.apex().clone();
        let pipeline = server(Arc::clone(&zone), History::default());
        for transport in [Transport::Tcp, Transport::Tls] {
            let (request, _) = request(&apex, Asked::Axfr(None), false, None);
            let mut out = vec![0; MAX_MESSAGE_LEN];
            let step = ask(&pipeline, &request, transport, &mut out);
            let messages = messages(&pipeline, step);
            let received = full(read(&apex, Asked::Axfr(None), None, &messages));
            assert_eq!(records(&received), records(&zone), "{}", file.1);
        }
    }
}

#[test]
fn s2_2_each_message_is_filled_to_16383_bytes_its_header_as_the_rfc_says() {
    let (_, root) = roots();
    let pipeline = server(Arc::clone(&root), History::default());
    let (request, _) = request(&dns("."), Asked::Axfr(None), true, None);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let step = ask(&pipeline, &request, Transport::Tcp, &mut out);
    let messages = messages(&pipeline, step);
    let (last, filled) = messages.split_last().expect("messages");
    // Records are gathered by their length uncompressed, RDATA names compression shortens: a message is filled
    // to 90% at least.
    let lens: Vec<_> = messages.iter().map(Vec::len).collect();
    let filled = filled
        .iter()
        .all(|m| m.len() <= MESSAGE_LEN && m.len() > MESSAGE_LEN / 10 * 9);
    assert!(filled, "{lens:?}");
    assert!(last.len() <= MESSAGE_LEN);
    let records: usize = messages.iter().map(|m| decode(m).answer.len()).sum();
    assert_eq!(records, root.record_count() + 1);
    for (n, message) in messages.iter().enumerate() {
        let message = decode(message);
        assert_eq!(message.header.id, ID);
        // AA, QR, no TC, RA, AD nor CD (§2.2.1), the question in the first only, OPT in each (RFC 9103 §6.3.4).
        assert_eq!(message.header.flags, Flags::QR | Flags::AA);
        assert_eq!(message.rcode(), Rcode::NOERROR);
        assert_eq!(message.questions.len(), usize::from(n == 0));
        assert_eq!(message.authority, []);
        assert!(message.edns.is_some());
    }
}

#[test]
fn s4_2_axfr_over_udp_and_transfers_over_other_transports_are_refused_not_supported() {
    let zone = load(FILES[2]);
    let pipeline = server(zone, History::default());
    let mut out = vec![0; MAX_MESSAGE_LEN];
    for (asked, transport) in [
        (Asked::Axfr(None), Transport::Udp),
        (Asked::Axfr(None), Transport::Quic),
        (Asked::Ixfr(Serial::new(0)), Transport::Https),
    ] {
        let (request, _) = request(&dns("example."), asked, true, None);
        let step = ask(&pipeline, &request, transport, &mut out);
        let reply = reply(&step, &out);
        assert_eq!(reply.rcode(), Rcode::REFUSED, "{transport:?}");
        assert_eq!(ede(&reply), Some(InfoCode::NOT_SUPPORTED));
    }
}

#[test]
fn s2_2_1_a_name_that_is_no_zones_apex_is_notauth() {
    let pipeline = server(load(FILES[2]), History::default());
    let mut out = vec![0; MAX_MESSAGE_LEN];
    for name in ["a.example.", "example.org."] {
        let (request, _) = request(&dns(name), Asked::Axfr(None), false, None);
        let step = ask(&pipeline, &request, Transport::Tcp, &mut out);
        assert_eq!(reply(&step, &out).rcode(), Rcode::NOTAUTH, "{name}");
    }
}

// --- RFC 5936 §5, D211 ---

#[test]
fn s5_a_client_the_access_list_does_not_permit_is_refused_prohibited() {
    let zone = load(FILES[2]);
    let pipeline = Pipeline::new(vec![Stage::Authoritative(
        Authoritative::new([zone]).expect("one zone"),
    )]);
    let (request, _) = request(&dns("example."), Asked::Axfr(None), true, None);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let step = ask(&pipeline, &request, Transport::Tcp, &mut out);
    let reply = reply(&step, &out);
    assert_eq!(reply.rcode(), Rcode::REFUSED);
    assert_eq!(ede(&reply), Some(InfoCode::PROHIBITED));
}

// --- RFC 8945 §5.3.1 ---

#[test]
fn s5_3_1_every_message_of_a_signed_transfer_is_signed() {
    let (_, root) = roots();
    let pipeline = server(Arc::clone(&root), History::default());
    let key = key();
    let (request, verifier) = request(&dns("."), Asked::Axfr(None), true, Some(&key));
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let step = ask(&pipeline, &request, Transport::Tcp, &mut out);
    let messages = messages(&pipeline, step);
    assert!(messages.len() > 50, "{} messages", messages.len());
    // The reader verifies each message's TSIG over the one before (RFC 8945 §5.3.1).
    let received = full(read(&dns("."), Asked::Axfr(None), verifier, &messages));
    assert_eq!(received.record_count(), root.record_count());
}

#[test]
fn s5_3_1_a_key_a_reload_revokes_cuts_the_transfer_at_the_next_message() {
    let zone = load(FILES[6]);
    let pipeline = server(Arc::clone(&zone), History::default());
    let key = key();
    let (request, _) = request(zone.apex(), Asked::Axfr(None), false, Some(&key));
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let Step::Transfer(mut transfer) = ask(&pipeline, &request, Transport::Tcp, &mut out) else {
        unreachable!("a transfer");
    };
    let reloaded = Pipeline::new(vec![]).with_keys(
        Keyring::new([
            Key::from_base64(dns("other"), key.algorithm(), TSIG_KEY.secret).expect("a secret"),
        ])
        .expect("a key"),
        Arc::new(|| NOW),
    );
    assert_eq!(transfer.next(&reloaded, &mut out), Next::Cut);
    assert!(matches!(
        transfer.next(&pipeline, &mut out),
        Next::Message(_)
    ));
}

#[test]
fn s6_3_3_a_transfer_over_the_limit_is_answered_servfail_signed() {
    let zone = load(FILES[6]);
    let pipeline = server(Arc::clone(&zone), History::default());
    let key = key();
    let (request, verifier) = request(zone.apex(), Asked::Axfr(None), true, Some(&key));
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let Step::Transfer(transfer) = ask(&pipeline, &request, Transport::Tcp, &mut out) else {
        unreachable!("a transfer");
    };
    let refused: Box<Transfer> = transfer;
    let len = refused
        .refuse(&pipeline, (Rcode::SERVFAIL, None), &mut out)
        .expect("written");
    let mut verifier = verifier.expect("signed");
    assert!(verifier.verify(&out[..len], NOW).is_ok());
    let reply = decode(&out[..len]);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(reply.questions.len(), 1);
    assert!(!reply.header.flags.contains(Flags::AA));
}

// --- RFC 1995 §2, §4, §6 ---

/// The history of the root from its previous serial to its current one.
fn root_history() -> (Arc<Zone>, Arc<Zone>, History) {
    let (previous, current) = roots();
    let changeset = Zone::diff(&previous, &current).expect("a difference");
    let history = History::default().with(changeset, current.record_count());
    (previous, current, history)
}

#[test]
fn s4_an_ixfr_from_a_serial_in_the_history_gets_the_changes() {
    let (previous, current, history) = root_history();
    let pipeline = server(Arc::clone(&current), history);
    let key = key();
    for signer in [None, Some(&key)] {
        let asked = Asked::Ixfr(Serial::new(previous.soa().serial));
        let (request, verifier) = request(&dns("."), asked, true, signer);
        let mut out = vec![0; MAX_MESSAGE_LEN];
        let step = ask(&pipeline, &request, Transport::Tcp, &mut out);
        assert!(matches!(&step, Step::Transfer(transfer) if transfer.incremental()));
        let messages = messages(&pipeline, step);
        let Received::Incremental(changes) = read(&dns("."), asked, verifier, &messages) else {
            unreachable!("not the changes");
        };
        let expected = Zone::diff(&previous, &current).expect("a difference");
        assert_eq!(changes, [expected]);
    }
}

#[test]
fn s6_changes_are_condensed_into_one() {
    let (previous, current) = roots();
    let middle = Serial::new(previous.soa().serial)
        .checked_add(1)
        .expect("a serial");
    let diff = Zone::diff(&previous, &current).expect("a difference");
    // previous → middle (the SOA alone), middle → current (the records).
    let soa = |serial: Serial| {
        let mut soa = previous.soa().clone();
        soa.serial = serial.get();
        Record::new(
            dns("."),
            previous.class(),
            previous.soa_ttl(),
            &RData::Soa(soa),
        )
    };
    let first =
        Changeset::new(previous.soa_record(), soa(middle), vec![], vec![]).expect("a changeset");
    let second = Changeset::new(
        soa(middle),
        current.soa_record(),
        diff.removed().to_vec(),
        diff.added().to_vec(),
    )
    .expect("a changeset");
    let history = History::default()
        .with(first, current.record_count())
        .with(second, current.record_count());
    assert_eq!(history.len(), 2);
    let pipeline = server(Arc::clone(&current), history);
    let asked = Asked::Ixfr(Serial::new(previous.soa().serial));
    let (request, _) = request(&dns("."), asked, false, None);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let step = ask(&pipeline, &request, Transport::Tcp, &mut out);
    let Received::Incremental(changes) = read(&dns("."), asked, None, &messages(&pipeline, step))
    else {
        unreachable!("not the changes");
    };
    assert_eq!(changes, [diff]);
}

#[test]
fn s4_the_history_keeps_twenty_changesets_and_no_more_records_than_the_zone() {
    let (previous, current) = roots();
    let soa = |serial: u32| {
        let mut soa = previous.soa().clone();
        soa.serial = serial;
        Record::new(
            dns("."),
            previous.class(),
            previous.soa_ttl(),
            &RData::Soa(soa),
        )
    };
    let diff = Zone::diff(&previous, &current).expect("a difference");
    let record = diff.added()[0].clone();
    // `steps` changesets of one record each, added then removed, for a zone of `zone` records.
    let start = previous.soa().serial;
    let chain = |steps: u32, zone: usize| {
        (start..start + steps).fold(History::default(), |history, serial| {
            let one = vec![record.clone()];
            let (removed, added) = if serial % 2 == 0 {
                (vec![], one)
            } else {
                (one, vec![])
            };
            let step = Changeset::new(soa(serial), soa(serial + 1), removed, added);
            history.with(step.expect("a changeset"), zone)
        })
    };
    let deep = chain(22, 1000);
    assert_eq!(deep.len(), History::DEPTH);
    assert_eq!(deep.tip(), Some(Serial::new(start + 22)));
    assert_eq!(chain(21, 20).len(), History::DEPTH);

    let records = diff.removed().len() + diff.added().len();
    assert!(!History::default().with(diff.clone(), records).is_empty());
    assert!(History::default().with(diff, records - 1).is_empty());
}

#[test]
fn s4_an_ixfr_from_a_serial_not_in_the_history_gets_the_zone() {
    let (_, current, history) = root_history();
    let pipeline = server(Arc::clone(&current), history);
    let asked = Asked::Ixfr(Serial::new(1));
    let (request, _) = request(&dns("."), asked, false, None);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let step = ask(&pipeline, &request, Transport::Tcp, &mut out);
    assert!(matches!(&step, Step::Transfer(transfer) if !transfer.incremental()));
    let received = full(read(&dns("."), asked, None, &messages(&pipeline, step)));
    assert_eq!(received.record_count(), current.record_count());
}

#[test]
fn s2_an_ixfr_from_the_current_serial_or_over_udp_gets_the_soa() {
    let (previous, current, history) = root_history();
    let pipeline = server(Arc::clone(&current), history);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    for (serial, transport) in [
        (current.soa().serial, Transport::Tcp),
        (current.soa().serial.wrapping_add(1), Transport::Tcp),
        (previous.soa().serial, Transport::Udp),
    ] {
        let asked = Asked::Ixfr(Serial::new(serial));
        let (request, _) = request(&dns("."), asked, true, None);
        let step = ask(&pipeline, &request, transport, &mut out);
        let reply = reply(&step, &out);
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AA));
        assert_eq!(
            reply.answer,
            [current.soa_record()],
            "{serial} over {transport:?}"
        );
    }
}

#[test]
fn s3_an_ixfr_without_the_clients_soa_is_formerr() {
    let pipeline = server(load(FILES[2]), History::default());
    let (request, _) = request(&dns("example."), Asked::Axfr(None), false, None);
    let mut message = decode(&request);
    message.questions[0].qtype = RecordType::IXFR;
    let mut out = vec![0; MAX_MESSAGE_LEN];
    let step = ask(&pipeline, &wire(&message), Transport::Tcp, &mut out);
    assert_eq!(reply(&step, &out).rcode(), Rcode::FORMERR);
}
