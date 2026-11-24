//! UPDATE requests in the pipeline (RFC 2136 §3, RFC 3007 §3, D216): read whole, their zone found and their client
//! permitted by the zone's access list (D211), then handed to the server as [`Step::Update`], whose reply
//! [`Pipeline::updated`] writes (§3.8) and signs when the request was (RFC 8945 §5.3). The requests are `knsupdate`'s
//! to Knot DNS 3.6.2, captured (D203).

use std::net::IpAddr;
use std::sync::Arc;

use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Message, Opcode, Rcode, Transport};
use dedens_server::{
    Action, Authoritative, Grant, Network, Pipeline, Stage, Step, Updating, ZoneAccess,
};
use dedens_testkit::authoritative::{Peer, Recording};
use dedens_testkit::dns;
use dedens_tsig::{Keyring, ResponseVerifier, Verified};
use dedens_zone::{Limits, Zone};

use crate::authoritative::example;
use crate::tsig::{captured, key};
use crate::util::decode;

/// The address the requests come from.
const CLIENT: &str = "192.0.2.1";

/// The zone `zonetransfer.me.` of the captures, the one the signed requests update.
fn zonetransfer() -> Arc<Zone> {
    let records = dedens_testkit::authoritative::zone("zonetransfer.me.zone");
    let loaded = Zone::from_records(dns("zonetransfer.me."), records, &Limits::default());
    Arc::new(loaded.expect("the zone").zone)
}

/// The access lists permitting updates to every client, its requests signed with `key` or unsigned without.
fn updaters(key: Option<&dedens_tsig::Key>) -> ZoneAccess {
    let any: [Network; 2] = [
        "0.0.0.0/0".parse().expect("a network"),
        "::/0".parse().expect("a network"),
    ];
    ZoneAccess::default().with(Action::Update, [Grant::new(any, key)])
}

/// A server for `example.` open to unsigned updates, as Knot's of the captures, and for `zonetransfer.me.` to
/// updates signed with the captures' key; it verifies with that key, its clock at `now`.
fn server(now: u64) -> Pipeline {
    let key = key();
    let stage = Authoritative::guarded([
        (example(), updaters(None)),
        (zonetransfer(), updaters(Some(&key))),
    ])
    .expect("two zones");
    let keys = Keyring::new([key]).expect("one key");
    Pipeline::new(vec![Stage::Authoritative(stage)]).with_keys(keys, Arc::new(move || now))
}

/// The step of `pipeline` for `request`, and the bytes of a reply.
fn step(pipeline: &Pipeline, request: &[u8], transport: Transport) -> (Step, Vec<u8>) {
    let from: IpAddr = CLIENT.parse().expect("an address");
    let mut out = vec![0; 65535];
    let step = pipeline.query(request, transport, from, 0, &mut out);
    let reply = match step {
        Step::Reply(len) => out[..len].to_vec(),
        _ => Vec::new(),
    };
    (step, reply)
}

/// The reply of `pipeline` to `updating` with `rcode`.
fn updated(pipeline: &Pipeline, updating: &Updating, rcode: Rcode) -> Vec<u8> {
    let mut out = vec![0; 65535];
    let Step::Reply(len) = pipeline.updated(updating, rcode, None, &mut out) else {
        unreachable!("a reply");
    };
    out[..len].to_vec()
}

/// Knot's reply in the capture `id`.
fn knots_reply(id: &str) -> Vec<u8> {
    (Recording::read(id).messages.into_iter())
        .find(|packet| packet.from == Peer::Server)
        .expect("a reply")
        .message
}

/// §3.8: every unsigned request to `example.` Knot made reaches the server, and the reply to it, with the RCODE
/// Knot gave, is Knot's to the byte: the header and the zone section of the request. The one outside the zone is
/// NOTZONE before it reaches it (§3.4.1.3).
#[test]
fn rfc2136_s3_8_the_replies_are_knots() {
    let pipeline = server(0);
    let mut made = 0;
    for id in Recording::ids()
        .into_iter()
        .filter(|id| id.starts_with("update-"))
    {
        let recording = Recording::read(&id);
        if recording.zone != dns("example.") || recording.key.is_some() {
            continue;
        }
        let (request, transport) = captured(&id);
        let knot = knots_reply(&id);
        let (step, reply) = step(&pipeline, &request, transport);
        if let Step::Update(updating) = step {
            assert_eq!(updating.update().zone(), &dns("example."), "{id}");
            let rcode = decode(&knot).rcode();
            assert_eq!(updated(&pipeline, &updating, rcode), knot, "{id}");
            made += 1;
        } else {
            assert_eq!(id, "update-add-outside-zone");
            assert_eq!(reply, knot, "{id}");
        }
    }
    assert_eq!(made, 20);
}

/// RFC 8945 §5.3, D211: a signed request of a client the access list permits is handed on, and the reply to it
/// is signed with its key.
#[test]
fn rfc8945_s5_3_a_signed_update_is_answered_signed() {
    let key = key();
    let (request, transport) = captured("update-signed");
    let record = dedens_proto::find_tsig(&request)
        .expect("well formed")
        .expect("signed");
    let time = record.tsig.time_signed();
    let pipeline = server(time);
    let (Step::Update(updating), _) = step(&pipeline, &request, transport) else {
        unreachable!("an update");
    };
    assert_eq!(updating.update().zone(), &dns("zonetransfer.me."));
    let reply = updated(&pipeline, &updating, Rcode::NOERROR);
    let mut verifier = ResponseVerifier::new(&key, record.tsig.mac());
    assert_eq!(verifier.verify(&reply, time).ok(), Some(Verified::Signed));
    let reply = decode(&reply);
    assert_eq!(
        (reply.rcode(), reply.header.opcode),
        (Rcode::NOERROR, Opcode::UPDATE)
    );
}

/// RFC 2136 §3.3, RFC 3007 §3, D211: a client the access list does not permit is REFUSED, signed when its request
/// is: unsigned to `zonetransfer.me.`, signed with a key `example.`'s list does not name; with EDE 18 to a client
/// with EDNS. Knot says NOTAUTH to both (D211).
#[test]
fn rfc2136_s3_3_a_client_not_permitted_is_refused() {
    let key = key();
    for id in ["update-unsigned-refused", "update-signed-key-not-allowed"] {
        let (request, transport) = captured(id);
        let record = dedens_proto::find_tsig(&request).expect("well formed");
        let time = record
            .as_ref()
            .map_or(0, |record| record.tsig.time_signed());
        let (step, reply) = step(&server(time), &request, transport);
        assert!(matches!(step, Step::Reply(_)), "{id}: {step:?}");
        if let Some(record) = record {
            let mut verifier = ResponseVerifier::new(&key, record.tsig.mac());
            assert_eq!(
                verifier.verify(&reply, time).ok(),
                Some(Verified::Signed),
                "{id}"
            );
        }
        assert_eq!(decode(&reply).rcode(), Rcode::REFUSED, "{id}");
        assert_eq!(decode(&knots_reply(id)).rcode(), Rcode::NOTAUTH, "{id}");
    }
    // With EDNS, the reason.
    let (request, transport) = captured("update-unsigned-refused");
    let mut message = Message::decode(&request).expect("a message").message;
    message.edns = Some(dedens_proto::edns::Edns::default());
    let request = message.to_vec().expect("a message");
    let (_, reply) = step(&server(0), &request, transport);
    let options = decode(&reply).edns.expect("our OPT record").options;
    assert!(
        matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::PROHIBITED),
        "{options:?}"
    );
}

/// RFC 2136 §3.1.1: an update of a zone the server does not serve is NOTAUTH, one of a name below a zone it does
/// too: the zone section names the zone's apex.
#[test]
fn rfc2136_s3_1_1_a_zone_not_served_is_notauth() {
    let pipeline = Pipeline::new(vec![Stage::Authoritative(
        Authoritative::guarded([(example(), updaters(None))]).expect("one zone"),
    )]);
    let (request, transport) = captured("update-add-name");
    for zone in ["example.org.", "a.example."] {
        let mut message = Message::decode(&request).expect("a message").message;
        message.questions[0].name = dns(zone);
        message.authority.clear();
        let request = message.to_vec().expect("a message");
        let (_, reply) = step(&pipeline, &request, transport);
        assert_eq!(decode(&reply).rcode(), Rcode::NOTAUTH, "{zone}");
    }
}

/// D41: without an authoritative stage, an UPDATE is not implemented.
#[test]
fn without_zones_an_update_is_notimp() {
    let (request, transport) = captured("update-add-name");
    let (_, reply) = step(&Pipeline::new(Vec::new()), &request, transport);
    assert_eq!(decode(&reply).rcode(), Rcode::NOTIMP);
}
