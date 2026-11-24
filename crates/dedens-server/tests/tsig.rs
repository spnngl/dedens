//! Signed requests in the pipeline (D211, RFC 8945): the TSIG of a request is verified whatever its opcode (§5.2),
//! its failures are answered as §5.3.2 says, and the reply to a signed request is signed with its key (§5.3),
//! within the client's UDP payload. The requests are Knot's, captured (D203), or signed by `dedens-tsig`'s client
//! (D205), which verifies the replies.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use dedens_proto::edns::{Cookie, Edns, EdnsFlags, EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, Flags, Message, Opcode, Question, Rcode, Record, RecordType, Transport, Tsig, TsigError,
    TsigRecord, Ttl, find_tsig,
};
use dedens_server::{Cookies, Forward, Pipeline, Secret, Secrets, Stage, Step};
use dedens_testkit::authoritative::{self, Peer, Recording, TSIG_KEY};
use dedens_testkit::dns;
use dedens_tsig::{
    Algorithm, Key, Keyring, ResponseError, ResponseVerifier, Verified, sign_request,
};

use crate::authoritative::zones;
use crate::util::{decode, servers, wire};

/// When the queries this module signs are: any time will do, the server's clock is set to it.
const NOW: u64 = 1_750_000_000;

/// The key the captures were signed with, as Knot holds it.
pub(crate) fn key() -> Key {
    Key::from_base64(
        dns(TSIG_KEY.name),
        TSIG_KEY.algorithm.parse().expect("an algorithm"),
        TSIG_KEY.secret,
    )
    .expect("a valid secret")
}

/// `stages` verifying requests with [`key`], the clock at `now`.
fn signing(stages: Vec<Stage>, now: u64) -> Pipeline {
    let keys = Keyring::new([key()]).expect("one key");
    Pipeline::new(stages).with_keys(keys, Arc::new(move || now))
}

/// An authoritative server for `example.` verifying with [`key`], its clock at `now`.
fn server(now: u64) -> Pipeline {
    signing(vec![zones()], now)
}

/// The first request of the capture `id`, and its transport.
pub(crate) fn captured(id: &str) -> (Vec<u8>, Transport) {
    let packet = (Recording::read(id).messages.into_iter())
        .find(|packet| packet.from == Peer::Client)
        .expect("a request");
    let transport = match packet.transport {
        authoritative::Transport::Udp => Transport::Udp,
        authoritative::Transport::Tcp => Transport::Tcp,
    };
    (packet.message, transport)
}

fn tsig(wire: &[u8]) -> TsigRecord<'_> {
    find_tsig(wire).expect("well formed").expect("signed")
}

/// The reply of `pipeline` to `request` over `transport`.
fn answer(pipeline: &Pipeline, request: &[u8], transport: Transport) -> Vec<u8> {
    let from: IpAddr = "192.0.2.1".parse().expect("an address");
    let mut out = vec![0; 65535];
    let step = pipeline.query(request, transport, from, 0, &mut out);
    let Step::Reply(len) = step else {
        unreachable!("no reply: {step:?}");
    };
    out.truncate(len);
    out
}

/// `query` signed with [`key`] at [`NOW`], and the verifier of its reply.
fn signed<'k>(query: &Message<'_>, key: &'k Key) -> (Vec<u8>, ResponseVerifier<'k>) {
    let mut request = wire(query);
    let verifier = sign_request(key, &mut request, NOW).expect("signed");
    (request, verifier)
}

#[test]
fn s5_3_knots_signed_requests_get_signed_replies() {
    let key = key();
    for (id, rcode) in [
        // A zone transfer, which the core refuses until the transfer server (D41), and an UPDATE of a zone not
        // served, NOTAUTH (D216): their opcodes and types do not matter to the TSIG.
        ("axfr-tsig", Rcode::REFUSED),
        ("ixfr-tsig-uptodate", Rcode::REFUSED),
        ("update-signed", Rcode::NOTAUTH),
    ] {
        let (request, transport) = captured(id);
        let record = tsig(&request);
        let time = record.tsig.time_signed();
        let reply = answer(&server(time), &request, transport);
        let mut verifier = ResponseVerifier::new(&key, record.tsig.mac());
        assert_eq!(
            verifier.verify(&reply, time).ok(),
            Some(Verified::Signed),
            "{id}"
        );
        assert_eq!(decode(&reply).rcode(), rcode, "{id}");
    }
}

#[test]
fn s5_3_a_signed_query_is_answered_signed() {
    let key = key();
    let query = Message::query(7, Question::new(dns("example."), RecordType::SOA));
    let (request, mut verifier) = signed(&query, &key);
    let reply = answer(&server(NOW), &request, Transport::Udp);
    assert_eq!(verifier.verify(&reply, NOW).ok(), Some(Verified::Signed));
    let reply = decode(&reply);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AA));
    assert_eq!(reply.answer.len(), 1);
    // The TSIG is the last record, out of what the reply's sections are made of.
    assert_eq!(reply.additional.len(), 1);
}

#[test]
fn s5_3_a_signed_reply_keeps_within_the_udp_payload() {
    let key = key();
    let mut query = Message::query(7, Question::new(dns("example."), RecordType::DNSKEY));
    query.edns = Some(Edns {
        udp_payload: 512,
        flags: EdnsFlags::DO,
        ..Edns::default()
    });
    let (request, mut verifier) = signed(&query, &key);
    let unsigned = answer(&Pipeline::new(vec![zones()]), &wire(&query), Transport::Tcp);
    assert!(
        unsigned.len() > 512,
        "the DNSKEY RRset fills more than the payload"
    );
    let reply = answer(&server(NOW), &request, Transport::Udp);
    assert!(reply.len() <= 512, "{} bytes", reply.len());
    assert_eq!(verifier.verify(&reply, NOW).ok(), Some(Verified::Signed));
    assert!(decode(&reply).header.flags.contains(Flags::TC));
}

#[test]
fn s5_3_2_an_unknown_key_or_a_wrong_mac_is_answered_unsigned() {
    for (id, error) in [
        ("axfr-tsig-unknown-key", TsigError::BADKEY),
        ("axfr-tsig-bad-secret", TsigError::BADSIG),
        ("update-bad-secret", TsigError::BADSIG),
    ] {
        let (request, transport) = captured(id);
        let time = tsig(&request).tsig.time_signed();
        let reply = answer(&server(time), &request, transport);
        assert_eq!(decode(&reply).rcode(), Rcode::NOTAUTH, "{id}");
        let record = tsig(&reply);
        assert_eq!(record.tsig.error, error, "{id}");
        assert!(record.tsig.mac().is_empty(), "{id}: unsigned");
        assert_eq!(record.tsig.time_signed(), time, "{id}: the request's time");
    }
}

/// A name of `labels`, each that many times `letter`.
fn long(letter: char, labels: &[usize]) -> String {
    let mut name = String::new();
    for &len in labels {
        name.extend(std::iter::repeat_n(letter, len));
        name.push('.');
    }
    name
}

#[test]
fn s5_3_2_an_error_that_cannot_fit_the_payload_is_dropped() {
    // Without EDNS the reply holds 512 bytes: the header (12), the question (a name of 255 bytes, type and class),
    // the unsigned TSIG (the key's name, 10, `hmac-sha256.` 13, and 16 without a MAC): 310 and the key's name.
    let question = Question::new(dns(&long('q', &[63, 63, 63, 61])), RecordType::A);
    let mut query = Message::query(7, question);
    query.edns = None;
    for (labels, fits) in [([63, 63, 63, 8], true), ([63, 63, 63, 9], false)] {
        let unknown =
            Key::new(dns(&long('k', &labels)), key().algorithm(), vec![7; 32]).expect("a key");
        let (request, _) = signed(&query, &unknown);
        let mut out = vec![0; 65535];
        let from: IpAddr = "192.0.2.1".parse().expect("an address");
        let step = server(NOW).query(&request, Transport::Udp, from, 0, &mut out);
        if fits {
            assert!(matches!(step, Step::Reply(512)), "{step:?}");
            assert_eq!(tsig(&out[..512]).tsig.error, TsigError::BADKEY);
        } else {
            assert!(matches!(step, Step::Drop), "{step:?}");
        }
    }
}

#[test]
fn the_keys_are_the_pipelines() {
    assert_eq!(server(NOW).keys().map(Keyring::len), Some(1));
    assert!(Pipeline::new(vec![zones()]).keys().is_none());
}

#[test]
fn s5_2_3_a_time_outside_the_fudge_is_answered_badtime_signed() {
    let key = key();
    // The client's clock was 600 seconds behind Knot's, twice the fudge.
    let (request, transport) = captured("axfr-tsig-bad-time");
    let now = Recording::read("axfr-tsig-bad-time").captured_at;
    let signed = tsig(&request);
    assert!(signed.tsig.time_signed() + 300 < now);
    let reply = answer(&server(now), &request, transport);
    assert_eq!(decode(&reply).rcode(), Rcode::NOTAUTH);
    let record = tsig(&reply);
    assert_eq!(record.tsig.error, TsigError::BADTIME);
    // Other Data is the server's time (§5.2.3); Time Signed and Fudge are the request's.
    assert_eq!(record.tsig.other(), &now.to_be_bytes()[2..]);
    assert_eq!(record.tsig.time_signed(), signed.tsig.time_signed());
    assert_eq!(record.tsig.fudge, signed.tsig.fudge);
    // Signed over the request's MAC: it verifies, at the time it carries.
    let mut verifier = ResponseVerifier::new(&key, signed.tsig.mac());
    let refused = ResponseError::Refused {
        error: TsigError::BADTIME,
        authenticated: true,
    };
    assert_eq!(
        verifier.verify(&reply, signed.tsig.time_signed()),
        Err(refused)
    );
}

#[test]
fn s5_2_4_a_truncated_mac_is_answered_badtrunc_signed() {
    let key = key();
    let (request, transport) = captured("axfr-tsig");
    let record = tsig(&request);
    // The MAC cut to half the output, the least RFC 8945 §5.2.2.1 permits: a local policy refuses it (D205).
    let mac = &record.tsig.mac()[..16];
    let data = Tsig::new(
        record.tsig.algorithm.clone(),
        record.tsig.time_signed(),
        record.tsig.fudge,
        mac,
        record.tsig.original_id,
        record.tsig.error,
        record.tsig.other(),
    )
    .expect("a TSIG");
    let rdata = data.to_wire();
    let mut truncated = request[..record.start].to_vec();
    truncated.extend_from_slice(record.name.to_wire(&mut [0; 255]));
    // Type TSIG, class ANY, TTL 0 (RFC 8945 §4.2).
    truncated.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
    truncated.extend_from_slice(&u16::try_from(rdata.len()).expect("short").to_be_bytes());
    truncated.extend_from_slice(&rdata);
    let reply = answer(&server(record.tsig.time_signed()), &truncated, transport);
    assert_eq!(decode(&reply).rcode(), Rcode::NOTAUTH);
    assert_eq!(tsig(&reply).tsig.error, TsigError::BADTRUNC);
    // Signed over the request's MAC, the whole one: it verifies.
    let mut verifier = ResponseVerifier::new(&key, mac);
    let refused = ResponseError::Refused {
        error: TsigError::BADTRUNC,
        authenticated: true,
    };
    assert_eq!(
        verifier.verify(&reply, record.tsig.time_signed()),
        Err(refused)
    );
}

#[test]
fn s5_2_a_tsig_of_another_class_is_formerr() {
    let (mut request, transport) = captured("axfr-tsig");
    let record = tsig(&request);
    // The class follows the owner and the type: IN in place of ANY (RFC 8945 §4.2).
    let class = record.start + record.name.wire_len() + 2;
    let time = record.tsig.time_signed();
    request[class..class + 2].copy_from_slice(&[0, 1]);
    let reply = answer(&server(time), &request, transport);
    assert_eq!(decode(&reply).rcode(), Rcode::FORMERR);
    assert_eq!(find_tsig(&reply).ok().flatten(), None, "unsigned");
}

/// RFC 8945 §5.1: a TSIG that is not the last record is FORMERR, unsigned, wherever the pipeline looks for one.
#[test]
fn s5_1_a_tsig_that_is_not_last_is_formerr() {
    let (mut request, transport) = captured("axfr-tsig");
    let time = tsig(&request).tsig.time_signed();
    // An A record after the TSIG, counted in the additional section: the bytes of a message holding it alone, less
    // the header.
    let mut extra = Message::default();
    let data = RData::A(Ipv4Addr::new(192, 0, 2, 1));
    extra
        .additional
        .push(Record::new(dns("a."), Class::IN, Ttl::from_wire(60), &data));
    request.extend_from_slice(&wire(&extra)[12..]);
    let count = u16::from_be_bytes([request[10], request[11]]) + 1;
    request[10..12].copy_from_slice(&count.to_be_bytes());
    let reply = answer(&server(time), &request, transport);
    assert_eq!(decode(&reply).rcode(), Rcode::FORMERR);
    assert_eq!(find_tsig(&reply).ok().flatten(), None, "unsigned");
}

/// RFC 8945 §5.1: a request with two TSIGs is FORMERR, unsigned, not served as an unsigned one.
#[test]
fn s5_1_two_tsigs_are_formerr() {
    let (mut request, transport) = captured("axfr-tsig");
    let time = tsig(&request).tsig.time_signed();
    let start = tsig(&request).start;
    request.extend_from_within(start..);
    let count = u16::from_be_bytes([request[10], request[11]]) + 1;
    request[10..12].copy_from_slice(&count.to_be_bytes());
    let reply = answer(&server(time), &request, transport);
    assert_eq!(decode(&reply).rcode(), Rcode::FORMERR);
    assert_eq!(find_tsig(&reply).ok().flatten(), None, "unsigned");
}

#[test]
fn s5_3_a_signed_query_past_the_zones_is_refused_signed() {
    let key = key();
    let mut query = Message::query(7, Question::new(dns("example.org."), RecordType::A));
    query.header.flags = Flags::RD;
    query.edns = Some(Edns::default());
    let (request, mut verifier) = signed(&query, &key);
    // A forwarder past the zones: its replies come from upstream, later, and are not the server's to sign.
    let forward = Stage::Forward(Forward::new(servers()).expect("servers"));
    let reply = answer(
        &signing(vec![zones(), forward], NOW),
        &request,
        Transport::Udp,
    );
    assert_eq!(verifier.verify(&reply, NOW).ok(), Some(Verified::Signed));
    let reply = decode(&reply);
    assert_eq!(reply.rcode(), Rcode::REFUSED);
    let options = reply.edns.map(|edns| edns.options).unwrap_or_default();
    assert!(
        matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::NOT_AUTHORITATIVE),
        "{options:?}"
    );
}

/// The key of the captures' secret under `name` and `algorithm`.
fn named(name: &str, algorithm: Algorithm) -> Key {
    Key::from_base64(dns(name), algorithm, TSIG_KEY.secret).expect("a valid secret")
}

/// The reply `pipeline` gives to the request of `key` for `query`, over `transport`, and what it is verified with.
fn signed_answer<'k>(
    pipeline: &Pipeline,
    query: &Message<'_>,
    key: &'k Key,
    transport: Transport,
) -> (Vec<u8>, ResponseVerifier<'k>) {
    let (request, verifier) = signed(query, key);
    let reply = answer(pipeline, &request, transport);
    (reply, verifier)
}

#[test]
fn s5_3_an_unsigned_query_is_answered_unsigned_by_a_server_with_keys() {
    let query = Message::query(7, Question::new(dns("example."), RecordType::SOA));
    let reply = answer(&server(NOW), &wire(&query), Transport::Udp);
    assert_eq!(find_tsig(&reply).ok().flatten(), None, "unsigned");
    let reply = decode(&reply);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answer.len(), 1);
    assert_eq!(reply.additional.len(), 0);
}

/// RFC 8945 §10: a key is a name and an algorithm; the name's key with another algorithm is not the server's.
#[test]
fn s5_2_1_the_keys_name_with_another_algorithm_is_badkey() {
    let other = named(TSIG_KEY.name, Algorithm::HmacSha512);
    let query = Message::query(7, Question::new(dns("example."), RecordType::SOA));
    let (request, _) = signed(&query, &other);
    let reply = answer(&server(NOW), &request, Transport::Udp);
    assert_eq!(decode(&reply).rcode(), Rcode::NOTAUTH);
    let record = tsig(&reply);
    assert_eq!(record.tsig.error, TsigError::BADKEY);
    assert!(record.tsig.mac().is_empty(), "unsigned");
}

/// RFC 8945 §4.3.3, RFC 4034 §6.2: names compare without case, so a request naming the key in capitals is the
/// key's, and its reply verifies.
#[test]
fn s5_2_1_the_keys_name_in_another_case_is_the_key() {
    let capitals = named(&TSIG_KEY.name.to_uppercase(), key().algorithm());
    let query = Message::query(7, Question::new(dns("example."), RecordType::SOA));
    let (reply, mut verifier) = signed_answer(&server(NOW), &query, &capitals, Transport::Udp);
    assert_eq!(verifier.verify(&reply, NOW).ok(), Some(Verified::Signed));
    assert_eq!(decode(&reply).rcode(), Rcode::NOERROR);
}

/// RFC 8945 §5.3: the TSIG is the last record of the reply, after the OPT record with the COOKIE and the Padding
/// the reply carries (RFC 7873 §5.2.3, RFC 7830): signing adds it to what was built, whatever the options.
#[test]
fn s5_3_a_reply_with_a_cookie_and_padding_is_signed_after_them() {
    let key = key();
    let client = Cookie::new([1; 8], None).expect("a cookie");
    let mut query = Message::query(7, Question::new(dns("example."), RecordType::SOA));
    query.edns = Some(Edns {
        options: vec![EdnsOption::Cookie(client), EdnsOption::Padding(0)],
        ..Edns::default()
    });
    let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
        .parse()
        .expect("a secret");
    let cookies = Cookies::new(Secrets::new(secret, vec![]), Arc::new(|| 1_559_731_985));
    let pipeline = server(NOW).with_cookies(cookies);
    let (reply, mut verifier) = signed_answer(&pipeline, &query, &key, Transport::Tls);
    assert_eq!(verifier.verify(&reply, NOW).ok(), Some(Verified::Signed));
    let reply = decode(&reply);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    let options = reply.edns.expect("an OPT record").options;
    let [EdnsOption::Cookie(cookie), EdnsOption::Padding(_)] = options.as_slice() else {
        panic!("{options:?}");
    };
    assert_eq!(cookie.client(), client.client());
    assert!(cookie.server().is_some(), "{cookie:?}");
    assert_eq!(reply.additional.len(), 1, "the TSIG alone, past the OPT");
}

/// RFC 1996 §4.7, RFC 8945 §5.3: a NOTIFY is not implemented yet (D211), and a signed one is told so signed.
#[test]
fn s5_3_a_signed_notify_is_answered_notimp_signed() {
    let key = key();
    let mut query = Message::query(7, Question::new(dns("example."), RecordType::SOA));
    query.header.opcode = Opcode::NOTIFY;
    let (reply, mut verifier) = signed_answer(&server(NOW), &query, &key, Transport::Udp);
    assert_eq!(verifier.verify(&reply, NOW).ok(), Some(Verified::Signed));
    let reply = decode(&reply);
    assert_eq!(reply.rcode(), Rcode::NOTIMP);
    assert_eq!(reply.header.opcode, Opcode::NOTIFY);
}
