//! The transfer client (D210) against a primary on the loopback address that replays the captures of D203: AXFR
//! (RFC 5936 §2.2) and IXFR (RFC 1995 §4) streams of Knot, signed ones re-signed by `dedens-tsig` (RFC 8945
//! §5.3.1), the SOA query over UDP and TCP (RFC 7766 §5), a serial going back (RFC 1982), and each fault and bound a
//! typed error.

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dedens_net::io::Compio;
use dedens_net::tcp::frame;
use dedens_net::transfer::stream::{Asked, Reader, Step, StreamError, soa_response};
use dedens_net::transfer::{Limit, Limits, Transfer, TransferError, soa, transfer};
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Name, Rcode, Record, RecordType, Serial, find_tsig};
use dedens_testkit::authoritative::{Answers, Peer, Recording, Server, TSIG_KEY, Transport};
use dedens_testkit::dns;
use dedens_tsig::{Key, Keyring, Refusal, ResponseError, ResponseVerifier, verify_request};
use dedens_zone::{ChangesetError, Loaded, Source, WarningKind, Zone};

/// What a primary does on a connection once it read the query: writes `bytes`, then closes its side when `close`,
/// or holds the connection open, until the client goes either way.
struct Reply {
    bytes: Vec<Vec<u8>>,
    close: bool,
}

/// The reply of a primary to the query it read.
type Script = Box<dyn FnOnce(&[u8]) -> Reply + Send>;

/// The datagrams a primary sends back to the UDP query it read.
type Datagram = fn(&[u8]) -> Vec<Vec<u8>>;

/// A primary on one port of the loopback address: its TCP connections, one after the other, each get the next of
/// `scripts`; its UDP queries, the datagram of `udp`.
fn primary(udp: Option<Datagram>, scripts: Vec<Script>) -> SocketAddr {
    let (socket, listener) = loop {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
        if let Ok(listener) = TcpListener::bind(socket.local_addr().expect("bound")) {
            break (socket, listener);
        }
    };
    let addr = socket.local_addr().expect("bound");
    if let Some(udp) = udp {
        thread::spawn(move || {
            let mut buf = vec![0; 65535];
            while let Ok((len, client)) = socket.recv_from(&mut buf) {
                for datagram in udp(&buf[..len]) {
                    socket.send_to(&datagram, client).expect("sent");
                }
            }
        });
    }
    thread::spawn(move || {
        for (script, stream) in scripts.into_iter().zip(listener.incoming()) {
            let mut stream = stream.expect("a connection");
            let mut len = [0; 2];
            stream.read_exact(&mut len).expect("a query's length");
            let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut query).expect("a whole query");
            let reply = script(&query);
            for bytes in reply.bytes {
                // The client may have given up meanwhile.
                let _ = stream.write_all(&bytes);
            }
            if reply.close {
                let _ = stream.shutdown(Shutdown::Write);
            }
            let _ = stream.read_to_end(&mut Vec::new());
        }
    });
    addr
}

/// The responses of the recording `id`: those over TCP when it has any, else over UDP.
fn responses(id: &str) -> Vec<Vec<u8>> {
    let messages = Recording::read(id).messages;
    let tcp = messages.iter().any(|m| m.transport == Transport::Tcp);
    messages
        .into_iter()
        .filter(|m| m.from == Peer::Server && (m.transport == Transport::Tcp) == tcp)
        .map(|m| m.message)
        .collect()
}

/// The request of the recording `id` over TCP, or over UDP when it has none over TCP.
fn request(id: &str) -> Vec<u8> {
    let messages = Recording::read(id).messages;
    let tcp = messages.iter().any(|m| m.transport == Transport::Tcp);
    messages
        .into_iter()
        .find(|m| m.from == Peer::Client && (m.transport == Transport::Tcp) == tcp)
        .expect("a request")
        .message
}

/// `message` with the ID of `query`.
fn with_id(message: &[u8], query: &[u8]) -> Vec<u8> {
    let mut message = message.to_vec();
    message[..2].copy_from_slice(&query[..2]);
    message
}

/// Replays `messages` with the query's ID, then closes.
fn replay(messages: Vec<Vec<u8>>) -> Script {
    Box::new(move |query| Reply {
        bytes: messages
            .iter()
            .map(|m| frame(&with_id(m, query)).expect("under 64 KiB"))
            .collect(),
        close: true,
    })
}

/// Replays the responses of the recording `id`.
fn recorded(id: &str) -> Script {
    replay(responses(id))
}

/// The key of the captures, as Knot holds it.
fn key() -> Key {
    Key::from_base64(
        dns(&format!("{}.", TSIG_KEY.name)),
        TSIG_KEY.algorithm.parse().expect("hmac-sha256"),
        TSIG_KEY.secret,
    )
    .expect("a valid secret")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// `wire` without its TSIG record, if it has one.
fn strip(wire: &[u8]) -> Vec<u8> {
    let Some(tsig) = find_tsig(wire).expect("well formed") else {
        return wire.to_vec();
    };
    let mut stripped = wire[..tsig.start].to_vec();
    let additional = u16::from_be_bytes([stripped[10], stripped[11]]) - 1;
    stripped[10..12].copy_from_slice(&additional.to_be_bytes());
    stripped
}

/// What a signed stream replayed by [`resigned_with`] gets wrong.
#[derive(Clone, Copy)]
enum Fault {
    /// The last message has no TSIG.
    UnsignedEnd,
    /// The MAC of the message of that index is not the one computed.
    BadMac(usize),
    /// The message of that index is a SERVFAIL with no TSIG.
    UnsignedServfail(usize),
}

/// Replays the responses of the signed recording `id`, their TSIG made again for the query, now: the last one left
/// unsigned when `unsigned_end`.
fn resigned(id: &str, unsigned_end: bool) -> Script {
    resigned_with(id, unsigned_end.then_some(Fault::UnsignedEnd))
}

/// [`resigned`] with `fault`, if any.
fn resigned_with(id: &str, fault: Option<Fault>) -> Script {
    let messages = responses(id);
    Box::new(move |query| {
        let keys = Keyring::new([key()]).expect("one key");
        let request = verify_request(&keys, query, unix_now())
            .expect("a request signed with the key")
            .expect("signed");
        let mut signer = request.signer();
        let last = messages.len() - 1;
        let bytes = messages
            .iter()
            .enumerate()
            .map(|(n, m)| {
                let mut m = with_id(&strip(m), query);
                match fault {
                    Some(Fault::UnsignedEnd) if n == last => {}
                    Some(Fault::UnsignedServfail(at)) if n == at => {
                        // The RCODE is the low 4 bits of the header's fourth byte: SERVFAIL, 2.
                        m[3] = (m[3] & 0xF0) | 2;
                    }
                    _ => {
                        signer.sign(&mut m, unix_now()).expect("signed");
                        if matches!(fault, Some(Fault::BadMac(at)) if n == at) {
                            corrupt_mac(&mut m);
                        }
                    }
                }
                frame(&m).expect("under 64 KiB")
            })
            .collect();
        Reply { bytes, close: true }
    })
}

/// `wire` with the last byte of its MAC changed: the TSIG record is the last, and ends with the original ID, the
/// error and an empty Other Data, 6 bytes, as a NOERROR response's does.
fn corrupt_mac(wire: &mut [u8]) {
    let last_of_mac = wire.len() - 7;
    wire[last_of_mac] ^= 1;
}

/// Reads the query and holds the connection, answering nothing.
fn silent() -> Script {
    Box::new(|_| Reply {
        bytes: Vec::new(),
        close: false,
    })
}

/// The zone of `file` of `testdata/authoritative/zones/`, with origin `origin`.
fn text(file: &str, origin: &str) -> Zone {
    let text =
        std::fs::read(dedens_testkit::path("authoritative/zones").join(file)).expect("a zone");
    let source = Source {
        name: file,
        text: &text,
        default_ttl: None,
    };
    let mut include = |_: &str| Err("no $INCLUDE".to_owned());
    Zone::load(
        dns(origin),
        source,
        &mut include,
        &dedens_zone::Limits::default(),
    )
    .map_err(|report| report.to_string())
    .expect(file)
    .zone
}

/// The serial of the first SOA among the answer, then the authority records of `wire`.
fn serial(wire: &[u8]) -> Serial {
    let message = Message::decode(wire).expect("a message").message;
    message
        .answer
        .iter()
        .chain(&message.authority)
        .find_map(|r| match r.data() {
            RData::Soa(soa) => Some(Serial::new(soa.serial)),
            _ => None,
        })
        .expect("an SOA")
}

/// Transfers `zone` from `primary` with the default limits.
async fn from(
    primary: SocketAddr,
    zone: &str,
    serial: Option<Serial>,
    key: Option<&Key>,
) -> Result<Transfer, TransferError> {
    transfer(
        &Compio,
        primary,
        &dns(zone),
        serial,
        key,
        &Limits::default(),
    )
    .await
}

#[track_caller]
#[expect(clippy::panic, reason = "a test's helper fails the test")]
fn full(result: Result<Transfer, TransferError>) -> Loaded {
    match result {
        Ok(Transfer::Full(loaded)) => loaded,
        other => panic!("not a full zone: {other:?}"),
    }
}

#[track_caller]
#[expect(clippy::panic, reason = "a test's helper fails the test")]
fn stream_error(result: Result<Transfer, TransferError>) -> StreamError {
    match result {
        Err(TransferError::Stream(error)) => error,
        other => panic!("not refused: {other:?}"),
    }
}

/// The root serial the IXFR capture starts from.
const ROOT_PREVIOUS: Serial = Serial::new(2_026_111_401);

#[compio::test]
async fn rfc5936_2_2_root_axfr_is_its_zone() {
    let primary = primary(None, vec![recorded("axfr-root")]);
    let loaded = full(from(primary, ".", None, None).await);
    assert_eq!(loaded.zone, text("root.zone", "."));
}

#[compio::test]
async fn rfc5936_2_2_zonetransfer_me_axfr_is_its_zone() {
    let primary = primary(None, vec![recorded("axfr-zonetransfer.me")]);
    let loaded = full(from(primary, "zonetransfer.me.", None, None).await);
    assert_eq!(
        loaded.zone,
        text("zonetransfer.me.zone", "zonetransfer.me.")
    );
}

#[compio::test]
async fn rfc1995_4_root_ixfr_applies_to_the_next_serial() {
    let messages = responses("root-ixfr");
    let script: Script = Box::new(move |query| {
        // The query asks for an IXFR from the serial held, in an SOA of the authority section (RFC 1995 §3).
        let decoded = Message::decode(query).expect("a query").message;
        assert_eq!(decoded.questions[0].qtype, RecordType::IXFR);
        assert_eq!(serial(query), ROOT_PREVIOUS);
        replay(messages)(query)
    });
    let primary = primary(None, vec![script]);
    let Ok(Transfer::Incremental(changesets)) = from(primary, ".", Some(ROOT_PREVIOUS), None).await
    else {
        panic!("not incremental");
    };
    assert_eq!(changesets[0].from_serial(), ROOT_PREVIOUS);
    let mut zone = text("root-previous.zone", ".");
    for changeset in &changesets {
        zone = zone
            .apply(changeset, &dedens_zone::Limits::default())
            .map_err(|report| report.to_string())
            .expect("applies")
            .zone;
    }
    assert_eq!(zone, text("root.zone", "."));
}

#[compio::test]
async fn rfc1995_4_single_soa_is_up_to_date() {
    let ours = serial(&responses("ixfr-uptodate")[0]);
    let primary = primary(None, vec![recorded("ixfr-uptodate")]);
    let result = from(primary, "example.", Some(ours), None).await;
    assert!(matches!(result, Ok(Transfer::UpToDate)), "{result:?}");
}

#[compio::test]
async fn rfc1995_4_axfr_form_is_a_full_zone() {
    let ours = serial(&request("ixfr-unknown-serial"));
    let theirs = serial(&responses("ixfr-unknown-serial")[0]);
    let primary = primary(None, vec![recorded("ixfr-unknown-serial")]);
    let loaded = full(from(primary, "example.", Some(ours), None).await);
    assert_eq!(Serial::new(loaded.zone.soa().serial), theirs);
}

#[compio::test]
async fn rfc1995_4_difference_is_one_changeset() {
    let ours = serial(&request("ixfr-difference-tcp"));
    let primary = primary(None, vec![recorded("ixfr-difference-tcp")]);
    let Ok(Transfer::Incremental(changesets)) = from(primary, "example.", Some(ours), None).await
    else {
        panic!("not incremental");
    };
    assert_eq!(changesets.len(), 1);
    assert_eq!(changesets[0].from_serial(), ours);
    assert_eq!(changesets[0].removed(), []);
    assert!(
        changesets[0]
            .added()
            .iter()
            .any(|r| r.name == dns("dedens-new.example.") && r.rtype() == RecordType::A)
    );
}

#[compio::test]
async fn rfc1995_4_ixfr_refused_falls_back_to_axfr() {
    // An IXFR answered with an AXFR's question is asked again as an AXFR, which the same answer serves.
    let ours = Serial::new(2_019_100_800);
    let primary = primary(
        None,
        vec![
            recorded("axfr-zonetransfer.me"),
            recorded("axfr-zonetransfer.me"),
        ],
    );
    let loaded = full(from(primary, "zonetransfer.me.", Some(ours), None).await);
    assert_eq!(
        loaded.zone,
        text("zonetransfer.me.zone", "zonetransfer.me.")
    );
}

#[compio::test]
async fn rfc5936_2_2_error_rcode_is_refused() {
    let primary = primary(None, vec![recorded("axfr-unsigned-refused")]);
    let error = stream_error(from(primary, "zonetransfer.me.", None, None).await);
    // Knot answers an unsigned request for a key's zone with NOTAUTH, without TSIG.
    assert_eq!(error, StreamError::Rcode(Rcode::NOTAUTH));
}

#[compio::test]
async fn rfc1982_serial_going_back_is_refused() {
    let ahead = Serial::new(2_026_112_202);
    // The IXFR's changes start below the serial asked for; the AXFR asked then is behind it.
    let root = primary(None, vec![recorded("root-ixfr"), recorded("axfr-root")]);
    let error = stream_error(from(root, ".", Some(ahead), None).await);
    assert_eq!(
        error,
        StreamError::NotNewer {
            ours: ahead,
            theirs: Serial::new(2_026_112_201),
        }
    );
    // A single SOA behind the client's: no AXFR asked.
    let theirs = serial(&responses("ixfr-uptodate")[0]);
    let ours = theirs.checked_add(1).expect("a step");
    let example = primary(None, vec![recorded("ixfr-uptodate")]);
    let error = stream_error(from(example, "example.", Some(ours), None).await);
    assert_eq!(error, StreamError::NotNewer { ours, theirs });
}

#[compio::test]
async fn rfc5936_2_2_stream_cut_within_a_message_is_closed() {
    let first = responses("axfr-root").swap_remove(0);
    let script: Script = Box::new(move |query| {
        let framed = frame(&with_id(&first, query)).expect("under 64 KiB");
        Reply {
            bytes: vec![framed[..framed.len() / 2].to_vec()],
            close: true,
        }
    });
    let primary = primary(None, vec![script]);
    let result = from(primary, ".", None, None).await;
    assert!(matches!(result, Err(TransferError::Closed)), "{result:?}");
}

#[compio::test]
async fn rfc5936_2_2_missing_closing_soa_is_closed() {
    let mut messages = responses("axfr-root");
    messages.pop();
    let primary = primary(None, vec![replay(messages)]);
    let result = from(primary, ".", None, None).await;
    assert!(matches!(result, Err(TransferError::Closed)), "{result:?}");
}

#[compio::test]
async fn rfc5936_2_2_wrong_id_is_refused() {
    let messages = responses("axfr-zonetransfer.me");
    let script: Script = Box::new(move |query| {
        let mut other = query[..2].to_vec();
        other[1] ^= 1;
        replay(messages)(&other)
    });
    let primary = primary(None, vec![script]);
    let error = stream_error(from(primary, "zonetransfer.me.", None, None).await);
    assert!(matches!(error, StreamError::WrongId { .. }), "{error:?}");
}

#[compio::test]
async fn rfc8945_5_3_1_signed_axfr_verifies() {
    let key = key();
    let primary = primary(None, vec![resigned("axfr-tsig", false)]);
    let loaded = full(from(primary, "zonetransfer.me.", None, Some(&key)).await);
    assert_eq!(
        loaded.zone,
        text("zonetransfer.me.zone", "zonetransfer.me.")
    );
}

#[compio::test]
async fn rfc8945_5_3_1_signed_ixfr_up_to_date_verifies() {
    let key = key();
    let ours = serial(&responses("ixfr-tsig-uptodate")[0]);
    let primary = primary(None, vec![resigned("ixfr-tsig-uptodate", false)]);
    let result = from(primary, "zonetransfer.me.", Some(ours), Some(&key)).await;
    assert!(matches!(result, Ok(Transfer::UpToDate)), "{result:?}");
}

#[compio::test]
async fn rfc8945_5_3_1_unsigned_last_message_is_refused() {
    let key = key();
    let primary = primary(None, vec![resigned("axfr-tsig-stream", true)]);
    let error = stream_error(from(primary, ".", None, Some(&key)).await);
    assert_eq!(
        error,
        StreamError::Tsig {
            error: ResponseError::UnsignedEnd,
            rcode: Rcode::NOERROR,
        }
    );
}

#[test]
fn rfc8945_5_3_1_captured_signed_stream_verifies() {
    // Knot's own MACs, verified at the times it signed them, against the request's MAC.
    let key = key();
    let request = request("axfr-tsig-stream");
    let request_mac = find_tsig(&request)
        .expect("well formed")
        .expect("signed")
        .tsig
        .mac()
        .to_vec();
    let id = u16::from_be_bytes([request[0], request[1]]);
    let verifier = ResponseVerifier::new(&key, &request_mac);
    let mut reader = Reader::new(
        dns("."),
        id,
        Asked::Axfr(None),
        Some(verifier),
        &Limits::default(),
    );
    let mut messages = responses("axfr-tsig-stream").into_iter();
    let transfer = loop {
        let message = messages.next().expect("a message before the end");
        let now = find_tsig(&message)
            .expect("well formed")
            .expect("signed")
            .tsig
            .time_signed();
        match reader.message(&message, now).expect("accepted") {
            Step::More(next) => reader = next,
            Step::Done(transfer) => break transfer,
        }
    };
    assert!(messages.next().is_none());
    let Transfer::Full(loaded) = transfer else {
        panic!("not a full zone");
    };
    // The 1200 records the capture holds, besides its closing SOA.
    assert_eq!(loaded.zone.record_count(), 1200);
}

/// `message` as wire bytes.
fn encoded(message: &Message<'_>) -> Vec<u8> {
    let mut wire = vec![0; 65_535];
    let len = message.encode(&mut wire).expect("a message of 64 KiB");
    wire.truncate(len);
    wire
}

/// The transfer of `zone` the `recording`'s responses, each changed by `change`, make as answers to its request.
#[expect(clippy::panic, reason = "a test's helper fails the test")]
fn read(
    recording: &str,
    zone: &str,
    asked: Asked,
    change: impl Fn(Message<'static>) -> Vec<u8>,
) -> Result<Transfer, StreamError> {
    let request = request(recording);
    let id = u16::from_be_bytes([request[0], request[1]]);
    let mut reader = Reader::new(dns(zone), id, asked, None, &Limits::default());
    for response in responses(recording) {
        let wire = change(
            Message::decode(&response)
                .expect("a message")
                .message
                .into_owned(),
        );
        match reader.message(&wire, 0)? {
            Step::More(next) => reader = next,
            Step::Done(transfer) => return Ok(transfer),
        }
    }
    panic!("no end");
}

/// `soa` with `serial`.
#[expect(clippy::panic, reason = "a test's helper fails the test")]
fn with_serial(soa: &Record<'static>, serial: Serial) -> Record<'static> {
    let RData::Soa(mut data) = soa.data() else {
        panic!("not an SOA");
    };
    data.serial = serial.get();
    Record::new(soa.name.clone(), soa.class, soa.ttl, &RData::Soa(data))
}

#[test]
fn rfc5936_2_2_soa_of_another_serial_inside_is_refused() {
    let inside = serial(&responses("axfr-zonetransfer.me")[0])
        .checked_add(1)
        .expect("a step");
    let result = read(
        "axfr-zonetransfer.me",
        "zonetransfer.me.",
        Asked::Axfr(None),
        |mut message| {
            let soa = with_serial(&message.answer[0], inside);
            message.answer.insert(message.answer.len() / 2, soa);
            encoded(&message)
        },
    );
    assert_eq!(result.expect_err("refused"), StreamError::SoaInside(inside));
}

#[test]
fn rfc1995_4_changesets_not_consecutive_are_refused() {
    // [new, old, new, added..., new] becomes [latest, old, new, added..., gap, latest, latest]: a second changeset
    // that starts past where the first ended.
    let old = serial(&request("ixfr-difference-tcp"));
    let result = read(
        "ixfr-difference-tcp",
        "example.",
        Asked::Ixfr(old),
        |mut message| {
            let new = message.answer.pop().expect("the closing SOA");
            let at = |step| with_serial(&new, old.checked_add(step).expect("a step"));
            message.answer[0] = at(10);
            message.answer.extend([at(4), at(10), at(10)]);
            encoded(&message)
        },
    );
    assert_eq!(
        result.expect_err("refused"),
        StreamError::Changeset(ChangesetError::NotConsecutive)
    );
}

#[test]
fn rfc5936_2_2_query_is_no_response() {
    let result = read(
        "axfr-zonetransfer.me",
        "zonetransfer.me.",
        Asked::Axfr(None),
        |mut message| {
            message.header.flags = message.header.flags.without(Flags::QR);
            encoded(&message)
        },
    );
    assert_eq!(result.expect_err("refused"), StreamError::NotResponse);
}

#[test]
fn rfc5936_2_2_invalid_rdata_is_refused() {
    let result = read(
        "axfr-zonetransfer.me",
        "zonetransfer.me.",
        Asked::Axfr(None),
        |mut message| {
            message.authority.clear();
            message.additional.clear();
            message.edns = None;
            let mut wire = encoded(&message);
            // One more answer record, last in the message: an A record of 3 bytes, owned by the question's name.
            let count = u16::from_be_bytes([wire[6], wire[7]]) + 1;
            wire[6..8].copy_from_slice(&count.to_be_bytes());
            wire.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0, 0, 3, 192, 0, 2]);
            wire
        },
    );
    assert!(
        matches!(result, Err(StreamError::InvalidRdata { .. })),
        "{result:?}"
    );
}

#[test]
fn rfc1034_soa_of_another_name_is_no_soa() {
    let mut message = Message::decode(&root_soa())
        .expect("a message")
        .message
        .into_owned();
    let id = message.header.id;
    message.answer[0].name = dns("com.");
    let result = soa_response(&encoded(&message), id, &Name::root(), None, 0);
    assert_eq!(result.expect_err("refused"), StreamError::NoSoa);
}

#[compio::test]
async fn rfc8945_5_3_1_refused_key_is_a_tsig_error() {
    let key = key();
    for id in [
        "axfr-tsig-bad-secret",
        "axfr-tsig-unknown-key",
        "axfr-tsig-bad-time",
    ] {
        let primary = primary(None, vec![recorded(id)]);
        let error = stream_error(from(primary, "zonetransfer.me.", None, Some(&key)).await);
        assert!(
            matches!(
                error,
                StreamError::Tsig {
                    rcode: Rcode::NOTAUTH,
                    ..
                }
            ),
            "{id}: {error:?}"
        );
    }
}

/// The result of the AXFR `script` sends, of the root, under `limits`.
async fn bounded(script: Script, limits: Limits) -> Result<Transfer, TransferError> {
    let primary = primary(None, vec![script]);
    transfer(&Compio, primary, &Name::root(), None, None, &limits).await
}

#[compio::test]
async fn limits_each_bound_refuses() {
    let limit = |result: Result<Transfer, TransferError>| match result {
        Err(TransferError::Stream(StreamError::Limit(limit)) | TransferError::Limit(limit)) => {
            limit
        }
        other => panic!("not a limit: {other:?}"),
    };
    // The root's AXFR as it came: its counts are the tightest limits it passes, one less refuses it.
    let responses = responses("axfr-root");
    let exact = Limits {
        messages: responses.len(),
        bytes: responses.iter().map(Vec::len).sum(),
        records: (responses.iter())
            .map(|m| Message::decode(m).expect("a message").message.answer.len())
            .sum(),
        ..Limits::default()
    };
    full(bounded(recorded("axfr-root"), exact).await);
    let cases = [
        (
            Limits {
                messages: exact.messages - 1,
                ..exact
            },
            Limit::Messages,
        ),
        (
            Limits {
                bytes: exact.bytes - 1,
                ..exact
            },
            Limit::Bytes,
        ),
        (
            Limits {
                records: exact.records - 1,
                ..exact
            },
            Limit::Records,
        ),
    ];
    for (limits, expected) in cases {
        assert_eq!(
            limit(bounded(recorded("axfr-root"), limits).await),
            expected
        );
    }
    let short = Duration::from_millis(200);
    let time = Limits {
        time: short,
        ..Limits::default()
    };
    assert_eq!(limit(bounded(silent(), time).await), Limit::Time);
    let idle = Limits {
        idle: short,
        ..Limits::default()
    };
    assert_eq!(limit(bounded(silent(), idle).await), Limit::Idle);
}

/// A time or idle limit of `Duration::MAX`, as a caller says "none", is no overflow of the clock.
#[compio::test]
async fn limits_of_no_end_do_not_overflow_the_clock() {
    let limits = Limits {
        time: Duration::MAX,
        idle: Duration::MAX,
        ..Limits::default()
    };
    full(bounded(recorded("axfr-root"), limits).await);
}

#[compio::test]
async fn limits_records_per_rrset_refuse_the_zone() {
    // The root's 13 NS records are one RRset.
    let limits = Limits {
        zone: dedens_zone::Limits {
            records_per_rrset: 12,
            ..dedens_zone::Limits::default()
        },
        ..Limits::default()
    };
    let result = bounded(recorded("axfr-root"), limits).await;
    assert!(
        matches!(result, Err(TransferError::Stream(StreamError::Zone(_)))),
        "{result:?}"
    );
}

/// Knot's response to `. SOA` without EDNS, over UDP.
fn root_soa() -> Vec<u8> {
    Answers::read("root")
        .answers
        .into_iter()
        .find(|r| r.name == Name::root() && r.rtype == RecordType::SOA && r.edns_size.is_none())
        .expect("a captured SOA")
        .responses
        .remove(&Server::Knot)
        .expect("Knot's")
}

#[compio::test]
async fn rfc1035_soa_over_udp() {
    // A datagram of another ID, then one that is no response, waited past (RFC 5452 §9.1).
    let datagrams = |query: &[u8]| {
        let mut other = with_id(&root_soa(), query);
        other[1] ^= 1;
        let mut not_response = with_id(&root_soa(), query);
        not_response[2] &= !0x80;
        vec![other, not_response, with_id(&root_soa(), query)]
    };
    let primary = primary(Some(datagrams), Vec::new());
    let soa = soa(&Compio, primary, &Name::root(), None)
        .await
        .expect("an SOA");
    assert_eq!(Serial::new(soa.serial), serial(&root_soa()));
}

#[compio::test]
async fn rfc7766_5_truncated_soa_goes_over_tcp() {
    let truncated = |query: &[u8]| {
        let mut response = with_id(&root_soa(), query);
        response[2] |= 0x02;
        vec![response]
    };
    let primary = primary(Some(truncated), vec![replay(vec![root_soa()])]);
    let soa = soa(&Compio, primary, &Name::root(), None)
        .await
        .expect("an SOA");
    assert_eq!(Serial::new(soa.serial), serial(&root_soa()));
}

/// Knot's SOA response to `query`, a signed one, signed for it: its MAC changed when `corrupt`.
fn signed_soa(query: &[u8], corrupt: bool) -> Vec<u8> {
    let keys = Keyring::new([key()]).expect("one key");
    let request = verify_request(&keys, query, unix_now())
        .expect("a request signed with the key")
        .expect("signed");
    let mut response = with_id(&root_soa(), query);
    request
        .signer()
        .sign(&mut response, unix_now())
        .expect("signed");
    if corrupt {
        corrupt_mac(&mut response);
    }
    response
}

/// RFC 8945 §5.4, RFC 5452: anyone can send a datagram of the right ID, so one that fails verification, forged MAC
/// or none, is waited past, and the real response after it is the answer.
#[compio::test]
async fn rfc8945_5_4_udp_soa_waits_past_responses_that_fail_verification() {
    let datagrams = |query: &[u8]| {
        let unsigned = with_id(&root_soa(), query);
        vec![signed_soa(query, true), unsigned, signed_soa(query, false)]
    };
    let key = key();
    let primary = primary(Some(datagrams), Vec::new());
    let soa = soa(&Compio, primary, &Name::root(), Some(&key))
        .await
        .expect("an SOA");
    assert_eq!(Serial::new(soa.serial), serial(&root_soa()));
}

/// A BADTIME answer, signed, is the primary's own refusal and ends the query: it verifies, so no forger sent it.
#[compio::test]
async fn rfc8945_5_4_udp_soa_a_signed_tsig_error_ends_the_query() {
    let datagrams = |query: &[u8]| {
        let keys = Keyring::new([key()]).expect("one key");
        // The primary's clock is far from the request's.
        let Err(Refusal::NotAuth(refusal)) = verify_request(&keys, query, unix_now() + 3600) else {
            panic!("not a BADTIME");
        };
        let mut response = with_id(&root_soa(), query);
        refusal
            .sign(&mut response, unix_now() + 3600)
            .expect("signed");
        vec![response]
    };
    let key = key();
    let primary = primary(Some(datagrams), Vec::new());
    let result = soa(&Compio, primary, &Name::root(), Some(&key)).await;
    assert!(
        matches!(
            result,
            Err(TransferError::Stream(StreamError::Tsig {
                error: ResponseError::Refused {
                    authenticated: true,
                    ..
                },
                ..
            }))
        ),
        "{result:?}"
    );
}

/// A response over TCP that fails verification ends the query: nothing else is to come on the connection.
#[compio::test]
async fn rfc8945_5_4_tcp_soa_that_fails_verification_is_refused() {
    let truncated = |query: &[u8]| {
        let mut response = with_id(&root_soa(), query);
        response[2] |= 0x02;
        vec![response]
    };
    let script: Script = Box::new(|query| Reply {
        bytes: vec![frame(&signed_soa(query, true)).expect("under 64 KiB")],
        close: true,
    });
    let key = key();
    let primary = primary(Some(truncated), vec![script]);
    let result = soa(&Compio, primary, &Name::root(), Some(&key)).await;
    assert!(
        matches!(
            result,
            Err(TransferError::Stream(StreamError::Tsig {
                error: ResponseError::BadSig,
                ..
            }))
        ),
        "{result:?}"
    );
}

/// RFC 1995 §4: the changes lead from the client's serial to the opening SOA's, a newer one. A chain of steps of
/// less than 2^31 each that goes round the serial space to reach an opening SOA that is not newer, or one that
/// passes it on the way, is refused (NSD's "bad middle serial"), signed or not.
#[test]
fn rfc1995_4_changes_that_go_round_the_serial_space_are_refused() {
    let ours = serial(&request("ixfr-difference-tcp"));
    let at = |step: u32| Serial::new(ours.get().wrapping_add(step));
    let half = 0x7FFF_FFFF;
    let cases = [
        // Ahead of the client's, but the first step passes it.
        (
            10,
            StreamError::BadMiddleSerial {
                to: at(half),
                opening: at(10),
            },
        ),
        // One behind the client's, which three steps reach.
        (
            u32::MAX,
            StreamError::NotNewer {
                ours,
                theirs: at(u32::MAX),
            },
        ),
        // The client's own, which three steps come back to.
        (0, StreamError::NotNewer { ours, theirs: ours }),
    ];
    for (opening, expected) in cases {
        let result = read(
            "ixfr-difference-tcp",
            "example.",
            Asked::Ixfr(ours),
            |mut message| {
                let template = message.answer.pop().expect("the closing SOA");
                // [opening, then three changes of 2^31 - 1, 2^31 - 1 and 12 or so, and the opening again.]
                message.answer = [opening, 0, half, half, 2 * half, 2 * half, opening, opening]
                    .map(|step| with_serial(&template, at(step)))
                    .to_vec();
                encoded(&message)
            },
        );
        assert_eq!(result.expect_err("refused"), expected, "opening {opening}");
    }
}

/// A record of an AXFR outside the zone is dropped with a warning, as Knot does (D210): the zone is the rest.
#[test]
fn d210_a_record_outside_the_zone_in_an_axfr_is_dropped_with_a_warning() {
    let result = read(
        "axfr-zonetransfer.me",
        "zonetransfer.me.",
        Asked::Axfr(None),
        |mut message| {
            if message.answer.len() > 1 {
                let mut stranger = message.answer[1].clone();
                stranger.name = dns("stranger.example.");
                message.answer.insert(1, stranger);
            }
            encoded(&message)
        },
    );
    let Ok(Transfer::Full(loaded)) = result else {
        panic!("not a full zone: {result:?}");
    };
    assert_eq!(
        loaded.zone,
        text("zonetransfer.me.zone", "zonetransfer.me.")
    );
    let kinds: Vec<_> = (loaded.report.warnings.iter())
        .map(|warning| warning.kind.clone())
        .collect();
    assert_eq!(
        kinds,
        [WarningKind::OutsideZone {
            owner: dns("stranger.example."),
        }]
    );
}

/// A signed IXFR of changes, not only an up to date one, verifies and applies.
#[compio::test]
async fn rfc8945_5_3_1_signed_ixfr_with_changes_verifies() {
    let key = key();
    let primary = primary(None, vec![resigned("root-ixfr", false)]);
    let result = from(primary, ".", Some(ROOT_PREVIOUS), Some(&key)).await;
    let Ok(Transfer::Incremental(changesets)) = result else {
        panic!("not incremental: {result:?}");
    };
    let mut zone = text("root-previous.zone", ".");
    for changeset in &changesets {
        zone = zone
            .apply(changeset, &dedens_zone::Limits::default())
            .map_err(|report| report.to_string())
            .expect("applies")
            .zone;
    }
    assert_eq!(zone, text("root.zone", "."));
}

/// A TSIG failure in the middle of a signed IXFR ends the transfer: no AXFR is asked (RFC 8945 §5.3.1; an AXFR
/// would meet the same primary). The second script would serve the AXFR, which would make a zone.
#[compio::test]
async fn rfc8945_5_3_1_tsig_failure_mid_ixfr_is_not_retried_as_an_axfr() {
    let key = key();
    let cases = [
        (
            Fault::BadMac(5),
            StreamError::Tsig {
                error: ResponseError::BadSig,
                rcode: Rcode::NOERROR,
            },
        ),
        // An error with no TSIG after signed messages cannot be told from a forged one.
        (
            Fault::UnsignedServfail(5),
            StreamError::Tsig {
                error: ResponseError::UnsignedEnd,
                rcode: Rcode::SERVFAIL,
            },
        ),
    ];
    for (fault, expected) in cases {
        let scripts = vec![
            resigned_with("root-ixfr", Some(fault)),
            resigned("axfr-tsig-stream", false),
        ];
        let primary = primary(None, scripts);
        let error = stream_error(from(primary, ".", Some(ROOT_PREVIOUS), Some(&key)).await);
        assert_eq!(error, expected);
    }
}

/// RFC 5452 §4.3: the ID of each query is drawn at random: the IXFR's and the AXFR asked after it, over several
/// transfers, do not all carry one value.
#[compio::test]
async fn rfc5452_4_3_query_ids_are_random() {
    let (sent, received) = std::sync::mpsc::channel::<[u8; 2]>();
    let ours = Serial::new(2_019_100_800);
    for _ in 0..2 {
        let scripts: Vec<Script> = (0..2)
            .map(|_| {
                let sent = sent.clone();
                let script: Script = Box::new(move |query| {
                    sent.send([query[0], query[1]]).expect("received");
                    recorded("axfr-zonetransfer.me")(query)
                });
                script
            })
            .collect();
        let primary = primary(None, scripts);
        full(from(primary, "zonetransfer.me.", Some(ours), None).await);
    }
    drop(sent);
    let ids: std::collections::HashSet<_> = received.iter().collect();
    assert!(ids.len() > 1, "four queries, one ID: {ids:?}");
}
