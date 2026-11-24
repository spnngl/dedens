//! `dedensd`'s secondary zones (D215), against a primary on the loopback address that replays the captures of Knot
//! (D203): the first transfer an AXFR (RFC 5936 §2.2), the next an IXFR from the version kept on disk (RFC 1995 §4),
//! a restart serving that version (another `state_dir` taking one), a primary whose serial is behind ours not followed (RFC 1982 §3.2), and a zone
//! past its SOA expire (RFC 1034 §4.3.5) answered SERVFAIL with EDE 24 (RFC 8914 §4.25).

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dedens_proto::edns::{Edns, EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Name, Question, Rcode, RecordType};
use dedens_testkit::authoritative::{Answers, Peer, Recording, Server as Captured, Transport};

use crate::reload::logged;
use crate::util::{Server, ask_udp, silent};

/// The serial of the root zone of `root-previous.zone`, and of `root.zone`, which `root-ixfr` goes between.
const PREVIOUS: u32 = 2_026_111_401;
const ROOT: u32 = 2_026_112_201;

/// The serial of the zone of RFC 4035 Appendix A.
const EXAMPLE: u32 = 1_081_539_377;

/// A primary on one port of the loopback address: it answers each SOA query over UDP with `soa`, and its TCP
/// connections, one after the other, with the next of `streams`; each message with the query's ID.
fn primary(soa: Vec<u8>, streams: Vec<Vec<Vec<u8>>>) -> SocketAddr {
    let (socket, listener) = loop {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
        if let Ok(listener) = TcpListener::bind(socket.local_addr().expect("bound")) {
            break (socket, listener);
        }
    };
    let addr = socket.local_addr().expect("bound");
    thread::spawn(move || {
        let mut buf = vec![0; 65_535];
        while let Ok((len, client)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&with_id(&soa, &buf[..len]), client);
        }
    });
    thread::spawn(move || {
        for (messages, stream) in streams.into_iter().zip(listener.incoming()) {
            let mut stream = stream.expect("a connection");
            let mut len = [0; 2];
            stream.read_exact(&mut len).expect("a query's length");
            let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut query).expect("a whole query");
            for message in messages {
                let message = with_id(&message, &query);
                let len = u16::try_from(message.len()).expect("under 64 KiB");
                let _ = stream.write_all(&len.to_be_bytes());
                let _ = stream.write_all(&message);
            }
            let _ = stream.read_to_end(&mut Vec::new());
        }
    });
    addr
}

/// `message` with the ID of `query`.
fn with_id(message: &[u8], query: &[u8]) -> Vec<u8> {
    let mut message = message.to_vec();
    message[..2].copy_from_slice(&query[..2]);
    message
}

/// The responses of the recording `id`, over TCP.
fn stream(id: &str) -> Vec<Vec<u8>> {
    (Recording::read(id).messages.into_iter())
        .filter(|m| m.from == Peer::Server && m.transport == Transport::Tcp)
        .map(|m| m.message)
        .collect()
}

/// Knot's response to the SOA query of `zone` over UDP, in the answers `id`.
fn soa(id: &str, zone: &str) -> Vec<u8> {
    let zone: Name<'static> = zone.parse().expect("a name");
    (Answers::read(id).answers.into_iter())
        .find(|r| r.name == zone && r.rtype == RecordType::SOA && r.transport == Transport::Udp)
        .expect("a captured SOA")
        .responses
        .remove(&Captured::Knot)
        .expect("Knot's")
}

/// A server of the secondary zone `zone`, transferred from `primary`, its files in `state`.
fn secondary(listen: &str, zone: &str, primary: SocketAddr, state: &Path) -> String {
    format!(
        "listen: ['{listen}']\nstate_dir: '{}'\npipeline: [zones]\nstages:\n  zones:\n    type: authoritative\n    zones:\n      - {{name: '{zone}', secondary: {{primaries: [{{address: '{primary}'}}]}}}}\n",
        state.display()
    )
}

/// Writes the files of the secondary zone kept in directory `dir` of `state`: the zone of `file`, refreshed at
/// `refreshed` and expiring at `expires`.
fn kept(state: &Path, dir: &str, file: &Path, (refreshed, expires): (u64, u64)) {
    let dir = state.join("zones").join(dir);
    std::fs::create_dir_all(&dir).expect("made");
    std::fs::copy(file, dir.join("zone")).expect("copied");
    let timers = format!("refreshed {refreshed}\nexpires {expires}\n");
    std::fs::write(dir.join("timers"), timers).expect("written");
}

/// The time, in Unix seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// The reply of `server` to the SOA query of `zone`, with EDNS.
fn ask_soa(server: &Server, zone: &str) -> Message<'static> {
    let mut query = Message::query(
        1,
        Question::new(zone.parse().expect("a name"), RecordType::SOA),
    );
    query.edns = Some(Edns::default());
    ask_udp(server.addr, &query.to_vec().expect("a query fits"))
}

/// The serial `server` answers for `zone`, once it answers it within 30 s.
fn served(server: &Server, zone: &str) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let reply = ask_soa(server, zone);
        if reply.rcode() == Rcode::NOERROR {
            assert!(reply.header.flags.contains(Flags::AA), "{reply:?}");
            return serial(&reply).expect("a SOA");
        }
        assert!(Instant::now() < deadline, "{zone} is not served: {reply:?}");
        thread::sleep(Duration::from_millis(50));
    }
}

/// Waits until `server` answers `zone`'s SOA with serial `wanted`, within 30 s.
fn serves(server: &Server, zone: &str, wanted: u32) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while served(server, zone) != wanted {
        assert!(
            Instant::now() < deadline,
            "{zone} is not served at {wanted}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// The serial of the SOA in `reply`'s answer, if any.
fn serial(reply: &Message<'_>) -> Option<u32> {
    reply.answer.iter().find_map(|record| match record.data() {
        RData::Soa(soa) => Some(soa.serial),
        _ => None,
    })
}

/// The extended errors of `reply`.
fn errors(reply: &Message<'_>) -> Vec<InfoCode> {
    (reply.edns.iter().flat_map(|edns| &edns.options))
        .filter_map(|option| match option {
            EdnsOption::Ede(error) => Some(error.code),
            _ => None,
        })
        .collect()
}

/// RFC 5936 §2.2: a secondary zone is first transferred whole, kept on disk, and served from it after a restart
/// without asking the primary again before its refresh (D215).
#[test]
fn rfc5936_2_2_a_secondary_zone_is_transferred_kept_and_served_after_a_restart() {
    let state = tempfile::tempdir().expect("a directory");
    let root = primary(soa("root", "."), vec![stream("axfr-root")]);
    let mut server = Server::configured(|listen| secondary(listen, ".", root, state.path()));
    let transferred = server.event("secondary zone transferred").expect("logged");
    assert_eq!(transferred["fields"]["kind"], "full");
    assert_eq!(transferred["fields"]["serial"], ROOT);
    serves(&server, ".", ROOT);
    let dir = state.path().join("zones/root");
    assert!(dir.join("zone").is_file() && dir.join("timers").is_file());
    // The files stay where the thread started: another `state_dir` takes a restart.
    let elsewhere = tempfile::tempdir().expect("a directory");
    let listen = server.addr.to_string();
    let text = secondary(&listen, ".", root, elsewhere.path());
    std::fs::write(&server.config, text).expect("rewritten");
    server.hang_up();
    let changed = "changes to `state_dir` take a restart for the secondary zones";
    assert!(server.event(changed).is_some());
    drop(server);

    let (_quiet, nobody) = silent();
    let mut again = Server::configured(|listen| secondary(listen, ".", nobody, state.path()));
    let read = again
        .event("secondary zone read from disk")
        .expect("logged");
    assert_eq!(read["fields"]["serial"], ROOT);
    serves(&again, ".", ROOT);
    assert_eq!(
        logged(&again, "secondary zone refresh failed"),
        Vec::<serde_json::Value>::new()
    );
}

/// RFC 1995 §4: a zone kept at an older serial is brought to the primary's by the difference, journaled.
#[test]
fn rfc1995_4_a_zone_kept_on_disk_is_brought_up_to_date_by_an_ixfr() {
    let state = tempfile::tempdir().expect("a directory");
    let previous = dedens_testkit::path("authoritative/zones/root-previous.zone");
    kept(state.path(), "root", &previous, (0, now() + 604_800));
    let root = primary(soa("root", "."), vec![stream("root-ixfr")]);
    let mut server = Server::configured(|listen| secondary(listen, ".", root, state.path()));
    let read = server
        .event("secondary zone read from disk")
        .expect("logged");
    assert_eq!(read["fields"]["serial"], PREVIOUS);
    let transferred = server.event("secondary zone transferred").expect("logged");
    assert_eq!(transferred["fields"]["kind"], "incremental");
    assert_eq!(transferred["fields"]["serial"], ROOT);
    serves(&server, ".", ROOT);
    assert!(state.path().join("zones/root/journal").is_file());
}

/// RFC 1982 §3.2: a primary whose serial is behind the version served is not followed; the version stays.
#[test]
fn rfc1982_3_2_a_primary_behind_is_not_followed() {
    let state = tempfile::tempdir().expect("a directory");
    let example = dedens_testkit::path("zones/rfc4035_appendix_a.zone");
    kept(state.path(), "example.", &example, (0, now() + 3_600_000));
    // The SOA of the NSEC3 example zone: serial 1.
    let behind = primary(soa("nsec3_signed", "example."), Vec::new());
    let mut server =
        Server::configured(|listen| secondary(listen, "example.", behind, state.path()));
    let refused = server
        .event("primary serial behind ours, not followed")
        .expect("logged");
    assert_eq!(refused["fields"]["serial"], 1);
    assert_eq!(refused["fields"]["ours"], EXAMPLE);
    serves(&server, "example.", EXAMPLE);
}

/// RFC 1034 §4.3.5: a zone kept past its expire is not served: SERVFAIL with EDE 24 (RFC 8914 §4.25), as Knot
/// answers a zone without contents, until a transfer.
#[test]
fn rfc1034_4_3_5_an_expired_zone_is_answered_servfail() {
    let state = tempfile::tempdir().expect("a directory");
    let example = dedens_testkit::path("zones/rfc4035_appendix_a.zone");
    kept(state.path(), "example.", &example, (0, 1));
    let (_quiet, nobody) = silent();
    let mut server =
        Server::configured(|listen| secondary(listen, "example.", nobody, state.path()));
    server
        .event("secondary zone on disk expired, transferring it again")
        .expect("logged");
    let reply = ask_soa(&server, "example.");
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(errors(&reply), [InfoCode::INVALID_DATA]);
    assert_eq!(reply.answer.len(), 0);
}
