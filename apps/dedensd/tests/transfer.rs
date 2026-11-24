//! `dedensd`'s zone transfers out (D214), read by `dedens-net`'s transfer client (D210): AXFR (RFC 5936) over TCP,
//! IXFR (RFC 1995) answered from the changes of the reloads, a client the zone's access list denies refused (D211),
//! and a client that does not read holding its own connection alone, its transfers counted against the bounds of
//! RFC 9103 §6.3.3.

use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use dedens_net::transfer::stream::{Asked, Reader, Step as Read, ixfr_soa};
use dedens_net::transfer::{self, Limits, Transfer};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Message, Name, Question, Rcode, RecordType, Serial};
use socket2::{Domain, Socket, Type};

use crate::authoritative::zones;
use crate::util::{Server, ask_tcp, decode, framed, read_framed};

/// The ID of every request.
const ID: u16 = 0x0b0e;

/// The captured root zone.
fn root() -> String {
    let path = dedens_testkit::path("authoritative/zones/root.zone");
    path.display().to_string()
}

/// A server of `example.`, `ISI.EDU.` and the root, transfers permitted to `transfer`.
fn primary(listen: &str, (example, isi): (&Path, &Path), transfer: &str) -> String {
    let zone = |name: &str, file: &str| {
        format!(
            "      - {{name: '{name}', file: '{file}', transfer: [{{networks: ['{transfer}']}}]}}\n"
        )
    };
    format!(
        "listen: ['{listen}']\npipeline: [zones]\nstages:\n  zones:\n    type: authoritative\n    zones:\n{}{}{}",
        zone("example", &example.display().to_string()),
        zone("ISI.EDU", &isi.display().to_string()),
        zone(".", &root()),
    )
}

/// A connection to `server` that `asked` the zone `apex`, its receive buffer small: what it does not read stays
/// on the server, not in the kernel's buffers.
fn ask(server: SocketAddr, apex: &Name<'static>, asked: Asked) -> TcpStream {
    let authority = match asked {
        Asked::Ixfr(serial) => Some(ixfr_soa(apex, serial)),
        Asked::Axfr(_) => None,
    };
    let socket = Socket::new(Domain::for_address(server), Type::STREAM, None).expect("a socket");
    socket.set_recv_buffer_size(4096).expect("a buffer size");
    socket.connect(&server.into()).expect("connected");
    let mut stream = TcpStream::from(socket);
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a timeout");
    let request = transfer::query(apex, asked.qtype(), authority, ID);
    stream.write_all(&framed(&request)).expect("sent");
    stream
}

/// What the client reads of `server`'s answer to `asked` of `apex`.
fn received(server: SocketAddr, apex: &str, asked: Asked) -> Transfer {
    let apex: Name<'static> = apex.parse().expect("a name");
    let mut stream = ask(server, &apex, asked);
    let mut reader = Reader::new(apex, ID, asked, None, &Limits::default());
    loop {
        let message = read_framed(&mut stream).expect("a message");
        match reader.message(&message, 0).expect("a valid message") {
            Read::More(more) => reader = more,
            Read::Done(transfer) => return transfer,
        }
    }
}

/// The records of the zone file at `path`, as `dedens-zone` loads it, against those of `transfer`.
fn whole(transfer: Transfer) -> dedens_zone::Zone {
    let Transfer::Full(loaded) = transfer else {
        unreachable!("not the whole zone: {transfer:?}");
    };
    loaded.zone
}

/// RFC 5936 §2.2, RFC 1995 §4, D214: each zone is transferred whole; after a reload IXFR from the version before
/// gets the changes, from the current one its SOA alone; from a version the server never had, the zone whole.
#[test]
fn rfc5936_2_2_rfc1995_4_zones_are_transferred_whole_and_by_their_changes() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let mut server = Server::configured(|listen| primary(listen, (&example, &isi), "127.0.0.0/8"));
    for (apex, records) in [("example.", 63), ("ISI.EDU.", 17)] {
        let zone = whole(received(server.addr, apex, Asked::Axfr(None)));
        assert_eq!(zone.record_count(), records, "{apex}");
    }
    let root = whole(received(server.addr, ".", Asked::Axfr(None)));
    assert_eq!(root.soa().serial, 2_026_112_201);

    let text = std::fs::read_to_string(&isi).expect("the zone");
    std::fs::write(&isi, text.replace("20     ; SERIAL", "21     ; SERIAL")).expect("rewritten");
    let mailboxes = dir.path().join("mailboxes.zone");
    let mut text = std::fs::read_to_string(&mailboxes).expect("the mailboxes");
    text.push_str("MOE MB B.ISI.EDU.\n");
    std::fs::write(&mailboxes, text).expect("rewritten");
    server.hang_up();
    assert!(server.event("reloaded").is_some());

    let Transfer::Incremental(changes) =
        received(server.addr, "ISI.EDU.", Asked::Ixfr(Serial::new(20)))
    else {
        unreachable!("not the changes");
    };
    let [changes] = &changes[..] else {
        unreachable!("not one changeset: {changes:?}");
    };
    assert_eq!(
        (changes.from_serial(), changes.to_serial()),
        (Serial::new(20), Serial::new(21))
    );
    assert_eq!(changes.removed(), []);
    let added: Vec<_> = changes.added().iter().map(ToString::to_string).collect();
    assert_eq!(added, ["MOE.ISI.EDU.\t3600\tIN\tMB\tB.ISI.EDU."]);
    let current = received(server.addr, "ISI.EDU.", Asked::Ixfr(Serial::new(21)));
    assert!(matches!(current, Transfer::UpToDate), "{current:?}");
    let unknown = received(server.addr, "ISI.EDU.", Asked::Ixfr(Serial::new(19)));
    assert_eq!(whole(unknown).soa().serial, 21);
}

/// D211, RFC 8914 §4.19: a client the zone's `transfer` list does not name is refused, with the extended error
/// "Prohibited".
#[test]
fn d211_a_client_the_transfer_list_denies_is_refused_prohibited() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let server = Server::configured(|listen| primary(listen, (&example, &isi), "192.0.2.0/24"));
    let mut query = Message::query(
        ID,
        Question::new("example.".parse().expect("a name"), RecordType::AXFR),
    );
    query.edns = Some(dedens_proto::edns::Edns::default());
    let reply = ask_tcp(server.addr, &query.to_vec().expect("a query fits"));
    assert_eq!(reply.rcode(), Rcode::REFUSED);
    let edns = reply.edns.expect("an OPT record");
    assert!(
        matches!(&edns.options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::PROHIBITED),
        "{:?}",
        edns.options
    );
}

/// A connection that asked the root and read its first message alone: its transfer started, the rest waits.
fn stalled(server: SocketAddr) -> TcpStream {
    let mut stream = ask(server, &Name::root(), Asked::Axfr(None));
    let first = read_framed(&mut stream).expect("a message");
    assert_eq!(decode(&first).rcode(), Rcode::NOERROR);
    stream
}

/// RFC 9103 §6.3.3, RFC 7766 §10, D214: a client that asks the root and stops reading holds its own connection,
/// another transfer is made meanwhile; past two transfers at once to one client, the next is answered SERVFAIL.
#[test]
fn rfc9103_6_3_3_a_client_that_does_not_read_holds_its_connection_and_its_transfers() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let server = Server::configured(|listen| primary(listen, (&example, &isi), "127.0.0.0/8"));
    let first = stalled(server.addr);
    let started = Instant::now();
    let zone = whole(received(server.addr, "ISI.EDU.", Asked::Axfr(None)));
    assert_eq!(zone.soa().serial, 20);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let second = stalled(server.addr);
    let mut third = ask(server.addr, &Name::root(), Asked::Axfr(None));
    let reply = read_framed(&mut third).expect("a reply");
    let reply = decode(&reply);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(reply.questions.len(), 1);
    drop((first, second));
}
