//! `dedensd`'s `authoritative` stage (D208): its zones answered with AA (RFC 1034 §4.3.2), a reload loading again the
//! zone whose files changed and no other (D120), a zone that fails to load serving its last version (D55), and the
//! queries asked while it reloads all answered; requests signed with a key of `keys` answered signed (RFC 8945 §5.3,
//! D211).

use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Question, Rcode, RecordType, TsigError, find_tsig};
use dedens_testkit::authoritative::TSIG_KEY;
use dedens_tsig::{Key, ResponseError, Verified, sign_request};

use crate::reload::logged;
use crate::util::{Server, ask_udp, decode, framed, read_framed, write_key};

/// The zones of RFC 4035 Appendix A and of RFC 1035 §5.3, the latter's `$INCLUDE` named as in `dir`, copied to
/// `dir`: the files of `example.` and `ISI.EDU.`.
fn zones(dir: &Path) -> (PathBuf, PathBuf) {
    let testdata = dedens_testkit::path("zones");
    let example = dir.join("example.zone");
    std::fs::copy(testdata.join("rfc4035_appendix_a.zone"), &example).expect("copied");
    let isi = dir.join("isi.zone");
    let text = std::fs::read_to_string(testdata.join("rfc1035_isi.zone")).expect("the zone");
    std::fs::write(
        &isi,
        text.replace("<SUBSYS>ISI-MAILBOXES.TXT", "mailboxes.zone"),
    )
    .expect("written");
    std::fs::copy(
        testdata.join("rfc1035_isi_mailboxes.zone"),
        dir.join("mailboxes.zone"),
    )
    .expect("copied");
    (example, isi)
}

/// A server of the zones `example` and `isi` alone.
fn authoritative(listen: &str, (example, isi): (&Path, &Path)) -> String {
    format!(
        "listen: ['{listen}']\npipeline: [zones]\nstages:\n  zones:\n    type: authoritative\n    zones:\n      - {{name: example, file: '{}'}}\n      - {{name: ISI.EDU, file: '{}'}}\n",
        example.display(),
        isi.display()
    )
}

/// The reply of `server` to `name` and `qtype`, asked with RD.
fn ask(server: &Server, name: &str, qtype: RecordType) -> Message<'static> {
    let query = Message::query(1, Question::new(name.parse().expect("a name"), qtype))
        .to_vec()
        .expect("a query fits");
    ask_udp(server.addr, &query)
}

/// The serial of the SOA in `reply`, if any.
fn serial_of(reply: &Message<'_>) -> Option<u32> {
    reply.answer.iter().find_map(|record| match record.data() {
        RData::Soa(soa) => Some(soa.serial),
        _ => None,
    })
}

/// The serial of the SOA of `ISI.EDU.` that `server` answers.
fn serial(server: &Server) -> u32 {
    serial_of(&ask(server, "ISI.EDU.", RecordType::SOA)).expect("a SOA")
}

/// The apexes of the zones `server` has loaded so far, one per load.
fn loaded(server: &Server) -> Vec<String> {
    logged(server, "zone loaded")
        .into_iter()
        .map(|event| {
            event["fields"]["zone"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// RFC 1034 §4.3.2: a name in a zone is answered with AA, whatever RD; RA is clear, nothing recurses; a name in no
/// zone is refused.
#[test]
fn rfc1034_4_3_2_dedensd_answers_its_zones_with_aa() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let mut server = Server::configured(|listen| authoritative(listen, (&example, &isi)));
    // S3: the zones every client can query are logged at the start.
    let zones = server
        .event("every client can query these zones, whatever `access` says (D208)")
        .expect("the zones logged");
    assert_eq!(zones["fields"]["count"], 2, "{zones}");
    assert_eq!(zones["fields"]["zones"], "ISI.EDU. example.", "{zones}");
    let reply = ask(&server, "ns1.example.", RecordType::A);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AA), "{reply:?}");
    assert!(!reply.header.flags.contains(Flags::RA), "{reply:?}");
    assert_eq!(serial(&server), 20);
    // The record of the file `$INCLUDE` reads.
    let reply = ask(&server, "MOE.ISI.EDU.", RecordType::MB);
    assert_eq!(reply.answer.len(), 1, "{reply:?}");
    let reply = ask(&server, "example.org.", RecordType::A);
    assert_eq!(reply.rcode(), Rcode::REFUSED);
}

/// D208: a zone served below another that has no NS at its apex is warned of; one the parent delegates is not.
#[test]
fn a_zone_its_parent_does_not_delegate_is_warned_of() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let warning =
        "zone served below a zone with no NS at its apex: the parent does not delegate it";
    // `a.example.` is a cut of `example.` (RFC 4035 Appendix A), `d.example.` is none.
    for (child, warned) in [("a.example", false), ("d.example", true)] {
        let mut server = Server::configured(|listen| {
            authoritative(listen, (&example, &isi)).replace("ISI.EDU", child)
        });
        // Logged after the zones are built.
        let started = "every client can query these zones, whatever `access` says (D208)";
        assert!(server.event(started).is_some());
        let events = logged(&server, warning);
        if warned {
            assert_eq!(events.len(), 1, "{child}: {events:?}");
            assert_eq!(events[0]["fields"]["zone"], "d.example.");
            assert_eq!(events[0]["fields"]["parent"], "example.");
        } else {
            assert_eq!(events, Vec::<serde_json::Value>::new(), "{child}");
        }
    }
}

/// D120, D55: a reload loads again the zone whose file changed, no other; one that no longer loads keeps its last
/// version, the error logged, and the reload serves the rest.
#[test]
fn a_reload_loads_the_zone_that_changed_and_keeps_one_that_fails() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let mut server = Server::configured(|listen| authoritative(listen, (&example, &isi)));
    assert_eq!(loaded(&server), ["example.", "ISI.EDU."]);
    let warnings = "zone loaded with warnings";
    assert_eq!(logged(&server, warnings), Vec::<serde_json::Value>::new());

    // The next version adds a mailbox of another TTL to an `RRset`, a warning (RFC 2181 §5.2).
    let text = std::fs::read_to_string(&isi).expect("the zone");
    std::fs::write(&isi, text.replace("20     ; SERIAL", "21     ; SERIAL")).expect("rewritten");
    let mailboxes = dir.path().join("mailboxes.zone");
    let mut text = std::fs::read_to_string(&mailboxes).expect("the mailboxes");
    text.push_str("MOE 60 MB B.ISI.EDU.\n");
    std::fs::write(&mailboxes, text).expect("rewritten");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    assert_eq!(loaded(&server), ["example.", "ISI.EDU.", "ISI.EDU."]);
    assert_eq!(serial(&server), 21);
    let warned = logged(&server, warnings);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert_eq!(warned[0]["fields"]["zone"], "ISI.EDU.");

    std::fs::write(&isi, "not a zone\n").expect("rewritten");
    server.hang_up();
    let failed = server
        .event("zone failed to load, serving its last version")
        .expect("the failure logged");
    assert_eq!(failed["fields"]["zone"], "ISI.EDU.");
    assert!(server.event("reloaded").is_some());
    assert_eq!(serial(&server), 21);
}

/// D55, D208: the queries asked while a reload loads a zone again are all answered, by the old zone then the new.
#[test]
fn a_reload_drops_no_query() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let mut server = Server::configured(|listen| authoritative(listen, (&example, &isi)));
    let server_addr = server.addr;
    let done = Arc::new(AtomicBool::new(false));
    let asking = {
        let done = Arc::clone(&done);
        thread::spawn(move || {
            let query = Message::query(
                1,
                Question::new("ISI.EDU.".parse().expect("a name"), RecordType::SOA),
            )
            .to_vec()
            .expect("a query fits");
            let mut serials = Vec::new();
            while !done.load(Ordering::Relaxed) {
                // `ask_udp` fails the test on a query unanswered.
                serials.extend(serial_of(&ask_udp(server_addr, &query)));
            }
            serials
        })
    };
    let text = std::fs::read_to_string(&isi).expect("the zone");
    std::fs::write(&isi, text.replace("20     ; SERIAL", "21     ; SERIAL")).expect("rewritten");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    assert_eq!(serial(&server), 21);
    done.store(true, Ordering::Relaxed);
    let serials = asking.join().expect("every query answered");
    assert_ne!(serials.len(), 0);
    // In order: once the new zone answers, the old one never does again.
    assert!(
        serials.windows(2).all(|pair| pair[0] <= pair[1]),
        "{serials:?}"
    );
    assert!(
        serials.iter().all(|&serial| serial == 20 || serial == 21),
        "{serials:?}"
    );
}

/// The raw reply over a new TCP connection to `query`.
fn exchange_tcp(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(server).expect("connected");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a timeout");
    stream.write_all(&framed(query)).expect("sent");
    read_framed(&mut stream).expect("a reply")
}

/// Seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

/// The key of the captures (D203) named `name`.
fn key(name: &str) -> Key {
    let algorithm = TSIG_KEY.algorithm.parse().expect("an algorithm");
    Key::from_base64(name.parse().expect("a name"), algorithm, TSIG_KEY.secret).expect("a key")
}

/// RFC 8945 §5.3, D211: a query signed with a key of `keys`, read from its file at start, is answered signed with it,
/// over UDP and TCP; the client's verifier (D205) accepts the answer. One signed with a key the server does not have
/// is answered NOTAUTH BADKEY, unsigned (§5.3.2); an unsigned query is answered unsigned.
#[test]
fn rfc8945_5_3_a_signed_query_is_answered_signed() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let secret = dir.path().join("tsig.key");
    write_key(&secret, TSIG_KEY.secret);
    let mut server = Server::configured(|listen| {
        format!(
            "keys:\n  - {{name: {}, algorithm: {}, secret_file: '{}'}}\n{}",
            TSIG_KEY.name,
            TSIG_KEY.algorithm,
            secret.display(),
            authoritative(listen, (&example, &isi))
        )
    });
    assert!(
        server
            .event("every client can query these zones, whatever `access` says (D208)")
            .is_some()
    );
    let query = || {
        Message::query(
            7,
            Question::new("ISI.EDU.".parse().expect("a name"), RecordType::SOA),
        )
        .to_vec()
        .expect("a query fits")
    };
    let known = key(TSIG_KEY.name);
    for udp in [true, false] {
        let mut wire = query();
        let mut verifier = sign_request(&known, &mut wire, now()).expect("signed");
        let reply = if udp {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("a timeout");
            socket.send_to(&wire, server.addr).expect("sent");
            let mut buf = vec![0; 65535];
            let len = socket.recv(&mut buf).expect("a reply");
            buf.truncate(len);
            buf
        } else {
            exchange_tcp(server.addr, &wire)
        };
        assert_eq!(
            verifier.verify(&reply, now()),
            Ok(Verified::Signed),
            "udp {udp}"
        );
        verifier.finish().expect("complete");
        let message = decode(&reply);
        assert_eq!(message.rcode(), Rcode::NOERROR);
        assert_eq!(serial_of(&message), Some(20));
    }

    let unknown = key("another-key");
    let mut wire = query();
    let mut verifier = sign_request(&unknown, &mut wire, now()).expect("signed");
    let reply = exchange_tcp(server.addr, &wire);
    assert_eq!(decode(&reply).rcode(), Rcode::NOTAUTH);
    let refused = ResponseError::Refused {
        error: TsigError::BADKEY,
        authenticated: false,
    };
    assert_eq!(verifier.verify(&reply, now()), Err(refused));

    let reply = exchange_tcp(server.addr, &query());
    assert_eq!(
        find_tsig(&reply),
        Ok(None),
        "an unsigned query answered signed"
    );
}

/// D211, D115: a key file others can read is refused at start.
#[cfg(unix)]
#[test]
fn a_key_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let secret = dir.path().join("tsig.key");
    std::fs::write(&secret, TSIG_KEY.secret).expect("written");
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let text = format!(
        "keys:\n  - {{name: k, algorithm: hmac-sha256, secret_file: '{}'}}\n{}",
        secret.display(),
        authoritative("127.0.0.1:53", (&example, &isi))
    );
    let (code, stderr) = crate::util::validate(&text);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("can be accessed by others"), "{stderr}");
}

/// A `DNSCrypt` resolver serving `example.` alone, with `access` lines.
#[cfg(feature = "dnscrypt")]
fn dnscrypt(access: &str) -> crate::dnscrypt::Resolver {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, _) = zones(dir.path());
    let stages = format!(
        "pipeline: [zones]\nstages:\n  zones:\n    type: authoritative\n    zones:\n      - {{name: example, file: '{}'}}\n",
        example.display()
    );
    crate::dnscrypt::resolver_of("", access, &stages)
}

/// D208, D99: where zones are served, the certificates are answered over UDP, outside the pipeline and its rate
/// limit, only to a client the access lists permit, as without zones: any other source could have them reflected
/// at a victim. A client denied has them over TCP, where it proves its address.
#[cfg(feature = "dnscrypt")]
#[test]
fn a_denied_client_has_the_certificates_over_tcp_only() {
    use std::net::UdpSocket;
    use std::time::Duration;

    use dedens_proto::rdata::RData;

    let certificates = Message::query(
        9,
        Question::new(
            crate::dnscrypt::PROVIDER.parse().expect("a name"),
            RecordType::TXT,
        ),
    )
    .to_vec()
    .expect("a query");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("a timeout");
    for (allow, action, permitted) in [
        ("10.0.0.0/8", "refuse", false),
        ("10.0.0.0/8", "drop", false),
        ("127.0.0.0/8", "refuse", true),
    ] {
        let access = format!("access:\n  allow: ['{allow}']\n  action: {action}\n");
        let resolver = dnscrypt(&access);
        socket
            .send_to(&certificates, resolver.server.addr)
            .expect("sent");
        let mut buf = [0; 512];
        match socket.recv(&mut buf) {
            Ok(len) => {
                assert!(permitted, "{allow} {action}: UDP answered");
                let reply = crate::util::decode(&buf[..len]);
                assert!(matches!(reply.answer[0].data(), RData::Txt(_)));
            }
            Err(_) => assert!(!permitted, "{allow} {action}: UDP not answered"),
        }
        let reply = crate::util::ask_tcp(resolver.server.addr, &certificates);
        assert_eq!(reply.answer.len(), 2, "{allow} {action}: TCP");
    }
}

/// D208, D99: over `DNSCrypt` a zone answers a client the access lists deny, whatever the action, as over every
/// transport: the packets are opened for it. A name outside the zones gets what the lists say, sealed: REFUSED, or
/// nothing. Over TCP too, where the client has the certificates; over UDP it has them from TCP.
#[cfg(feature = "dnscrypt")]
#[test]
fn a_zone_answers_a_client_the_access_lists_deny_over_dnscrypt() {
    use dedens_net::client::Client;
    use dedens_proto::Transport;

    for (action, transport) in [
        ("refuse", Transport::Udp),
        ("drop", Transport::Udp),
        ("refuse", Transport::Tcp),
        ("drop", Transport::Tcp),
    ] {
        let access = format!("access:\n  allow: ['10.0.0.0/8']\n  action: {action}\n");
        let resolver = dnscrypt(&access);
        let ask = |name: &str| {
            let question = Question::new(name.parse().expect("a name"), RecordType::A);
            crate::dnscrypt::ask_message(
                &Client::new(),
                &resolver.stamp,
                Message::query(0x0102, question),
                transport,
            )
        };
        let response = ask("ns1.example.").expect("a zone answers");
        assert_eq!(response.transport, transport, "{action}");
        let reply = crate::util::decode(&response.wire);
        assert_eq!(reply.rcode(), Rcode::NOERROR, "{action} {transport:?}");
        assert!(
            reply.header.flags.contains(Flags::AA),
            "{action} {transport:?}: {reply:?}"
        );
        match ask("example.org.") {
            Ok(response) => {
                assert_eq!(action, "refuse");
                let reply = crate::util::decode(&response.wire);
                assert_eq!(reply.rcode(), Rcode::REFUSED);
            }
            Err(_) => assert_eq!(action, "drop"),
        }
    }
}
