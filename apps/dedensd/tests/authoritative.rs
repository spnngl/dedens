//! `dedensd`'s `authoritative` stage (D208): its zones answered with AA (RFC 1034 §4.3.2), a reload loading again the
//! zone whose files changed and no other (D120), a zone that fails to load serving its last version (D55), and the
//! queries asked while it reloads all answered.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Question, Rcode, RecordType};

use crate::reload::logged;
use crate::util::{Server, ask_udp};

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
    let server = Server::configured(|listen| authoritative(listen, (&example, &isi)));
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

/// D120, D55: a reload loads again the zone whose file changed, no other; one that no longer loads keeps its last
/// version, the error logged, and the reload serves the rest.
#[test]
fn a_reload_loads_the_zone_that_changed_and_keeps_one_that_fails() {
    let dir = tempfile::tempdir().expect("a directory");
    let (example, isi) = zones(dir.path());
    let mut server = Server::configured(|listen| authoritative(listen, (&example, &isi)));
    assert_eq!(loaded(&server), ["example.", "ISI.EDU."]);

    let text = std::fs::read_to_string(&isi).expect("the zone");
    std::fs::write(&isi, text.replace("20     ; SERIAL", "21     ; SERIAL")).expect("rewritten");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    assert_eq!(loaded(&server), ["example.", "ISI.EDU.", "ISI.EDU."]);
    assert_eq!(serial(&server), 21);

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
