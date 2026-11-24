//! RFC 9718 §3 and D128: `dedensd` fetching the root's trust anchors and their signature from a loopback HTTP
//! server for a validating forward stage: a pair that verifies is kept in `state_dir`, its keys and signing time,
//! and read by the validators of the reload that follows; under a later floor, that of a newer pair kept, it is
//! refused and the kept file stays in use. A kept file that does not read refuses the start, and leaves the anchors
//! in use at a reload. A `state_dir` that cannot be written is warned of, and the bundled anchors serve. The `.part`
//! file a killed run left is swept at start (D104).

use std::fs;
use std::path::Path;
use std::process::Command;

use dedens_proto::edns::{Edns, EdnsOption, InfoCode};
use dedens_proto::{Message, Rcode};
use dedens_testkit::dnssec::response;
use dedens_testkit::responder::Responder;

use crate::util::{Files, Server, ask_udp, silent, write_config};

/// When ICANN signed the captured pair (`testdata/dnssec`): its `signingTime`, 2025-03-25 20:25:02 UTC.
const SIGNED_AT: u64 = 1_742_934_302;

fn captured(name: &str) -> Vec<u8> {
    fs::read(dedens_testkit::path(&format!("dnssec/{name}"))).expect("a captured file")
}

/// A validating forward server listening on `listen`, the anchors at `url` kept in `state`, the rest sent to `at`.
fn config(listen: &str, url: &str, state: &Path, at: &str) -> String {
    format!(
        "listen: ['{listen}']\nroots:\n  anchors: '{url}'\nstate_dir: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{at}']\n    dnssec: validate\n",
        state.display()
    )
}

#[test]
fn rfc9718_3_a_verified_pair_is_kept_and_never_rolled_back() {
    let files = Files::start();
    files.serve("/root-anchors.xml", captured("root-anchors.xml"));
    files.serve("/root-anchors.p7s", captured("root-anchors.p7s"));
    let state = tempfile::tempdir().expect("a directory");
    // What a run killed while writing the kept file leaves: swept at start (D104).
    let leftover = state.path().join("root-anchors.x1y2.part");
    fs::write(&leftover, "").expect("written");
    let (_upstream, at) = silent();
    let at = at.to_string();
    let url = files.url("/root-anchors.xml");
    let mut server = Server::configured(|listen| config(listen, &url, state.path(), &at));
    assert!(server.event("removed a leftover of a download").is_some());
    assert!(!leftover.exists());
    let downloaded = server
        .event("root trust anchors downloaded")
        .expect("downloaded");
    assert_eq!(downloaded["fields"]["signed_at"], SIGNED_AT);
    assert!(server.event("reloaded").is_some());
    let kept = state.path().join("root-anchors");
    let text = fs::read_to_string(&kept).expect("kept");
    assert!(
        text.starts_with(&format!("dedens root anchors 1\nsigned-at {SIGNED_AT}\n")),
        "{text}"
    );
    server.hang_up();
    assert!(server.event("root trust anchors unchanged").is_some());

    // A newer pair was kept: the captured one, older, is refused, and the kept file stays.
    let later = text.replace(&SIGNED_AT.to_string(), &(SIGNED_AT + 1).to_string());
    fs::write(&kept, &later).expect("written");
    server.hang_up();
    let read = server
        .event("root trust anchors from the kept copy")
        .expect("read");
    assert_eq!(read["fields"]["signed_at"], SIGNED_AT + 1);
    assert!(
        server
            .event("root trust anchors download failed, keeping the ones in use")
            .is_some()
    );
    assert_eq!(fs::read_to_string(&kept).expect("kept"), later);

    // A kept file that does not read leaves the anchors in use at a reload, and refuses a start (D115).
    fs::write(&kept, "dedens root anchors 2\n").expect("written");
    server.hang_up();
    assert!(
        server
            .event("the kept root trust anchors do not read, keeping the ones in use")
            .is_some()
    );
    assert!(server.event("reloaded").is_some());
    drop(server);
    let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(write_config(&config(
            "127.0.0.1:0",
            &url,
            state.path(),
            &at,
        )))
        .output()
        .expect("dedensd runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("root-anchors"), "{stderr}");
}

/// D128: the validators trust the kept anchors, not the bundled ones, against a loopback upstream answering the
/// captures of `dedens-dnssec`, `nlnetlabs.nl` and its chain from the root. Their signatures are long expired by the system's clock, so no answer is secure; what
/// tells the anchors apart is where the chain breaks. The bundled anchors name KSK-2017 (20326), which is in the
/// captured root DNSKEY set: the chain ends at its expired signature. The kept file names KSK-2010 (19036) alone, the
/// captured pair's key with its end date removed: no root key matches it.
#[test]
fn the_validators_trust_the_kept_anchors() {
    let upstream = Responder::start(&[
        "alg8_a",
        "root_dnskey",
        "nl_ds",
        "nl_dnskey",
        "nlnetlabs_nl_ds",
        "nlnetlabs_nl_dnskey",
    ]);
    let files = Files::start();
    let url = files.url("/root-anchors.xml");
    let at = upstream.addr.to_string();
    let state = tempfile::tempdir().expect("a directory");
    let mut query = Message::query(1, response("alg8_a").questions.swap_remove(0));
    query.edns = Some(Edns::default());
    let query = query.to_vec().expect("a query fits");
    let ask = |server: &Server| {
        let reply = ask_udp(server.addr, &query);
        assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
        let options = reply.edns.iter().flat_map(|edns| &edns.options);
        options
            .filter_map(|option| match option {
                EdnsOption::Ede(error) => Some(error.code),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    let bundled = Server::configured(|listen| config(listen, &url, state.path(), &at));
    assert_eq!(ask(&bundled), [InfoCode::SIGNATURE_EXPIRED]);
    drop(bundled);

    fs::write(
        state.path().join("root-anchors"),
        format!("dedens root anchors 1\nsigned-at {SIGNED_AT}\nds 19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5 from 1279152000\n"),
    )
    .expect("written");
    let kept = Server::configured(|listen| config(listen, &url, state.path(), &at));
    assert_eq!(ask(&kept), [InfoCode::DNSKEY_MISSING]);
}

/// D128: a `state_dir` that cannot be written, here under a file, is warned of; the bundled anchors serve.
#[test]
fn a_state_dir_that_cannot_be_written_leaves_the_bundled_anchors() {
    let files = Files::start();
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("file");
    fs::write(&file, "").expect("written");
    let (_upstream, at) = silent();
    let at = at.to_string();
    let url = files.url("/root-anchors.xml");
    let mut server = Server::configured(|listen| config(listen, &url, &file.join("state"), &at));
    let warned = server
        .event("cannot write the directory: its root file is not fetched, the copy there or the bundled one serves")
        .expect("warned");
    assert!(
        warned["fields"]["dir"]
            .as_str()
            .is_some_and(|dir| dir.ends_with("state"))
    );
}
