//! RFC 9718 §3 and D128: `dedensd` fetching the root's trust anchors and their signature from a loopback HTTP
//! server for a validating forward stage: a pair that verifies is kept with its signing time and read by the
//! validators of the reload that follows; under a later floor, the floor of a newer pair kept, it is refused, the
//! files stay and the bundled anchors serve.

use std::fs;

use crate::util::{Files, Server, silent};

/// When ICANN signed the captured pair (`testdata/dnssec`): its `signingTime`, 2025-03-25 20:25:02 UTC.
const SIGNED_AT: u64 = 1_742_934_302;

fn captured(name: &str) -> Vec<u8> {
    fs::read(dedens_testkit::path(&format!("dnssec/{name}"))).expect("a captured file")
}

#[test]
fn rfc9718_3_a_verified_pair_is_kept_and_never_rolled_back() {
    let files = Files::start();
    files.serve("/root-anchors.xml", captured("root-anchors.xml"));
    files.serve("/root-anchors.p7s", captured("root-anchors.p7s"));
    let dir = tempfile::tempdir().expect("a directory");
    let (_upstream, at) = silent();
    let url = files.url("/root-anchors.xml");
    let mut server = Server::configured(|listen| {
        format!(
            "listen: ['{listen}']\nroots:\n  anchors: '{url}'\ndownloads:\n  dir: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{at}']\n    dnssec: validate\n",
            dir.path().display()
        )
    });
    let downloaded = server
        .event("root trust anchors downloaded")
        .expect("downloaded");
    assert_eq!(downloaded["fields"]["signed_at"], SIGNED_AT);
    let read = server
        .event("root trust anchors from the saved copy")
        .expect("read");
    assert_eq!(read["fields"]["signed_at"], SIGNED_AT);
    let signed_at = dir.path().join("root-anchors.signed_at");
    assert_eq!(
        fs::read_to_string(&signed_at).expect("saved"),
        format!("{SIGNED_AT}\n")
    );
    server.hang_up();
    assert!(server.event("root trust anchors unchanged").is_some());

    // A newer pair was kept: the captured one, older, is refused, at reload and at download.
    let floor = format!("{}\n", SIGNED_AT + 1);
    fs::write(&signed_at, &floor).expect("written");
    server.hang_up();
    assert!(
        server
            .event("the saved root trust anchors do not verify, using the bundled ones")
            .is_some()
    );
    assert!(
        server
            .event("root trust anchors download failed, keeping the ones in use")
            .is_some()
    );
    assert_eq!(fs::read_to_string(&signed_at).expect("kept"), floor);
    assert_eq!(
        fs::read(dir.path().join("root-anchors.xml")).expect("kept"),
        captured("root-anchors.xml")
    );
}
