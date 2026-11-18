//! D128 and D104: `dedensd` keeping IANA's TLD list fresh for its `tlds` stage. A list fetched from a loopback
//! HTTP server serves from the reload that follows, and after a restart from its saved copy, the server failing; a
//! list too short to be IANA's is refused, and the saved copy stays. A special-use TLD the stage has no rule for is
//! warned of, and answered as its status says. The list served is the bundled one, captured from IANA, edited
//! ([`fresh`]): no real list tells from it.

use std::fs;
use std::path::Path;

use dedens_proto::{Rcode, RecordType};

use crate::rfc6761::{ask, asked};
use crate::util::{Files, Server, silent, tld_list};

/// The bundled list generated now ([`tld_list`]), without `fr`, and with `lan` a special-use TLD as `test` is: a
/// list that tells from the bundled one, with a special-use TLD of no known use.
fn fresh() -> Vec<u8> {
    let mut list = tld_list();
    let domains = list["domains"].as_array_mut().expect("domains");
    domains.retain(|domain| domain["name"] != "fr");
    let mut lan = domains
        .iter()
        .find(|domain| domain["name"] == "test")
        .expect("test")
        .clone();
    lan["name"] = "lan".into();
    domains.push(lan);
    domains.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    serde_json::to_vec(&list).expect("JSON")
}

/// A server whose `tlds` stage reads the list at `url`, kept in `dir`, and forwards the rest to `upstream`.
fn config(listen: &str, url: &str, dir: &Path, upstream: &str) -> String {
    format!(
        "listen: ['{listen}']\nroots:\n  tlds: '{url}'\ndownloads:\n  dir: '{}'\npipeline: [tlds, up]\nstages:\n  tlds:\n    type: tlds\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 200\n    tries: 1\n",
        dir.display()
    )
}

#[test]
fn a_fetched_list_serves_and_outlives_failures_and_restarts() {
    let files = Files::start();
    files.serve("/tlds.json", fresh());
    let dir = tempfile::tempdir().expect("a directory");
    let (upstream, at) = silent();
    let at = at.to_string();
    let url = files.url("/tlds.json");
    let mut server = Server::configured(|listen| config(listen, &url, dir.path(), &at));
    let unknown = server
        .event("a special-use TLD the tlds stage has no rule for, answered as its status says")
        .expect("warned");
    assert_eq!(unknown["fields"]["tld"], "lan.");
    assert!(server.event("TLD list downloaded").is_some());
    assert!(server.event("reloaded").is_some());
    assert_eq!(
        ask(&server, "x.lan.", RecordType::A, false).rcode(),
        Rcode::NXDOMAIN
    );
    assert_eq!(
        ask(&server, "x.fr.", RecordType::A, false).rcode(),
        Rcode::NXDOMAIN
    );
    assert_eq!(
        ask(&server, "x.com.", RecordType::A, false).rcode(),
        Rcode::SERVFAIL
    );
    assert_eq!(asked(&upstream), ["x.com."]);

    // IANA's list cut to six TLDs is refused: the saved copy stays in use.
    let cut = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/dedens-roots/tests/data/tlds.json"
    );
    files.serve("/tlds.json", fs::read(cut).expect("the cut list"));
    server.hang_up();
    assert!(
        server
            .event("TLD list download failed, keeping the one in use")
            .is_some()
    );
    assert_eq!(
        ask(&server, "x.fr.", RecordType::A, false).rcode(),
        Rcode::NXDOMAIN
    );
    drop(server);

    // A start serves the saved copy at once, whatever the download does.
    files.serve("/tlds.json", "not a list");
    let mut server = Server::configured(|listen| config(listen, &url, dir.path(), &at));
    assert_eq!(
        ask(&server, "x.fr.", RecordType::A, false).rcode(),
        Rcode::NXDOMAIN
    );
    assert!(
        server
            .event("TLD list download failed, keeping the one in use")
            .is_some()
    );
    assert_eq!(
        ask(&server, "x.fr.", RecordType::A, false).rcode(),
        Rcode::NXDOMAIN
    );
    assert_eq!(asked(&upstream), Vec::<String>::new());
}
