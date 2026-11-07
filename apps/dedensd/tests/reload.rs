//! `dedensd` reloading its configuration file on SIGHUP (D55): the new pipeline answers, and one that does not read
//! leaves the running one in place; a list is read once, and again only when it changed (D120).

#![cfg(unix)]

mod common;

use std::net::IpAddr;

use common::{Server, ask_udp};
use dedens_proto::rdata::RData;
use dedens_proto::{Message, Question, Rcode, RecordType};

/// A server answering `www.example.` from a hosts stage.
fn hosts(listen: &str, address: &str) -> String {
    format!(
        "listen: ['{listen}']\npipeline: [hosts]\nstages:\n  hosts:\n    type: hosts\n    entries: ['{address} www.example']\n"
    )
}

/// The addresses `server` answers for `www.example.`.
fn addresses(server: &Server) -> Vec<IpAddr> {
    let name = "www.example.".parse().expect("a name");
    let query = Message::query(1, Question::new(name, RecordType::A))
        .to_vec()
        .expect("a query fits");
    ask_udp(server.addr, &query)
        .answer
        .iter()
        .filter_map(|record| match record.data() {
            RData::A(address) => Some(IpAddr::V4(address)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_reload_serves_the_new_configuration() {
    let mut server = Server::configured(|listen| hosts(listen, "192.0.2.1"));
    assert_eq!(addresses(&server), ["192.0.2.1".parse::<IpAddr>().unwrap()]);
    let listen = server.addr.to_string();
    std::fs::write(&server.config, hosts(&listen, "192.0.2.2")).expect("rewritten");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    assert_eq!(addresses(&server), ["192.0.2.2".parse::<IpAddr>().unwrap()]);
    // Nothing that takes a restart changed: nothing to warn of.
    let stderr = server.stderr();
    assert!(
        !stderr.iter().any(|line| line.contains("take a restart")),
        "{stderr:?}"
    );
}

#[test]
fn a_configuration_that_does_not_read_leaves_the_running_one() {
    let mut server = Server::configured(|listen| hosts(listen, "192.0.2.1"));
    let listen = server.addr.to_string();
    let broken = format!("listen: ['{listen}']\npipeline: [nope]\nstages: {{}}\n");
    std::fs::write(&server.config, broken).expect("rewritten");
    server.hang_up();
    let failed = server
        .event("reload failed, serving the previous configuration")
        .expect("the failure logged");
    let error = failed["fields"]["error"].as_str().expect("its error");
    assert!(error.contains("`nope`"), "{error}");
    assert_eq!(addresses(&server), ["192.0.2.1".parse::<IpAddr>().unwrap()]);
}

/// A server with three blocklist stages: the lists `a` and `b` in files, and `a` again.
fn blocklists(listen: &str, a: &std::path::Path, b: &std::path::Path) -> String {
    let (a, b) = (a.display(), b.display());
    format!(
        "listen: ['{listen}']\npipeline: [one, two, three, hosts]\nstages:\n  one:\n    type: blocklist\n    file: '{a}'\n  two:\n    type: blocklist\n    file: '{b}'\n  three:\n    type: blocklist\n    file: '{a}'\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 www.example']\n"
    )
}

/// Whether `server` blocks `name`.
fn blocks(server: &Server, name: &str) -> bool {
    let query = Message::query(
        1,
        Question::new(name.parse().expect("a name"), RecordType::A),
    )
    .to_vec()
    .expect("a query fits");
    ask_udp(server.addr, &query).rcode() == Rcode::NXDOMAIN
}

/// The events `server` has logged so far with `message`.
fn logged(server: &Server, message: &str) -> Vec<serde_json::Value> {
    server
        .stderr()
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["fields"]["message"] == message)
        .collect()
}

/// The files of the lists `server` has read so far, one per reading.
fn parsed(server: &Server) -> Vec<String> {
    logged(server, "list parsed")
        .into_iter()
        .map(|event| {
            event["fields"]["file"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// A list is read once however many stages name it, and a reload reads again the list that changed, and merges
/// again the stages that use it, no other.
#[test]
fn a_reload_reads_the_lists_that_changed_only() {
    let dir = tempfile::tempdir().expect("a directory");
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, "ads.example\n").expect("written");
    std::fs::write(&b, "tracker.example\n").expect("written");
    let mut server = Server::configured(|listen| blocklists(listen, &a, &b));
    let first = parsed(&server);
    assert_eq!(first.len(), 2, "{first:?}");
    // The stages one and three read the same list: one set.
    assert_eq!(logged(&server, "lists merged").len(), 2);
    assert!(blocks(&server, "ads.example."));
    assert!(blocks(&server, "tracker.example."));

    // Nothing changed: nothing is read again.
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    assert_eq!(parsed(&server), first);
    assert_eq!(logged(&server, "lists merged").len(), 2);

    // One list changed: it is read again, and its stage answers from it.
    std::fs::write(&b, "tracker.example\nmetrics.example\n").expect("rewritten");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    let second = parsed(&server);
    assert_eq!(second.len(), 3, "{second:?}");
    assert_eq!(second[2], b.display().to_string());
    assert_eq!(logged(&server, "lists merged").len(), 3);
    assert!(blocks(&server, "metrics.example."));
    assert!(blocks(&server, "ads.example."));

    // A list that stops reading is refused as before, the running configuration kept.
    std::fs::write(&a, "not a name\n").expect("rewritten");
    server.hang_up();
    let failed = server
        .event("reload failed, serving the previous configuration")
        .expect("the failure logged");
    let error = failed["fields"]["error"].as_str().expect("its error");
    assert!(error.contains("a.txt` line 1"), "{error}");
    assert!(blocks(&server, "ads.example."));
}
