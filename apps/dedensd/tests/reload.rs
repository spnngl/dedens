//! `dedensd` reloading its configuration file on SIGHUP (D55): the new pipeline answers, and one that does not read
//! leaves the running one in place.

#![cfg(unix)]

mod common;

use std::net::IpAddr;

use common::{Server, ask_udp};
use dedens_proto::{Message, Question, RData, RecordType};

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
