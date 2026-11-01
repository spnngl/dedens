//! `dedensd` checked by a `dedens` query file (D34): each query of `tests/end_to_end.yaml` asked of a running
//! server, its reply held to the query's expectations, the way `dedens -f` does; a caching forwarder asks its
//! upstream once per question.

mod common;

use common::{Responder, Server, ask_tcp, ask_udp};
use dedens_proto::Question;
use dedens_scenario::QueryFile;

#[test]
fn replies_meet_the_query_file() {
    let file = QueryFile::parse(include_str!("end_to_end.yaml")).expect("a query file");
    let upstream = Responder::start(&["a", "mx", "cname_chain", "nxdomain_soa", "txt_large"]);
    let server = Server::start(upstream.addr, "");
    let mut failures = Vec::new();
    for (id, query) in (1..).zip(&file.queries) {
        let options = query.options.clone().or(file.options.clone());
        let mut message = options.query(Question::new(query.name.clone(), query.qtype));
        message.header.id = id;
        let wire = message.to_vec().expect("a query fits");
        let reply = if options.tcp == Some(true) {
            ask_tcp(server.addr, &wire)
        } else {
            ask_udp(server.addr, &wire)
        };
        assert_eq!(reply.header.id, id);
        // Names compare without case; their text keeps it.
        assert_eq!(reply.questions[0].name.to_string(), query.name.to_string());
        let expect = query.expect.as_ref().expect("an expectation");
        failures.extend(
            expect
                .check(&reply)
                .into_iter()
                .map(|failure| format!("{}: {failure}", query.id())),
        );
    }
    assert_eq!(failures, Vec::<String>::new());
    // Five questions; the rest came from the cache.
    assert_eq!(upstream.queries(), 5);
}
