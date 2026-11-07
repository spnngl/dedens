//! RFC 9619 in the server core: a query with more than one question gets FORMERR (§3).

mod common;

use common::{captured, decode, forwarder, query_for, run, wire};
use dedens_proto::{Rcode, Transport};

#[test]
fn two_questions_get_formerr_without_asking_upstream() {
    let mut query = query_for(&captured("a"));
    query.questions.push(query.questions[0].clone());
    let done = run(&forwarder(), &wire(&query), Transport::Udp, &[]);
    assert_eq!(done.asked, []);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::FORMERR);
    assert_eq!(reply.questions, query.questions[..1]);
}
