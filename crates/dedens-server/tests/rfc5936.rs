//! RFC 5936 in the server core: zone transfers, AXFR and IXFR (RFC 1995), come from a zone's servers, so a
//! forwarder refuses them over either transport; none is defined over UDP (§4.2).

mod common;

use common::{decode, dns, forwarder, run, wire};
use dedens_proto::{Message, Question, Rcode, RecordType};
use dedens_server::Transport;

#[test]
fn zone_transfers_are_refused() {
    for qtype in [RecordType::AXFR, RecordType::IXFR] {
        for transport in [Transport::Udp, Transport::Tcp] {
            let query = Message::query(7, Question::new(dns("example.com"), qtype));
            let done = run(&forwarder(), &wire(&query), transport, &[]);
            assert_eq!(done.asked, []);
            let wire = done.reply.expect("a reply");
            assert_eq!(
                decode(&wire).rcode(),
                Rcode::REFUSED,
                "{qtype} over {transport:?}"
            );
        }
    }
}
