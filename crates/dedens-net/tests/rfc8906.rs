//! RFC 8906 §3 and §8: a server that does not answer may have dropped the packet; a timeout is no sign that it
//! does not know EDNS, so every try keeps the query as it was.

mod common;

use common::{expect_failure, expect_send, query_with_cookie, secs, sent, start, t0};
use dedens_net::exchange::{Failure, Options};

#[test]
fn timeouts_keep_edns_and_the_cookie() {
    let now = t0();
    let query = query_with_cookie(None);
    let mut exchange = start(&query, Options::default(), now);
    let first = exchange.wire().to_vec();
    for n in 1..=2 {
        exchange = expect_send(exchange.time_out(now + secs(5 * n)));
        assert_eq!(exchange.wire(), first);
        assert_eq!(sent(&exchange).edns, query.edns);
    }
    assert_eq!(
        expect_failure(exchange.time_out(now + secs(15))),
        Failure::TimedOut { sends: 3 }
    );
}
