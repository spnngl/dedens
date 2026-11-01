//! What the cache keeps of a verdict (D77): the AD bit of the replies follows it, never the response's own; a
//! bogus response is kept briefly (RFC 4035 §4.7), answers clients that check, and its data answers those that do
//! not (RFC 4035 §3.2.2).

mod common;

use common::{T0, a, dns, lookup, query_with, response, small_cache};
use dedens_cache::{Cache, Checked, Hit, Lookup, StalePolicy};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Flags, Message, Query, Rcode, RecordType};

/// Stores a response for `www.example` A with AD as `upstream_ad` says, as `checked`.
fn store(cache: &Cache, upstream_ad: bool, checked: Checked) {
    store_for(cache, upstream_ad, true, checked);
}

/// [`store`] for the clients that set DO as `dnssec_ok` says.
fn store_for(cache: &Cache, upstream_ad: bool, dnssec_ok: bool, checked: Checked) {
    let mut wire = response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("www.example", 3600, 1)],
        vec![],
    );
    if upstream_ad {
        wire[3] |= 0x20;
    }
    let query = query_with(1, "www.example", RecordType::A, Flags::RD, dnssec_ok);
    cache
        .insert_checked(
            &Query::read(&query).expect("a query"),
            &Message::decode(&wire).expect("a response"),
            T0,
            checked,
        )
        .expect("a cacheable response");
}

fn ad(cache: &Cache, flags: Flags, dnssec_ok: bool) -> bool {
    let query = query_with(2, "www.example", RecordType::A, flags, dnssec_ok);
    let (found, served) = lookup(cache, &query, T0 + 1, StalePolicy::Never);
    assert!(matches!(found, Lookup::Hit(_)), "{found:?}");
    served
        .expect("a served response")
        .header
        .flags
        .contains(Flags::AD)
}

#[test]
fn a_secure_response_is_served_with_ad_to_clients_that_asked_for_it() {
    let cache = small_cache();
    store(&cache, false, Checked::Secure);
    assert!(ad(&cache, Flags::RD, true));
    assert!(ad(&cache, Flags::RD | Flags::AD, true));
}

#[test]
fn ad_is_left_out_for_clients_with_neither_ad_nor_do() {
    let cache = small_cache();
    store_for(&cache, false, false, Checked::Secure);
    assert!(!ad(&cache, Flags::RD, false), "RFC 6840 §5.8");
    assert!(ad(&cache, Flags::RD | Flags::AD, false));
}

#[test]
fn the_ad_bit_of_upstream_does_not_outlive_the_verdict() {
    // The key of a CD client holds the bogus response's data, the other's holds the verdict.
    for (checked, flags) in [
        (Checked::Insecure, Flags::RD),
        (
            Checked::Bogus(InfoCode::DNSSEC_BOGUS),
            Flags::RD | Flags::CD,
        ),
    ] {
        let cache = small_cache();
        store(&cache, true, checked);
        assert!(!ad(&cache, flags, true), "{checked:?}");
    }
    let cache = small_cache();
    store(&cache, true, Checked::Unchecked);
    assert!(ad(&cache, Flags::RD, true), "unchecked: as stored");
}

#[test]
fn a_bogus_response_is_kept_for_the_bogus_ttl_never_stale() {
    let cache = small_cache();
    let code = InfoCode::DNSSEC_BOGUS;
    store(&cache, false, Checked::Bogus(code));
    let query = query_with(2, "www.example", RecordType::A, Flags::RD, true);
    let (found, _) = lookup(&cache, &query, T0 + 59, StalePolicy::Always);
    let Lookup::Hit(Hit { checked, .. }) = found else {
        panic!("{found:?}")
    };
    assert_eq!(checked, Checked::Bogus(code));
    let (found, _) = lookup(&cache, &query, T0 + 61, StalePolicy::Always);
    assert!(!matches!(found, Lookup::Hit(_)), "{found:?}");
}

#[test]
fn the_data_of_a_bogus_response_answers_clients_that_disabled_checking() {
    let cache = small_cache();
    store(&cache, false, Checked::Bogus(InfoCode::DNSSEC_BOGUS));
    let query = query_with(2, "www.example", RecordType::A, Flags::RD | Flags::CD, true);
    let (found, served) = lookup(&cache, &query, T0 + 50, StalePolicy::Never);
    let Lookup::Hit(Hit { checked, .. }) = found else {
        panic!("{found:?}")
    };
    assert_eq!(checked, Checked::Insecure);
    let served = served.expect("data");
    assert_eq!(served.answer[0].name, dns("www.example"));
    assert_eq!(
        served.answer[0].ttl.get(),
        10,
        "60 seconds, not the 3600 of the record"
    );
    let (found, _) = lookup(&cache, &query, T0 + 61, StalePolicy::Always);
    assert!(!matches!(found, Lookup::Hit(_)), "{found:?}");
}
