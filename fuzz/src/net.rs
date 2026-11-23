//! Targets of dedens-net: `resolv.conf`, the DNS stamps of `DNSCrypt`, the sans-IO core of `DoH` (RFC 8484): URI
//! Templates, a server's reading of requests and a client's reading of responses, and the stream of a zone transfer
//! (D210).

use std::cmp::Ordering;

use dedens_net::doh::{self, Method, Template};
use dedens_net::resolv_conf::ResolvConf;
use dedens_net::stamp::{Relay, Stamp};
use dedens_net::transfer::stream::{Asked, Reader, Step};
use dedens_net::transfer::{Limits, Transfer};
use dedens_proto::rdata::RData;
use dedens_proto::{MAX_MESSAGE_LEN, Message, Name, RecordType, Serial, find_tsig};
use dedens_tsig::{Algorithm, Key, ResponseVerifier};
use dedens_zone::Changeset;

/// Arbitrary text as `/etc/resolv.conf`: `ndots` stays at most 15, and any of its words has the name itself and at
/// most one candidate per search domain.
///
/// # Panics
///
/// On a bug in the reader.
pub fn parse_resolv_conf(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let conf = ResolvConf::parse(text);
    assert!(conf.ndots <= 15, "ndots {} above 15", conf.ndots);
    for word in text.split_ascii_whitespace() {
        if let Some(candidates) = conf.candidates(word) {
            assert!(
                !candidates.is_empty() && candidates.len() <= conf.search.len() + 1,
                "{word}: {} candidates",
                candidates.len()
            );
        }
    }
}

/// Arbitrary text as a DNS stamp (draft-denis-dns-stamps-02, D102): a stamp that reads is written back as it was, but
/// for the reserved bits of its properties, which are zero when written; what is written reads again as the same stamp
/// and is written the same.
///
/// # Panics
///
/// On a bug in the reader.
pub fn parse_dns_stamp(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // A relay as a client is told of one: a stamp or an address (D100).
    if let Ok(relay) = text.parse::<Relay>() {
        let written = Stamp::Relay(relay).to_string();
        assert_eq!(written.parse::<Relay>(), Ok(relay), "{written}");
    }
    let Ok(stamp) = text.parse::<Stamp>() else {
        return;
    };
    let written = stamp.to_string();
    assert_eq!(written.parse::<Stamp>().as_ref(), Ok(&stamp), "{written}");
    match stamp {
        Stamp::Relay(_) => assert_eq!(written, text, "does not write back as it was"),
        Stamp::DnsCrypt(_) => assert_eq!(written.len(), text.len(), "{written}"),
    }
}

/// Arbitrary text as a `DoH` URI Template (RFC 8484 §3, RFC 9461 §5): what is accepted reads back from its own
/// text, and the requests it makes are read back by a server as the query.
///
/// # Panics
///
/// On a bug in the reader.
pub fn parse_doh_template(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(template) = Template::parse(text) else {
        return;
    };
    let shown = template.to_string();
    assert_eq!(
        Template::parse(&shown).ok().as_ref(),
        Some(&template),
        "{shown}: does not read back"
    );
    let query = [0, 0, 1, 0, 0, 1];
    for method in [Method::Get, Method::Post] {
        // A template of a path nearly as long as `http` allows has no room for the query.
        let Ok(request) = doh::request(&template, &query, method) else {
            continue;
        };
        assert_eq!(
            doh::server_request(&request, request.body()),
            Ok(query.to_vec()),
            "{shown}: {method:?}"
        );
    }
}

/// Arbitrary bytes as the request of a `DoH` client: the first byte picks the method and the content type, the
/// rest is the `dns` parameter of a GET or the body of a POST. A query read is never empty nor above 65535
/// bytes, and any error is one of the statuses RFC 8484 §4.1 and §6 give.
///
/// # Panics
///
/// On a bug in the reader.
pub fn server_request(data: &[u8]) {
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let method = match shape & 3 {
        0 => http::Method::GET,
        1 => http::Method::POST,
        2 => http::Method::PUT,
        _ => http::Method::HEAD,
    };
    let mut builder = http::Request::builder().method(method.clone());
    if shape & 4 != 0 {
        builder = builder.header(http::header::CONTENT_TYPE, doh::MEDIA_TYPE);
    }
    let (uri, body) = if method == http::Method::GET {
        let query = String::from_utf8_lossy(rest);
        (format!("https://doh.example/dns-query?{query}"), &[][..])
    } else {
        ("https://doh.example/dns-query".to_owned(), rest)
    };
    let Ok(request) = builder.uri(uri).body(()) else {
        return;
    };
    match doh::server_request(&request, body) {
        Ok(query) => {
            assert!(
                !query.is_empty() && query.len() <= MAX_MESSAGE_LEN,
                "a query of {} bytes",
                query.len()
            );
            if method == http::Method::GET {
                let parameter = format!("dns={}", dedens_proto::encode_base64url(&query));
                assert!(
                    request
                        .uri()
                        .query()
                        .is_some_and(|q| q.split('&').any(|p| p == parameter)),
                    "{parameter} is not in the URI"
                );
            } else {
                assert_eq!(query, body);
            }
        }
        Err(status) => assert!(
            [400, 405, 413, 415].contains(&status.as_u16()),
            "status {status}"
        ),
    }
}

/// Arbitrary bytes as the HTTP response of a `DoH` server: `meta`, `Age`, `Date` and the body, apart by NUL bytes;
/// the first byte of `meta` picks the status and whether the content type is the DNS one. The `Age` and the
/// `Date` only ever lower TTLs (RFC 8484 §5.1) and do not change whether the response is one.
///
/// # Panics
///
/// On a bug in the reader.
pub fn read_doh_response(data: &[u8]) {
    const STATUSES: [u16; 6] = [200, 203, 204, 301, 404, 503];
    let mut parts = data.splitn(4, |&byte| byte == 0);
    let (Some(meta), Some(age), Some(stamp), Some(body)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    let shape = usize::from(meta.first().copied().unwrap_or(0));
    let Ok(status) = http::StatusCode::from_u16(STATUSES[shape % STATUSES.len()]) else {
        return;
    };
    let plain = || {
        let mut builder = http::Response::builder().status(status);
        if shape & 0x80 != 0 {
            builder = builder.header(http::header::CONTENT_TYPE, doh::MEDIA_TYPE);
        }
        builder
    };
    let (Ok(age), Ok(stamp)) = (
        http::HeaderValue::from_bytes(age),
        http::HeaderValue::from_bytes(stamp),
    ) else {
        return;
    };
    let Ok(with) = plain()
        .header(http::header::AGE, age)
        .header(http::header::DATE, stamp)
        .body(())
    else {
        return;
    };
    let Ok(without) = plain().body(()) else {
        return;
    };
    let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_793_522_455);
    match (
        doh::response(&with, body, now),
        doh::response(&without, body, now),
    ) {
        (Ok(aged), Ok(fresh)) => {
            let ttls = |m: &Message<'_>| -> Vec<u32> {
                [&m.answer, &m.authority, &m.additional]
                    .into_iter()
                    .flatten()
                    .map(|record| record.ttl.get())
                    .collect()
            };
            let (aged, fresh) = (ttls(&aged.message), ttls(&fresh.message));
            assert_eq!(aged.len(), fresh.len(), "the records differ");
            assert!(
                aged.iter().zip(&fresh).all(|(aged, fresh)| aged <= fresh),
                "a TTL grew: {aged:?} from {fresh:?}"
            );
        }
        (Err(_), Err(_)) => {}
        (aged, fresh) => panic!("Age and Date change the result: {aged:?}, {fresh:?}"),
    }
}

/// Arbitrary bytes as a zone transfer over TCP (D210), each message behind its length in two octets: the request,
/// whose ID, question and SOA say what was asked (RFC 5936 §2.2, RFC 1995 §3), then the responses, read by
/// `transfer::stream::Reader` up to its end. A full zone is the zone asked for; changes start at the serial asked
/// from and follow one another, ahead of it, to the serial of the opening SOA.
///
/// # Panics
///
/// On a bug in the reader.
pub fn transfer_stream(data: &[u8]) {
    transfer(data, None);
}

/// [`transfer_stream`] with a request signed with a fixed key, the one of the captures (D203), and every message
/// of the response verified: the key's name and secret are what the seeds of `axfr-tsig-stream` were signed with.
///
/// # Panics
///
/// On a bug in the reader or the verifier.
pub fn transfer_signed(data: &[u8]) {
    let name = Name::from_labels([b"dedens-test-key".as_slice()]).expect("a valid name");
    let key = Key::from_base64(
        name,
        Algorithm::HmacSha256,
        "ZGVkZW5zIHRlc3Qga2V5IGZvciBUU0lHIGNhcHR1cmVzCg==",
    )
    .expect("a key");
    transfer(data, Some(&key));
}

/// The transfer of `data`: with `key`, the request's TSIG gives the MAC and the time of the verifier.
fn transfer(data: &[u8], key: Option<&Key>) {
    let mut messages = frames(data);
    let Some(wire) = messages.next() else {
        return;
    };
    let Ok(request) = Message::decode(wire) else {
        return;
    };
    let (verifier, now) = match (key, find_tsig(wire)) {
        (None, _) => (None, 0),
        (Some(key), Ok(Some(tsig))) if &tsig.name == key.name() => (
            Some(ResponseVerifier::new(key, tsig.tsig.mac())),
            tsig.tsig.time_signed(),
        ),
        (Some(_), _) => return,
    };
    let request = request.message;
    let Some(question) = request.questions.first() else {
        return;
    };
    let from = request
        .authority
        .iter()
        .find_map(|record| match record.data() {
            RData::Soa(soa) => Some(Serial::new(soa.serial)),
            _ => None,
        });
    let asked = match (question.qtype, from) {
        (RecordType::IXFR, Some(from)) => Asked::Ixfr(from),
        (RecordType::AXFR, from) => Asked::Axfr(from),
        _ => return,
    };
    let zone = question.name.clone().into_owned();
    let limits = Limits::default();
    let mut reader = Reader::new(zone.clone(), request.header.id, asked, verifier, &limits);
    let mut opening = None;
    for message in messages {
        opening = opening.or_else(|| opening_serial(message));
        match reader.message(message, now) {
            Ok(Step::More(next)) => reader = next,
            Ok(Step::Done(Transfer::Full(loaded))) => {
                assert_eq!(loaded.zone.apex(), &zone, "another zone");
                if let Some(from) = from {
                    let serial = Serial::new(loaded.zone.soa().serial);
                    assert_eq!(
                        serial.partial_cmp(&from),
                        Some(Ordering::Greater),
                        "not newer"
                    );
                }
                return;
            }
            Ok(Step::Done(Transfer::Incremental(changesets))) => {
                assert_eq!(
                    changesets.first().map(Changeset::from_serial),
                    from,
                    "changes from another serial"
                );
                for pair in changesets.windows(2) {
                    assert_eq!(pair[0].to_serial(), pair[1].from_serial(), "a gap");
                }
                let last = changesets.last().map(Changeset::to_serial);
                assert_eq!(last, opening, "changes not up to the opening SOA");
                assert_eq!(
                    last.zip(from).map(|(to, from)| to.partial_cmp(&from)),
                    Some(Some(Ordering::Greater)),
                    "changes not ahead of the serial asked"
                );
                return;
            }
            Ok(Step::Done(Transfer::UpToDate)) | Err(_) => return,
        }
    }
}

/// The serial of the first answer of `message` when it is an SOA.
fn opening_serial(message: &[u8]) -> Option<Serial> {
    let message = Message::decode(message).ok()?.message;
    match message.answer.first()?.data() {
        RData::Soa(soa) => Some(Serial::new(soa.serial)),
        _ => None,
    }
}

/// The messages of `data`, each behind its length in two octets, up to the first that is cut short.
fn frames(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (length, rest) = data.split_first_chunk::<2>()?;
        let message = rest.get(..usize::from(u16::from_be_bytes(*length)))?;
        data = &rest[message.len()..];
        Some(message)
    })
}
