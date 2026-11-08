//! Targets of dedens-net: `resolv.conf`, and the sans-IO core of `DoH` (RFC 8484): URI Templates, a server's
//! reading of requests and a client's reading of responses.

use dedens_net::doh::{self, Method, Template};
use dedens_net::resolv_conf::ResolvConf;
use dedens_proto::{MAX_MESSAGE_LEN, Message};

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
