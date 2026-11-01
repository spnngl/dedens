//! DNS over HTTPS (RFC 8484): the examples of §4.1.1 and §4.2.2 byte for byte, the status codes of a server,
//! the freshness of §5.1, and responses captured from public servers (`tests/testdata/doh/capture.nu`).

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{query, sent, start, t0};
use dedens_net::doh::{
    DohError, MEDIA_TYPE, Method, Template, TemplateError, request, response, server_request,
    server_response,
};
use dedens_net::exchange::{Options, Transport};
use dedens_proto::edns::EdnsOption;
use dedens_proto::{Message, RData, Rcode, RecordType};
use http::header::{ACCEPT, AGE, CACHE_CONTROL, CONTENT_TYPE, DATE};
use http::{Response, StatusCode};

/// The server of the RFC's examples.
const TEMPLATE: &str = "https://dnsserver.example.net/dns-query{?dns}";

/// §4.1.1: a query for `www.example.com. A`.
const WWW_QUERY: &str = "00 00 01 00 00 01 00 00  00 00 00 00 03 77 77 77
                         07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 00 01 00
                         01";

/// §4.1.1: a query for `a.62characterlabel-makes-base64url-distinct-from-standard-base64.example.com. A`.
const LONG_QUERY: &str = "00 00 01 00 00 01 00 00  00 00 00 00 01 61 3e 36
                          32 63 68 61 72 61 63 74  65 72 6c 61 62 65 6c 2d
                          6d 61 6b 65 73 2d 62 61  73 65 36 34 75 72 6c 2d
                          64 69 73 74 69 6e 63 74  2d 66 72 6f 6d 2d 73 74
                          61 6e 64 61 72 64 2d 62  61 73 65 36 34 07 65 78
                          61 6d 70 6c 65 03 63 6f  6d 00 00 01 00 01";

/// §4.2.2: the answer for `www.example.com. AAAA`, whose TTL is 3709.
const WWW_RESPONSE: &str = "00 00 81 80 00 01 00 01  00 00 00 00 03 77 77 77
                            07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 00 1c 00
                            01 c0 0c 00 1c 00 01 00  00 0e 7d 00 10 20 01 0d
                            b8 ab cd 00 12 00 01 00  02 00 03 00 04";

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).expect("a hex byte"))
        .collect()
}

fn template() -> Template {
    Template::parse(TEMPLATE).expect("a template")
}

/// A 200 response of the DNS media type with the headers `extra`.
fn http_response(extra: &[(&str, &str)]) -> Response<()> {
    let mut builder = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, MEDIA_TYPE);
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(()).expect("a response")
}

/// The time `seconds` after the epoch.
fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// The TTL of the one answer of `body` read as the response `headers` make it at `now`.
fn answer_ttl(headers: &[(&str, &str)], now: SystemTime) -> u32 {
    let body = hex(WWW_RESPONSE);
    let decoded = response(&http_response(headers), &body, now).expect("a response");
    decoded.message.answer[0].ttl.get()
}

// --- §4.1: the request

/// §4.1.1: the GET of the first example: `dns` is the query, base64url without padding.
#[test]
fn s4_1_1_get_example() {
    let request = request(&template(), &hex(WWW_QUERY), Method::Get).expect("a request");
    assert_eq!(request.method(), http::Method::GET);
    assert_eq!(request.uri().scheme_str(), Some("https"));
    assert_eq!(
        request.uri().authority().map(http::uri::Authority::as_str),
        Some("dnsserver.example.net")
    );
    assert_eq!(
        request
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str),
        Some("/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
    );
    assert_eq!(request.headers().get(ACCEPT).expect("accept"), MEDIA_TYPE);
    assert!(request.headers().get(CONTENT_TYPE).is_none());
    assert_eq!(request.body(), &Vec::<u8>::new());
}

/// §4.1.1: the POST of the second example: the query as the body, the template without its variable.
#[test]
fn s4_1_1_post_example() {
    let request = request(&template(), &hex(WWW_QUERY), Method::Post).expect("a request");
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(
        request
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str),
        Some("/dns-query")
    );
    assert_eq!(request.headers().get(ACCEPT).expect("accept"), MEDIA_TYPE);
    assert_eq!(
        request.headers().get(CONTENT_TYPE).expect("content type"),
        MEDIA_TYPE
    );
    assert_eq!(request.body().len(), 33);
    assert_eq!(request.body(), &hex(WWW_QUERY));
}

/// §4.1.1: the third example, whose base64url differs from base64 by its alphabet and the padding it omits.
#[test]
fn s4_1_1_base64url_example() {
    let query = hex(LONG_QUERY);
    assert_eq!(query.len(), 94);
    let request = request(&template(), &query, Method::Get).expect("a request");
    assert_eq!(
        request
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str),
        Some(concat!(
            "/dns-query?dns=AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJl",
            "bC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1z",
            "dGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ"
        ))
    );
}

/// §4.1: what the server reads back from each request is the query.
#[test]
fn s4_1_a_server_reads_what_the_client_sends() {
    for method in [Method::Get, Method::Post] {
        for query in [hex(WWW_QUERY), hex(LONG_QUERY)] {
            let request = request(&template(), &query, method).expect("a request");
            assert_eq!(server_request(&request, request.body()), Ok(query));
        }
    }
}

/// §4.1: a template with a path and a query, as `{&dns}` joins one.
#[test]
fn s4_1_the_variable_joins_an_existing_query() {
    let template = Template::parse("https://doh.example/q?x=1{&dns}").expect("a template");
    let get = request(&template, &hex(WWW_QUERY), Method::Get).expect("a request");
    assert_eq!(
        get.uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str),
        Some("/q?x=1&dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
    );
    let post = request(&template, &hex(WWW_QUERY), Method::Post).expect("a request");
    assert_eq!(
        post.uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str),
        Some("/q?x=1")
    );
}

/// §3, §5: the template is `https`, and `{?dns}` is implied when a URL has no expression, as dig reads it.
#[test]
fn s3_templates() {
    let full = Template::parse("https://doh.example:8443/dns-query{?dns}").expect("a template");
    assert_eq!(full.authority().as_str(), "doh.example:8443");
    assert_eq!(full.to_string(), "https://doh.example:8443/dns-query{?dns}");
    assert_eq!(
        Template::parse("https://doh.example:8443/dns-query").expect("a template"),
        full
    );
    assert_eq!(
        Template::parse("HTTPS://doh.example/").expect("a template"),
        Template::parse("https://doh.example").expect("a template")
    );
    // A provider's URL with a trailing slash and none of the variable (docs/providers/providers.yaml).
    let cleanbrowsing =
        Template::parse("https://doh.cleanbrowsing.org/doh/security-filter/").expect("a template");
    assert_eq!(
        cleanbrowsing.to_string(),
        "https://doh.cleanbrowsing.org/doh/security-filter/{?dns}"
    );
}

/// §5: a template for another scheme is refused, and so is one dig could not use.
#[test]
fn s5_bad_templates() {
    assert!(matches!(
        Template::parse("http://doh.example/dns-query{?dns}"),
        Err(TemplateError::NotHttps)
    ));
    assert!(matches!(
        Template::parse("/dns-query"),
        Err(TemplateError::NotHttps)
    ));
    assert!(matches!(Template::parse(""), Err(TemplateError::NotHttps)));
    assert!(matches!(
        Template::parse("https://user:pw@doh.example/dns-query"),
        Err(TemplateError::UserInfo)
    ));
    assert!(matches!(
        Template::parse("https://doh example/dns-query"),
        Err(TemplateError::Authority(_))
    ));
    assert!(matches!(
        Template::parse("https:///dns-query"),
        Err(TemplateError::Authority(_))
    ));
    for bad in [
        "https://doh.example/{dns}",
        "https://doh.example/{?dns,type}",
        "https://doh.example/{?dns}/more",
        "https://doh.example/{+dns}",
        "https://doh.example/q?x=1{?dns}",
        "https://doh.example/q{&dns}",
        "https://doh.example/{?dns}{?dns}",
    ] {
        assert!(
            matches!(Template::parse(bad), Err(TemplateError::Expression)),
            "{bad}"
        );
    }
    assert!(matches!(
        Template::parse("https://doh.example/dns#query{?dns}"),
        Err(TemplateError::Path(_))
    ));
}

/// §4.1: the ID is 0 and the query is padded to a multiple of 128 bytes with no keepalive over HTTPS, as over
/// QUIC (RFC 8467 §4.1, RFC 8484 §9).
#[test]
fn s4_1_a_query_over_https_has_id_0_and_padding() {
    let mut keepalive = query();
    keepalive.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Keepalive(None)];
    let mut options = Options::default();
    options.transport = Transport::Https;
    let exchange = start(&keepalive, options, t0());
    assert_eq!(exchange.wire().len() % 128, 0);
    let sent = sent(&exchange);
    assert_eq!(sent.header.id, 0);
    let options = sent.edns.expect("EDNS").options;
    assert!(
        matches!(options.as_slice(), [EdnsOption::Padding(_)]),
        "{options:?}"
    );
}

// --- §4.2: the response

/// §4.2.2: the example response, TTL as the server sent it.
#[test]
fn s4_2_2_response_example() {
    let body = hex(WWW_RESPONSE);
    let headers = http_response(&[(CACHE_CONTROL.as_str(), "max-age=3709")]);
    let decoded = response(&headers, &body, at(1_000_000)).expect("a response");
    assert_eq!(decoded.violations, []);
    let message = decoded.message;
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answer.len(), 1);
    assert_eq!(message.answer[0].rtype(), RecordType::AAAA);
    assert_eq!(message.answer[0].ttl.get(), 3709);
    assert!(matches!(message.answer[0].data(), RData::Aaaa(_)));
}

/// §4.2.1: a 2xx with any rcode is a DNS response; other statuses are not, whatever the body holds.
#[test]
fn s4_2_1_statuses() {
    let body = hex(WWW_RESPONSE);
    for ok in [200, 203] {
        let headers = Response::builder()
            .status(ok)
            .header(CONTENT_TYPE, MEDIA_TYPE)
            .body(())
            .expect("a response");
        assert!(response(&headers, &body, at(0)).is_ok(), "{ok}");
    }
    for status in [301, 304, 400, 404, 415, 429, 500, 503] {
        let headers = Response::builder()
            .status(status)
            .header(CONTENT_TYPE, MEDIA_TYPE)
            .body(())
            .expect("a response");
        match response(&headers, &body, at(0)) {
            Err(DohError::Status(code)) => assert_eq!(code.as_u16(), status),
            other => panic!("{status}: {other:?}"),
        }
    }
}

/// §4.2: a response that is not `application/dns-message` is no DNS response; parameters and case do not matter.
#[test]
fn s4_2_content_type() {
    let body = hex(WWW_RESPONSE);
    let with = |value: &str| {
        Response::builder()
            .header(CONTENT_TYPE, value)
            .body(())
            .expect("a response")
    };
    for good in [
        "application/dns-message",
        "Application/DNS-Message",
        "application/dns-message; charset=binary",
    ] {
        assert!(response(&with(good), &body, at(0)).is_ok(), "{good}");
    }
    for bad in [
        "text/html",
        "application/dns-json",
        "application/dns-messages",
        "",
    ] {
        assert!(
            matches!(
                response(&with(bad), &body, at(0)),
                Err(DohError::ContentType(Some(_)))
            ),
            "{bad}"
        );
    }
    let none = Response::new(());
    assert!(matches!(
        response(&none, &body, at(0)),
        Err(DohError::ContentType(None))
    ));
}

/// §4.2: a body that is not a DNS message is an error, never a panic.
#[test]
fn s4_2_a_body_that_is_not_a_message() {
    for body in [&b""[..], b"<html>", &hex(WWW_RESPONSE)[..20]] {
        assert!(
            matches!(
                response(&http_response(&[]), body, at(0)),
                Err(DohError::Decode(_))
            ),
            "{body:?}"
        );
    }
}

// --- §5.1: freshness

/// §5.1, RFC 9111 §4.2.3: a response a cache kept for `Age` seconds has that much less to live.
#[test]
fn s5_1_age_reduces_ttls() {
    assert_eq!(answer_ttl(&[], at(0)), 3709);
    assert_eq!(answer_ttl(&[(AGE.as_str(), "0")], at(0)), 3709);
    assert_eq!(answer_ttl(&[(AGE.as_str(), "100")], at(0)), 3609);
    assert_eq!(answer_ttl(&[(AGE.as_str(), "3709")], at(0)), 0);
    // Floor 0: older than the record.
    assert_eq!(answer_ttl(&[(AGE.as_str(), "5000")], at(0)), 0);
    assert_eq!(
        answer_ttl(&[(AGE.as_str(), "99999999999999999999")], at(0)),
        0
    );
}

/// RFC 9111 §5.1: the first member of a list is the age, what is not a number is ignored.
#[test]
fn s5_1_age_that_is_not_a_number() {
    assert_eq!(answer_ttl(&[(AGE.as_str(), "100, 200")], at(0)), 3609);
    for bad in ["abc", "-5", "1.5", "", "10s", "+10"] {
        assert_eq!(answer_ttl(&[(AGE.as_str(), bad)], at(0)), 3709, "{bad}");
    }
}

/// RFC 9111 §4.2.3: the apparent age, the time since `Date`, counts when it is more than `Age`.
#[test]
fn s5_1_date_gives_the_apparent_age() {
    // 1994-11-06T08:49:37Z, the date of RFC 9110's example, is 784111777.
    let date = (DATE.as_str(), "Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(answer_ttl(&[date], at(784_111_777)), 3709);
    assert_eq!(answer_ttl(&[date], at(784_111_777 + 60)), 3649);
    assert_eq!(answer_ttl(&[date], at(784_111_777 - 60)), 3709);
    // The larger of the two ages.
    assert_eq!(
        answer_ttl(&[date, (AGE.as_str(), "10")], at(784_111_777 + 60)),
        3649
    );
    assert_eq!(
        answer_ttl(&[date, (AGE.as_str(), "100")], at(784_111_777 + 60)),
        3609
    );
    // A date that is not an IMF-fixdate, or not a date, counts for nothing.
    for bad in [
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "Sun, 06 Nov 1994 08:49:37 GMT x",
        "Sun, 06 Nov 1994 25:49:37 GMT",
        "Sun, 06 Foo 1994 08:49:37 GMT",
        "",
    ] {
        assert_eq!(
            answer_ttl(&[(DATE.as_str(), bad)], at(784_111_777 + 60)),
            3709,
            "{bad}"
        );
    }
    // Leap days: 2024-02-29T12:00:00Z is 1709208000.
    assert_eq!(
        answer_ttl(
            &[(DATE.as_str(), "Thu, 29 Feb 2024 12:00:00 GMT")],
            at(1_709_208_000 + 9)
        ),
        3700
    );
    assert_eq!(
        answer_ttl(
            &[(DATE.as_str(), "Fri, 01 Mar 2024 00:00:00 GMT")],
            at(1_709_251_200 + 9)
        ),
        3700
    );
}

// --- the server

/// A GET request whose URI is `uri`.
fn get(uri: &str) -> http::Request<()> {
    http::Request::get(uri).body(()).expect("a request")
}

/// A request `method` with an optional content type.
fn with(method: http::Method, content_type: Option<&str>) -> http::Request<()> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri("https://doh.example/dns-query");
    if let Some(value) = content_type {
        builder = builder.header(CONTENT_TYPE, value);
    }
    builder.body(()).expect("a request")
}

/// §4.1: the server reads a GET and a POST; a GET finds `dns` among other parameters.
#[test]
fn s4_1_server_reads_queries() {
    let query = hex(WWW_QUERY);
    assert_eq!(
        server_request(
            &get("https://doh.example/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"),
            &[]
        ),
        Ok(query.clone())
    );
    assert_eq!(
        server_request(
            &get("/dns-query?ct&x=1&dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB&y"),
            &[]
        ),
        Ok(query.clone())
    );
    assert_eq!(
        server_request(&with(http::Method::POST, Some(MEDIA_TYPE)), &query),
        Ok(query.clone())
    );
    assert_eq!(
        server_request(
            &with(http::Method::POST, Some("Application/DNS-Message; q=1")),
            &query
        ),
        Ok(query)
    );
}

/// §4.1: a GET without a usable `dns` parameter is a bad request; so is an empty query.
#[test]
fn s4_1_server_400() {
    for uri in [
        "/dns-query",
        "/dns-query?",
        "/dns-query?dns",
        "/dns-query?dns=",
        "/dns-query?xdns=AAAB",
        // Padding, and the standard alphabet, are not base64url without padding.
        "/dns-query?dns=AAAB=",
        "/dns-query?dns=AA==",
        "/dns-query?dns=AA+B",
        "/dns-query?dns=AA/B",
        // One character too many for any byte count.
        "/dns-query?dns=AAAAA",
        "/dns-query?dns=%41%41%41%41",
    ] {
        assert_eq!(
            server_request(&get(uri), &[]),
            Err(StatusCode::BAD_REQUEST),
            "{uri}"
        );
    }
    assert_eq!(
        server_request(&with(http::Method::POST, Some(MEDIA_TYPE)), &[]),
        Err(StatusCode::BAD_REQUEST)
    );
}

/// §4.1, §5.4: a POST of another content type is 415; other methods 405.
#[test]
fn s4_1_server_415_and_405() {
    let query = hex(WWW_QUERY);
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/dns-json"),
        Some("application/dns-message2"),
    ] {
        assert_eq!(
            server_request(&with(http::Method::POST, content_type), &query),
            Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
            "{content_type:?}"
        );
    }
    for method in [
        http::Method::PUT,
        http::Method::DELETE,
        http::Method::PATCH,
        http::Method::HEAD,
        http::Method::OPTIONS,
    ] {
        assert_eq!(
            server_request(&with(method.clone(), Some(MEDIA_TYPE)), &query),
            Err(StatusCode::METHOD_NOT_ALLOWED),
            "{method}"
        );
    }
}

/// §6: a message is 65535 bytes at most.
#[test]
fn s6_server_413() {
    let post = with(http::Method::POST, Some(MEDIA_TYPE));
    assert_eq!(
        server_request(&post, &vec![0; 65_535]).map(|q| q.len()),
        Ok(65_535)
    );
    assert_eq!(
        server_request(&post, &vec![0; 65_536]),
        Err(StatusCode::PAYLOAD_TOO_LARGE)
    );
    // A GET of the same size does not fit a URI of `http`: the client cannot make it.
    assert!(request(&template(), &vec![0; 65_535], Method::Get).is_err());
    assert!(request(&template(), &vec![0; 40_000], Method::Get).is_ok());
}

/// §4.2.2, §5.1: the response of a server to a GET has `max-age` of the least TTL; the example's is 3709.
#[test]
fn s5_1_server_max_age_of_the_least_ttl() {
    let reply = server_response(hex(WWW_RESPONSE), &http::Method::GET).expect("a response");
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.headers().get(CONTENT_TYPE).expect("type"), MEDIA_TYPE);
    assert_eq!(
        reply.headers().get(CACHE_CONTROL).expect("max-age"),
        "max-age=3709"
    );
    assert_eq!(reply.body(), &hex(WWW_RESPONSE));
}

/// §5.1: the answer to a POST is not cacheable, so says nothing about it.
#[test]
fn s5_1_server_post_has_no_cache_control() {
    let reply = server_response(hex(WWW_RESPONSE), &http::Method::POST).expect("a response");
    assert_eq!(reply.status(), StatusCode::OK);
    assert!(reply.headers().get(CACHE_CONTROL).is_none());
    assert_eq!(reply.headers().get(CONTENT_TYPE).expect("type"), MEDIA_TYPE);
}

/// §4.2.1, §5.1: an error without a SOA is 200 with `max-age=0`; and what is not a message is the caller's bug.
#[test]
fn s4_2_1_server_errors_are_200_with_max_age_0() {
    let servfail = common::response(&query(), Rcode::SERVFAIL);
    let reply = server_response(common::wire(&servfail), &http::Method::GET).expect("a response");
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        reply.headers().get(CACHE_CONTROL).expect("max-age"),
        "max-age=0"
    );
    assert!(server_response(vec![1, 2, 3], &http::Method::GET).is_err());
    // A POST is not read at all.
    assert!(server_response(vec![1, 2, 3], &http::Method::POST).is_ok());
}

// --- captured responses

/// What `capture.nu` saved of one exchange.
struct Capture {
    query: Vec<u8>,
    method: Method,
    headers: Response<()>,
    body: Vec<u8>,
    /// When the server sent it, from its `Date`.
    date: Option<u64>,
}

fn capture(id: &str) -> Capture {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/doh");
    let read = |extension: &str| std::fs::read(dir.join(format!("{id}.{extension}"))).expect(id);
    let text = String::from_utf8(read("headers")).expect("ASCII headers");
    let mut lines = text.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("a status line");
    let mut builder = Response::builder().status(status);
    let mut date = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(": ") {
            builder = builder.header(name, value);
            if name == "date" {
                assert_eq!(value, CAPTURE_DATE, "{id}");
                date = Some(CAPTURE_UNIX);
            }
        }
    }
    let method = if id.ends_with("_post") || id.ends_with("_https") {
        Method::Post
    } else {
        Method::Get
    };
    Capture {
        query: read("query"),
        method,
        headers: builder.body(()).expect("headers"),
        body: read("body"),
        date,
    }
}

/// The `date` header of every capture that has one, and its seconds since the epoch.
const CAPTURE_DATE: &str = "Sun, 01 Nov 2026 08:40:55 GMT";
const CAPTURE_UNIX: u64 = 1_793_522_455;

const CAPTURES: [&str; 6] = [
    "cloudflare_a",
    "cloudflare_nxdomain",
    "google_aaaa",
    "google_a_post",
    "quad9_mx",
    "adguard_https",
];

/// Every captured response parses: the server answers the question asked, the ID of the query, 0, with the QR flag.
#[test]
fn captured_responses_parse() {
    for id in CAPTURES {
        let captured = capture(id);
        let now = at(captured.date.unwrap_or(CAPTURE_UNIX));
        let decoded = response(&captured.headers, &captured.body, now).expect(id);
        assert!(
            decoded.violations.is_empty(),
            "{id}: {:?}",
            decoded.violations
        );
        let asked = Message::decode(&captured.query).expect(id).message;
        let message = decoded.message;
        assert_eq!(message.header.id, 0, "{id}");
        assert_eq!(message.questions, asked.questions, "{id}");
        assert!(
            message.header.flags.contains(dedens_proto::Flags::QR),
            "{id}"
        );
    }
}

/// A captured NXDOMAIN is a 200 and a DNS response: its SOA gives the freshness.
#[test]
fn captured_nxdomain_is_a_response() {
    let captured = capture("cloudflare_nxdomain");
    let decoded =
        response(&captured.headers, &captured.body, at(CAPTURE_UNIX)).expect("a response");
    assert_eq!(decoded.message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(decoded.message.answer, []);
    let reply = server_response(captured.body.clone(), &http::Method::GET).expect("a response");
    let soa = decoded
        .message
        .authority
        .iter()
        .find_map(|record| match record.data() {
            RData::Soa(soa) => Some(record.ttl.get().min(soa.minimum)),
            _ => None,
        })
        .expect("a SOA");
    assert_eq!(
        reply.headers().get(CACHE_CONTROL).expect("max-age"),
        format!("max-age={soa}").as_str()
    );
}

/// RFC 9111 §4.2.3: the same captures read later have the TTLs reduced by the time since their `Date`.
#[test]
fn captured_responses_age() {
    for id in ["google_aaaa", "adguard_https"] {
        let captured = capture(id);
        let sent_at = captured.date.expect("a date");
        let fresh = response(&captured.headers, &captured.body, at(sent_at)).expect(id);
        let later = response(&captured.headers, &captured.body, at(sent_at + 7)).expect(id);
        let older = response(&captured.headers, &captured.body, at(sent_at + 1_000_000)).expect(id);
        assert!(!fresh.message.answer.is_empty(), "{id}");
        for ((fresh, later), older) in fresh
            .message
            .answer
            .iter()
            .zip(&later.message.answer)
            .zip(&older.message.answer)
        {
            assert_eq!(later.ttl.get(), fresh.ttl.get().saturating_sub(7), "{id}");
            assert_eq!(older.ttl.get(), 0, "{id}");
        }
    }
}

/// The captured queries are what [`request`] makes of them and the server reads back, by GET and POST.
#[test]
fn captured_queries_go_through_the_request() {
    let template = Template::parse("https://dns.example/dns-query").expect("a template");
    for id in CAPTURES {
        let captured = capture(id);
        for method in [Method::Get, Method::Post] {
            let request = request(&template, &captured.query, method).expect(id);
            assert_eq!(
                server_request(&request, request.body()),
                Ok(captured.query.clone()),
                "{id}"
            );
        }
        // Whichever the method the capture was made with, a server of ours answers it the same.
        let reply = server_response(
            captured.body.clone(),
            match captured.method {
                Method::Get => &http::Method::GET,
                Method::Post => &http::Method::POST,
            },
        )
        .expect(id);
        assert_eq!(reply.body(), &captured.body);
    }
}
