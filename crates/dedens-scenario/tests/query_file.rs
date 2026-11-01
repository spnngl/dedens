//! Query files read from YAML and JSON, and their expectations checked against captured responses.

use std::time::Duration;

use dedens_net::exchange::{self, Transport};
use dedens_proto::edns::{Cookie, EdnsFlags, EdnsOption};
use dedens_proto::{Flags, Message, Name, Question, RecordType};
use dedens_scenario::{CookieOption, DnssecStatus, Id, Latency, Options, QueryFile, Timeout};

/// The captured response to `example.com. A`: two A records, TTL 29.
const A: &[u8] = include_bytes!("../../dedens-proto/tests/testdata/a.bin");
/// The captured NXDOMAIN for `nonexistent.invalid. A`, the root SOA in authority.
const NXDOMAIN: &[u8] = include_bytes!("../../dedens-proto/tests/testdata/nxdomain_soa.bin");

const YAML: &str = "
server: 1.1.1.1
options: {recurse: false, cookie: false}
queries:
  - name: example.com
    type: A
    options: {tcp: true, time: 2s, tries: 1, bufsize: 4096, cookie: '0102030405060708'}
    expect:
      rcode: NOERROR
      flags: [qr, ra]
      answer:
        - example.com. 29 IN A 104.20.23.154
        - example.com. IN A 172.66.147.243
  - id: nx
    name: nonexistent.invalid.
    type: A
    server: 9.9.9.9:53
    expect: {rcode: NXDOMAIN, answer: []}
";

fn decode(wire: &[u8]) -> Message<'_> {
    Message::decode(wire).expect("captured").message
}

#[test]
fn yaml_and_json_read_the_same() {
    let yaml = QueryFile::parse(YAML).expect("valid YAML");
    let json = QueryFile::parse(
        r#"{"server": "1.1.1.1", "options": {"recurse": false, "cookie": false}, "queries": [
            {"name": "example.com", "type": "A",
             "options": {"tcp": true, "time": "2s", "tries": 1, "bufsize": 4096, "cookie": "0102030405060708"},
             "expect": {"rcode": "NOERROR", "flags": ["qr", "ra"], "answer": [
                "example.com. 29 IN A 104.20.23.154", "example.com. IN A 172.66.147.243"]}},
            {"id": "nx", "name": "nonexistent.invalid.", "type": "A", "server": "9.9.9.9:53",
             "expect": {"rcode": "NXDOMAIN", "answer": []}}]}"#,
    )
    .expect("valid JSON");
    assert_eq!(yaml, json);

    let [first, nx] = yaml.queries.as_slice() else {
        panic!("two queries");
    };
    assert_eq!(first.id().as_str(), "example.com_A");
    assert_eq!(nx.id().as_str(), "nx");
    assert_eq!(
        first.name,
        "example.com.".parse::<Name<'_>>().expect("valid")
    );
    assert_eq!(first.qtype, RecordType::A);
    let options = first.options.clone().or(yaml.options.clone());
    assert_eq!(options.recurse, Some(false));
    assert_eq!(options.time, Some(Timeout(Duration::from_secs(2))));
    assert!(matches!(options.cookie, Some(CookieOption::Fixed(_))));
    assert_eq!(
        nx.options.clone().or(yaml.options.clone()).cookie,
        Some(CookieOption::Off)
    );
}

#[test]
fn met_expectations_report_nothing() {
    let file = QueryFile::parse(YAML).expect("valid");
    for (query, wire) in file.queries.iter().zip([A, NXDOMAIN]) {
        let expect = query.expect.as_ref().expect("an expectation");
        assert_eq!(
            expect.check(&decode(wire)),
            Vec::<String>::new(),
            "{}",
            query.id()
        );
    }
}

#[test]
fn broken_expectations_are_reported_in_words() {
    let file = QueryFile::parse(
        "queries:
  - name: example.com
    type: A
    expect:
      rcode: NXDOMAIN
      flags: [aa, rd]
      answer:
        - example.com. 30 IN A 104.20.23.154
        - example.com. IN A 192.0.2.1
",
    )
    .expect("valid");
    let expect = file.queries[0].expect.as_ref().expect("an expectation");
    assert_eq!(
        expect.check(&decode(A)),
        [
            "rcode NOERROR instead of NXDOMAIN",
            "flag aa not set",
            "answer: missing example.com. 30 IN A 104.20.23.154",
            "answer: missing example.com. IN A 192.0.2.1",
            "answer: unexpected example.com.\t29\tIN\tA\t104.20.23.154",
            "answer: unexpected example.com.\t29\tIN\tA\t172.66.147.243",
        ]
    );
}

#[test]
fn unknown_fields_and_bad_values_are_errors() {
    for text in [
        "queries: [{name: example.com, type: A, color: red}]",
        "queries: [{name: example.com, type: A, options: {tcpp: true}}]",
        "queries: [{name: example.com, type: A, expect: {flags: [xx]}}]",
        "queries: [{name: example.com, type: NOTATYPE}]",
        "queries: [{name: example.com, type: A, options: {time: soon}}]",
        "queries: [{id: ../x, name: example.com, type: A}]",
        "queries: [{id: a/b, name: example.com, type: A}]",
        "queries: [{name: example.com, type: A}, {name: example.com., type: A}]",
        "queries: [{name: example.com, type: A, expect: {answer: [not a record]}}]",
        "queries: [{type: A}]",
        "server: 1.1.1.1",
    ] {
        assert!(QueryFile::parse(text).is_err(), "{text}");
    }
}

#[test]
fn a_record_expected_twice_must_come_twice() {
    let file = QueryFile::parse(
        "queries:
  - name: example.com
    type: A
    expect:
      answer:
        - example.com. IN A 104.20.23.154
        - example.com. IN A 104.20.23.154
        - example.com. IN A 172.66.147.243
",
    )
    .expect("valid");
    let expect = file.queries[0].expect.as_ref().expect("an expectation");
    assert_eq!(
        expect.check(&decode(A)),
        ["answer: missing example.com. IN A 104.20.23.154"]
    );
}

#[test]
fn an_expected_record_without_a_ttl_reports_what_is_wrong() {
    let error = QueryFile::parse(
        "queries: [{name: example.com, type: A, expect: {answer: ['example.com. IN A 192.0.2']}}]",
    )
    .expect_err("an invalid address")
    .to_string();
    assert!(
        error.ends_with("line 1, column 19: invalid IPv4 address"),
        "{error}"
    );
    // With a TTL, the line is read once.
    let error = QueryFile::parse(
        "queries: [{name: example.com, type: A, expect: {answer: ['example.com. 60 IN A 192.0.2']}}]",
    )
    .expect_err("an invalid address")
    .to_string();
    assert!(
        error.ends_with("line 1, column 22: invalid IPv4 address"),
        "{error}"
    );
}

#[test]
fn ids_name_the_server_without_the_dns_port() {
    let id = Id::of(&"example.com.".parse().expect("a name"), RecordType::A);
    let at = |server: &str| {
        id.at(server.parse().expect("an address"))
            .as_str()
            .to_owned()
    };
    assert_eq!(id.to_string(), "example.com_A");
    assert_eq!(at("192.0.2.1:53"), "example.com_A@192.0.2.1");
    assert_eq!(at("[2001:db8::1]:53"), "example.com_A@2001:db8::1");
    assert_eq!(at("[2001:db8::1]:5353"), "example.com_A@[2001:db8::1]:5353");
}

#[test]
fn latency_needs_an_answer() {
    assert_eq!(Latency::of(3, &mut []), None);
    let latency = Latency::of(3, &mut [30, 10]).expect("answered");
    assert_eq!(
        (
            latency.errors,
            latency.min_us,
            latency.p50_us,
            latency.max_us
        ),
        (1, 10, 10, 30)
    );
}

#[test]
fn options_build_the_query_and_the_exchange() {
    let question = Question::new(Name::root(), RecordType::NS);
    let plain = Options::default();
    let query = plain.query(question.clone());
    assert_eq!(query.header.flags, Flags::RD.with(Flags::AD));
    let edns = query.edns.expect("EDNS by default");
    assert_eq!((edns.flags, edns.options.len()), (EdnsFlags::default(), 0));
    let exchange = plain.exchange();
    assert_eq!(exchange, exchange::Options::default());
    assert!(exchange.tcp_fallback && exchange.cookies);

    let cookie = Cookie::new([1, 2, 3, 4, 5, 6, 7, 8], None).expect("a client cookie");
    let set = Options {
        tcp: Some(true),
        ignore: Some(true),
        dnssec: Some(true),
        nsid: Some(true),
        cookie: Some(CookieOption::Fixed(cookie)),
        ..Options::default()
    };
    let edns = set.query(question).edns.expect("EDNS by default");
    assert_eq!(edns.flags, EdnsFlags::DO);
    assert_eq!(
        edns.options,
        [
            EdnsOption::Nsid(Vec::new().into()),
            EdnsOption::Cookie(cookie)
        ]
    );
    let exchange = set.exchange();
    assert_eq!(exchange.transport, Transport::Tcp);
    assert!(!exchange.tcp_fallback && exchange.cookies);
    let off = Options {
        cookie: Some(CookieOption::Off),
        ..Options::default()
    };
    assert!(!off.exchange().cookies);
}

const VALIDATING: &str = "
options: {validate: true, trust_anchor: root.keys, insecure: [bad.example, test]}
queries:
  - name: example.com
    type: A
    expect: {dnssec: bogus}
  - name: example.org
    type: A
    options: {validate: false}
";

#[test]
fn validation_options_and_the_dnssec_expectation_are_read() {
    let file = QueryFile::parse(VALIDATING).expect("valid");
    let [bogus, off] = file.queries.as_slice() else {
        panic!("two queries");
    };
    let options = bogus.options.clone().or(file.options.clone());
    assert_eq!(options.validate, Some(true));
    assert_eq!(options.trust_anchor.as_deref(), Some("root.keys".as_ref()));
    let insecure: Vec<_> = options
        .insecure
        .iter()
        .flatten()
        .map(ToString::to_string)
        .collect();
    assert_eq!(insecure, ["bad.example.", "test."]);
    assert!(options.validating());
    assert!(!off.options.clone().or(file.options.clone()).validating());
    let expect = bogus.expect.as_ref().expect("an expectation");
    assert_eq!(expect.dnssec, Some(DnssecStatus::Bogus));
}

#[test]
fn the_dnssec_expectation_is_checked_against_the_verdict() {
    let file = QueryFile::parse(VALIDATING).expect("valid");
    let expect = file.queries[0].expect.as_ref().expect("an expectation");
    assert_eq!(expect.check_dnssec(Some(DnssecStatus::Bogus)), None);
    assert_eq!(
        expect.check_dnssec(Some(DnssecStatus::Secure)).as_deref(),
        Some("dnssec secure instead of bogus")
    );
    assert_eq!(
        expect.check_dnssec(None).as_deref(),
        Some("dnssec bogus expected, but not validated")
    );
    let none = QueryFile::parse("queries: [{name: a.example, type: A, expect: {rcode: NOERROR}}]")
        .expect("valid");
    let expect = none.queries[0].expect.as_ref().expect("an expectation");
    assert_eq!(expect.check_dnssec(Some(DnssecStatus::Bogus)), None);
    assert!(
        QueryFile::parse("queries: [{name: a.example, type: A, expect: {dnssec: maybe}}]").is_err()
    );
}

#[test]
fn validation_sets_do_and_cd_and_refuses_what_contradicts_it() {
    let question = Question::new(Name::root(), RecordType::NS);
    let validate = Options {
        validate: Some(true),
        ..Options::default()
    };
    let query = validate.query(question.clone());
    assert!(query.header.flags.contains(Flags::CD));
    assert!(query.edns.expect("EDNS").flags.contains(EdnsFlags::DO));
    assert_eq!(validate.check(), Ok(()));
    // An anchor or a negative one asks for validation too, until `validate` says no.
    let anchored = Options {
        trust_anchor: Some("root.keys".into()),
        ..Options::default()
    };
    assert!(anchored.validating());
    let off = Options {
        validate: Some(false),
        ..anchored
    };
    assert!(!off.validating());
    assert!(!off.query(question).header.flags.contains(Flags::CD));
    for conflicting in [
        Options {
            edns: Some(false),
            ..validate.clone()
        },
        Options {
            dnssec: Some(false),
            ..validate.clone()
        },
        Options {
            cdflag: Some(false),
            ..validate
        },
    ] {
        assert!(conflicting.check().is_err(), "{conflicting:?}");
    }
}
