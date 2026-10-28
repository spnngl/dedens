//! Query files read from YAML and JSON, and their expectations checked against captured responses.

use std::time::Duration;

use dedens_proto::{Message, Name, RecordType};
use dedens_scenario::{CookieOption, QueryFile, Timeout};

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
    let options = first.options.or(yaml.options);
    assert_eq!(options.recurse, Some(false));
    assert_eq!(options.time, Some(Timeout(Duration::from_secs(2))));
    assert!(matches!(options.cookie, Some(CookieOption::Fixed(_))));
    assert_eq!(nx.options.or(yaml.options).cookie, Some(CookieOption::Off));
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
    assert!(!error.contains("no TTL"), "{error}");
}
