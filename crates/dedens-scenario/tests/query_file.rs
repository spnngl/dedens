//! Query files read from YAML and JSON, and their expectations checked against captured responses.

use std::time::Duration;

use dedens_proto::{Message, Name, RecordType};
use dedens_scenario::{CookieOption, Format, Options, QueryFile, Timeout};

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
    options: {tcp: true, timeout: 2s, tries: 1, bufsize: 4096, cookie: '0102030405060708'}
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
    let yaml = QueryFile::parse(YAML, Format::Yaml).expect("valid YAML");
    let json = QueryFile::parse(
        r#"{"server": "1.1.1.1", "options": {"recurse": false, "cookie": false}, "queries": [
            {"name": "example.com", "type": "A",
             "options": {"tcp": true, "timeout": "2s", "tries": 1, "bufsize": 4096, "cookie": "0102030405060708"},
             "expect": {"rcode": "NOERROR", "flags": ["qr", "ra"], "answer": [
                "example.com. 29 IN A 104.20.23.154", "example.com. IN A 172.66.147.243"]}},
            {"id": "nx", "name": "nonexistent.invalid.", "type": "A", "server": "9.9.9.9:53",
             "expect": {"rcode": "NXDOMAIN", "answer": []}}]}"#,
        Format::Json,
    )
    .expect("valid JSON");
    assert_eq!(yaml, json);

    let [first, nx] = yaml.queries.as_slice() else {
        panic!("two queries");
    };
    assert_eq!(first.id(), "example.com_A");
    assert_eq!(nx.id(), "nx");
    assert_eq!(
        first.name,
        "example.com.".parse::<Name<'_>>().expect("valid")
    );
    assert_eq!(first.qtype, RecordType::A);
    let options = first.options.or(yaml.options);
    assert_eq!(options.recurse, Some(false));
    assert_eq!(options.timeout, Some(Timeout(Duration::from_secs(2))));
    assert!(matches!(options.cookie, Some(CookieOption::Fixed(_))));
    assert_eq!(nx.options.or(yaml.options).cookie, Some(CookieOption::Off));
}

#[test]
fn met_expectations_report_nothing() {
    let file = QueryFile::parse(YAML, Format::Yaml).expect("valid");
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
        Format::Yaml,
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
        "queries: [{name: example.com, type: A, options: {timeout: soon}}]",
        "queries: [{name: example.com, type: A, expect: {answer: [not a record]}}]",
        "queries: [{type: A}]",
        "server: 1.1.1.1",
    ] {
        assert!(QueryFile::parse(text, Format::Yaml).is_err(), "{text}");
    }
}

#[test]
fn options_build_the_query() {
    let options = Options {
        recurse: Some(false),
        cd: Some(true),
        dnssec: Some(true),
        nsid: Some(true),
        bufsize: Some(4096),
        ..Options::default()
    };
    let query = options.query(dedens_proto::Question::new(Name::root(), RecordType::NS));
    let flags: Vec<_> = query.header.flags.names().collect();
    assert_eq!(flags, ["ad", "cd"]);
    let edns = query.edns.expect("EDNS on by default");
    assert_eq!(edns.udp_payload, 4096);
    assert!(edns.flags.contains(dedens_proto::EdnsFlags::DO));
    assert_eq!(edns.options.len(), 1);

    let plain = Options {
        edns: Some(false),
        ..Options::default()
    };
    assert!(
        plain
            .query(dedens_proto::Question::new(Name::root(), RecordType::NS))
            .edns
            .is_none()
    );
}
