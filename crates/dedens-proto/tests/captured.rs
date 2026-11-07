//! Responses captured from public servers by `just capture` (`testdata/capture.yaml`): they decode without a violation and
//! re-encode to an equal message.

use std::fs;
use std::path::PathBuf;

use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Rcode, Record, RecordType};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata")
}

fn capture(name: &str) -> Message<'static> {
    let wire = fs::read(dir().join(format!("{name}.bin"))).expect("captured file");
    let decoded = Message::decode(&wire).expect("decodes");
    assert_eq!(decoded.violations, [], "{name}");
    decoded.message.into_owned()
}

#[test]
fn every_capture_decodes_and_round_trips() {
    let mut count = 0;
    for entry in fs::read_dir(dir()).expect("testdata directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "bin") {
            continue;
        }
        let name = path
            .file_stem()
            .expect("stem")
            .to_string_lossy()
            .into_owned();
        let message = capture(&name);
        let wire = message.to_vec().expect("encodes");
        let again = Message::decode(&wire).expect("decodes again");
        assert_eq!(again.violations, [], "{name}");
        assert_eq!(again.message, message, "{name}");
        count += 1;
    }
    assert!(count >= 16, "{count} captures");
}

#[test]
fn a_response_has_an_answer_and_opt() {
    let message = capture("a");
    assert!(message.header.flags.contains(Flags::QR));
    assert!(
        message
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::A(_)))
    );
    assert!(message.edns.is_some());
}

#[test]
fn a_cname_chain_ends_in_an_address() {
    let message = capture("cname_chain");
    assert!(matches!(
        message.answer.first().map(Record::data),
        Some(RData::Cname(_))
    ));
    assert!(
        message
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::A(_)))
    );
}

#[test]
fn nxdomain_carries_the_zone_soa() {
    let message = capture("nxdomain_soa");
    assert_eq!(message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(message.answer, []);
    assert!(
        message
            .authority
            .iter()
            .any(|r| matches!(r.data(), RData::Soa(_)))
    );
}

#[test]
fn a_large_txt_answer_decodes() {
    let message = capture("txt_large");
    assert!(
        message
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Txt(_)))
    );
}

#[test]
fn https_and_caa_and_srv_have_typed_data() {
    assert!(
        capture("https")
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Https(_)))
    );
    assert!(
        capture("caa")
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Caa(_)))
    );
    assert!(
        capture("srv")
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Srv(_)))
    );
}

#[test]
fn any_gets_a_minimal_hinfo_answer_rfc8482() {
    let message = capture("any_rfc8482");
    assert_eq!(message.answer.len(), 1);
    // HINFO has no typed RDATA in D11: it stays opaque.
    assert_eq!(
        message.answer.first().map(|r| r.data().rtype()),
        Some(RecordType(13))
    );
}

#[test]
fn a_truncated_response_has_tc_and_no_records() {
    let message = capture("truncated");
    assert!(message.header.flags.contains(Flags::TC));
    assert_eq!(message.answer, []);
}

#[test]
fn a_dnssec_failure_comes_with_an_extended_error() {
    let message = capture("ede");
    assert_eq!(message.rcode(), Rcode::SERVFAIL);
    let edns = message.edns.expect("OPT");
    assert!(
        edns.options
            .iter()
            .any(|o| matches!(o, EdnsOption::Ede(e) if e.code == InfoCode::DNSKEY_MISSING))
    );
}

#[test]
fn nsid_is_answered() {
    let edns = capture("nsid").edns.expect("OPT");
    assert!(
        edns.options
            .iter()
            .any(|o| matches!(o, EdnsOption::Nsid(id) if !id.is_empty()))
    );
}

#[test]
fn a_cookie_is_returned_with_a_server_part() {
    let edns = capture("cookie").edns.expect("OPT");
    let cookie = edns.options.iter().find_map(|o| match o {
        EdnsOption::Cookie(c) => Some(c),
        _ => None,
    });
    let cookie = cookie.expect("COOKIE option");
    assert_eq!(cookie.client(), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(cookie.server().is_some());
}

#[test]
fn referrals_are_told_from_other_responses() {
    let zone = |name: &str| capture(name).referral().map(ToString::to_string);
    assert_eq!(zone("referral_root").as_deref(), Some("com."));
    assert_eq!(zone("referral_com").as_deref(), Some("example.com."));
    // An answer, NXDOMAIN and NODATA (with a SOA), an HINFO answer and SERVFAIL are not.
    for name in ["a", "nxdomain_soa", "nodata", "any_rfc8482", "ede"] {
        assert_eq!(zone(name), None, "{name}");
    }
}
