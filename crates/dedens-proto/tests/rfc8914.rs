//! RFC 8914: Extended DNS Errors (§2).

mod common;

use common::{decode_options, option_wire};
use dedens_proto::Violation;
use dedens_proto::edns::{EdnsOption, ExtendedError, InfoCode, OptionCode};

fn options(data: &[u8]) -> (Vec<EdnsOption<'static>>, Vec<Violation>) {
    let decoded = decode_options(&option_wire(15, data));
    (
        decoded.message.edns.expect("OPT record").options,
        decoded.violations,
    )
}

#[test]
fn s2_info_code_and_text() {
    let (options, violations) = options(&[0, 15, b'n', b'o']);
    assert_eq!(violations, []);
    assert_eq!(
        options,
        [EdnsOption::Ede(ExtendedError {
            code: InfoCode::BLOCKED,
            text: "no".into()
        })]
    );
}

#[test]
fn s2_the_text_may_be_empty() {
    let (options, violations) = options(&[0, 3]);
    assert_eq!(violations, []);
    assert_eq!(
        options,
        [EdnsOption::Ede(ExtendedError {
            code: InfoCode::STALE_ANSWER,
            text: "".into()
        })]
    );
}

#[test]
fn s2_the_text_is_utf8() {
    let data = [0, 0, 0xFF, 0xFE];
    let (options, violations) = options(&data);
    assert!(matches!(
        violations.as_slice(),
        [Violation::InvalidOption {
            code: OptionCode::EDE,
            ..
        }]
    ));
    assert_eq!(
        options,
        [EdnsOption::Unknown {
            code: OptionCode::EDE,
            data: data.as_slice().into()
        }]
    );
}

#[test]
fn s2_without_an_info_code_it_is_invalid() {
    let (options, violations) = options(&[7]);
    assert_eq!(violations.len(), 1);
    assert!(matches!(options.as_slice(), [EdnsOption::Unknown { .. }]));
}

#[test]
fn s4_registered_codes_have_names() {
    assert_eq!(InfoCode::BLOCKED.to_string(), "Blocked");
    assert_eq!(InfoCode::DNSSEC_BOGUS.0, 6);
    assert_eq!(InfoCode(1000).to_string(), "EDE1000");
}
