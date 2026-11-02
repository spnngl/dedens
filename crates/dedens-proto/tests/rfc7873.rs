//! RFC 7873: DNS cookies (§4).

mod common;

use common::{decode_options, option_wire};
use dedens_proto::Violation;
use dedens_proto::edns::{Cookie, EdnsOption, OptionCode, UnknownOption};

const CLIENT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn options(data: &[u8]) -> (Vec<EdnsOption<'static>>, Vec<Violation>) {
    let decoded = decode_options(&option_wire(10, data));
    (
        decoded.message.edns.expect("OPT record").options,
        decoded.violations,
    )
}

#[test]
fn s4_1_a_client_cookie_alone() {
    let (options, violations) = options(&CLIENT);
    assert_eq!(violations, []);
    assert_eq!(
        options,
        [EdnsOption::Cookie(Cookie::new(CLIENT, None).unwrap())]
    );
}

#[test]
fn s4_2_a_server_cookie_is_8_to_32_bytes() {
    for len in [8, 16, 32] {
        let mut data = CLIENT.to_vec();
        data.extend(vec![9; len]);
        let (options, violations) = options(&data);
        assert_eq!(violations, [], "{len}");
        let [EdnsOption::Cookie(cookie)] = options.as_slice() else {
            panic!("one cookie")
        };
        assert_eq!(cookie.client(), CLIENT);
        assert_eq!(cookie.server().map(<[u8]>::len), Some(len));
    }
}

#[test]
fn s4_other_lengths_are_kept_unknown() {
    for len in [0, 7, 9, 15, 41] {
        let data = vec![0; len];
        let (options, violations) = options(&data);
        assert!(
            matches!(
                violations.as_slice(),
                [Violation::InvalidOption {
                    code: OptionCode::COOKIE,
                    ..
                }]
            ),
            "{len}"
        );
        assert_eq!(
            options,
            [EdnsOption::Unknown(
                UnknownOption::new(OptionCode::COOKIE, &data).expect("invalid cookie")
            )]
        );
    }
}

/// §5.2: with several COOKIE options in a request only the first is considered, a later one is ignored even if its
/// length is invalid (so no violation) or its data differs.
#[test]
fn s5_2_only_the_first_cookie_option_is_read() {
    let first = option_wire(10, &CLIENT);
    for later in [vec![0; 7], vec![9; 41], vec![5; 8], vec![6; 16]] {
        let mut wire = first.clone();
        wire.extend(option_wire(10, &later));
        wire.extend(option_wire(65001, &[1]));
        let decoded = decode_options(&wire);
        assert_eq!(decoded.violations, [], "{later:?}");
        let options = decoded.message.edns.expect("OPT record").options;
        assert_eq!(
            options,
            [
                EdnsOption::Cookie(Cookie::new(CLIENT, None).unwrap()),
                EdnsOption::Unknown(UnknownOption::new(OptionCode(65001), &[1]).unwrap())
            ],
            "{later:?}"
        );
    }
}

#[test]
fn s4_a_server_cookie_of_bad_size_cannot_be_built() {
    assert!(Cookie::new(CLIENT, Some(&[0; 7])).is_err());
    assert!(Cookie::new(CLIENT, Some(&[0; 33])).is_err());
}
