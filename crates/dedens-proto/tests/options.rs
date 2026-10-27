//! RFC 7830 (padding), RFC 7828 (TCP keepalive) and RFC 5001 (NSID) options.

mod common;

use common::{decode_options, option_wire};
use dedens_proto::edns::{EdnsOption, OptionCode};
use dedens_proto::{Edns, Message};

fn options(code: u16, data: &[u8]) -> Vec<EdnsOption> {
    decode_options(&option_wire(code, data))
        .message
        .edns
        .expect("OPT record")
        .options
}

fn encoded(option: EdnsOption) -> Vec<u8> {
    let message = Message {
        edns: Some(Edns {
            options: vec![option],
            ..Edns::default()
        }),
        ..Message::default()
    };
    message.to_vec().expect("fits")
}

#[test]
fn rfc7830_s3_padding_is_its_length_in_zero_bytes() {
    assert_eq!(options(12, &[0; 5]), [EdnsOption::Padding(5)]);
    assert_eq!(options(12, &[]), [EdnsOption::Padding(0)]);
    let wire = encoded(EdnsOption::Padding(3));
    assert_eq!(wire[wire.len() - 7..], [0, 12, 0, 3, 0, 0, 0]);
}

#[test]
fn rfc7830_s3_padding_content_is_ignored() {
    assert_eq!(options(12, &[1, 2]), [EdnsOption::Padding(2)]);
}

#[test]
fn rfc7828_s3_the_timeout_is_absent_in_a_query() {
    assert_eq!(options(11, &[]), [EdnsOption::Keepalive(None)]);
    assert_eq!(options(11, &[0, 100]), [EdnsOption::Keepalive(Some(100))]);
}

#[test]
fn rfc7828_s3_other_lengths_are_invalid() {
    for data in [&[1u8][..], &[1, 2, 3]] {
        let decoded = decode_options(&option_wire(11, data));
        assert_eq!(decoded.violations.len(), 1);
        assert_eq!(
            decoded.message.edns.expect("OPT record").options,
            [EdnsOption::Unknown {
                code: OptionCode::KEEPALIVE,
                data: data.into()
            }]
        );
    }
}

#[test]
fn rfc5001_s2_nsid_is_empty_in_a_query_and_opaque_in_a_response() {
    assert_eq!(options(3, &[]), [EdnsOption::Nsid([].into())]);
    assert_eq!(
        options(3, b"ns1.example"),
        [EdnsOption::Nsid((*b"ns1.example").into())]
    );
}
