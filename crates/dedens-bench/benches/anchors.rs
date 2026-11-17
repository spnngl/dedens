//! IANA's signed root anchors (D127): `TrustAnchors::verified` on the captured pair, and on the captured `.p7s`
//! grown to a size with digest algorithms out of DER order, which `der` sorts by insertion as it decodes: the cost
//! that bounds the `.p7s` to `MAX_P7S`. The `digestAlgorithms` set is not signed, so the grown pair still verifies.

use std::hint::black_box;

use dedens_dnssec::{MAX_P7S, TrustAnchors};

/// What `just roots` captured, and when.
const XML: &[u8] = include_bytes!("../../../testdata/dnssec/root-anchors.xml");
const P7S: &[u8] = include_bytes!("../../../testdata/dnssec/root-anchors.p7s");
const CAPTURED_AT: &str = include_str!("../../../testdata/dnssec/root-anchors.captured_at");

fn main() {
    divan::main();
}

fn now() -> u64 {
    CAPTURED_AT.trim().parse().expect("Unix time in seconds")
}

#[divan::bench]
fn verified(bencher: divan::Bencher<'_, '_>) {
    let now = now();
    bencher.bench_local(|| {
        TrustAnchors::verified(black_box(XML), black_box(P7S), now, None)
            .expect("the captured pair")
    });
}

#[divan::bench(args = [4 * 1024, 8 * 1024, MAX_P7S], sample_count = 20)]
fn verified_grown(bencher: divan::Bencher<'_, '_>, size: usize) {
    let (now, p7s) = (now(), grown(size));
    bencher.bench_local(|| {
        TrustAnchors::verified(black_box(XML), black_box(&p7s), now, None).expect("the grown pair")
    });
}

/// The captured `.p7s`, at most `size` bytes, its `digestAlgorithms` followed by distinct identifiers (OIDs
/// 1.2.3.x.y, 8 bytes each) in decreasing DER order: insertion sort's worst case.
fn grown(size: usize) -> Vec<u8> {
    // ContentInfo { contentType, [0] { SignedData { version, digestAlgorithms, rest } } } (RFC 5652 §3, §5.1).
    let info = value(P7S);
    let signed_data = value(value(&info[tlv_len(info)..]));
    let version = &signed_data[..tlv_len(signed_data)];
    let after_version = &signed_data[version.len()..];
    let set = &after_version[..tlv_len(after_version)];
    let rest = &after_version[set.len()..];
    let count = (size - P7S.len() - 2) / 8;
    let mut algorithms = value(set).to_vec();
    for i in (0..count).rev() {
        let (high, low) = (
            u8::try_from(i / 128).expect("i < 16384"),
            u8::try_from(i % 128).expect("< 128"),
        );
        algorithms.extend_from_slice(&[0x30, 0x06, 0x06, 0x04, 0x2a, 0x03, high, low]);
    }
    let signed_data = [version, &tlv(0x31, &algorithms), rest].concat();
    let content = tlv(0xa0, &tlv(0x30, &signed_data));
    let content_type = &info[..tlv_len(info)];
    let p7s = tlv(0x30, &[content_type, &content].concat());
    assert!(p7s.len() <= size, "{} bytes, more than {size}", p7s.len());
    p7s
}

/// The header length and the value length of the DER TLV `der` starts with (lengths of up to two bytes).
fn header(der: &[u8]) -> (usize, usize) {
    match der[1] {
        0x81 => (3, usize::from(der[2])),
        0x82 => (4, usize::from(u16::from_be_bytes([der[2], der[3]]))),
        short => (2, usize::from(short)),
    }
}

/// The whole length of the TLV `der` starts with.
fn tlv_len(der: &[u8]) -> usize {
    let (header, len) = header(der);
    header + len
}

/// The value of the TLV `der` starts with.
fn value(der: &[u8]) -> &[u8] {
    let (header, len) = header(der);
    &der[header..header + len]
}

/// The TLV of `tag` and `value` (values of up to 64 KiB).
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let len = u16::try_from(value.len()).expect("a value of up to 64 KiB");
    let mut der = match len {
        0..0x80 => vec![tag, u8::try_from(len).expect("< 0x80")],
        0x80..0x100 => vec![tag, 0x81, u8::try_from(len).expect("< 0x100")],
        _ => [&[tag, 0x82][..], &len.to_be_bytes()].concat(),
    };
    der.extend_from_slice(value);
    der
}
