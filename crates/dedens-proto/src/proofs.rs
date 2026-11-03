//! Kani proofs of the wire decoders (D145): for every input up to a few bytes, decoding never panics and stops.
//! `just kani` runs them; fuzzing samples longer inputs.

use crate::header::{HEADER_LEN, Header};
use crate::name::Name;
use crate::wire::{Reader, Writer};

/// Bytes after the header in the inputs of [`name_decoding`]: room for a few labels and a chain of pointers.
const NAME_BYTES: usize = 12;

/// A name read at any position past the header of any message of up to [`NAME_BYTES`] more bytes, with
/// compression pointers (RFC 1035 §4.1.4) or without (RFC 3597 §4): the decoder never panics and stops, and a name
/// it returns ends past its start and inside the input. The header's bytes are zeros: no pointer may point there.
#[kani::proof]
#[kani::unwind(14)]
fn name_decoding() {
    let mut bytes = [0; HEADER_LEN + NAME_BYTES];
    let tail: [u8; NAME_BYTES] = kani::any();
    bytes[HEADER_LEN..].copy_from_slice(&tail);
    let len = kani::any_where(|&len: &usize| (HEADER_LEN..=bytes.len()).contains(&len));
    let start = kani::any_where(|&start: &usize| (HEADER_LEN..=len).contains(&start));
    let mut r = Reader::range(&bytes[..len], start, len);
    let decoded = if kani::any() {
        Name::decode(&mut r)
    } else {
        Name::decode_uncompressed(&mut r)
    };
    if decoded.is_ok() {
        assert!(start < r.position() && r.position() <= len);
    }
}

/// The header of any input (RFC 1035 §4.1.1): read exactly when the input holds its 12 bytes.
#[kani::proof]
fn header_peeking() {
    let bytes: [u8; HEADER_LEN + 1] = kani::any();
    let len = kani::any_where(|&len: &usize| len <= bytes.len());
    assert_eq!(Header::peek(&bytes[..len]).is_some(), len >= HEADER_LEN);
}

/// Every header (RFC 1035 §4.1.1) decodes and encodes back to its 12 bytes: no flag, code or count is lost.
#[kani::proof]
fn header_round_trip() {
    let bytes: [u8; HEADER_LEN] = kani::any();
    let Ok((header, counts)) = Header::decode(&mut Reader::new(&bytes)) else {
        panic!("12 bytes hold a header");
    };
    let mut buf = [0; HEADER_LEN];
    let mut w = Writer::uncompressed(&mut buf);
    assert!(header.encode(counts, &mut w).is_ok());
    assert_eq!(w.written(), bytes);
}
