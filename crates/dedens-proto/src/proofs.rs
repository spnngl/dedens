//! Kani proofs of the wire format (D145): for every input up to a few bytes, decoding never panics and stops, and
//! what is decoded or appended is what the RFC says. `just kani dedens-proto` runs them, and the private ones in
//! the modules (`zero_bytes`, client subnet); fuzzing samples longer inputs.

use crate::codes::RecordType;
use crate::edns::{Edns, EdnsFlags};
use crate::header::{HEADER_LEN, Header};
use crate::name::Name;
use crate::rdata::TypeBitmap;
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

/// The OPT record appended to any message of up to 25 bytes in its buffer, as a server adds its EDNS to a response
/// from the cache (RFC 6891 §6.1.2): it fits exactly when the buffer holds the header, the 11 bytes of the record and
/// ARCOUNT can count one more; then ARCOUNT gains 1 and the record follows the message, the rest unchanged; else
/// nothing changes.
#[kani::proof]
#[kani::unwind(27)]
fn edns_appending() {
    const N: usize = HEADER_LEN + 13;
    let original: [u8; N] = kani::any();
    let mut buf = original;
    let len: usize = kani::any();
    let edns = Edns {
        udp_payload: kani::any(),
        ext_rcode: kani::any(),
        version: kani::any(),
        flags: EdnsFlags::from_bits(kani::any()),
        options: Vec::new(),
    };
    let result = edns.append(&mut buf, len);
    let arcount = |b: &[u8; N]| u16::from_be_bytes([b[10], b[11]]);
    let fits = (HEADER_LEN..=N - 11).contains(&len) && arcount(&original) < u16::MAX;
    assert_eq!(result.is_ok(), fits);
    if fits {
        assert_eq!(result.ok(), Some(len + 11));
        assert_eq!(arcount(&buf), arcount(&original) + 1);
        assert_eq!(buf[..10], original[..10]);
        assert_eq!(buf[12..len], original[12..len]);
        let [payload_hi, payload_lo] = edns.udp_payload.to_be_bytes();
        let [flags_hi, flags_lo] = edns.flags.bits().to_be_bytes();
        let record = [
            0,
            0,
            41,
            payload_hi,
            payload_lo,
            edns.ext_rcode,
            edns.version,
            flags_hi,
            flags_lo,
            0,
            0,
        ];
        assert_eq!(buf[len..len + 11], record);
        assert_eq!(buf[len + 11..], original[len + 11..]);
    } else {
        assert_eq!(buf[..len.min(N)], original[..len.min(N)]);
    }
}

/// Type bit maps of up to 6 bytes (RFC 4034 §4.1.2): any bytes are read without panicking, and in bit maps they
/// hold, a type is found by `contains` exactly when `types` lists it.
#[kani::proof]
#[kani::unwind(9)]
fn type_bitmap_reading() {
    let bytes: [u8; 6] = kani::any();
    let len = kani::any_where(|&len: &usize| len <= bytes.len());
    let Ok(bitmap) = TypeBitmap::from_wire(&bytes[..len]) else {
        return;
    };
    let rtype = RecordType(kani::any());
    assert_eq!(bitmap.contains(rtype), bitmap.types().any(|t| t == rtype));
}
