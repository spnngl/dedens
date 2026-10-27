//! Fuzz entry points: one function per parser of outside data, each fed arbitrary bytes and required never
//! to panic.
//!
//! `cargo-fuzz` (nightly) reaches them through the shims in `fuzz_targets/`; `cargo test --lib` (stable,
//! `just fuzz-smoke`) replays the captured responses plus mutated variants through [`TARGETS`].

use dedens_proto::{EncodeError, Flags, Message, MessageIndex};

#[cfg(test)]
mod smoke;

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] =
    &[("decode_message", decode_message), ("read_view", read_view)];

/// A DNS message off the wire, read in place: it reads what [`Message::decode`] reads, or fails as it does, and
/// every accessor works on what it accepts.
///
/// # Panics
///
/// On a disagreement, or a bug in the reader.
pub fn read_view(data: &[u8]) {
    let mut index = MessageIndex::new();
    let viewed = index.read(data).map(|view| view.to_decoded());
    let decoded = Message::decode(data);
    // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
    assert_eq!(
        format!("{viewed:?}"),
        format!("{decoded:?}"),
        "view and decoder agree"
    );
}

/// A DNS message off the wire.
///
/// Whatever decodes must encode (unless pointers expanded it past 65535 bytes) and decode again to the same
/// message, names byte for byte. Without violations, the encoding is conforming, and truncating it at any size
/// keeps a conforming prefix of it.
///
/// # Panics
///
/// On a bug in the decoder or encoder: that is what fuzzing looks for.
pub fn decode_message(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let wire = match decoded.message.to_vec() {
        Ok(wire) => wire,
        Err(EncodeError::BufferFull) => return,
        Err(e) => panic!("a decoded message must encode: {e}"),
    };
    let again = Message::decode(&wire).expect("what the encoder wrote decodes");
    // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
    assert_eq!(
        format!("{:?}", again.message),
        format!("{:?}", decoded.message),
        "round trip"
    );
    if !decoded.violations.is_empty() {
        return;
    }
    assert_eq!(again.violations, [], "what the encoder wrote is conforming");
    let size = usize::from(data.first().copied().unwrap_or_default()) * wire.len() / 255;
    truncate(&decoded.message, size);
}

/// Encodes `message` into `size` bytes, dropping records: what is written must be a conforming prefix.
fn truncate(message: &Message, size: usize) {
    let mut buf = vec![0; size];
    let Ok(encoded) = message.encode_truncated(&mut buf) else {
        return;
    };
    let wire = buf
        .get(..encoded.len)
        .expect("the length is within the buffer");
    let cut = Message::decode(wire).expect("a truncated message decodes");
    assert_eq!(cut.violations, [], "a truncated message is conforming");
    let cut = cut.message;
    let tc = message.header.flags.contains(Flags::TC) || encoded.truncated;
    assert_eq!(cut.header.flags.contains(Flags::TC), tc);
    assert_eq!(cut.edns, message.edns, "the OPT record is kept");
    let sections = [
        (&cut.answer, &message.answer),
        (&cut.authority, &message.authority),
        (&cut.additional, &message.additional),
    ];
    let mut kept = 0;
    for (cut, whole) in sections {
        assert!(whole.starts_with(cut), "each section is a prefix");
        kept += cut.len();
    }
    let total = message.answer.len() + message.authority.len() + message.additional.len();
    assert_eq!(kept + encoded.dropped, total);
}
