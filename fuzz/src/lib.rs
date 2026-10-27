//! Fuzz entry points: one function per parser of outside data, each fed arbitrary bytes and required never
//! to panic.
//!
//! `cargo-fuzz` (nightly) reaches them through the shims in `fuzz_targets/`; `cargo test --lib` (stable,
//! `just fuzz-smoke`) replays the captured responses plus mutated variants through [`TARGETS`].

use dedens_proto::{EncodeError, Message};

#[cfg(test)]
mod smoke;

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] = &[("decode_message", decode_message)];

/// A DNS message off the wire. One that decodes without a violation must encode and decode again to the
/// same message; with violations the lifted OPT record and the opaque leftovers may swap places.
///
/// # Panics
///
/// On a bug in the decoder or encoder: that is what fuzzing looks for.
pub fn decode_message(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    if !decoded.violations.is_empty() {
        return;
    }
    let wire = match decoded.message.to_vec() {
        Ok(wire) => wire,
        // Pointers can expand a message past what the encoder's bounded name table can compress again.
        Err(EncodeError::BufferFull) => return,
        Err(e) => panic!("a decoded message must encode: {e}"),
    };
    let again = Message::decode(&wire).expect("what the encoder wrote decodes");
    assert_eq!(again.violations, [], "what the encoder wrote is conforming");
    assert_eq!(again.message, decoded.message, "round trip");
}
