//! Inputs shared by the benches of `dedens-proto` against other DNS libraries (D14): the Rust ones in
//! `benches/`, the Go `miekg/dns` (the codec of `CoreDNS`) in `go/`.

/// Captured responses, smallest to largest: one A record; MX records with their A glue; a TXT answer of
/// 1.2 kB.
pub const CASES: [&str; 3] = ["a", "mx", "txt_large"];

/// The captured response `case` from `crates/dedens-proto/tests/testdata/`.
///
/// # Panics
///
/// When the file cannot be read: the benches have nothing to measure.
#[must_use]
#[expect(
    clippy::panic,
    reason = "a bench without its input has nothing to measure"
)]
pub fn wire(case: &str) -> Vec<u8> {
    let path = format!(
        "{}/../dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("captured response {path}: {e}"))
}
