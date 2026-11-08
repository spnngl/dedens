# rdata

RDATA of each typed record type (D11), and `Opaque` for every other one (RFC 3597). Each type's file, named after
the type (D159; A, AAAA, NS, CNAME and PTR: a module in `mod.rs`), decodes, encodes, reads and writes its text.
Records store RDATA as `WireRdata` bytes and read these types on demand (D28).

A new type: its file (`decode`, `encode`, `from_text`, `into_owned`, `Display`; RFC and section on each public
item), a `RecordType` constant (D19), a line in the `rdata_types!` table of `mod.rs` (D139), a `tests/rfcNNNN.rs`,
a proptest strategy in `tests/common/mod.rs`, a line in `testdata/zones/every_type.zone` and in `EVERY_TYPE` of
`tests/text.rs` (then `INSTA_UPDATE=always cargo test` for its snapshot), and its `docs/rfc/coverage.md` row. Names
inside RDATA are compressed only for RFC 1035 types (D10); a pointer in a name that must not be compressed makes the
RDATA invalid and opaque (D70).
