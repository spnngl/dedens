# rdata

RDATA of each typed record type (D11), and `Opaque` for every other one (RFC 3597). Each file decodes, encodes,
reads and writes its text.

A new type: its file, a `RecordType` constant (D19), an `RData` arm in each dispatch of `mod.rs`, a
`tests/rfcNNNN.rs`, a proptest strategy in `tests/common/mod.rs`, a line in `tests/zones/every_type.zone`, and
its `docs/rfc/coverage.md` row. Names inside RDATA are compressed only for RFC 1035 types (D10).
