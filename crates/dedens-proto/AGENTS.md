# dedens-proto

The DNS wire format and zone-file text: messages, names, records, EDNS, read and written. Sans-IO: it encodes
and decodes byte slices; sockets, timers and compio live in `dedens-net`.

- Layout (D13): topic modules at `src/`, one RDATA or EDNS option file per type or per group sharing a format,
  named after the defining RFC (`rdata/rfc2782_srv.rs`, `rdata/rfc1035_domain_name.rs`).
- Every reader of outside bytes or text gets a fuzz target in `fuzz/src/lib.rs`; an in-place reader (`view`,
  `query`) is fuzzed against `Message::decode`.
- Speed is measured in `crates/dedens-bench`; read D14 before touching `wire`, `name` or `message`.
