# dedens-proto

The DNS wire format and zone-file text: messages, names, records, EDNS, read and written. Sans-IO: it encodes
and decodes byte slices; sockets, timers and compio live in `dedens-net` and the apps.

- Layout (D13): topic modules at `src/`, one RDATA or EDNS option file per type or per group sharing a format,
  named after the defining RFC (`rdata/rfc2782_srv.rs`, `rdata/rfc1035_domain_name.rs`).
- An in-place reader (`Query::read`) is fuzzed against `Message::decode` (`read_query` in `fuzz/src/lib.rs`).
- The encoder's name table (`wire.rs`, D10, D112) compares a bounded number of names for each lookup, so that
  encoding a name costs O(L log L) in its length L, whatever the upstream's names. A change to how names are hashed or searched
  keeps `encode_64k` of `collisions`, `chains` and `flips` within 2x of `spread`.
- Speed is measured in `crates/dedens-bench`; read D14 before touching `wire`, `name` or `message`.
