# dedens-proto

The DNS wire format and zone-file text: messages, names, records, EDNS, read and written. Sans-IO: it encodes
and decodes byte slices; sockets, timers and compio live in `dedens-net` and the apps.

- Layout (D13, D159): topic modules at `src/`, one RDATA or EDNS option file per type or per group sharing a
  format, named after the type (`rdata/srv.rs`, `edns/cookie.rs`); each public item's doc cites its RFC and section.
- One path per item (D160): `rdata` and `edns` are public modules, read as `rdata::RData`, `edns::Edns`; the other
  modules are private and `lib.rs` re-exports each of their public items at the root, in one sorted list.
- An in-place reader (`Query::read`) is fuzzed against `Message::decode` (`read_query` in `fuzz/src/proto.rs`).
- `src/proofs.rs` holds Kani's proofs of the name and header decoders (`just kani`, D145); a change to their loops
  runs it.
- The encoder's name table (`wire.rs`, D10, D112) compares a bounded number of names for each lookup, so that
  encoding a name costs O(L log L) in its length L, whatever the upstream's names. A change to how names are hashed or searched
  keeps `encode_64k` of `collisions`, `chains` and `flips` within 2x of `spread`.
- Speed is measured in `crates/dedens-bench`; read D14 before touching `wire`, `name` or `message`.
