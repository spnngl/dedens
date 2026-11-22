# dedens-tsig

TSIG (RFC 8945, D205): the keys, and signing and verifying messages on both sides of a request, a response or a TCP
stream of responses. Sans-I/O: bytes and the clock (`now`, Unix seconds) in, bytes out. `src/lib.rs` says what each
type is; the record's RDATA and `find_tsig` are in `dedens-proto`.

- The digest is built in one place, `src/digest.rs` (`Digest`); the server and the client share it. A change to what
  goes in it (RFC 8945 §4.3, §5.3.1) is checked by `tests/util.rs` `Reference`, a second computation written from the
  RFC with `ring` only, and by Knot's captures (`tests/captures.rs`): never edit either to follow the code.
- The order of `verify_request`'s checks is the RFC's (§5.2: format, key, MAC, time, truncation), and it decides what
  a client sees: an unknown key and a wrong MAC are answered unsigned, BADTIME and BADTRUNC signed. A new refusal
  is a variant with its RFC section and a test in `tests/server.rs`.
- MACs are compared in constant time (`digest::matches`, a prefix when truncated); never with `==`.
- Secrets live in `Zeroizing`, `Debug` of a `Key` hides them, and a key is never logged. The `ring` HMAC key made for
  each message is not wiped (D205).
- Truncated MACs are BADTRUNC on the server and refused by the client, with no setting (D205).
- The `fuzz` target `tsig_verify` (`fuzz/src/tsig.rs`) holds the invariant that a message with no TSIG, signed,
  verifies on both sides; it needs a change when `sign_request` or `ResponseSigner::sign` do.
