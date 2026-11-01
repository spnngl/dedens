# dedens-dnssec

DNSSEC validation, sans-IO (D69): signatures, denial of existence and the chain of trust over records its
caller fetched. The caller owns the clock, the questions and the sockets. Crypto is `ring` (D71), nothing
else. `crypto/`: signatures, key tags, DS and NSEC3 hashes, `Budget`. `anchor.rs`: trust anchors, the root's
bundled in `root.ds` (`just root-anchors`, D72), and negative ones. `rrsig/`: `RrSet`, its canonical form,
`verify` and `verify_any` of an `RRset` by RRSIG and DNSKEY, `trusted_keys` of a DNSKEY `RRset` by DS, `SigError`
and its EDE code (D73). `denial/`: what verified NSEC and NSEC3 records prove (D74), pure set logic. One module
per concern; tests of RFC behaviour in `tests/rfcNNNN.rs`.

- `tests/testdata/`: real responses from `just capture-dnssec` (the queries of `capture.yaml`), `captured_at`
  the "now" of the tests, `README.md` what each shows and the verdict a validator gives. Read by
  `tests/captured.rs` and `tests/captured_rrsig.rs`; fuzz seeds. Never edit by hand.
- `tests/zones/`: example zones of RFCs read by the tests (RFC 4035 Appendix A; RFC 5155 Appendix A is in
  `dedens-proto`). `tests/common/denial.rs`: helpers of the denial tests; `tests/denial_captured.rs` checks each
  negative capture proves what its rcode says, and lists them: a new capture with a denial goes in its table.
