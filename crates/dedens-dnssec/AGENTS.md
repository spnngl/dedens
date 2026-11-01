# dedens-dnssec

DNSSEC validation, sans-IO (D69): signatures, denial of existence and the chain of trust over records its
caller fetched. The caller owns the clock, the questions and the sockets. Crypto is `ring` (D71), nothing
else. `crypto/`: signatures, key tags, DS and NSEC3 hashes, `Budget`. `anchor.rs`: trust anchors, the root's
bundled in `root.ds` (`just root-anchors`, D72), and negative ones. One module per concern; tests of RFC behaviour
in `tests/rfcNNNN.rs`.

- `tests/testdata/`: real responses from `just capture-dnssec` (the queries of `capture.yaml`), `captured_at`
  the "now" of the tests, `README.md` what each shows and the verdict a validator gives. Read by
  `tests/captured.rs`; fuzz seeds. Never edit by hand.
