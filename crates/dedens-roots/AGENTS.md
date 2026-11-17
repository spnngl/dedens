# dedens-roots

IANA's root hints and TLD list (D126), bundled and read from fresh copies; `src/lib.rs` says what each type is.

- `src/named.root`, `src/tlds.json` and `tests/data/tlds.json` are written by `just roots`, never by hand: the
  bundled `tlds.json` is IANA's cut to the members `src/tlds.rs` reads, the test copy six entries of the same download
  in full. A member read from a new place goes in the recipe's `jq` filter too, or the bundled list lacks it.
- `Tlds::read` refuses a copy holding fewer than half the bundled TLDs; `Tlds::bundled` does not check itself.
- The DS records of `tlds.json` are hints, never trust anchors: the file is unsigned (D126).
