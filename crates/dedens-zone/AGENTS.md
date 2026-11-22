# dedens-zone

Zone text into a checked, immutable `Zone` (D204); `src/lib.rs` says what each type is.

- A check goes in `Builder`: `add` for what one record shows, `finish` for what the whole zone does. Never over a
  finished `Zone`, which has lost the lines. A new error or warning is a variant of `ErrorKind` or `WarningKind`
  with its RFC section in the message, and a test in `tests/checks.rs` or `tests/marks.rs` that breaks a zone by it.
- A new bound is a `Limits` field with its default's reason and prior art in the doc, and a test in
  `tests/limits.rs` that reaches it; `fuzz/src/zone.rs` sets small ones so the fuzz target reaches them too.
- `Kind::Occluded` is every name below a delegation point or a DNAME owner; an empty non-terminal below one is
  occluded, not empty. `finish` finds them walking the names in canonical order: it relies on the names under a
  name being next to it.
- RRSIGs are kept apart from the `RRset`s, by the type they cover, so the CNAME check sees only NSEC beside a CNAME.
- `testdata/zones/every_type.zone` is the fuzzing seed of `dedens-proto`, and no zone for this loader (classes CH,
  HS, CLASS32, a name outside the zone): `tests/rfc_zones.rs` shows its refusals; do not edit it for the loader.
- DNAME has no typed text form yet: tests write it as `\#` generic RDATA.
