# dedens-zone

Zone text into a checked, immutable `Zone` (D204), the changesets between versions and their journal file (D207), and
what it answers (`answer.rs`, `reply.rs`, D206); `src/lib.rs` says what each type is.

- A check goes in `Builder`: `add` for what one record shows, `finish` for what the whole zone does. Never over a
  finished `Zone`, which has lost the lines. A new error or warning is a variant of `ErrorKind` or `WarningKind`
  with its RFC section in the message, and a test in `tests/checks.rs` or `tests/marks.rs` that breaks a zone by it.
- A new bound is a `Limits` field with its default's reason and prior art in the doc, and a test in
  `tests/limits.rs` that reaches it; `fuzz/src/zone.rs` sets small ones so the fuzz target reaches them too.
- `Kind::Occluded { cut }` is every name below a delegation point or a DNAME owner; an empty non-terminal below one
  is occluded, not empty. `cut` is the index of the outermost cut's node in the sorted nodes, which `answer` reads
  instead of walking: the index must stay right when nodes are added or removed (`Zone::apply` rebuilds through
  `Builder`). `finish` finds them walking the names in canonical order: it relies on the names under a name being
  next to it.
- `Zone::apply` goes through `Builder` too (`from_zone`, `remove`, then `add`), so a check added to `add` or `finish`
  holds for a changed zone as for a loaded one; a record of the old zone has line 0 in a `Place`, a changeset's the
  number of its record. The journal is the only file I/O of the crate (blocking: callers run it off the serving
  thread); `journal::format` is pure bytes, which `fuzz` `journal_read` reads, and a change to the file's format
  changes its header, `MAGIC`, and `fuzz/seeds/example.journal` (`DEDENS_WRITE_SEED=1 cargo test -p dedens-zone
  fuzz_seed`).
- RRSIGs are kept apart from the `RRset`s, by the type they cover, so the CNAME check sees only NSEC beside a CNAME.
- `testdata/zones/every_type.zone` is the fuzzing seed of `dedens-proto`, and no zone for this loader (classes CH,
  HS, CLASS32, a name outside the zone): `tests/rfc_zones.rs` shows its refusals; do not edit it for the loader.
- DNAME has no typed text form yet: tests write it as `\#` generic RDATA.
- A change to `Zone::answer` goes with `fuzz/src/zone.rs` (`zone_answer`), `tests/answer.rs` (the RFC examples)
  and `tests/reference.rs` (Knot and NSD, by D203's rules); a difference there is D203's or a bug, never a changed
  expectation. The answer must not allocate zone data: bench `answer_zone` and `reply_zone` after touching it, the
  127-label and DNAME-growth cases included (the lookup is one bisection for a name that is a node and two for one that is not, never a search per ancestor or
  a walk from the apex).
- `Zone`'s nodes are a sorted `Vec`, not a map (D206): a lookup by a name that lives shorter than the zone must still
  return a node that lives as long as the zone. `locate` bisects for the name asked and, if it is no node, takes the closest
  encloser from the node before it, relying on D204: every ancestor of a node is a node, so the name's closest
  encloser is the ancestor it shares the most labels with that node. `fn address_node` reads an occluded node's cut
  the same way, with no walk.
- A name holding only NSEC3 records is no name for `answer` (RFC 5155 §7.2), though it is a node.
