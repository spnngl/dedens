# Wire format

Decisions; the rules and the index are in [`README.md`](README.md).

- D7 `Name<'a>`: wire-form bytes, case kept, compared and hashed ASCII case-insensitively (RFC 4343); built only
  through validating constructors. Private representation: a slice of the input without pointers, input plus
  offset with pointers (labels read on demand, pointers checked once), or owned bytes. Rejected: a 255-byte
  inline buffer (about 300 bytes per record); copying compressed names at decode (the allocation borrowing
  removes).
- D7a (amended by D139) Decoding borrows: one set of types with a lifetime, `Message<'static>` is the owned form
  (`into_owned()` or built by hand). Variable-length values (TXT, SVCB parameters, CAA, opaque RDATA, EDNS options)
  stay as checked wire bytes read through accessors, so they keep their invariants. Rejected: a borrowed view beside
  the owned types (every RDATA type twice); a lazy message (errors at every access).
- D8 `Message`: header, questions, answer, authority, additional, and EDNS lifted out of additional, so no
  caller searches for the OPT record.
- D9 Decoder: a compression pointer points strictly before the current label (no loops), past the header, to
  labels ending before the bytes that point to them (a prior name, RFC 1035 §4.1.4), at most 127 per name
  (no long chains); unknown types are opaque (RFC 3597); every input decodes or errors (fuzzed). Broken structure
  is an error. A readable message breaking a rule (several OPT; OPT outside additional, not at the root or with an
  option running past its RDATA, RFC 6891 §6.1.2; QDCOUNT > 1 per RFC 9619; trailing bytes) decodes with
  violations: the CLI shows them, the server answers FORMERR. Well-delimited but invalid RDATA or EDNS option is
  kept opaque with a violation, as is an OPT record whose options overrun it, its options unread, so typed values
  always hold their invariants; except in types whose names may be compressed (RFC 3597 §4), where it is an
  error, since their pointers mean nothing outside the message.
- D10 (amended by D112) Encoder: into a caller buffer with a size limit, no allocation (fits io_uring registered
  buffers), plus a `Vec` convenience. Compresses names only in RFC 1035 types (RFC 3597 §4), never into the header,
  through a fixed open-addressing table matched byte for byte (case kept, no allocation); a record with the owner of
  the previous one points to it without a lookup, as Unbound does (TXT answer 367 → 170 ns). Truncation stops at the
  first record that does not fit; TC only when answer or authority lost records; a cut additional RRset goes whole,
  since without TC a partial RRset passes for complete (RFC 2181 §9); OPT is always kept and opens additional (RFC
  6891 §7). Header fields too large for their bits are an error, never masked. EDNS UDP payload 1232 (DNS Flag Day
  2020).
- D112 (amends D10) The encoder's name table is keyed on a hash of the whole suffix, not of the first label and the
  length, and bounds the work of a lookup. The hash is folded from the root, so each byte of a name is hashed once for
  all its suffixes; each step multiplies by a constant as wide as two registers and folds the halves, so no flipped
  bits cancel (`FxHash` steps do, for any seed), from a seed random for each process. A slot keeps an 8-bit tag of the
  hash beside its offset, a probe reads 8 tags in one word, and a name is compared with the written message only where
  a tag agrees, at most 4 times for a lookup: names picked to share a tag lose their own compression, not the
  encoder's time. Names are looked up longest suffix first for 8 suffixes, then by a binary search for the first one
  held: the table holds every suffix of a name it holds (past its 192 names the shortest stay; a name that crosses
  what a pointer reaches keeps the suffixes before it, and compresses less), so the encode of a name is O(L log L) in
  its length L. Why: the first table hashed the first label and the length, so names of a hostile upstream sharing
  both made a lookup compare with the whole run, and a name of 100 labels cost 100 lookups (`benchmarks.md`: ms
  against µs for 64 KiB). The seed alone does not stop collisions made for the hash function itself; the cap on
  comparisons bounds them whatever the hash, and the seed makes them hard to make. Costs: the hash of every suffix of
  a name, about +17% on the encode of an MX response (+50 ns), less on the others, and 256 bytes more to clear,
  paid where a response is stored or a plugin answers: a cache hit serves stored bytes, not encoded again (D21).
  Messages are the same but where a table fills. `Name`'s `Hash` (D7) stays: hashing label by label was slower.
  Rejected: names keyed by (label, offset of the rest) and looked up from the root (one probe for each shared label:
  `deep_hit` 3.5x worse, small encodes +23%); a table of 512 slots (small encodes 12-25% slower); a cap on the labels
  looked up (deep names stay uncompressed).
- D11 Typed RDATA: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA, SVCB, HTTPS, OPT, and the DNSSEC types of
  D70; others opaque until added. The other types with compressible names (RFC 3597 §4: MD MF MB MG MR
  MINFO, RP AFSDB RT SIG PX NXT NAPTR) are parsed by a field layout and kept opaque with their names
  expanded, so opaque data never holds a pointer.
- D12 (amended by D159) Typed EDNS options: cookie (RFC 7873), Extended DNS Error (RFC 8914), padding (RFC 7830), client subnet
  (RFC 7871), TCP keepalive (RFC 7828), NSID (RFC 5001). Typed SVCB keys: RFC 9460 keys 0-6 and dohpath (RFC
  9461). Others opaque. An opaque option (`UnknownOption::new`) refuses data that reads as its typed option, so
  an option has one form and equals itself read back.
- D13 (amended by D159, D162) Topic modules, RDATA and conformance tests by RFC (`crates/dedens-proto/AGENTS.md`). Rejected strict
  `rfcNNNN/` folders: names, the header and rcodes are each defined across several RFCs.
- D19 Codes (type, class, opcode, rcode, EDNS option, SVCB key) are newtypes with named constants, not enums
  with an `Unknown` arm: every value has one representation and a new code is one constant. `Record` has no
  type field: its RDATA gives the type, so they cannot disagree.
- D20 (superseded by D28) `MessageView`: a message read in place for the server's hot path (cache lookups,
  serving cached bytes with lower TTLs). One pass checks exactly what `Message::decode` checks (fuzzed against
  it) and stores two 16-bit offsets per entry in a `MessageIndex` sized once for the most entries a 65535-byte
  message holds (13104, 52 KB): never allocates, never trusts claimed counts. Gains: no allocation, O(1)
  access to any record, TTL offsets for rewriting a copy.
- D21 `Query`: a query read in place, without the D20 table: header, first question, `EdnsView`, violations;
  checks what `Message::decode` checks (fuzzed against it). `Edns::append` writes an OPT after a message
  already in a buffer, so the server adds EDNS to cached bytes without re-encoding.
- D28 (supersedes D20) `Record` keeps its RDATA as checked wire bytes with its type (`WireRdata`), borrowed from the message
  (names in it may point elsewhere there) or owned (no pointers); `Record::data()` reads the typed `RData` on
  demand. No hot path reads inside RDATA (the cache serves bytes, a forwarder checks then stores), so decode
  checks every RDATA (D9) and builds nothing; encode copies the bytes, except for the types whose names may be
  compressed (RFC 3597 §4), read and written again. Equality and hashing go through `RData`, so names in RDATA
  compare without case (RFC 4343). Replaces D20: with decoding into reused vectors (`decode_reusing`), one
  `Message` is as cheap as the view, and `ttl_offsets` gives the cache the TTL positions. Messages over
  65535 bytes are refused. Gain: one message type instead of two, at the same measured speed
  (`docs/benchmarks.md`); typed records were expected to explain the encode gap with Unbound and did not.
  Rejected: expanding compressed names at decode (one allocation per such record).
- D59 The fixed wire layouts, the header and the fields after a question's or a record's name, are `zerocopy`
  structs of big-endian byte-array fields (`network_endian::U16`), read in place with one bounds check
  (`Reader::fields`) and written with one copy. No `unsafe` of ours, no alignment need on the input. Measured
  in one session (`docs/benchmarks.md`): cache hit 3-8% faster, query read ~10%, decode and encode the same
  or a few % faster. Rejected: `#[repr(C, packed)]` native integers (a byte swap per read on little-endian
  CPUs anyway, references to fields refused, `unsafe` to cast the input); a `union` of RDATA (no tag, `unsafe`
  reads, and names, strings and lists cannot be laid over the wire: `RData` is that union with its tag, read
  on demand, D28); one `Reader::array::<N>` read per layout split into fields by hand, the same single bounds
  check without the crate: not measured, as the gains above are against the former six reads of one field each,
  so zerocopy is kept by owner decision, not by a measured gain over it. Names stay hand-parsed: their length
  varies and they may point elsewhere.
- D70 (amended by D159) DNSSEC RDATA, typed: DS and CDS (`Ds`), DNSKEY and CDNSKEY (`Dnskey`), RRSIG, NSEC, NSEC3, NSEC3PARAM
  (RFC 4034, 5155, 7344, 8078), one file per format (D13); a CDS is a `Ds` under its own `RData` arm, so the
  two cannot be mixed up. Types only: the validator's checks (digest length, key format, times, hash order)
  and canonical form are `dedens-dnssec`'s. Rules:
  - Invalid RDATA is kept opaque with a violation (D9), so a type has one form: a DNSKEY protocol other than
    3 (RFC 4034 §2.1.2); an empty DS digest, DNSKEY key, RRSIG signature or NSEC3 hash, which no text could
    write; a type bitmap that breaks RFC 4034 §4.1.2 (windows out of order, a window of 0 or over 32 bytes, a
    trailing zero byte). `TypeBitmap` holds the checked wire bytes, so a set of types has one value. The
    protocol is not stored: it is 3.
  - The RRSIG signer and the NSEC next name are read with `Name::decode_uncompressed`: a pointer makes the
    RDATA invalid and opaque (as the SVCB target, RFC 9460 §2.2), so `may_hold_compressed_names` stays false
    for them. Rejected: expanding the pointer (the signed bytes would change) and failing the message (one
    bad record would drop an answer; the validator reads an opaque RRSIG or NSEC as unusable).
  - `Rrsig::signed_rdata` is the RDATA without the signature, the signer as on the wire, case kept (RFC 4034
    §3.1.8.1); lowercasing for the canonical form is the validator's.
  - Text: algorithm, digest type and hash are bare numbers (D69), read as numbers or mnemonics. Digest in hex
    (any case read, lowercase written), key and signature in base64 (padded and canonical, as D12's `ech`),
    blanks allowed within both (RFC 4034 §5.3); NSEC3 salt in hex or `-`, next hashed owner in base32hex
    without padding (RFC 4648 §7, any case read, lowercase written, hand-written in `text/encoding.rs`);
    types as mnemonics or `TYPEn` in numeric order, read in any order. RRSIG times are written
    `YYYYMMDDHHmmSS` in UTC and read as that or as up to 10 digits (RFC 4034 §3.2), kept as the `u32` of the
    wire (a date past 2106-02-07 wraps, RFC 4034 §3.1.5; one before 1970 is refused). The delete forms
    (RFC 8078 §4) are read as the RFC writes them, `0 0 0 0` and `0 3 0 0`, and written `0 0 0 00` and
    `0 3 0 AA==`: the payload is one zero byte (`is_delete`), and a lone `0` means that nowhere else.
- D125 (builds on D28) Every typed RDATA fits 65535 bytes by construction (RFC 1035 §3.2.1: RDLENGTH is 16 bits): each
  constructor and decoder refuses a longer wire form (each holds a `MAX_RDATA_LEN` check; names are at most 255
  bytes; names expanded on decode are checked in `Opaque::decode_with`). A new `RData` type keeps this. So
  `Record::new` and `WireRdata::new` stay infallible, and `RData::with_wire`, which asserted it (audit L17), now
  debug-asserts it and in release hands `f` no bytes. The test `s3_2_1_typed_rdata_up_to_65535_bytes_makes_a_record`
  pins the boundary of each constructor with a long field (`Svcb::new` with the longest target included); it
  never reaches the changed line, and would have passed with the old `assert!`. Rejected: `Record::new` returning
  `Result` (about 25 callers, an error none can see); a release panic (a length no caller can act on).
- D139 (amends D7a; builds on D125) The typed `RData` is one table, `rdata_types!` at the top of `rdata/mod.rs`: a
  line a type, `Variant(payload) = RecordType constant, codec`, builds the enum and the six matches on it
  (`into_owned`, `rtype`, `decode_fields`, `encode`, `from_text`, `Display`). Why: `decode_fields` and `from_text` end
  in `_ =>` for the types outside the table (RFC 3597, kept), so a typed variant missing its arm there read as
  `Opaque` and compiled; only the type's own tests caught it. Now a variant exists with all its arms or not at all.
  The codec is the payload type or, for A, AAAA, NS, CNAME and PTR, the module of the type; it gives `decode`,
  `encode`, `from_text` and `into_owned`. Adding a type: its file with those four and `Display`, each constructor and
  decoder holding D125's `MAX_RDATA_LEN` check, a line in the table, the rest of `crates/dedens-proto/AGENTS.md`. Costs:
  cargo-mutants does not mutate code a macro generates, so the six matches are no longer mutated; the text errors of
  NS, CNAME and PTR say "domain name", not "NS name", "CNAME target", "PTR name". Kept because it deletes 49
  lines (+142, -191: the table and the macro against the enum and the matches, with `from_text` and `into_owned` added
  to three codecs); the `message` and `zone` benches move within their spread, so `benchmarks.md` is unchanged.
  Rejected: a test that every type of the fuzzing seed reads typed from its text and from the wire (+32 lines, built
  and run against the removed arm): it fails on a missing arm only for a type whose seed line exists, where the table
  needs no line to be right.
- D159 (amends D12, D13, D70; amended by D162) An RDATA or EDNS option file is named after its type
  (`rdata/srv.rs`, `edns/cookie.rs`), not its RFC; the RFC and section go on each public item's doc, where `cargo doc` and a reader of the item see
  them. Why: a file name held one RFC, while SVCB, the DNSSEC types and the options each span several, and 13
  public items cited none. A codec of a few lines with no type of its own is inlined where it is used: A, AAAA
  and the one-name types (NS, CNAME, PTR) as modules in `rdata/mod.rs` beside the `rdata_types!` table (D139),
  NSID, keepalive and padding as arms of `EdnsOption`'s decode and encode. Tests were then one file per RFC,
  `tests/rfcNNNN.rs`; topic modules since D162. Behaviour is unchanged. Rejected: keeping the RFC prefix (`rfc2782_srv.rs`): it sorts the
  files by RFC number, which no reader looks for.
