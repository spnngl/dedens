# Decisions

Each decision: the choice, its reason, the alternatives rejected. A number is never reused: a replaced decision is
marked superseded. Measurements: [`benchmarks.md`](benchmarks.md). Open questions: [`TODECIDE.md`](TODECIDE.md).

## Scope

- D1 Crates per [`ARCHITECTURE.md`](../ARCHITECTURE.md), all on `dedens-proto`. CLI and server are separate
  binaries.
- D2 (amended by D60) Order: unencrypted core DNS first (wire format, UDP, TCP), then DNSSEC and encrypted transports (DoT, DoH,
  DoQ). A stub resolver and CLI first; forwarder, recursive and authoritative servers follow.
- D3 Own wire format, for full control of RFC behaviour and speed. hickory-dns and NLnet Labs' `domain` are
  reference code only.
- D4 Runtime: compio, features `io-uring` and `polling`: io_uring on Linux, polling at runtime where io_uring
  is blocked (containers, seccomp), kqueue on macOS, rustls and QUIC ready. Rejected: tokio-uring (dead since
  2024-05), monoio (5 commits a year), glommio (dead since 2025-04), tokio's `io-uring` feature (files only), raw
  `io-uring` (we would write a runtime). Fallback: tokio. Risk: compio is 0.x, contained by D5.
- D5 `dedens-proto` is sans-IO, so a runtime change touches one crate and the server reuses the codec as is.
- D6 Linux and macOS. Stable pinned in `rust-toolchain.toml` and bumped by Renovate, so new lints arrive as a
  PR, not a red CI; MSRV 1.95. One nightly pinned by date in the justfile, bumped by hand with RAPx, for
  rustfmt, `-Z` flags and RAPx only: an unpinned nightly reformats code on its own.
- D69 (amends D2) DNSSEC comes before the recursive resolver, as a validating stub and forwarder: `dedens`
  and `dedensd`'s forward stage validate the answers of an upstream they do not trust to have validated, and
  only the validator's verdict (secure, insecure, bogus, indeterminate) reaches the cache and the reply. The
  code is `dedens-dnssec`, sans-IO, the clock passed in. ODoH (RFC 9230) and DoC (RFC 9953) are experimental:
  `dedens-odoh` and the `odoh` and `doc` Cargo features, off by default and forwarded from `dedens-net` to
  both binaries, so a default build carries neither (`just check` builds with all features). Text forms: the
  DNSSEC record types print as their mnemonic and parse from it or from `TYPEn` (RFC 3597); algorithm,
  digest and NSEC3 hash numbers (`SecAlgorithm`, `DigestType`, `Nsec3HashAlgorithm`) print as their IANA
  mnemonic and parse from it or from the bare number, which zone text writes. Open questions this phase
  leaves: [`TODECIDE.md`](TODECIDE.md). Steps: `plan/4-dnssec-experimental/`.
- D71 (amends D69) DNSSEC crypto is `dedens_dnssec::crypto` on `ring`, which is already in the lock through
  rustls, and `data-encoding` for test and bench data. Policy, after RFC 9904 §3 and RFC 6840 §5.2: validated
  are RSASHA1 and its NSEC3 alias (5, 7), RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13),
  ECDSAP384SHA384 (14), Ed25519 (15); DS digests SHA-1, SHA-256, SHA-384 (1, 2, 4). Unsupported, so the zone or
  delegation is insecure (EDE 1 and 2): RSAMD5, DSA (1, 3, 6), GOST (12, DS digest 3), Ed448 (16, `ring` has
  none), GOST 2012 (23), SM3 (DS 6), private and unknown codes. SHA-1 signatures stay validated, as RFC 9905 §2
  tells implementations, though it tells operators to treat them as unsupported: too many signed zones still
  use them (README item 3); [`TODECIDE.md`](TODECIDE.md) holds the switch. RSA keys: RFC 3110 §2, modulus 1024
  to 4096 bits (`ring`'s `_1024_8192` variants, capped at RFC 3110 §2's 4096 where ring allows 8192), exponent
  odd, 3 to 2^33 (`ring`'s bounds); anything else, the 512-bit keys of RFC 5155 Appendix A and RFC 5702 §6.1
  included, is an unusable key. Accepted deviation from RFC 3110 §2: the reader takes leading zeros in the
  exponent and in the modulus, and a three-octet exponent length where the exponent is short, as the zones in
  the wild publish such keys and `ring` takes the key all the same.
  `ring` does not tell a refused key from a bad signature: an ECDSA point off the curve and an Ed25519 key that
  is no curve point are reported as a bad signature (tested). A bad signature is therefore not proof of a
  forged answer, and an unusable key is the verdict of the validator (step 04), not of `crypto`: a key no
  signature can use is no key, so the algorithm counts as unsupported and the data as unsigned for it (RFC 6840
  §5.2), and `supported` tells that case from a refusal of the algorithm. `Budget` bounds the work of one
  validation, spent before each `verify` and `nsec3_hash` by the caller: 64 signature verifications and 8192
  NSEC3 hashes (`iterations + 1` per name). Sized from `benchmarks.md`: 64 verifications cost at most 22 ms
  (P-384, the slowest) where a chain of five zones needs about 20; 8192 hashes are 0.75 ms and cover 54 names
  at 150 iterations, where a denial proof hashes about a dozen. An exhausted counter stays exhausted; the
  caller picks the verdict (RFC 9276 §3.2: insecure or SERVFAIL for NSEC3; bogus for signatures, as the
  KeyTrap guidance has it), `crypto` only refuses. Signature examples are verified here from signed data built
  by hand from the RFC text in `tests/common/mod.rs`, test-only; `verify`, `key_tag`, `ds_digest` and
  `nsec3_hash` have the fuzz target `dnssec_crypto`. Rejected: aws-lc-rs (a C build, a second backend beside
  rustls's), RustCrypto crates (more dependencies for what `ring` does; Ed448 alone would justify one, see
  TODECIDE), a `Budget` of wall-clock time (not reproducible, and the clock is passed in, D69).
- D72 Trust anchors are `dedens_dnssec::anchor::TrustAnchors`: DS or DNSKEY records per zone (RFC 4035 §4.4),
  and negative trust anchors (RFC 7646). The root's are bundled as `crates/dedens-dnssec/src/root.ds`, DS text
  that `just root-anchors` writes from IANA's `root-anchors.xml`: the `KeyDigest` entries valid at that moment
  (RFC 9718 §2.2), by an awk script, as the file is flat and a Rust XML parser would be a dependency for one
  file. The CMS signature of §3.2 is not checked: the file and its `.p7s` come from the same site, so the
  check proves nothing the HTTPS fetch does not; the test is that every bundled DS matches a key of the
  captured root DNSKEY RRset (`tests/rfc9718.rs`), and the key tags are the two of RFC 9718 §2.2. A user's
  anchors are zone text read by `ZoneReader` (the parser the fuzz targets already feed, so no new target), as
  Unbound's `trust-anchor-file`: absolute owners, class IN only, TTL defaulted to 0, DS and DNSKEY only (a CDS
  or CDNSKEY is not an anchor), no `$INCLUDE` (the library reads no file), at least one record (an empty set
  would call every answer insecure). Each error names its line (`ZoneReader::line` was added to `dedens-proto`
  for it). An NTA lives on `TrustAnchors`, `negative(name)` being true at and below it unless a deeper positive
  anchor restarts validation (RFC 7646 §1.1's example); at the same depth the NTA wins, as the operator added
  it to override. An NTA has no end time, though RFC 7646 §2.1 asks implementations to allow one: it lasts as
  long as the value does, and the caller drops it by building the anchors anew; [`TODECIDE.md`](TODECIDE.md)
  holds the rest. Anchors are fixed while running: RFC 5011 stays in TODECIDE.
- D73 (amends D71) `dedens_dnssec::rrsig` authenticates one `RRset` and one DNSKEY `RRset`, sans-IO; chain walking
  and denial are 05 and 06. `RrSet::group` builds `RRset`s from a section (owner, class, type; RFC 2181 §5.2:
  TTL the minimum); `Signature` and `Key` borrow the RRSIG and DNSKEY records of an `RRset`, a DNSKEY whose
  protocol is not 3 being opaque, so never a `Key`. `verify(rrset, sig, key, now, budget)` checks RFC 4035 §5.3.1
  in this order, the cheap checks first and nothing allocated before they pass: coverage (owner, class, type);
  the signer at or above the owner, and not the owner for a DS (it belongs to the parent, RFC 4035 §2.4: the
  child's own signature on it is the child vouching for itself) and the owner for a DNSKEY (§5.2); the labels
  field neither above the owner's count (a leading `*` not counted) nor below the signer's (the expansion of a
  wildcard of a zone above the signer's); algorithm supported; the key is the signer's, of the algorithm and
  key tag; REVOKE (RFC 5011 §7); zone key bit; the validity window in serial arithmetic (RFC 1982; edges
  inclusive, no skew, `now` is Unix seconds truncated to 32 bits); then one `Budget` verification and the
  signature. The kept TTL is the least of the `RRset`'s, the RRSIG record's, the original TTL and the seconds to
  expiration (RFC 4035 §5.3.3). A wildcard expansion (labels below the owner's) is verified against `*.` and the
  rightmost labels, and `Verified::wildcard` returns the closest encloser; `Verified` is `must_use`, because a
  wildcard answer proves nothing about the absence of a closer name, which 06 asks 05 to prove (RFC 4035
  §5.3.4). Zone cuts are the caller's (06): `verify` knows the signer is above the owner, not that its DNSKEY
  `RRset` is of the zone that holds the `RRset`; the caller picks the keys of the parent for a DS, of the child
  for its apex DNSKEY, and of the zone below which the owner is not delegated further for the rest (a NS
  `RRset` or glue under a cut is not signed by the child, RFC 4035 §2.2). `verify_any` tries every covering
  RRSIG against every key of its signer, key tag and algorithm, and stops at the first success (RFC 6840 §5.4:
  one valid RRSIG is enough, the others disregarded). An RRSIG whose algorithm is not supported is disregarded
  whatever the keys (RFC 6840 §5.12), and so is the key no signature can use (D71, the 512-bit RSA key):
  `verify_any` never says "unsupported". Which algorithms a zone is signed with is for its DS records (RFC 4035
  §5.2, RFC 6840 §5.11), so only `trusted_keys` can find a zone insecure; otherwise one forged RRSIG of an
  unknown algorithm beside a forged answer would downgrade a signed zone to insecure. This replaces D71's
  "an unusable key makes the algorithm unsigned" for RRsets: an `RRset` whose RRSIGs are all disregarded is
  `NoSignature`, bogus once its zone is known to be signed; a DS or DNSKEY of an unsupported algorithm is what
  makes it insecure. A pair tried by `verify` alone still says `UnsupportedAlgorithm`. KeyTrap: at most 8
  failures per `RRset` (`MAX_FAILED`, as Unbound's `MAX_VALIDATE_RRSIGS`), counting every RRSIG or RRSIG and key
  pair that fails for whatever reason, cheap or costly, but the lack of a key (an RRSIG without a key costs
  nothing and a zone may sign with keys we were not given); then `TooManyFailures`. The canonical RDATA is built
  once per `RRset` and the owner and signed data once per RRSIG, not per pair. The shared `Budget` of D71
  bounds the whole validation, its exhaustion its own error, bogus (the KeyTrap guidance). With none
  succeeding the error returned is the closest to a success, in `SigError::rank` order. `trusted_keys(dnskeys,
  sigs, ds, now, budget)` counts the DS records whose digest type and algorithm are supported (else
  `UnsupportedDigest` or `UnsupportedAlgorithm` when none counts, which `SigError::is_unsupported` tells: the
  zone is insecure, RFC 4035 §5.2, RFC 6840 §5.2), ignores a SHA-1 DS where a stronger digest of the same key
  (key tag and algorithm) is present (RFC 4509 §3: of the key, not of the `RRset`, so a SHA-1 DS of another key
  still counts), indexes the DS records by key tag and algorithm once, matches each DNSKEY by digest against
  those of its tag and algorithm only, and requires the DNSKEY `RRset` to verify by one of those keys (RFC 4035
  §5.2). A zone can publish many keys of one tag before its `RRset` is authenticated, so more than 8 keys that
  match a tag and no digest are `TooManyFailures`; a DS that matches no key is `NoKeyForDs`, bogus. Every
  `SigError` maps to one EDE code (RFC 8914 §4) through `SigError::ede(&RrSet)`, whose text names the `RRset`
  and the key tag: 1, 2, 6, 7, 8, 9 (missing and revoked keys), 10, 11, 25. Canonical form (RFC 4034 §6, RFC
  6840 §5.1) lowercases the owner and the names in the RDATA of the types of RFC 4034 §6.2 (NSEC's next name
  apart, the RRSIG's signer included; A6 left out, historic, RFC 6563), sorts the RDATA as unsigned bytes and
  drops duplicates (§6.3). The name layouts are a table in `rrsig/canonical.rs`, not those of `RData::Opaque`:
  that list says where compression pointers may occur (RFC 3597 §4), and DNAME and KX are not in it.
  `WireRdata::wire` (`dedens-proto`) returns the RDATA uncompressed for it. Tests: RFC examples and the 00b
  captures, every signed `RRset` of them verifies, and fails 1 s after expiration, 1 s before inception and
  with a byte of RDATA flipped (`tests/captured_rrsig.rs`); `benchmarks.md` has the cost of a whole `verify`;
  the fuzz target `rrsig_verify` runs the grouping, `verify_any` and `trusted_keys` over the records of any
  message and asserts that no input makes data insecure. RFC 8080 §6.1's Ed25519 RRSIG says 3 labels for
  `example.com.`, which has 2: as an `RRset` it is `BadLabels` (RFC 4035 §5.3.1), and `crypto` checks the
  signature over its bytes (`tests/rfc8080.rs`).
- D74 (amends D69) Denial of existence is `dedens_dnssec::denial`, pure set logic over NSEC and NSEC3 records the
  caller verified, each signed by the zone's `apex` (step 06 checks; this trusts them and the module docs list what
  it owes). `prove` answers a question that got a name error, no data or a referral, `prove_wildcard_answer` one
  that got a wildcard expansion (the RRSIG's label count gives the next closer name); the result is a `Fact`
  (`NameError { compact }`, `NoData`, `WildcardNoData`, `WildcardAnswer`, `InsecureDelegation`) with the TTL of the
  proof, the least of the records used (RFC 9077 §3), or an `Unproven` reason: the caller picks the verdict, as for
  `Budget` (D71). A DS question's `NoData` is the parent's: an NSEC or NSEC3 with SOA is the child's and proves
  nothing of the delegation (`FromChildApex`, RFC 4035 §5.2, RFC 6840 §4.4), and NS without DS and SOA, or an
  opt-out span, is `InsecureDelegation`, which is also the proof of a referral to an unsigned child (RFC 5155
  §8.9). Per RFC 6840 §4.1 an NSEC or NSEC3 at a delegation proves no name below it nor a type at its owner but
  DS, and one with DNAME proves no name below its owner. The CNAME bit counts in every no data (§4.3). NSEC3
  records are used when the response has usable ones (SHA-1, flags 0 or 1, owner one 32-digit base32hex label below
  the apex), NSEC otherwise; the records of more than one parameter set (iterations, salt) are
  `ConflictingNsec3Parameters`, for the caller to make bogus (RFC 5155 §8.2 allows it; no order of records picks
  the set). `Name` has no order: canonical order (RFC 4034 §6.1) is private to `denial`. NSEC3 hashes are paid from
  the `Budget`, one per name a proof tries, none kept between calls. Iterations above `MaxIterations`, default 150
  as Unbound and BIND (RFC 9276 §3.2 recommends 0 but tells validators to accept some; the limit is a parameter),
  are `IterationsAboveLimit` in any record's set, refused before any hashing: the response is insecure, with EDE 27
  (`info_code`). Compact denial (RFC 9824): an NSEC or NSEC3 matching the name with NXNAME in its bitmap is a
  `NameError { compact: true }` for any type, so 06 and 08 tell it from an NXDOMAIN (the response is NOERROR,
  §3.3); NXNAME is never a question to answer, `NxnameQuery` carries EDE 30 (§3.5). A proof over a next closer
  name that an opt-out NSEC3 covers is `Proof::opt_out` (RFC 5155 §9.2: the name may be an unsigned delegation, so
  no AD; Unbound does the same): set for a name error, wildcard no data and wildcard answer, never for a name the
  records match. A DS question whose next closer name is in an opt-out span is an `InsecureDelegation` even when the
  response also proves the wildcard absent. Tests: RFC 4035 Appendix B (the Appendix A zone, in `tests/zones/`), RFC
  5155 Appendix B, RFC 6840 §4, RFC 9276, RFC 9824, and every negative capture of `tests/testdata/`; the proptests
  check that against a whole NSEC or NSEC3 chain each name or hash is matched or covered by exactly one record. Fuzz
  target `denial`: any records and question through `prove` and `prove_wildcard_answer` under every ancestor of the
  name as the apex.
- D75 (amends D69) The validator is `dedens_dnssec::validator`, sans-IO: `Validator::new(TrustAnchors, Limits)` (shared,
  `Clone`, `Send + Sync`) and `start(question, response, now) -> Validation` for the final answer to a question,
  `start_referral` for a referral. The caller drives a `Validation`: `step()` is `Next::Ask(question)`, to send with
  RD, DO and CD set (RFC 6840 §5.9) and give back with `answer(Some(response))` or `answer(None)` (a failed query),
  or `Next::Done(Verdict)`. `step`, not `next`, and `now` once at `start`, not per call (the plan's sketch): a
  validation is one instant, so a chain cannot straddle a signature's expiry, and `Iterator::next` would mislead.
  `now` is `u64` Unix seconds, as the cache and the pipeline count seconds from any origin; the signatures take it
  modulo 2^32 (RFC 4034 §3.1.5, serial arithmetic, D73). A response that is no complete answer to the question (not
  its one question, in class IN, TC set) is `Indeterminate` at once, as an answer to one of the validator's own
  questions is, which also makes a truncated DS or DNSKEY answer indeterminate, never bogus (RFC 1035 §4.1.1).
  `Verdict` is RFC 4035 §4.3 with two more: `Secure { ttl }`, `Incomplete { next, ttl }`, `Referral { child,
  delegation }`, `Insecure { reason }`, `Bogus { ede }`, `Indeterminate { ede }`; `ede()` the code and text to attach
  (RFC 8914), the text of an insecure reason included.
  What Secure covers: every `RRset` of class IN in the answer and the authority section is authentic (RFC 4035
  §3.2.3, RFC 6840 §5.8), what the response lacks is proven absent, and the rcode agrees with the proof (a name error
  is NXDOMAIN, or NOERROR when compact, RFC 9824; no data is NOERROR; NXDOMAIN with an answer is bogus). It does not
  cover the additional section, other classes, or the unsigned CNAME a DNAME synthesizes (RFC 6672 §5.3.3), which the
  caller strips or never relies on, and it is not the AD bit: the upstream's AD is never read, and the caller sets AD
  from `Secure` alone. A CNAME chain that stops before the type asked, with no denial, is authentic as far as it
  goes: `Incomplete`, the caller chases `next`, and it is never AD. A referral is no answer: judged as the final
  answer it is bogus (its NS records are unsigned, nothing denies the type) or insecure, so a forged referral has
  no way to secure; `start_referral` judges only the delegation, by the DS records of the child or their proven
  absence, and says `Referral` with `Signed` or `Unsigned { reason }`, never `Secure`, so no TTL and no AD come of
  it. A referral that answers one of the validator's DS questions is read as any DS answer: its DS or its
  proof, else bogus.
  The chain of trust is walked top-down from the closest anchor to the owner of each `RRset` (the name asked for a
  DS, the parent's apex): the DS of each label, then where there is a zone its DNSKEY (RFC 4035 §5.2). The walk
  goes to the owner (RFC 4035 §5.3.1), never to the signer a signature names, so a rewritten signer cannot pick
  the keys, an `RRset` signed by an ancestor's keys is bogus, every RRSIG is tried (a junk one first costs
  nothing) and a forged signer cannot turn bogus into insecure. It costs one DS question per label
  below the last zone, which the key cache of 06b pays once. A DS RRset is verified by the parent's keys and then
  vouches for the DNSKEY RRset (`trusted_keys`); no DS is the parent's NSEC or NSEC3 proof (D74): an insecure
  delegation (insecure, `UnsignedDelegation`), or no cut (the name is in the parent's zone). A DS question at a
  name that is a CNAME (or below a DNAME, or a wildcard CNAME) gets the CNAME: if it verifies, the name is no cut.
  Data below an insecure zone, at or below a negative anchor (D72, RFC 7646 §2, nothing asked), or with no anchor
  above it, is insecure. Unsigned in a secure zone, or in a zone the keys of which are not its owner's, is bogus
  (EDE 10, 6); every NSEC, NSEC3 and SOA of the authority section must verify, or the response is bogus. A wildcard
  expansion also needs the no-closer proof of `prove_wildcard_answer`, else bogus (RFC 4035 §5.3.4). An opt-out
  proof, in a denial, a wildcard answer or the DS of a delegation, is insecure, `OptOut`, never secure (RFC 5155
  §9.2): `tests/testdata/README.md` says so of `google_com_ds`, `edgekey_net_ds`, `nxdomain_nsec3_optout` and
  `nxdomain_nsec3_salt`. Only verified NSEC and NSEC3 records signed by the zone reach `denial`. A negative proof
  lasts at most three hours and the SOA's TTL and MINIMUM (RFC 9077 §3.4), and the keys' TTL. Failures: a
  signature or DS that fails is bogus with `SigError::ede`; a DS no key matches, bogus with EDE 9; an unsupported
  algorithm or digest in a DS is insecure with EDE 1 or 2 (D71, RFC 6840 §5.2; RRSIGs of unknown algorithms are
  disregarded, D73); NSEC3 iterations above `Limits::iterations` (`MaxIterations`, default 150, D74) are insecure
  with EDE 27; `ConflictingNsec3Parameters`, a missing or contradictory proof and any other `Unproven` are bogus
  (EDE 12, 6); an exhausted `Budget` (D71, shared by the whole validation) is bogus, not insecure, since insecure
  would let a forger downgrade by spending it. Other limits are `Indeterminate`: more than `Limits::questions` (32)
  questions, a name more than `Limits::depth` (32) labels below its anchor (counted from the anchor, so the order of
  the questions changes nothing; EDE 5), a question the caller could not answer (EDE 22), a response with an
  rcode but NOERROR and NXDOMAIN (EDE 5), NXNAME asked (EDE 30). Each zone's outcome (secure keys with their TTL,
  insecure, bogus) is written by one private function, `settle`, and read by one other, `zone_of`; delegations are
  not cached apart from them and an indeterminate outcome is never written, so 06b's cache goes there and holds
  only what the data decides. Not done: the SHA-1 switch (TODECIDE: it needs a filter in `rrsig`); an opt-out
  wildcard answer is untested against a capture, none exists. Tests: `tests/validator.rs`, a scripted caller that
  answers from the captures at `captured_at`: every capture with the verdict of its README, forged referrals,
  signers, rcodes, authority records, CNAME and DNAME hops, DS denials, mixed-case names, truncation. Fuzz target
  `validate`: any bytes as the response, its questions answered from the captured chains, whole, cut or with a bit
  flipped; seeded by the captures.

## Wire format

- D7 `Name<'a>`: wire-form bytes, case kept, compared and hashed ASCII case-insensitively (RFC 4343); built only
  through validating constructors. Private representation: a slice of the input without pointers, input plus
  offset with pointers (labels read on demand, pointers checked once), or owned bytes. Rejected: a 255-byte
  inline buffer (about 300 bytes per record); copying compressed names at decode (the allocation borrowing
  removes).
- D7a Decoding borrows: one set of types with a lifetime, `Message<'static>` is the owned form (`into_owned()`
  or built by hand). Variable-length values (TXT, SVCB parameters, CAA, opaque RDATA, EDNS options) stay as
  checked wire bytes read through accessors, so they keep their invariants. Rejected: a borrowed view beside
  the owned types (every RDATA type twice); a lazy message (errors at every access).
- D8 `Message`: header, questions, answer, authority, additional, and EDNS lifted out of additional, so no
  caller searches for the OPT record.
- D9 Decoder: a compression pointer points strictly before the current label (no loops), past the header, to
  labels ending before the bytes that point to them (a prior name, RFC 1035 §4.1.4), at most 127 per name
  (no long chains); unknown types are opaque (RFC 3597); every input decodes or errors (fuzzed). Broken structure
  is an error. A readable message breaking a rule (several OPT, OPT outside additional or not at the root,
  QDCOUNT > 1 per RFC 9619, trailing bytes) decodes with violations: the CLI shows them, the server answers
  FORMERR. Well-delimited but invalid RDATA or EDNS option is kept opaque with a violation, so typed values
  always hold their invariants; except in types whose names may be compressed (RFC 3597 §4), where it is an
  error, since their pointers mean nothing outside the message.
- D10 Encoder: into a caller buffer with a size limit, no allocation (fits io_uring registered buffers), plus a
  `Vec` convenience. Compresses names only in RFC 1035 types (RFC 3597 §4), never into the header, through a fixed
  open-addressing table matched byte for byte (case kept, no allocation); a record with the owner of the previous
  one points to it without a lookup, as Unbound does (TXT answer 367 → 170 ns). Truncation stops at the first
  record that does not fit; TC only when answer or authority lost records; a cut additional RRset goes whole, since
  without TC a partial RRset passes for complete (RFC 2181 §9); OPT is always kept and opens additional (RFC 6891
  §7). Header fields too large for their bits are an error, never masked. EDNS UDP payload 1232 (DNS Flag Day
  2020).
- D11 Typed RDATA: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA, SVCB, HTTPS, OPT, and the DNSSEC types of
  D70; others opaque until added. The other types with compressible names (RFC 3597 §4: MD MF MB MG MR
  MINFO, RP AFSDB RT SIG PX NXT NAPTR) are parsed by a field layout and kept opaque with their names
  expanded, so opaque data never holds a pointer.
- D12 Typed EDNS options: cookie (RFC 7873), Extended DNS Error (RFC 8914), padding (RFC 7830), client subnet
  (RFC 7871), TCP keepalive (RFC 7828), NSID (RFC 5001). Typed SVCB keys: RFC 9460 keys 0-6 and dohpath (RFC
  9461). Others opaque. An opaque option (`UnknownOption::new`) refuses data that reads as its typed option, so
  an option has one form and equals itself read back.
- D13 Topic modules, RDATA and conformance tests by RFC (`crates/dedens-proto/AGENTS.md`). Rejected strict
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
- D28 `Record` keeps its RDATA as checked wire bytes with its type (`WireRdata`), borrowed from the message
  (names in it may point elsewhere there) or owned (no pointers); `Record::data()` reads the typed `RData` on
  demand. No hot path reads inside RDATA (the cache serves bytes, a forwarder checks then stores), so decode
  checks every RDATA (D9) and builds nothing; encode copies the bytes, except for the types whose names may be
  compressed (RFC 3597 §4), read and written again. Equality and hashing go through `RData`, so names in RDATA
  compare without case (RFC 4343). Replaces D20: with decoding into reused vectors (`decode_reusing`), one
  `Message` is as cheap as the view, and `message::ttl_offsets` gives the cache the TTL positions. Messages over
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
- D70 DNSSEC RDATA, typed: DS and CDS (`Ds`), DNSKEY and CDNSKEY (`Dnskey`), RRSIG, NSEC, NSEC3, NSEC3PARAM
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

## Transports

- D26 `dedens-net` splits like `dedens-proto`: a sans-IO client core (retries, response matching, TC fallback,
  EDNS fallback, cookies) fed bytes and time, so tests drive drops, delays and forged replies exactly without a
  server; a thin compio layer moves the bytes, tested over loopback only. Public at both levels: `Client` for
  the whole exchange, and the UDP and TCP exchanges for callers that pick the transport (`+tcp`, the
  forwarder). Rejected: an in-process test server (slower, less exact), real servers in CI (cannot forge a
  wrong ID or a drop). compio 0.19.2 until 0.20 is released.
- D27 (amended by D50, D53) Client behaviour:
  - UDP: a pool of sockets per server (D50); a random ID from `getrandom`, drawn 256 bytes at a time: a call costs
    846 ns on macOS, 14 ns on Linux (vDSO).
  - Matching: source address, ID and question (case-insensitive) or the datagram is dropped and the wait goes
    on, as hickory and Unbound do; miekg/dns fails on a wrong ID and CoreDNS checks the ID only. `0x20` case
    randomization of the question is an option, off by default as in Unbound.
  - dig's defaults: 3 tries, 5 s each. TC over UDP is retried over TCP. EDNS is dropped once on FORMERR or
    NOTIMP to an EDNS query (RFC 6891 §7), never on a timeout (RFC 8906); `+noednsneg` turns it off. A query
    changed by a fallback goes with the next ID, so a late response to the query before cannot end the exchange.
  - Cookies (RFC 7873 §5): the client cookie drawn from `getrandom` once per pair of source and server
    addresses, a memoized random function of both as §4.1 asks, without a hash to pick; server cookies kept
    per server for the life of the client, including the fresh one of a BADCOOKIE; BADCOOKIE retried with it
    over UDP, then over TCP (§5.3).
  - TCP (RFC 7766): one connection per server, queries pipelined and matched by ID in any order, each under an
    ID free on the connection (§6.2.1), the caller's put back in the response; the ID of a query that stopped
    waiting stays taken until its response comes. Idle close; edns-tcp-keepalive sent empty in TCP queries only
    and its timeout honoured when shorter, 0 taking no new query (RFC 7828); a closed
    connection retried once on a new one, as is one whose IDs are all taken. Queries are written whole by a task of
    the connection, so a query that stops waiting never cuts a message short; those queued meanwhile go in one
    write (D53). A write lasts the idle time at most, and a query that times out with nothing read on its
    connection since it was sent closes it: a server that stopped reading or answering is replaced. A connection
    that cannot open fails each query waiting for it with its error. A connection slower than a try, waited for
    the source address of a cookie, costs that try, not the exchange.
- D31 The sans-IO exchange (`dedens-net::exchange`) takes the query whole from the caller, ID and cookie in
  it, and owns no randomness or secret; `0x20` takes its random bits as an option, which also turns on the
  exact-case match, so a randomized question is never matched loosely. Each step consumes the `Exchange`
  and returns `Send`, `Wait` or `Done`: a finished exchange cannot be fed. Only timeouts spend tries, and tries lost to a socket error or a slow connection; the TC,
  EDNS and cookie fallbacks each happen a bounded number of times. Stricter than dig: FORMERR and NOTIMP
  alone may leave the question out; once a server has sent a cookie, a response without one is dropped, even
  without OPT (RFC 7873 §5.3 MUST), at the price of timeouts if that server loses cookie support mid-process.
- D68 (amends D31) An exchange that runs out of tries after dropping a response for its cookie fails as
  `Forged`, not `TimedOut`: "no response after N queries, responses with a wrong cookie dropped (RFC 7873
  §5.3)", so a packet cache answering with an earlier client's cookie is told from silence (UncensoredDNS,
  D67). Exit code 9, as a timeout (D33).
- D60 (amends D2) Encrypted transports come before DNSSEC: DoT, then DoQ and DoH, each in the client and CLI
  first, then in `dedensd`. DoT (RFC 7858) is D27's TCP connection with a TLS session on it: one pipelined
  connection per server, the same idle, keepalive and retry rules. The TLS stream splits into halves locked only
  while polled (futures-util); compio's split holds its lock across a read and would stall the writer. rustls
  with ring, already in the lock through ureq; TLS 1.2 and 1.3 (RFC 8310 §9); ALPN `dot` (RFC 9461 §4.1).
  - Strict privacy profile by default (RFC 8310 §6.6): the OS trust store (`rustls-platform-verifier`, as D57),
    and the certificate must hold the name after `#`, else the host name given, else the address (§8.1).
    `--tls-ca=FILE` trusts the authorities of a PEM file instead; `--tls-insecure` any certificate, for tests.
    Rejected: dig's default, which verifies nothing without `+tls-ca`.
  - Queries over TLS are padded to a multiple of 128 bytes (RFC 8467 §4.1); padding the caller set is replaced.
    Replies to a padded query over TLS or QUIC are padded to a multiple of 468 bytes, with zeros, though the
    reply buffer is reused (RFC 7830 §3-4).
    The CLI refuses `+noedns` over TLS or QUIC, which would leave a query unpadded.
  - The CLI writes a TLS server `tls://HOST[:PORT][#NAME]`, or any server with `+tls`; port 853 unless given. An
    address, `[ADDRESS]:PORT` or with its zone, is taken as such before any name; a name for TLS is made only
    over TLS or QUIC.
  - Tests make their certificates with rcgen at run time, so no private key is checked in.
- D61 DoQ (RFC 9250) goes through compio's QUIC (`compio-quic`, quinn-proto underneath), no QUIC of our own.
  One connection per server and certificate name, opened on first use: queries meanwhile wait for it instead of
  opening another. Each query goes alone on its own bidirectional stream, behind its length, with ID 0
  (§4.2.1) and no cookie, since QUIC checks the client's address itself. The connection closes after D27's idle
  time (§4.4) and is opened again on the next query; a query on a reused connection found closed goes again once
  on a new one, as D27's TCP. A query given up is cancelled with STOP_SENDING and RESET_STREAM (§4.3.1). A
  response is read up to its 2 + 65535 bytes, a longer stream being a protocol error; the server may open no
  stream (§4.3.3), the client allowing none.
  - TLS 1.3 only (RFC 9001 §4.2), ALPN `doq`, the same trust as D60 (strict profile). No 0-RTT, early data off: a query waits for
    the handshake, since one in early data could be replayed (§4.5).
  - Queries are padded as over TLS (§5.4), and carry no edns-tcp-keepalive (§5.5.2).
  - The CLI writes a QUIC server `quic://HOST[:PORT][#NAME]`, or any server with `+quic`; UDP port 853 unless
    given.
- D62 (amended by D82, D83) DoH (RFC 8484) waits for compio to release tokio's I/O traits on its streams (the `h2`
  crate needs them; draft on branch `feat/io-tokio-compat` of compio); no adapter of our own meanwhile.
  ~~HTTP/3 waits for compio too.~~ Queries go by GET by default, ID 0 so HTTP caches can keep them (§4.1), and
  by POST with `+https-post`, as dig.
- D82 (amends D62) DoH goes over HTTP/3 first, on compio's released `h3` feature (compio 0.19.2,
  `compio-quic/h3`, the `h3` crate 0.0.8) over the QUIC connection of D61; HTTP/2 follows when a compio release
  carries the `tokio::io` traits, as D62 says. `h3` calls itself "very experimental" and is pre-1.0 (API may
  change, bugs possible); accepted because compio's QUIC is the only QUIC we have (D61), HTTP/3 over it costs no
  adapter, and it sits behind `Transport::Https`, so replacing it touches one module. Rejected: our own HTTP/3
  (a protocol of its own to fuzz and keep), waiting for HTTP/2 (blocks DoH and ODoH on a compio release).
  The core is sans-IO like D26 and knows no HTTP version: `dedens-net::doh` makes and reads `http` types
  (`http` is a workspace dependency), so HTTP/3 and HTTP/2 carry the same code, for the client, `dedensd` and ODoH.
  - `Transport::Https`: the whole message, up to 65535 bytes, no length prefix (RFC 8484 §6). ID 0 as over QUIC,
    no edns-tcp-keepalive (RFC 7828 does not apply, §9), queries padded to 128 bytes and replies to padded
    queries to 468 bytes (D60). TC means the server could not get a full answer (§9), not a retry over TCP.
  - `Template`: `https://host[:port]/path{?dns}`, or the same without the expression, `{?dns}` implied as dig and
    kdig take it (a provider's `https://doh.cleanbrowsing.org/doh/security-filter/` has none); the path of an
    SVCB `dohpath` (RFC 9461 §5), whose `dns` variable must be written. The one expression is `{?dns}`, or
    `{&dns}` after a query: any other RFC 6570 expression is refused, since DoH defines no other variable. No
    user information; a `dns` parameter of its own in the path is refused, as the server would read one of two.
  - A response is a DNS response if its status is 2xx whatever the rcode (§4.2.1), its content type
    `application/dns-message` (parameters and case ignored) and its body a DNS message. TTLs go down by the
    larger of `Age` and the time since `Date` (§5.1, RFC 9111 §4.2.3, without the response delay), to 0 at
    least: a copy a cache kept is not read as fresh. A bad `Age` is ignored (RFC 9111 §5.1); only the
    IMF-fixdate form of `Date` is read (RFC 9110 §5.6.7).
  - A server answers a GET with `cache-control: max-age` of the least TTL of the answer and of the SOA of the
    authority section (least of its TTL and MINIMUM, RFC 2308 §5), 0 without any, and a POST with none, which
    §5.1 makes uncacheable. Errors of the request are statuses without a DNS message: 405, 415, 400, 413.
    Whether the query is a DNS message is the caller's (FORMERR, §4.2.1).
- D83 (completes D82) The client asks DoH over HTTP/3, `Transport::Https` in `dedens-net::https`. RFC 9114 over a
  QUIC connection with ALPN `h3`, TLS 1.3 and the trust of D60 (RFC 8484 §3, strict profile).
  - One connection per server and certificate name, opened on first use and shared by concurrent queries, one
    request stream each. It is opened again after a GOAWAY or a close; a request a reused connection refused
    (GOAWAY, `H3_REQUEST_REJECTED`, closed) goes once more on a new one, as D61. The endpoints and dialing are
    `dial.rs`, shared with DoQ; HTTP/3 lets the server open 16 unidirectional streams (control, QPACK), DoQ none.
  - No retry of its own: D27's rules for stream transports, ID 0, timeouts as QUIC. A status other than 2xx, a
    wrong content type or a body that is no DNS message is an error of the exchange, not a response (D82).
  - The CLI writes `https://HOST[:PORT][/PATH][#NAME]`, port 443; the path is that of the URL, else of
    `+https=PATH`, else `/dns-query`. `+https`, `+https-get` (default) and `+https-post` turn it on for any
    server, as `+tls` does. `+https` is refused with `+tcp`, `+tls`, `+quic` (one transport each), `+trace` (D40)
    and `+noedns` (the padding, D60); `+https-get` with `+https-post`.
  - HTTP/3 is the one version: there is no `+http3` option yet. HTTP/2 (phase 4, step 23) adds the version
    choice and may make HTTP/2 the default of `https://` (RFC 8484 §5.2), HTTP/3 on `+http3`.
  - A response reports transport `DoH`, `-v` and JSON `exchange.http` the HTTP version and status.
  - `providers.yaml`: `https` URLs are asked over HTTP/3 by `just providers`; `https_h2` holds those of servers
    where HTTP/3 does not answer (November 2026: no `h3` in Alt-Svc, or a handshake that stalls), parsed only,
    until HTTP/2 (D67).
- D78 (amends D69) ODoH crypto (RFC 9230) is `dedens-odoh`, sans-IO, for the one suite RFC 9230 §9 requires:
  DHKEM(X25519, HKDF-SHA256) (0x0020), HKDF-SHA256 (1), AES-128-GCM (1). HPKE (RFC 9180) is the `hpke` crate
  (0.15.1, MIT or Apache-2.0, RustCrypto primitives, features `aes`, `alloc`, `x25519` only, passes `cargo deny`);
  the response's AES-GCM (RFC 9230 §6.2 `derive_secrets`) is `ring`'s, which D71 has already, so two AES-GCM
  implementations are in the tree (`hpke`'s for HPKE, which `ring` cannot serve; `ring`'s for the response).
  Accepted: each has one job, and a second `ring` AES-GCM inside HPKE is the thing `ring` cannot offer. HKDF is
  ours, one HMAC of `ring` per `Extract` or `Expand` of at most one block (RFC 5869, tested on its A.1 vector):
  `ring`'s `Prk` cannot be wiped and its `expand` returns a `Result` that an infallible length would only
  `expect`. Rejected: HPKE on `ring` (its agreement API holds no static X25519 key and has no `DeriveKeyPair`: a
  target could not keep a key), our own HPKE (a key schedule to keep right for no gain; the crate passes RFC 9180
  Appendix A.1.1 here), the `odoh-rs` crate (D3: protocol code is ours; its code was read for the scheme only),
  `aws-lc-rs` (a second native crypto library next to `ring`; not evaluated further).
  - Configs: `ObliviousDoHConfigs::parse` keeps the configs of version 1 with that suite and skips every other, as
    §5 tells clients and `odoh-rs` does: another version, KEM, KDF or AEAD, and one of ours that is malformed (a
    field past its config, bytes after its fields, an empty key or one that is not 32 bytes). A list whose own
    framing is broken (truncated, trailing bytes, empty) is an error, as is a list with no usable config
    (`WireError::NoUsableConfig`), so a caller never holds an empty list. `parse` then `encode` drops what was
    skipped. The key ID (§6.1) is computed once, with the config. How a client finds the list is out of scope of
    RFC 9230 §5; it is not specified here.
  - Messages: the bounds of §6.1 are checked when a message is built, so writing cannot fail. A plaintext holds
    the padding as a length: non-zero padding cannot be built, and one received is refused (§7, §8), as are
    trailing bytes and any message type but 1 and 2.
  - Padding: the caller chooses it; `query_padding` and `response_padding` round the DNS message to 128 and 468
    bytes (RFC 8467 §4.1, as D60 for DoH), as §11 tells implementations. Inside the encryption, so messages of
    one block have one size on the wire (tested). The live target of Cloudflare answers without padding.
  - Randomness comes in as an argument (`CryptoRng`), so tests replay RFC 9180's ephemeral key and odoh-go's
    response nonces; a target key is derived from a 32-byte secret the caller keeps (`DeriveKeyPair`), so no key
    generation or storage lives here. The docs of `encrypt_query` and `encrypt_response` warn that a replayed
    generator repeats the ephemeral key or the response nonce. `ResponseContext` is consumed by its response
    (`encrypt_response` is the one call that encrypts under the secrets, so a second would reuse the nonce
    input). `QueryContext` is borrowed by `decrypt_response`: opening encrypts nothing, and a proxy's forged
    answer must not cost the client the context of a query still waiting for the target's.
  - Secrets: the exporter secret, the retained query plaintext (it salts the response keys), the HKDF output,
    the AEAD key bytes, nonce and salt are `Zeroizing`, wiped when dropped. `hpke` wipes its own (shared
    secret, exporter secret, AEAD key and nonce, private key). Not wiped: `ring`'s HMAC keys, its `LessSafeKey`
    schedule and the HMAC tag buffer, the plaintext DNS messages, the serialized query before it is sealed
    (`seal` copies it), and copies the allocator moved. Best effort, not a guarantee. No `unwrap`, `expect` or `as` in non-test code:
    the lengths are typed (`Field`, constant prefixes).
  - `ExchangeError::UnknownKey` is the 401 of §4.3 and every other failure of `decrypt_query` the 400. HTTP (the
    media type, §4.1's ban on caching, discovery) belongs to `dedens-net`.
  - Tests: RFC 9180 A.1.1, the vectors of `cloudflare/odoh-go` (the target side, byte for byte), the config
    Cloudflare serves, and round trips (`tests/rfc9230.rs`); the client side reads the odoh-go responses through
    the target's secrets (the vectors hold no ephemeral key). Failure paths are tested: small-order keys,
    ciphertext shorter than the tag, non-zero padding in a response, bounds. Fuzz targets `parse_odoh_configs`,
    `parse_odoh_message`, `odoh_decrypt` (seeded with a valid odoh-go query and response). A query encrypted here was answered by `odoh.cloudflare-dns.com` and its
    response decrypted (2026-11-01, one-off, not a test). Bench: `docs/benchmarks.md`.

- D80 (amends D69) CoAP is our own sans-IO codec, `dedens_net::coap` (RFC 7252, RFC 7959, RFC 8132), for DoC (RFC 9953):
  no crate of CoAP is pulled in, since DoC needs a small part of it and the rest would carry its own socket, clock
  and randomness, which D26 keeps out of the exchanges. It is not behind the `doc` feature: the module has no
  dependency, and the fuzz target and tests build it anyway. The socket is step 13's.
  - `Message` parses and writes every datagram of the RFC, options kept in order whether known or not, so a message
    of minimal encodings writes back byte for byte. An unknown critical option is reported (`unknown_critical`),
    never dropped (RFC 7252 §5.4.1); the answer is the caller's.
  - `exchange::Exchange` is the client of one request, confirmable only, fed time and datagrams like D26's: the
    caller passes the first message ID, the token and a seed, the jitter between ACK_TIMEOUT and 1.5 times it
    being a xorshift of that seed. Piggybacked and separate responses (empty ACK, then a confirmable response it
    acknowledges), RST, duplicates and a response of an unknown token (RST) follow RFC 7252 §4-5. A separate
    response is waited for `separate_timeout` (93 s, MAX_TRANSMIT_WAIT: the RFC gives none).
  - Block-wise (RFC 7959): Block2 responses are reassembled up to 65535 bytes, a follow-up asking for the next
    block in a new message ID and the same token, the ETag compared across blocks; the server's smaller block size
    is followed. A request over `block1_size` goes in Block1 blocks, 2.31 answered by the next one, the server's
    smaller size followed. A follow-up for a Block2 carries the request's payload when the request went whole, as
    a FETCH body is part of the cache key (RFC 8132 §2) and a server keeping nothing needs the query again;
    aiocoap's client sends none, and its server does not need it. Block1 requests' follow-ups carry none
    (RFC 7959 Figure 10).
  - `server::Dedup` remembers the reply to a confirmable request by (endpoint, message ID) for EXCHANGE_LIFETIME
    (247 s), at most a given number of entries, the oldest dropped first; a duplicate gets the same reply.
  - `docpath` is `SvcParam::DocPath(Vec<Box<[u8]>>)` (RFC 9953 §3.2, key 10): the wire is `alpn`'s with empty
    segments allowed, the text a comma-separated list, no segment the root path. One empty segment prints in the
    `key10="\000"` form, a single empty item being no different from the empty list in the text.
  - Tests read datagrams captured from aiocoap (`tests/testdata/coap/`, `capture.nu`), libcoap not being here.

## Presentation format

- D25 Zone text (`dedens-proto::text`, RFC 1035 §5, RFC 2308 §4, RFC 3597 §5): own lexer, base64 and hex.
  Read: BIND TTL units, `\#` for every type (known ones typed), case as written. Written: one tab-separated
  line per record, absolute names, TTL in seconds, `\#` on request (`generic()`). `ZoneReader` hands
  `$INCLUDE` to the caller (no file I/O in the library; the caller bounds depth and vets paths) and stops at
  the first error, with line and column. No `$GENERATE`. Stricter than BIND where BIND only warns: TTL over
  2³¹−1 is an error, no SOA-minimum fallback, query and meta types and classes (RFC 6895 §3.1-3.2) and RDATA
  over 65535 bytes are refused. A `"` opens a quoted part at a token's start, or after the first `=` in SVCB
  parameters only (RFC 9460 §2.1), as BIND; a `\` ending a line outside quotes is an error (it joins entries).
  `\#` RDATA its type refuses stays opaque with the reason (`DecodedRecord`), as on the wire (D9). RFC 1035
  §5.2 zone checks belong to the zone-loading layer.
- D29 A quoted part ends on its line: an unescaped newline inside quotes is an error, as in BIND (`isc_lex`
  without `ISC_LEXOPT_QSTRINGMULTILINE`, how it reads zone files); `\` before the newline keeps it in the
  text. RFC 1035 §5.1 leaves it open; a missing `"` would otherwise swallow the entries after it silently.

## Performance and safety

- D14 Bar: no slower than hickory-proto; target: faster than `domain`. Baselines run in the same benches:
  hickory-proto, `domain` and Go's `miekg/dns` (the codec of CoreDNS), in `crates/dedens-bench` as regular
  dependencies so `cargo deny` checks them; Unbound's C codec, built from a pinned release by
  `just bench-unbound`. `unsafe` only where a profile shows bounds checks matter. `Message::decode_reusing`
  decodes without allocating once warm; the server decodes each upstream response once with `Message::decode`
  (D46).
- D15 `unsafe` is a hot-path tool: the bench first, then Miri and RAPx. Every crate root has
  `#![forbid(unsafe_code)]`, which nothing below can override; a crate opting in replaces it with the
  workspace's `deny` (`Cargo.toml`) and allows `unsafe_code` on the one module of the measured hot path.
- D16 Checks beyond the gate, each added with its trigger: Miri with the first `unsafe`, loom with the first
  hand-written concurrent structure, cargo-semver-checks with the first crates.io release, fuzzing with the
  first fuzz target. RAPx weekly, outside the gate: it builds on rustc internals and breaks on unrelated
  nightly changes.
- D22 Response cache (`dedens-cache`, sans-IO, time passed in as seconds): one cache shared by compio's
  per-core threads, `Mutex` shards picked by keyed SipHash (no collision flooding). Own code, not
  `moka`/`quick_cache`: slab shards with S3-FIFO eviction under a byte budget (a scan of one-time names leaves
  popular ones; a ghost queue of evicted hashes sends a key asked again to main). Whole responses only; an
  RRset cache comes with the recursive resolver. Key: lowercased question, type, class, DO, CD, of standard
  queries only (QR clear, opcode QUERY), not meta types (RFC 6895 §3.1; ANY is cached). `insert` takes the
  client's query and the response the forwarder decoded, never decoding again; the caller asks upstream with
  the query's DO and CD. Checked (RFC 2308, no TC, no violations, no client subnet scope above 0, RFC 7871
  §7.3.1) and encoded once without OPT, its TTL offsets after it in the same allocation. Negative (NXDOMAIN, or no
  answer of the type asked, after any CNAME chain) only with an SOA at or above the chain's last name, and the
  chain's TTLs within the negative TTL (RFC 2308 §2, §5). A hit copies and patches ID, flags (AA and Z clear, AD
  only when asked), question case and TTLs, never above the stored TTL; one too large for the buffer is encoded
  again truncated, outside the lock. Serve-stale (RFC 8767: 30 s answer TTL, 3 days kept) and failure holds (RFC
  9520: 5 s doubling to 300 s, 30 s with stale data, never above 300 s; a failure during a hold does not count, a
  quiet spell over 300 s starts over); the caller decides when stale data may answer.

## CLI

- D17 (superseded by D36) Query files in JSON or YAML, picked by extension or `--format`.
- D36 Query files (`dedens-scenario`), so the server's tests reuse them: one serde model (queries, options,
  optional expectations; a failed one makes `dedens` exit non-zero) read as YAML 1.2 by serde-saphyr, `-` for
  stdin. JSON is YAML 1.2, so JSON files read too, at the price of YAML-worded errors; no input format flag, no
  second reader. `dedens` drops dig's layout (`--dig`): JSON and YAML serve scripts, the human output people, and
  dig itself a side-by-side comparison. Rejected: serde_yaml (archived 2024-03), serde-yaml-ng (no commit in a
  year).
- D18 `dedens`, dig but better: dig argv (`@server name type class +opts`) and long flags; query files;
  output for humans by default, JSON or YAML for scripts (D37), `+short`, color; several names, types or servers
  per run, concurrent, side by side; timing, transport, sizes, EDNS, cookies and EDE in words; `+trace`;
  `--repeat N` with latency percentiles; `--save-wire` (the source of captured test data); default server from
  `/etc/resolv.conf`. `-x ADDR` asks PTR for the `in-addr.arpa` or `ip6.arpa` name of an address (RFC 1035 §3.5,
  RFC 3152). The `resolv.conf` search list (`search`, `domain`, `ndots`) applies only with `+search`, as in dig: a
  debugging tool asks for the name typed. Unicode names are converted to A-labels (IDNA2008, RFC 5891 and 5895) and
  shown as such, with labels mixing scripts flagged (IDN homographs).
- D32 CLI arguments: a pre-pass turns dig tokens into long flags (`@srv` → `--server srv`, `+opt` → `--opt`,
  `+noopt` → `--opt=false` for an on/off flag only, `+opt=v` → `--opt=v`, `opt` any unique prefix as in dig;
  `-t TYPE`, `-c CLASS`, `-q NAME` → words; `-p PORT` for a server without one), leaving the value of a flag and
  anything after `--` alone, then clap parses. One option set for both spellings (clap derived on
  `dedens_scenario::Options` behind its `clap` feature), one help. An option needing EDNS (`bufsize`, `dnssec`,
  `nsid`, `cookie`) with `+noedns` is a usage error; AXFR/IXFR are refused until supported; several
  `@servers`: D38. At most 64 queries in flight; each result prints, in argument order, as soon as it is ready.
  Several names and types per run go concurrently on one compio runtime; as in dig, a name is asked the types
  written after it, and one without any the types written before the first name, else A. Output formats: D37;
  color with anstream/anstyle, `--color auto|always|never`, `NO_COLOR` honoured. IDNA with the `idna` crate (UTS 46
  nontransitional, near RFC 5895) and `unicode-script` for mixed-script labels (Han with kana, Hangul or Bopomofo,
  and Latin, being one writing, UTS 39 §5.2), both in `apps/dedens`: the library stays ASCII. `resolv.conf` read by
  our own parser (`nameserver`, `search`, `domain`, `ndots`), `DEDENS_RESOLV_CONF` overriding its path for tests;
  no Windows yet. `+search` tries the next candidate on NXDOMAIN. A class word applies to every query of the run.
  `-f FILE --only ID` runs some queries of a file.
- D33 Exit codes of `dedens`: 0 a response came, whatever its rcode (as dig); 1 an expectation failed; 2 usage;
  9 no reply (timeout, a refused or reset connection); 10 any other error, a failed `--save-wire` write too,
  which leaves the other results.
- D34 Query file schema (D36): top-level `server` and `options`, then `queries`, each with `id` (the
  `--save-wire` file name, so no `/`, `\`, `.` or `..`, unique in the file; default `name_type`, `root_type`
  for the root), `name`, `type`, its own `server`/`options`, and `expect`: `rcode`, `flags` that must be set,
  and `answer`/`authority`/`additional` as presentation lines compared as lists in any order, a line written
  twice expecting two records, the TTL compared only when written. `--save-wire DIR` writes the response to
  `DIR/<id>.bin`. Options are dig's `+` options by name (`tcp`, `ignore`, `recurse`, `cdflag`, `adflag`, `edns`,
  `bufsize`, `dnssec`, `nsid`, `cookie`, `time`, `tries`), each one left out inherited (command line, query, file,
  dig's default); `cookie` is `true`, `false` or a fixed cookie in hex, so captures repeat. `+ignore` and
  `+nocookie` need `dedens-net` exchange options `tcp_fallback` and `cookies`.
- D35 (superseded by D37) `--json` as JSON lines, every field present however empty.
- D37 `dedens --format human|short|json|yaml` (`+short`, `--json`, `--yaml` its shorthands, one at most), each
  response printed as it is ready. `human`, the default, is for reading: a status line (question, rcode in color
  and in words unless NOERROR, RTT, server without port 53, transport), then each non-empty section under its
  name, a record's owner shown once per run of the same owner and its TTL as a duration (`45m41s`); `no records`
  for an empty NOERROR answer; one quiet line of the flags worth a word (authoritative, truncated, recursion
  unavailable, DNSSEC-validated, checking disabled), EDNS and the sizes; EDE, violations and failures in red, one
  per line. `json` (one object per line) and `yaml` (one `---` document each) are for programs and stay short:
  the `dedens-scenario` report, TTLs in seconds, RTT in microseconds, an empty list or string and EDNS version 0
  left out, an absent field meaning empty. Server, transport, RTT (`rtt_us`), sends and query size sit in an
  `exchange` object, absent for a response read from a file; each record is `{name, ttl, class, type, data}`
  with `data` its presentation text; EDNS options are typed (`nsid`, `cookie`, `ede`, else `other` with the data
  in words, EDE text with control characters escaped); protocol violations (D9) go in `violations`, broken
  expectations in `failures`. Serialized only, until the server's tests need to read it back. Replaces D35,
  whose objects held every field however empty.
- D38 Several `@servers`: each query is asked of each, the blocks of one query together in argument order,
  each id then `name_type@server` (port left out when 53, `+tls` or `+quic` after it for a `tls://` or
  `quic://` server) so `--save-wire` keeps them apart. A query file's
  queries go to the command line's servers when given. The human format ends a query's blocks with
  `servers disagree: a, b vs c` when the rcodes or answer records, TTL and order aside, differ; JSON and YAML
  leave the comparison to their reader. A server that does not answer is left out of it.
- D39 `--repeat N` (`+repeat=N`): each query is asked of each server N times in a row, not concurrently, so
  the round trips are the server's and not our queue's. The last response is printed, with a `latency` object
  when N > 1: `sent`, `errors` (left out when 0) and `min_us`/`p50_us`/`p90_us`/`p99_us`/`max_us`, nearest
  rank over the answered round trips; the human format shows them in milliseconds on one line. Exit code 0 when
  any answer came, else the last error's.
- D40 `+trace`: each query asked from the root servers (IANA's `named.root`, bundled; `just root-hints`
  refreshes it) without RD, down the referrals (RFC 1034 §4.3.2: NOERROR, no answer, no AA, NS and no SOA in
  the authority section, a SOA being NODATA per RFC 2308 §2.2), one report per hop, until an answer, NXDOMAIN,
  NODATA or an authoritative response. A referral that comes no closer, an error rcode or a lame response sends
  the hop to the next address (RFC 1034 §5.3.3), three at most, IPv4 and IPv6 in turn so either route works.
  Glue is an address record of a name server inside the answering server's zone (RFC 2181 §5.4.1), unlike dig;
  name servers without glue are looked up the same way, A then AAAA, at most 4 deep, those inside the referred
  zone skipped (they lead back to the same referral). A trace makes 100 exchanges at most. No DNSSEC
  validation, no CNAME following. Refused with `@server`, `-f`, `--repeat`, `--search`, `+tls` and `+quic`. The human format
  counts the additional records of a referral hop instead of listing them. `DEDENS_ROOTS` replaces the roots
  for tests.
- D67 Public resolvers live in `docs/providers/providers.yaml`: a provider's facts (operator, country,
  privacy) and its resolvers, each with what it blocks and what it does with a broken DNSSEC signature, both
  measured, not announced (Quad9's "unsecured" validates, CleanBrowsing's servers disagree, Comodo blocks
  nothing, DNS4EU's child variants block gambling), and its endpoints per transport, DoH URLs asked over HTTP/3
  (D83), those of servers without it kept as data until HTTP/2. `apps/dedens/tests/providers.rs` reads it into
  typed structs: `cargo test` checks the file offline; `just providers` (an ignored test, outside `just check`, which stays offline) asks, through one
  `dedens -f -` run (2 tries), `example.com` of every endpoint, `dnssec-failed.org` of each resolver, and
  each resolver the canaries of each category: one blocked if `blocks` lists the category, all answered if not.
  Blocked is NXDOMAIN, EDE 15 to 17, no address, `0.0.0.0`, loopback or a listed block page. No provider
  publishes a canary its peers block, and threat feeds differ (HaGeZi's lists EICAR's test site, not WICAR's),
  so the canaries are names measured to split the resolvers so. An address family without a route is skipped
  (IPv6 on CI); half the queries failing stops the test, the network being down. Each failure is then asked
  again alone with 8 tries, 16 runs at once, since public servers drop queries (Comodo half of them) and
  QUIC connections sharing a socket stall (`docs/TODECIDE.md`). A REFUSED with EDE 16 (Censored) passes: the
  resolver answered, the law where the test runs refused (OpenDNS from France). A resolver whose packet cache
  answers with an earlier client's cookie (UncensoredDNS), which `dedens` drops as forged (RFC 7873 §5.3,
  D68), is marked `stale_cookies` and asked without a cookie. Rejected: a query file generated from it (a file
  to keep in step), a test per endpoint (a process each, hundreds).

## Server

- D23 (amended by D54) Pipeline: each listener runs an ordered chain of stages; a stage answers, passes the query on, or passes
  it on and sees the response back. Order from the config, not the build (CoreDNS's fixed `plugin.cfg` order
  confuses users). Branching is a router stage (zone, client CIDR, listener, qtype, view), no general graph: a
  query has one response. Declarative matchers compiled at load; scripting costs microseconds against a
  150 ns cache hit. Built-in stages are enum variants behind Cargo features; custom binaries register extra
  stage types (trait objects) on the server library. Stages before the cache are synchronous, without
  allocation or copy of the query. (Not yet: features, router stage; custom stage types are D54 plugins.)
- D24 (narrowed by D44) Configuration: a directory of TOML, YAML or JSON files, one serde model (as D36), merged;
  components named, typed by a `type` key. Errors, not warnings: unknown field, duplicate name, unused component.
  `${VAR}`, `${VAR:-default}` (`$$` escapes), `SECRET[backend.key]`. `dedensd validate` builds the pipeline without
  binding; JSON Schema from the types (schemars); config tests run D36 query files. Reload (SIGHUP, file watch)
  builds the new pipeline, then swaps it (`ArcSwap`); in-flight queries finish on the old one; cache and upstream
  connections survive.
- D41 (amended by D43, D46) Server core (`dedens-server`), sans-IO as D26: `Pipeline::query` takes the query's
  bytes and transport and returns a step: a reply in the caller's buffer, nothing, or a request for an upstream
  server whose response goes back through `Pipeline::receive`; `apps/dedensd` does the I/O. Before the stages the
  core answers what none should see: responses and bytes shorter than a header are dropped; FORMERR to a query it
  cannot read (the header alone, no OPT), that breaks a rule (D9) or has no question; NOTIMP to opcodes other than
  QUERY; BADVERS to EDNS versions above 0; REFUSED to AXFR and IXFR, and when no stage answers. A reply has the
  client's ID, opcode and question in its case; QR and RA set, RD and CD copied, AA clear, AD only for a query with
  AD or DO (RFC 6840 §5.8); our OPT (1232 bytes, DO copied) only when the query had one. Over UDP it fits the
  client's payload, 512 to 1232 bytes, 512 without EDNS, truncated as D10; over TCP it comes whole. The forward
  stage asks its servers in order, the next on no response, one undecodable or breaking a rule, TC, or SERVFAIL,
  REFUSED, NOTIMP, FORMERR (RFC 1035 §7.3); after the last, SERVFAIL. Upstream gets the client's question, RD set,
  AD and CD copied, our EDNS with DO and none of the client's options: the client subnet never leaves (privacy),
  cookies are per hop (D27). Rejected: an async stage trait over a mock upstream (sans-IO tests are exact, as D26).
- D42 (amended by D45, D47-D49, D52, D65, D66, D84) `dedensd` I/O around D41: one compio thread per core on Linux, each with its
  own UDP socket and TCP listener on every `listen` address (`SO_REUSEPORT`, the kernel spreading queries), one
  thread elsewhere, where `SO_REUSEPORT` does not spread; IPv6 sockets IPv6-only, so `[::]` and `0.0.0.0` bind
  together. Every socket is bound before any thread starts, so a taken address fails the start. A reply the
  pipeline builds at once goes out from the socket's task; a query for upstream gets a task owning its `Upstream`
  and asks with the thread's `dedens_net::Client`, over the client's transport, with the forward stage's timeout
  and tries (D45). TCP (RFC 7766): queries read in turn, each answered when ready, replies in any order through one
  writer (§6.2.1.1); reading stops after 10 s without a query, the connection closes once pending replies are
  written (§6.2.3). Listeners and upstreams from the configuration (D44). Rejected: one socket shared by all
  threads (contention on one receive queue); a task per query on the cached path (an allocation per hit).
- D43 (amended by D45, D46) Cache stage (D22 in D41's pipeline): `Stage::Cache` looks the query up at `now`,
  seconds the caller passes (`dedensd`: since start), so `Pipeline::query` and `Pipeline::receive` take it. A hit
  is the stored bytes patched by `dedens-cache`, then D41's flags (AA clear, RA set, AD as asked, TC kept) and our
  OPT when the query had one; room for the OPT is kept before the lookup, and a stale hit leaves 6 more bytes for
  its EDE option (`Cache::STALE_ROOM`), since freshness is known only after. A miss runs the later stages, and the
  forward stage's usable response is stored under the client's query (its DO and CD bits), then answers as a hit,
  not encoded again (`miss` bench, mx: 1.5 → 1.1 µs), through `Cache::stored`: no use counted for eviction nor in
  the lookup metrics, else every name asked once would look asked twice, defeating S3-FIFO's scan resistance;
  unstored responses (D22) are still the reply, encoded. After the last server fails, the failure is held (RFC 9520
  §3.2); during a hold the reply is SERVFAIL, upstream unasked. Expired data answers while failing
  (`StalePolicy::IfFailing`), and on the client timer (D45): after the last server fails, and during the hold, with
  TTL 30 and EDE 3, or 19 for NXDOMAIN (RFC 8767, RFC 8914 §4.4). A fresh hit under 10% of its TTL is
  `Step::Refresh`: the reply now, then the same upstream query whose response is only stored, ending in
  `Step::Drop`; a failed refresh is not held. `Upstream` owns what it needs (a copy of the query's bytes, read
  again on the way back; stage and server indices), so it outlives the query's buffer, and `Pipeline::receive`
  takes it back. Rejected: reading the query again in `dedensd`'s upstream task (a second cache lookup, a miss
  counted twice, and no way to tell a refresh from a reply).
- D44 (amended by D64-D66, D84) `dedensd` configuration, D24 narrowed for the first server: one YAML file (`--config`), as D36's query
  files; `listen` addresses, `pipeline` (stage names in order), `stages` (name to settings
  under `type`: `cache` with `dedens_cache::Config`'s fields, `forward` with `servers`, `IP` meaning port 53),
  `upstream_ca` (D65).
  `${VAR}` is replaced in the text before YAML reads it; a value spanning lines is refused, as it would add YAML.
  Errors: unknown fields, duplicate names, a stage listed and not defined, defined and not listed, listed twice or
  after a forward stage (which answers every query). `dedensd validate` reads the file and builds the pipeline
  without binding; SIGHUP reloads it (D55). Later, with need: a directory merged, `SECRET[..]`, JSON Schema.
- D45 Upstream patience and the client response timer (RFC 8767 §5), changing D42 and D43: a forward stage
  waits `timeout_ms` per query (default 3000, slow authoritative chains take over 1 s) and sends each server
  `tries` queries (default 2), carried on `Upstream` (`Upstream::patience`). A cache stage's
  `stale_answer_after_ms` (default 1800, the RFC's suggestion; 0 waits for resolution) is the client response
  timer: `dedensd` races it against the upstream exchange, and when it ends first calls `Pipeline::stale`,
  which answers with expired data (`StalePolicy::Always`, TTL 30, EDE 3 or 19) if the cache keeps any. The
  exchange goes on: its response only refreshes the entry, so the next query has it fresh; its failure is held,
  with no second reply. A refresh of a fresh entry (D43) has no timer. Rejected: a stale answer without
  resolution going on (the next query would wait again); a second task per query for the timer (the exchange
  future is polled with a deadline, then awaited).
- D46 Review fixes to D41-D45. A query without RD gets fresh cached data only (RFC 1034 §4.3.1: no recursion;
  RFC 8767 §5: no expired data), else REFUSED with EDE 20 (Not Authoritative, RFC 8914 §4.21); it never goes
  upstream, so it cannot start a hold every client shares. Upstream queries set RD (a refresh started by such a
  query too) and copy the client's AD (RFC 6840 §5.7), so AD can come back. `dedensd` turns the EDNS fallback
  off: a response without OPT would be stored for clients with DO (RFC 3225). A failure of ours
  (`ClientError::is_local`: no randomness, no socket, any socket error but the network or server refusing,
  resetting or unreachable) is `Pipeline::abandon`: SERVFAIL, no next server, no hold. The configuration refuses
  a second cache stage (it would never be filled). A panicking serving thread ends `dedensd` with an error.
  The client response timer of D45 runs only when the cache keeps expired data for the query
  (`Lookup::Expired`). A cache hit allocates nothing (`benches/server.rs`). The exchange checks a response with
  `Query::read`, and the pipeline decodes it once.
- D47 (amended by D64) `dedensd` limits, per thread (RFC 7766 §10, D42 had none): 1024 upstream queries in flight (past them a
  UDP query is dropped, a TCP one answered SERVFAIL), 256 TCP connections (past them a new one is closed at once);
  per connection, 64 queries in flight (reading waits; a bounded channel is the semaphore), 128 KiB of queued
  replies (reading waits), and 10 s for the queue to empty from its first reply (a client that reads slower than
  it asks loses its connection). A query waiting upstream holds no reply buffer until a reply is made. Constants
  for now; configuration with need. Client allow and block lists come later (`docs/TODECIDE.md`).
- D48 Four tasks answer on each UDP socket of a thread, so a receive stays posted while one answers or sends:
  one task waited for its reply to go out before receiving again. `just bench-dnsperf` (Linux, io_uring, one
  core, cache hits) measures `dedensd` against a git ref: 1 task about 310k queries/s, 2 about 340k, 4 about
  415k, 8 and 16 no better. A TCP connection's writer writes the replies queued meanwhile together, up to 65535
  bytes: one write a reply held TCP to about 185k queries/s, batches reach about 1.8M (dnsperf pipelines 500
  queries). Copying each reply for the writer costs nothing measurable there (copying it twice did not move the
  numbers), so replies keep their copy and the writer task, which reads on while writing and keeps the replies
  of concurrent queries whole.
- D49 UDP queries arrive in buffers made once per thread (256 of 4096 bytes, compio's buffer pool): on Linux one
  io_uring multishot receive per socket fills them, and the socket's four tasks (D48) take turns at its stream
  of datagrams behind a lock, each giving its buffer back before its reply waits to be sent. About 400k →
  480k queries/s (`just bench-dnsperf`); 16 tasks no better. A query longer than a buffer (about 3.9 KiB) is
  cut short and read as broken; the socket keeps datagrams while every buffer is taken. Rejected: a receive
  asked for each datagram into the task's own 64 KiB buffer (one submission and one buffer per receive).
- D50 Upstream UDP queries share a fixed pool of 256 sockets per server and client (`dedens-net::udp`), each opened
  on first use on port 0 and connected, then kept: a query takes one at random and waits for datagrams with its
  ID, which the socket's task receives for every query on it. An off-path attacker guesses the ID and the
  socket: 16 + 8 bits (RFC 5452 §9.2), against about 32 with a socket per query; cookies (RFC 7873) and `0x20`
  stay the way to win more. Matching stays D27's: a datagram goes to each query waiting for its ID, and the
  exchange drops those of another question. A datagram is received whole, up to 65535 bytes, into
  one buffer per socket, whatever size the queries advertised. A socket error goes to the queries that sent on
  it, each counting it as a lost try; errors in a row pause the socket's task 10 ms. Forwarding to a second `dedensd` (`just bench-dnsperf HEAD forward`): about 125k → 127k queries/s,
  the upstream on one core being the limit there. Rejected: renewing sockets on a timer (no attack measured
  against a kept port yet); muxing by question too (the exchange checks it).
- D51 The io_uring of a serving thread runs completion work cooperatively (`COOP_TASKRUN` and `TASKRUN_FLAG`,
  Linux 5.19): when the thread enters the kernel, instead of interrupting it as a signal does. Forwarding
  (`just bench-dnsperf HEAD forward`): 135k → 158k queries/s; cache hits over UDP and TCP unchanged. Rejected:
  `SINGLE_ISSUER` with `DEFER_TASKRUN` (Linux 6.1), no better (160k); `SQPOLL` (cache hits over UDP 475k → 230k,
  forwarding 155k → 82k).
- D52 (superseded by D63) A TCP query answered after upstream writes its reply into a 65535-byte buffer the thread kept from an
  earlier one (up to 32, 2 MiB), not a new one. The buffer is zeroed first unless `zero_buffers: false` in the
  configuration: no byte of an earlier reply stays in it, should a bug ever send past the reply's length (the
  encoder writes before it reads, so nothing leaks today). Only these spare buffers are: the buffer each UDP
  task and each TCP connection reuse for the replies made at once (cache hits, plugins) keeps earlier replies'
  bytes past the current one's length; whether to zero or drop them is open. Forwarding over TCP (`just bench-dnsperf HEAD forward-tcp`):
  84k zeroing new buffers → 90k-92k reusing them unzeroed; zeroing them again costs part of it (79k-88k against
  87k-90k). Rejected: skipping the zeroing of new buffers (uninitialized memory behind `unsafe`).
- D63 (supersedes D52) A `dedensd` thread makes its TCP replies and its replies after upstream in one 65535-byte
  buffer, allocated at its start, and copies each reply's bytes out to send them: behind its length for TCP, as
  framing already copied it. Making a reply never waits, so the buffer is borrowed only meanwhile and one serves
  every task. Only a reply's bytes leave it, never those of an earlier reply, so there is nothing to zero:
  `zero_buffers`, the spare buffers and each TCP connection's own 65535-byte buffer (16 MiB a thread at 256
  connections) are gone. Each UDP task keeps its 1232-byte buffer for the replies it makes at once: it is owned
  by the send in flight and reused, and only the reply's length is sent. Forwarding over TCP (`just
  bench-dnsperf HEAD forward-tcp`): 230k-270k → 303k-305k queries/s; over UDP and from the cache unchanged.
- D53 Upstream TCP: the connection's writer task writes the queries queued meanwhile together, up to 65535 bytes,
  as D48's writer does for replies: one write and one wake-up of the server for many. Forwarding over TCP
  (`just bench-dnsperf HEAD forward-tcp`): about 87k → 275k queries/s, average latency 5.7 → 1.8 ms.
- D54 (amended by D64) Plugins (D23's custom stage types, for built-in stages too): `dedens_server::Plugin`, a trait object in
  `Stage::Plugin`, answers a query at once from what it holds, or passes it on; no upstream, no cache entry.
  Plugins live in `dedens-plugins`, configured in `dedensd` under their own `type`; cache and forward stay core
  stages, tied to the upstream steps. An answer is a response code, records already in wire form
  (`dedens_server::Records`, written once after a question for their name, so their compression pointers hold
  in any reply to that name), AA, and an extended error: the reply copies the records after the client's
  question, allocating nothing; records that do not fit are left out with TC (RFC 2181 §9). AA when the plugin
  holds the name's data as local knowledge (RFC 1035 §4.1.1, RFC 9499 §6), clear when it applies a policy.
  Plugins answer queries without RD too: their data is local. Rejected: a stage enum per plugin in the core
  (each plugin would grow `dedens-server`); plugins writing the reply themselves (each would redo D41's flags,
  OPT and sizing). Files are read at start and on each reload (D55).
  - `hosts`: lines in the `/etc/hosts` format, inline then from a file; A, AAAA and the PTR of each address to
    its first name, TTL 3600 unless set (as `CoreDNS`); a listed name asked another type has no data (RFC 2308
    §2.2) unless `fallthrough` passes it on; addresses with a zone (`fe80::1%lo0`) are left out.
  - `blocklist`: names, one a line or in the `/etc/hosts` format of published lists, blocking themselves and
    their subdomains; `action` NXDOMAIN (default), NODATA, REFUSED or the unspecified address, each with EDE 15
    Blocked (RFC 8914 §4.16), AA clear. Of hosts lines only those of `0.0.0.0`, `::`, `127.0.0.1`, `::1` count,
    without names of one label or starting with `localhost`: such files open with their host's own entries
    (`127.0.0.1 localhost`, `127.0.0.1 local`), and blocking `local` would block all of mDNS's `.local`.
    Formats, duplicates and the allowlist in D56.
- D55 (amended by D64) `dedensd` reloads its configuration file on SIGHUP (systemd's `ExecReload=kill -HUP $MAINPID`): the file
  is read and the pipeline built as at start, then swapped in. Each serving thread compares a generation counter
  before each query (one atomic load) and takes the new pipeline under a lock only when it changed, holding it in
  an `Rc` so a query touches no count shared between threads; a query waiting on upstream ends on the pipeline it
  started on. The cache stage is an `Arc<Cache>` kept while its settings are unchanged, else a new empty one. A
  file that does not read, or a hosts or blocklist file it names, leaves the running pipeline and logs an error;
  `listen` takes a restart (a warning), as does the thread count. Counted in
  `dedensd_reloads_total{result="ok|error"}`. The handler comes from `signal-hook`, installed before the
  server logs that it serves, so no SIGHUP ends the process. Rejected: compio's `signal`, which restores the
  default action between two waits, so a second SIGHUP during a reload would end the process; `arc-swap`,
  whose guards may not be held across an await and whose `Arc` clones share a count between threads. Later:
  watching the file, and upstreams pushed while running (D-Bus, for a systemd-resolved replacement).
- D56 Blocklist contents. `*.name`, hagezi's format for Blocky, is read as `name`: Blocky's documentation says it
  blocks the name and its subdomains, as any entry here does. A plain line holds one name. Names are host names,
  not zone-file names, which read nearly anything (`<html>`, `||ads.example^`, URLs) so that an error page passed
  as a list: ASCII letters, digits, `-` and `_` between dots, a label not all digits (no address is a name), an
  optional trailing dot, `*.` only first; no escapes, no root (`.`, `@`). Hosts lines leave out addresses as
  names (StevenBlack's `0.0.0.0 0.0.0.0`) and lines of an address with a zone (`fe80::1%lo0`), of the host's
  own entries. A byte order mark opening a list or hosts file is dropped. An `allow` list
  (entries, file) lets a name through when it or a parent is listed, whichever parent is blocked, as numa and
  Blocky do; looked up only for blocked names. Names listed twice count once, counted in the log. Lines
  from the server's own configuration must all read; downloaded ones (`Origin::Downloaded`) skip lines that do
  not, and the text is refused when it has none or fewer than half read, as an error page served with status
  200 does (numa's rule). Adblock syntax (`||name^`, `@@`) later, with need.
- D57 (amended by D64) `dedensd` downloads blocklist and allowlist `urls` (`https://`, or `http://` for a server of one's own)
  with `ureq` 3, blocking, on the thread that reloads on SIGHUP: off the query path, and one thread so a refresh
  never swaps in a pipeline older than a reload's. Rejected: `cyper`, compio's client (hyper, a 0.10 beta).
  Certificates are checked against the OS trust store (`rustls-platform-verifier`); list hosts are resolved by
  the system resolver, possibly `dedensd` itself, which forwards them. Each list is kept in `downloads.dir`
  (`/var/cache/dedensd`) under the 64-bit FNV-1a hash of its URL, written to a `.part` file then renamed, with
  its `ETag` beside it: a start or reload reads the copies and serves at once (a list not downloaded yet is
  empty), and fetching sends `If-None-Match`, so an unchanged list is neither downloaded nor read again (304).
  An `https://` list is fetched with `https_only`: a redirect cannot take it to `http://`. A text replaces the
  copy only when it reads as a downloaded list (D56), at most 256 MB, within 30 s. Lists are fetched once the
  server serves, on each SIGHUP after its reload, and every `downloads.refresh_minutes` (1440, as numa and
  Pi-hole); a failure keeps the copy and retries after 1 min, doubling up to the interval. A change rebuilds the
  pipeline as a reload does (D55; the cache kept). Counted in
  `dedensd_list_fetches_total{result="changed|unchanged|error"}`. Later, with need: a list swapped alone instead
  of the pipeline, per-list intervals.
- D58 A blocklist holds the 64-bit `SipHash` of each name's lowercase wire form under a key drawn per `Lists`
  (std's `RandomState`), in a `HashSet<u64>` hashing them no further: 8 bytes a name instead of the name and its
  allocation. Published lists of 2.29M names: 110 MB resident instead of 240 MB, read in 0.64 s instead of
  0.87 s, lookups as fast (`benches/blocklist.rs`). A false match needs two names of equal hash, 2^-64 a pair:
  ~10^12 queries per wrong answer against 2M names, and the key, unknown outside the process, keeps a client from
  aiming at one. The cost: names cannot be listed back, so a blocked name under a blocked parent is no longer
  dropped (2% of those lists, 0.4 MB). Rejected: names in one buffer with offsets (~55 MB, exact, more code); a
  sorted `Vec<u64>` (18 MB instead of the set's 37 MB, a binary search per label); a trie or FST (a dependency,
  slower to build).
- D87 Published blocklists live in `docs/blocklists/blocklists.yaml`, as D67's resolvers: a source's facts
  (maintainer, licence, how it is built) and its main lists, each with its URL, what it holds, how often it
  changes and its `format`, measured: names, `*.name` and hosts lines, which `dedensd` reads (D56), adblock rules,
  URLs, and addresses or networks (IP feeds, kept for their information: `dedensd` blocks names, not
  addresses). `apps/dedensd/tests/blocklists.rs` reads it into typed structs: `cargo test` checks the file
  offline; `just blocklists` (ignored, outside `just check`) downloads each list as `dedensd` does (D57; 120 s,
  3 tries since oisd answers 503 now and then) and checks that most of its lines are of its format, and that a
  list of a format `dedensd` reads reads as a downloaded list. Licences differ: several forbid commercial use or
  redistribution (OpenPhish, Maltrail, Binary Defense), which the file quotes; none is a default of `dedensd`.
  Rejected: list sizes in the file (they change daily; the test prints them).
- D88 (amends D87) The blocklist file is parsed, not read as prose. `updated` is an ISO 8601 duration of weeks
  to seconds (`P1D`, `PT30M`; years and months have no fixed length) or `irregular`. A source has a `status`:
  `active`, `frozen: <date>` (unchanged since that day: 1Hosts, ipanalytics, botvrij), or `retired`, the only one
  with `lists: []`. Its `license` is an SPDX id of a short known set, `custom` or `none`, the quoted `terms`
  going with the last two only; `use` (`free`, `no-resale`, `non-commercial`, `ask`, `unknown`) is our reading of
  the terms, an SPDX licence being `free`. `just blocklists` also checks freshness: a list's date is its
  `Last-Modified`, else, on `raw.githubusercontent.com`, its last commit from GitHub's API (60 requests an hour,
  more with `GITHUB_TOKEN`); an active list older than 3 updates and a day, or a frozen one changed after its
  day, fails, so a list that stops or resumes shows. A list `dedensd` does not read is checked on its first
  MiB, its format being in every line. Dates are parsed by hand in the test, a date crate being a dependency for
  three formats.
- D64 Review fixes to D44, D47, D54, D55 and D57.
  - Limits (D47): a TCP connection bounds the bytes of its queued replies, not their count: reading waits while
    more than 128 KiB wait for the writer, and the queue must empty within 10 s of its first reply, else the
    connection closes (a client asking faster than it reads). Replies of upstream queries are queued without
    waiting, so none holds its 65535-byte buffer meanwhile; the worst left is 64 replies of 64 KiB in flight past
    the bound. A TCP query the thread has no upstream slot for gets SERVFAIL (`Pipeline::abandon`) instead of
    closing the connection; a UDP one is still dropped. A UDP receive that fails right after another waits
    100 ms, as `accept` does, instead of spinning.
  - Panics: a serving thread waits on the tasks of its sockets, so one that panics (compio catches the panic and
    keeps it silent) fails the thread, and `dedensd` (D46). The reload thread runs each fetch and each reload
    under `catch_unwind`: a panic is logged and counts as a failure, and later reloads still run.
  - Configuration (D44): a hosts or blocklist stage after a cache stage is refused: the cache, kept across
    reloads (D55), would keep answering a name a reload newly blocks until its TTL ends. `refresh_minutes` above
    a year (527040) is refused. `${VAR}` values with `\r` are refused as those with `\n`; lines whose first
    non-blank character is `#` are comments, left as written.
  - Reloads (D55, D57): a list change rebuilds the pipeline from the configuration text last loaded, not the file,
    which may be half edited; only SIGHUP reads the file, and its lists are fetched at once after.
  - Downloads (D57): an `https://` list is fetched with `https_only`, so a redirect cannot take it to `http://`;
    `http://` URLs stay for a server of one's own. A copy and its `ETag` never disagree: the old tag is removed,
    then the copy and the new tag are each written to a `.part` file, flushed, renamed and the directory flushed;
    the list counts as changed once its copy is renamed, a tag that cannot be written only logged.
- D65 (amends D42) Each upstream server of a forward stage has its own transport, written as in the CLI (D60,
  D61): `IP[:PORT]` over the client's (UDP for a query over UDP, TCP for one over a connection), `tls://` over TLS
  and `quic://` over QUIC, port 853 unless set, `#NAME` for the name the certificate must hold, else the address
  (RFC 8310 §8.1). An address only: a host name would need resolving before `dedensd` can resolve. One stage
  can mix transports, the first server over TLS and the next plain. Upstream certificates are checked against
  the OS trust store, or the PEM file of a top-level `upstream_ca`, which a reload cannot change (each thread's
  `dedens_net::Client` holds it; changing it logs that it takes a restart). `dedens-server` only carries the
  transport and name (`Server`, `Via`), staying sans-IO. Rejected: transport settings per stage (`transport:
  tls`, `tls_name`), which cannot mix servers.
- D66 (amends D42, D44) `dedensd` answers over TLS (RFC 7858) and QUIC (RFC 9250) on `listen` addresses behind
  `tls://` and `quic://`, port 853 unless set; with a top-level `tls: {certificate, key}` of PEM files, required
  with such an address and refused without one. A reload reads the files again and the next handshakes present
  the new certificate (`dedens_net::tls::Presented`, a rustls certificate resolver); a bad file fails the reload.
  rustls with ring, ALPN `dot` or `doq` alone, TLS 1.3 alone over QUIC, no 0-RTT (RFC 9250 §4.5). Over TLS a
  connection is a TCP one (D47's limits, its handshake within the idle time), its halves polled as the client's
  (D60). Over QUIC each query is alone on a stream the client opens, read to its end: a stream that is not one
  query behind its length, a Message ID other than 0, or an edns-tcp-keepalive option closes the connection with
  `DOQ_PROTOCOL_ERROR` (§4.3.3); a connection holds 64 streams at once and counts as a TCP one against the
  thread's connections; each thread's QUIC socket takes `SO_REUSEPORT`, so a client changing address may land
  on another thread and lose its connection. Replies to padded queries are padded (D60).
- D84 (amends D42, D44, D65; completes D82, D83) `dedensd` serves DNS over HTTPS on HTTP/3 (RFC 8484, RFC 9114) and
  forwards to DoH upstreams. A `listen` address `https://ADDR[:PORT][/PATH]` (port 443, path `/dns-query`; a path
  with a query, a fragment or a template expression is refused) takes UDP, as `quic://` does: the certificate of
  `tls` (D66) is required with it, ALPN `h3`, TLS 1.3 alone, no 0-RTT, the connection counted against the thread's
  TCP ones, idle time D27's, 64 request streams and 16 unidirectional ones (control and QPACK, D83) at once, the
  connection set up and each request read within that idle time. A request goes through D82's `server_request`,
  then the pipeline as any query (over `Transport::Https`: padding as D60 says); a request for another path is 404
  whatever its method, a query the pipeline drops is 400 (RFC 8484 §4.2.1: the status says the request is bad,
  not the DNS answer), the other statuses are D82's. The reply is D82's `server_response`: `cache-control` for a
  GET only. Stats (D30): `dedensd_doh_queries_total{method, status}`, the method `get`, `post` or `other` and the
  status one of those above or `other`, so labels stay few. An upstream `https://IP[:PORT][/PATH][#NAME]`
  (`Via::Https`, port 443, path `/dns-query`) is asked over D83's connection by GET, whatever transport the
  client came over; `#NAME` is the certificate name (D65) and the authority of the URL, else the address is. An
  address only, as D65: a host name would need resolving first (docs/TODECIDE.md). Rejected: HTTP/2 or
  HTTP/1.1 listeners (step 23), and `Listen` matching the request's authority, which the path alone serves.

## Observability

- D30 Metrics through the `metrics` facade, tracing through `tracing`; each library takes them behind its own
  `metrics` or `tracing` Cargo feature, compiled away without it, and the binaries turn them on by default.
  Handles are made once with the component, not looked up per event; no recorder means no-op handles.
  `dedens-proto` has none: its functions are pure and return errors, violations and truncation as values, which
  the server counts where it calls them. The cache counts lookups by outcome, prefetches, inserts and evictions
  (names in `crates/dedens-cache/src/metrics.rs`); spans belong to net, server and CLI, not to hot paths of proto
  or cache. `dedensd` will export Prometheus (not yet: it builds the cache without `metrics`); the CLI prints
  `tracing-subscriber` text on stderr (`dedensd` one JSON object a line, `--log-format text` for people, so tests
  and log pipelines read fields, not prose), `-v` for debug (dropped messages, retries, fallbacks, `+trace` referrals, a
  span per hop) and `-vv` for trace (every message sent and received), without `env-filter` and its regexes; its
  `dedens: …` errors stay plain output. OpenTelemetry later. Cost in `docs/benchmarks.md`.
