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
- D71 (amends D69; amended by D106) DNSSEC crypto is `dedens_dnssec::crypto` on `ring`, which is already in the lock
  through rustls, and `data-encoding` for test and bench data. Policy, after RFC 9904 §3 and RFC 6840 §5.2: validated
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
- D74 (amends D69; amended by D106) Denial of existence is `dedens_dnssec::denial`, pure set logic over NSEC and NSEC3
  records the caller verified, each signed by the zone's `apex` (step 06 checks; this trusts them and the module docs list
  what it owes). `prove` answers a question that got a name error, no data or a referral, `prove_wildcard_answer` one
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
- D75 (amends D69; amended by D86, D106) The validator is `dedens_dnssec::validator`, sans-IO:
  `Validator::new(TrustAnchors, Limits)` (shared, `Clone`, `Send + Sync`) and `start(question, response, now) ->
  Validation` for the final answer to a question, `start_referral` for a referral. The caller drives a `Validation`:
  `step()` is `Next::Ask(question)`, to send with RD, DO and CD set (RFC 6840 §5.9) and give back with
  `answer(Some(response))` or `answer(None)` (a failed query), or `Next::Done(Verdict)`. `step`, not `next`, and `now`
  once at `start`, not per call (the plan's sketch): a validation is one instant, so a chain cannot straddle a signature's
  expiry, and `Iterator::next` would mislead. `now` is `u64` Unix seconds, as the cache and the pipeline count seconds
  from any origin; the signatures take it modulo 2^32 (RFC 4034 §3.1.5, serial arithmetic, D73). A response that is no
  complete answer to the question (not its one question, in class IN, TC set) is `Indeterminate` at once, as an answer to
  one of the validator's own questions is, which also makes a truncated DS or DNSKEY answer indeterminate, never bogus
  (RFC 1035 §4.1.1). `Verdict` is RFC 4035 §4.3 with two more: `Secure { ttl }`, `Incomplete { next, ttl }`, `Referral {
  child, delegation }`, `Insecure { reason }`, `Bogus { ede }`, `Indeterminate { ede }`; `ede()` the code and text to
  attach (RFC 8914), the text of an insecure reason included.
  What Secure covers: every `RRset` of class IN in the answer and the authority section is authentic (RFC 4035
  §3.2.3, RFC 6840 §5.8), what the response lacks is proven absent, and the rcode agrees with the proof (a name error
  is NXDOMAIN, or NOERROR when compact, RFC 9824; no data is NOERROR; NXDOMAIN with an answer is bogus). It does not
  cover the additional section, other classes, the sets off the name path (Bailiwick, below), or the unsigned CNAME a
  DNAME synthesizes (RFC 6672 §5.3.3). `validator::covered(&Message)` is the one definition of what Secure covers:
  the response cut to the records it is about, computed with the validator's own predicates (the same `Parsed` and
  `synthesized`), so the two cannot drift; a caller hands out or shows `covered` of a secure response, never the
  response. It drops the additional section, other classes, the sets off the path, the RRSIGs that sign nothing,
  and the RRSIG of the CNAME a DNAME makes, which stays: the validator skips verifying that CNAME set only when
  every record of it is the one the DNAME makes (RFC 4035 §4.8 lets the resolver return it; a client that does not
  synthesize it would otherwise lose the answer), so another record in it is checked as any CNAME: unsigned,
  bogus. Secure is not the AD bit: the upstream's AD is never read, and the caller sets AD
  from `Secure` alone. A CNAME chain that stops before the type asked, with no denial, is authentic as far as it
  goes: `Incomplete`, the caller chases `next`, and it is never AD. A referral is no answer: judged as the final
  answer it is bogus (its NS records are unsigned, nothing denies the type) or insecure, so a forged referral has
  no way to secure; `start_referral` judges only the delegation, by the DS records of the child or their proven
  absence, and says `Referral` with `Signed` or `Unsigned { reason }`, never `Secure`, so no TTL and no AD come of
  it. A referral that answers one of the validator's DS questions is read as any DS answer: its DS or its
  proof, else bogus. `Referral { Signed }` is a verified DS `RRset` with a record of a supported algorithm and
  digest (else `Unsigned { UnsupportedAlgorithm | UnsupportedDigest }`, RFC 4035 §5.2, RFC 6840 §5.2); the NS
  records and the glue are unauthenticated and that the sender is the parent is not proven, so the caller treats
  a referral as a hint to follow. `Incomplete.next` is the server's: the caller bounds its CNAME chasing and takes
  no 0x20 entropy from it.
  Bailiwick: only the `RRsets` of the answer section at a name the answer passes through (the question's name and
  the targets of its CNAME and DNAME chain, or the owner of a DNAME above one) and those of the authority section
  at or above such a name are walked and verified; the others are out of bailiwick, change no verdict, and are
  cut by `covered`, as the additional section is. The chain of trust is walked top-down from the closest anchor to the owner of each `RRset` (the name asked for a
  DS, the parent's apex): the DS of each label, then where there is a zone its DNSKEY (RFC 4035 §5.2). The walk
  goes to the owner (RFC 4035 §5.3.1), never to the signer a signature names, so a rewritten signer cannot pick
  the keys, an `RRset` signed by an ancestor's keys is bogus, every RRSIG is tried (a junk one first costs
  nothing) and a forged signer cannot turn bogus into insecure. Signatures are grouped by owner and type
  covered once per response, and the first bogus `RRset` ends the check, so junk costs no more than its size. It
  costs one DS question per label below the last zone, which the key cache (D86) pays once; an IPv6 reverse name
  of 34 labels (a real capture, `ip6_ptr`) takes about 40 questions and 80 signature checks. A DS RRset is verified by the parent's keys and then
  vouches for the DNSKEY RRset (`trusted_keys`); no DS is the parent's NSEC or NSEC3 proof (D74): an insecure
  delegation (insecure, `UnsignedDelegation`), or no cut (the name is in the parent's zone). A DS question at a
  name that is a CNAME (or below a DNAME, or a wildcard CNAME) gets the CNAME: if it verifies, the name is no cut.
  Data below an insecure zone, at or below a negative anchor (D72, RFC 7646 §2, nothing asked), or with no anchor
  above it, is insecure. Unsigned in a secure zone, or in a zone the keys of which are not its owner's, is bogus
  (EDE 10, 6); every NSEC, NSEC3 and SOA of the authority section must verify, or the response is bogus, each with the keys of
  the zone that signed it among the zones the response is about (a wildcard answer of one zone and the no data
  of another carry proofs of both). A wildcard
  expansion also needs the no-closer proof of `prove_wildcard_answer`, else bogus (RFC 4035 §5.3.4). An opt-out
  proof, in a denial, a wildcard answer or the DS of a delegation, is insecure, `OptOut`, never secure (RFC 5155
  §9.2): `tests/testdata/README.md` says so of `google_com_ds`, `edgekey_net_ds`, `nxdomain_nsec3_optout` and
  `nxdomain_nsec3_salt`. Only verified NSEC and NSEC3 records signed by the zone reach `denial`. A negative proof
  lasts at most three hours and the SOA's TTL and MINIMUM (RFC 9077 §3.4), and the keys' TTL. Failures: a
  signature or DS that fails is bogus with `SigError::ede`; a DS no key matches, bogus with EDE 9; an unsupported
  algorithm or digest in a DS is insecure with EDE 1 or 2 (D71, RFC 6840 §5.2; RRSIGs of unknown algorithms are
  disregarded, D73); NSEC3 iterations above `Limits::iterations` (`MaxIterations`, default 150, D74) are insecure
  with EDE 27; `ConflictingNsec3Parameters`, a missing or contradictory proof and any other `Unproven` are bogus
  (EDE 12, 6); an exhausted `Budget` (D71, shared by the whole validation) is indeterminate, never bogus (it says nothing
  of the data: a long walk spends it) and never insecure (a forger would downgrade by spending it), and never
  stored in a zone's outcome. Its default here is 128 signature checks, where `Budget::default` has 64: the 34 DS
  proofs of the reverse name above need about 80. Limits are `Indeterminate`: more than `Limits::questions` (64)
  questions, a name more than `Limits::depth` (127, a name's most) labels below its anchor (counted from the anchor, so the order of
  the questions changes nothing; EDE 5), a question the caller could not answer (EDE 22), a response with an
  rcode but NOERROR and NXDOMAIN (EDE 5), NXNAME asked (EDE 30). Each zone's outcome (secure keys with their TTL,
  insecure, bogus) is written by one private function, `settle`, and read by one other, `zone_of`; delegations are
  not cached apart from them and an indeterminate outcome is never written, so D86's cache goes there and holds
  only what the data decides. `Validation::cost() -> Cost { questions, verifications, nsec3_blocks }` (additive,
  `#[non_exhaustive]`) is what the validation spent so far of those limits, for a caller that bounds what a
  client's query costs across validations, as D77 does. Not done: the SHA-1 switch (TODECIDE: it needs a filter in
  `rrsig`). Opt-out wildcards: the TLDs `ph` and `ws`
  serve a wildcard whose proof of the next closer name is an opt-out NSEC3, and their wildcard answer and no data are
  insecure (RFC 5155 §9.2), as 8.8.8.8, 9.9.9.9 and 1.1.1.1 (no `ad`) and BIND's `delv` (unsigned answer) say; a
  wildcard under NSEC (`internet.nl`) is secure, as they and `delv` say. Found by the captures: the DS of a name that
  does not exist under an opt-out span is an NXDOMAIN with the proof of an insecure delegation (RFC 5155 §8.6), which
  was bogus and is insecure now (an NSEC proof of one stays bogus under NXDOMAIN: the name is there). Not
  agreeing: 8.8.8.8 answers SERVFAIL (EDE 12) for the DS of `wildcard-test.internet.nl`, whose proof `delv` and
  1.1.1.1 and 9.9.9.9 (`ad`) accept, as the validator does (RFC 4035 §3.1.3.4). Tests: `tests/validator.rs`, a scripted caller that
  answers from the captures at `captured_at`: every capture with the verdict of its README, forged referrals,
  signers, rcodes, authority records, CNAME and DNAME hops, DS denials, mixed-case names, truncation. Fuzz target
  `validate`: any bytes as the response, its questions answered from the captured chains, whole, cut or with a bit
  flipped; seeded by the captures.
- D77 (amends D41, D43, D45; builds on D75; amended by D106, D114, D117) A forward stage validates with `dnssec: validate` (default
  `off`; `off` is read for the boolean YAML makes of it); `trust_anchors: FILE` (zone text of DS or DNSKEY records, else
  the bundled root) and `insecure: [names]` (negative anchors, RFC 7646) only with it, else the configuration is refused.
  One `Validator` per stage, built by `config.rs` at each read; a reload keeps the one of a stage whose validation is
  unchanged, the tag of its anchors file text and negative anchors the same (D55, D86). The wall clock is
  the caller's (`Validating::new(validator, clock)`, Unix seconds): the pipeline's `now` is a monotonic `u32`.
  The glue is `dedens-server`'s `validate.rs`: `Check` owns a `Validation` and the client's answer, and the
  pipeline turns each `Next::Ask` into a `Step::Upstream` whose `Upstream::request()` is the validator's question
  (RD, DO and CD, no client option, AD clear: RFC 4035 §4.6, RFC 6840 §5.9) and which goes to the server that
  answered the last question: one that failed is not asked again by the same query, so a dead server costs one
  question's patience (`tries`/`timeout_ms` of D45), not each one's. So `serve.rs` is unchanged. A validating
  stage's query for the client's own question also carries CD and DO whatever the client set; a client with CD (or
  a question not of class IN) is answered unvalidated, AD clear, from a plain forwarder's query (the client's AD
  and CD, RFC 6840 §5.7; upstream's AD is not read). Every
  validation question is an upstream query of its own and counts as one (`dedens_validation_questions_total`); none
  is read from or written to the answer cache, and each answer is untrusted input to the validator. A key cache
  (06b) slots into `Validating`, not the pipeline. Prefetch and stale refresh validate as any query.
  Verdicts (`dedens_validations_total{verdict}`): AD is set by `Secure` alone, never from the upstream's bit, and
  only for a client with DO or AD (RFC 6840 §5.8). A secure response is cut by `validator::covered` (D75) to
  what the verdict covers before it is served or cached: the additional section, other classes, the sets the
  validator ignores and the RRSIGs that sign nothing are dropped (RFC 4035 §3.2.3); the CNAME a DNAME makes stays.
  Every TTL is capped at the verdict's. `Incomplete`: the answer of
  `next` is validated apart, at most 8 names a query (as `dedens`; `next` is the upstream's, not 0x20 entropy, and
  dedensd sends no 0x20); the chain's answer is then delivered insecure, AD clear, cached at most as long as the
  incomplete part, whatever the second verdict, but bogus and indeterminate end it, and a ninth name is
  indeterminate. All the questions of a query, the chase included, are at most 64 (`MAX_QUESTIONS`; the
  validator's `Limits` bound each validation separately): past it the verdict is indeterminate.
  Cost (`validate.rs`, `Allowance`): D75 bounds one validation, but a client can send many cheap queries that each
  walk a chain, and a chase starts a validation for each name (up to 9 × 128 signature checks). A unit is a question
  upstream (the client's too), a signature check, or 4096 NSEC3 hashes (`Validation::cost`): about 10 µs on the
  common algorithms, 340 µs on a P-384 one, the worst a unit stands for (`benches/dnssec.rs`, `benchmarks.md`). One
  query costs at most `Allowance::per_query` (256), the sum over its chase: past it the verdict is indeterminate
  (EDE 5, validation ran, failure held as any). All the queries share a token bucket in `Validating` (clones share
  it; `Validating::allowing`; defaults: `per_second` 10 000, `burst` 20 000): `Pipeline::query`, before the client's
  question is sent, takes a unit if the bucket has one left, and the query that finds none is answered SERVFAIL
  with EDE 14 (Not Ready) and nothing is asked, decoded or validated (`dedens_validations_total{verdict="shed"}`);
  the work of the validations is charged to it as it runs, so it can go into debt (at most the in-flight queries'
  `per_query` each) and is refilled by the clock of `Validating` (a clock gone back refills nothing). Shed is not
  failed: nothing is held in the cache, or a flood would fail the names it asks for, and the client may ask
  again; a refresh that finds the bucket empty is not made, the reply stands. EDE 14, not 22/23 (those claim an
  upstream or network failure, none was tried, and a client's resolver retries elsewhere and moves the flood), nor
  5/6 (no DNSSEC verdict was reached). Each client network has a share of it too (D117); the bucket
  here is the global one. A hit in the cache stage costs no unit, a client with CD
  none; a warm validation (D86) two. Measured: `serve_shed` 0.11 µs, `serve_warm` 6.2 µs, `serve_cold` 110 µs, no
  slower from 1 to 8 threads (`benchmarks.md`). Tests: `tests/limits.rs` of `dedens-server`, `a_validation_reports_what_it_cost`
  in `dedens-dnssec/tests/validator.rs`. `Insecure`: AD clear, cached as it came, for at most `max_insecure_ttl` (D93). `Bogus`: SERVFAIL with the EDE code
  (RFC 8914; the code only: the OPT of a reply carries no text), and the response cached for `Config::bogus_ttl`
  (60 s, Unbound's `val-bogus-ttl`; RFC 4035 §4.7: small, assigned), never served stale; a hit answers
  SERVFAIL+EDE without validating, a client with CD gets the data (RFC 4035 §3.2.2: the cache stores it under the CD
  key as well, `Checked::Insecure`); a prefetch or stale refresh that turns bogus is dropped, not stored: bad data does
  not replace good data still in the cache. `Indeterminate`: SERVFAIL with EDE, not cached: the failure hold of D43 (RFC 9520)
  starts, which may outlast 60 s once repeated. A question unanswered by every server is indeterminate, not bogus.
  Cache: an entry records `Checked` (`Unchecked`, `Secure`, `Insecure`, `Bogus(code)`) beside the response; a hit
  sets or clears AD from it (only `Secure` sets it, D114; clear on a secure entry served stale: expired data is no longer vouched for by the
  signatures), and nothing else of DNSSEC is in the cache. A reload keeps the cache stage only while every forward
  stage validates the same way (`Validating::tagged`: dnssec mode, trust anchor text, negative anchors, set by
  `config.rs`): else entries from another validator, or none, would be served under the old AD and verdicts. It stores each response whole under the
  client's key (DO and CD bits), so the RRSIGs are in a DO client's entry and out of the others' (RFC 4035 §3.2.1,
  §4.5: one atomic entry per answer): no per-RRset storage. Not done (TODECIDE): the BAD-cache threshold of RFC 4035
  §4.7, an EDE on a cached insecure answer or `InsecureReason::info_code()`, an EDE 22/23 for an upstream SERVFAIL, a
  validation deadline, aggressive use of NSEC (RFC 8198). `Forward` no longer implements `PartialEq` and `Eq`: it
  holds the validator's closure. Tests: `tests/rfc4035.rs` and
  `tests/rfc6840.rs` of `dedens-server` (upstream answers the captures of `dedens-dnssec` at `captured_at`),
  `dedens-cache/tests/checked.rs`, the configuration tests of `config.rs`; bench `hit_secure` of `benches/server.rs`.

- D76 (amends D32, D34, D37, D40, D69; amended by D86) `dedens +validate` is a validating stub resolver (RFC 4035 §4.9, RFC 4033 §5):
  the server is a transport, never trusted. `validate` is an `Options` field, so a query file carries it, and it
  sets DO and CD on the query (the response is wanted even when it is bogus, RFC 6840 §5.9; RD stays as the user
  has it) and gives `dedens_dnssec::validator` the response: `apps/dedens/src/validate.rs` is the glue, a loop
  `step()`, send, `answer()` (D75). Each `Next::Ask` goes to the same server over the same transport, with the
  query's own options (UDP with the TCP fallback, TLS, QUIC, HTTPS, CoAP, ODoH proxy), and an unanswered or
  unreadable one is `answer(None)`. One `Validator` per set of anchors in a run, shared by its queries and its key
  cache (D86), so only a query that finds no zone known asks the chain, one DS question per label (`-v` traces each
  question). The
  upstream's AD bit is never read: the human report names it `AD set by the server` once a verdict is shown, apart
  from the verdict. Only `Secure` is shown as validated, and then only what it covers (D75): the report of a
  secure response is `validator::covered` of it, as dedensd serves it; `--save-wire` keeps the response as received. `Incomplete { next }` is chased: `next` is
  asked of the same server and validated on its own, at most 8 times, then indeterminate; the verdict is that of
  the last answer, never an AD of the first. `Referral` cannot come of `start`; a `Referral` or `Incomplete`
  that reaches the report is indeterminate. `--trust-anchor FILE` (DS or DNSKEY records in zone text,
  `TrustAnchors::read`, D72) replaces the bundled root anchors, `--insecure NAME` (repeatable, `insecure:` a list
  in a file) adds negative trust anchors (RFC 7646, no end time, TODECIDE); each of them turns validation on unless
  `+novalidate` says otherwise, so an anchor file is never silently ignored. `+noedns`, `+nodnssec` and `+nocd`
  with validation, and `+trace` with it (a trace does not follow CNAMEs or ask a chain, D40), are usage errors,
  as D32 does for options needing EDNS; a file whose `expect` has `dnssec` for a query that does not validate
  is an error at load. `DEDENS_NOW` (Unix seconds) replaces the clock of validation, as `DEDENS_ROOTS` does the
  roots, for tests. The report has a `dnssec` object, `status` (`secure`, `insecure`, `bogus`, `indeterminate`),
  `ede` (`code`, `purpose`, `text`, as an EDE option of the response) and `reason` (an insecure verdict's words),
  in JSON and YAML; the human format ends with one line, green when secure, plain when insecure, red with the
  EDE when bogus or indeterminate; `+short` prints nothing of it but a line to stderr for the last two, like a
  violation. The expectation `dnssec: secure|insecure|bogus|indeterminate` (D34) fails the query as any other,
  exit 1. Exit codes stay D33's: a bogus response alone exits 0, since the verdict is the answer the tool
  gives. Tests: `apps/dedens/tests/cli.rs` against the captures of `crates/dedens-dnssec/tests/testdata` at their
  `captured_at`: secure, insecure and bogus in each format, the questions asked, a wrong or a right anchor file,
  a negative anchor, the expectation, the usage errors; by hand against 1.1.1.1, `cloudflare.com` is secure and
  `dnssec-failed.org` bogus with EDE 9.

- D86 (amends D75, D76, D77; amended by D92) The key cache: what a `Validator`'s validations learn of zones is kept
  for the validations after them, in `validator/cache.rs`. It is written by `settle` and read by `zone_of` (D75), nothing
  else, so the rules for what goes in live in one place, `Zone::lifetime`. It is inside the `Validator` behind a
  `Mutex` (the `Validator` stays `Clone`, `Send + Sync`; clones share it), and anchors and limits are fixed for a
  validator, so a change of trust anchors or negative anchors is a new `Validator` with an empty cache, and nothing
  stale outlives it; a reload that changes neither keeps the `Validator`, so the keys stay (`config.rs` compares the
  tag it gives `Validating`, as it does for the answer cache, D77). API, additive fields only: `Limits::key_cache` (`usize`, entries per table, default 4096; 0
  turns the cache off) and `Limits::key_cache_bytes` (`usize`, default 4 MiB); `Limits { .., ..Limits::default() }`
  as before. `Limits` is not `#[non_exhaustive]`: the integration tests and the callers of steps 07 and 08 build it
  as a struct literal with `..Limits::default()`, which `#[non_exhaustive]` forbids outside the crate; a literal
  without the `..` breaks with any new field. `Validation::start` takes the time as before: it is the cache's
  clock too, so there is no clock inside.
  Kinds and TTLs. Secure keys: the TTL `keys_from_ds` and `anchor_keys` give, the least of the verified DNSKEY
  `RRset`'s, the DS `RRset`'s and the signatures' remaining validity (RFC 4035 §5.3.3, RFC 2181 §8), and no more
  than a day, whatever the signatures allow (Unbound's `cache-max-ttl` 86400: a key rolled over or a DS removed
  waits no longer; the same cap holds for every kind). Insecure
  (unsigned delegation, opt-out, unsupported algorithm or digest, NSEC3 iterations above the limit): the TTL of the
  proof, that of a denial held to the keys' and RFC 9077 §3.4's three hours (an opt-out proof's TTL lacked both
  until now: nothing read it). A name that is no zone cut (a proven absence of DS, or a verified CNAME or DNAME)
  is kept with the TTL of that proof, with the insecure zones. Bogus: 60 seconds
  (Unbound's `val-bogus-ttl`), for a zone only, by name (superseded by D92). A hit gives the TTL it has left, so what
  is derived from it never outlives it, and a hit is never written back, so reading renews nothing.
  Never kept: an indeterminate outcome or one of the budget (D71), nor `Failure::Transient`: a bogus verdict that
  says nothing lasting of the zone: every bogus found before the zone's keys were reached (a DS that fails, a
  denial that does not hold), the signature limit of D73 (`TooManyFailures`), a DNSKEY answer that is empty,
  missing, unsigned, of keys no signature names, expired or not yet valid (`SigError::is_proven` is false: any
  answer can lack those, and a replay repeats them), any bogus resting on the response `start` was given
  (`Validation::seeded`: the caller's, however fetched) (superseded by D92: no failure is kept), and any outcome
  inherited from the parent zone (`Zone::Beneath`, recomputed from its entry); nor what a trust anchor decides (no
  anchor, negative anchor), which is the `Validator`'s own and costs nothing to find. A validation keeps what it settled in its own map as
  before (so no step spends the budget twice) and copies a hit into it, so that it sees one outcome whatever the
  cache does meanwhile.
  Time: an entry is a hit while `at <= now < at + ttl`, `at` the time given to the validation that wrote it. A `now`
  before `at` (the clock gone back) is a miss, never a longer life.
  Poisoning. Secure, insecure and no-cut entries come of verified data only: a signature under keys that a DS or
  an anchor vouches for, a denial bound to the name asked, so what an attacker sends is either true (then it is what
  an honest answer gives) or no entry. One validation's forged DS, signature or denial changes no other
  (`tests/validator.rs`). The one thing a forged answer can still do is the bogus zone, and only for two facts:
  the DNSKEY answer to the validator's own question under an authentic DS or anchor either lacks the key the DS
  digests (`NoKeyForDs`) or has a signature by that key that does not check (`BadSignature`). Whoever answers that
  question can say so, as it could for its own validation: no answer is authenticated before its keys are, and a
  sans-IO validator does not retry another server or TCP as Unbound's iterator does before it stores the failure
  (no `Next::Retry`: TODECIDE has the cost and the case for it). The entry is kept to what limits the harm: 60 s,
  fixed, never renewed by a hit, one zone (the name of the zone that failed, not its children's names)
  (superseded by D92: no bogus zone is kept).
  Bound: three tables by kind, keys of secure zones, names (no zone cut, insecure zone) and bogus zones, each with
  its own entry bound (`key_cache`) and its share of `key_cache_bytes` (half, a quarter, a quarter) (superseded by
  D92: two tables, half each), each evicting
  its least recently used entry (a hit is a use; an expired entry is dropped when read; a `HashMap` and a `BTreeMap`
  by tick, so insert, hit and eviction are logarithmic under the lock, never a scan). A flood of names under a zone
  of an attacker, each with a proof of no DS and the longest TTL it can have, evicts names, never keys; the TTL
  decides nothing about eviction. An entry costs 256 bytes, its name twice (the slot and its recency entry), the owner again and each
  key as its struct and bytes for a secure zone, each allocation with 16 more (an estimate of what the allocator holds,
  not a measurement), and a zone whose keys cost more than 16 KiB (a DNSKEY `RRset` padded with keys no DS names: the signature covers them all, and every key of
  the set is trusted, so the set cannot be cut to the keys a DS names) is used by the validation that found it
  and not kept: an attacker pins no more than 16 KiB for each name of a zone it signs, and no more than 2 MiB of
  keys all told by default. At the 4 MiB default a real set (two or three keys, about 1 KiB on the wire, about 1.5 KiB as cost) leaves room for
  some thirteen hundred zones; a resolver for more raises `key_cache_bytes`.
  Rank: an entry of a weaker kind never replaces a live one of a stronger (keys over names over bogus), so a
  forged answer, or a denial replayed while its signatures last, cannot unseat the keys of a zone, nor a bogus
  entry a proof of insecurity; once the keys expire the name is free (the bogus rank superseded by D92). The price
  is that a real change (a DS removed, a zone made insecure) waits for the keys' TTL, at most a day, as for any
  cache of keys.
  Known and left: a CD=1 answer found bogus is stored as insecure for 60 s (`insert_checked`), over a fresher entry
  of the same key, the same upstream data; and the SOA owner of a negative answer is not checked as the zone's apex, so
  it sets only the negative TTL, which the cache caps.
  A `Mutex`, not an `RwLock` or shards: a validation runs only for a response the response cache lacked, the lock is
  held for one lookup or insert, never across a signature check, and `validate_warm` at 8 threads
  slows 5x against the lock-free `validate_cold`'s 2.2x (`benchmarks.md`: in a tight loop of 4.6 µs validations the
  lock shows, which real validations, far fewer than one per cache miss, do not). Measured: a warm validation of
  `alg8_a` is 4.6 µs against 106 µs, asking no question (the first figures, 54 and 168 µs, counted a file read
  of the bench). Singleflight (`apps/dedensd/src/flights.rs`, the layer that sends): the questions of the validator
  (`Upstream::probe`, not the client's own) in flight are keyed by server, UDP or not (a truncated UDP answer is
  no TCP one) and question, in a map shared by the threads and kept across reloads (`Current`). The first query to
  need one sends it; the others wait for its response and hand it to `Pipeline::receive` as their own. The sender
  publishes after its own `receive`, which settles what the response proved in the key cache, so a query that
  asks after finds the zone cached; one that was already walking the zone verifies it again (a pending zone in the
  validator would make `step()` wait, which the sans-IO validator does not say: TODECIDE). A sender that fails
  to send, or is cancelled, frees the others to ask; one whose server did not answer hands the others that
  failure, as theirs. The validator crate is unchanged. Tests: `flights.rs` unit tests, `tests/flights.rs` of
  `dedensd`: 8 clients make one DNSKEY question of the root, not 8.
  Tests: `tests/validator.rs`, a warm validation asks none, the entry holds for its TTL and not a second more, a
  clock gone back, an answer nobody gave, an exhausted budget and a forged DS are not kept, a bogus zone is held 60 s
  and not renewed (superseded by D92), a DNSKEY answer that proves nothing, or that `start` was given, is never
  kept, insecure and no-cut entries are kept, a negative anchor is its validator's own, clones and threads;
  `validator/cache.rs`, the flood, LRU order, bytes and the entry limit, rank, the day and the clock gone back. Fuzz target `validate`: a new
  validator per input, the validation run twice with the same answers (picked by question), the second from the
  cache of the first, and the two verdicts agree unless one is indeterminate.

- D92 (amends D86) The key cache keeps no bogus zone: its tables are two, keys and names. A validation that fails
  at a zone's keys settles it in its own map as before (no step spends the budget twice), and the next
  validation walks the zone again. Gone with the table: `Kind::Bogus`, `BOGUS_TTL`, `Failure::Transient`
  (now a bogus verdict, as any), `Unusable::undecided`, `Validation::seeded` and `SigError::is_proven`, which
  only decided what the table could store; `key_cache_bytes` is half for keys and half for names (the names
  table doubled, the keys' share is as it was). The response cache keeps a bad answer for `Config::bogus_ttl`
  (D77), per question, never served stale.
  Why. A DNSKEY answer is no authenticated one before its keys are, and whoever sends it, a server of the
  stage, a forger or a replay, can lack the key the DS digests or break the signature of that key. The 60 s
  entry made that one answer the verdict of every validation under a sound zone: a one-answer denial of the zone
  for a minute, to every client. Unbound stores the failure only after it tried its other servers; the sans-IO
  validator cannot, and `Next::Retry` would add a variant every caller of `step()` matches (`dedens`,
  `dedens-server`, the fuzz target), a retry state per zone, and a way to ask a server other than the one that
  answered (an `Upstream` knows its next server only after a failure; a stage of one could only repeat over TCP).
  Less code wins: with no entry, a lie costs the validation it was told to, and the next one asks again.
  Revisit `Next::Retry` when a deployment forwards to several servers, one of which lies or breaks, and a bogus
  zone shows in its logs.
  Cost. A zone bogus to everyone is walked by each validation under it: for `rhybar.cz` (its DS matches none of
  its keys; the keys of `cz` cached) 2 questions, the DS and the DNSKEY, and one signature check, the same every
  time (`tests/validator.rs`). The validator's questions never use the answer cache (D77), so each query for a
  name under such a zone costs those 2 upstream questions, whatever the response cache holds; only concurrent
  ones share them (singleflight, D86). The response cache holds the bad answer 60 s per question, so with a cache
  stage a client asking the same question costs one walk a minute; without one, every query does. RFC 4035 §4.7:
  a resolver with a BAD cache "MUST take steps to prevent the cache from being useful as a denial-of-service attack
  amplifier". Here the bad answer's TTL is small and assigned (`bogus_ttl`), and what an attacker can make a
  query cost is bounded: by the questions, budget and failed checks of one validation (`Limits::questions`,
  `budget`; D73, D75) and by the allowance of all of them (`Allowance`, `per_second`, D77), a flood of different
  names paying it as any uncached query does. Not met: §4.7's threshold of failures before a bad answer is
  served from the cache (TODECIDE, D77).
  Tests: `validator/cache.rs`, a failure and a name inherited are kept nowhere; `tests/validator.rs`, a bogus zone
  is asked again each time and the sound zones around it keep their keys, repeated walks under a bogus zone cost
  2 questions and 1 check each, a failure an answerer can force is the validation it lied to and no other, and
  the DNSKEY answers that prove nothing or that `start` was given are never kept (D86, as before). `validate_*`
  and `serve_*` do not move (`benchmarks.md`, run before and after).
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
- D27 (amended by D50, D53, D108, D114) Client behaviour:
  - UDP: a pool of sockets per server (D50); a random ID from `getrandom`, drawn 256 bytes at a time: a call costs
    846 ns on macOS, 14 ns on Linux (vDSO).
  - Matching: source address, ID and question (case-insensitive) or the datagram is dropped and the wait goes
    on, as hickory and Unbound do; miekg/dns fails on a wrong ID and CoreDNS checks the ID only. `0x20` case
    randomization of the question is an option, off by default as in Unbound.
  - dig's defaults: 3 tries, 5 s each. TC over UDP is retried over TCP. EDNS is dropped once on FORMERR or
    NOTIMP to an EDNS query (RFC 6891 §7), never on a timeout (RFC 8906); `+noednsneg` turns it off. A query
    changed by a fallback goes with another ID, so a late response to the query before cannot end the exchange
    (D114 says how the ID is drawn and when EDNS is dropped).
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
    write (D53), at most 1024 (D108). A write lasts the idle time at most, and a query that times out with no
    response read on its connection since it was sent closes it: a server that stopped reading or answering is replaced. A connection
    that cannot open fails each query waiting for it with its error. A connection slower than a try, waited for
    the source address of a cookie, costs that try, not the exchange.
- D31 (amended by D114) The sans-IO exchange (`dedens-net::exchange`) takes the query whole from the caller, ID and
  cookie in it, and owns no randomness or secret (D114: the IDs of changed queries come from the caller too); `0x20`
  takes its random bits as an option, which also turns on the exact-case match, so a randomized question is never matched loosely. Each step consumes the `Exchange`
  and returns `Send`, `Wait` or `Done`: a finished exchange cannot be fed. Only timeouts spend tries, and tries lost to a socket error or a slow connection; the TC,
  EDNS and cookie fallbacks each happen a bounded number of times. Stricter than dig: FORMERR and NOTIMP
  alone may leave the question out (D114); once a server has sent a cookie, a response without one is dropped, even
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
- D61 (amended by D109) DoQ (RFC 9250) goes through compio's QUIC (`compio-quic`, quinn-proto underneath), no QUIC of our own.
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
    queries to 468 bytes (D60). TC means the server could not get a full answer (§9), not a retry over TCP. A POST
    states its `content-length`: `cloudflare-dns.com` answers an HTTP/3 POST without it 405 (found by the live check
    of D84, 2026-11-01; HTTP/2 clients always send it, and `h3` does not add it).
  - Checked live (2026-11-01): `dns.google`, `cloudflare-dns.com`, `dns.adguard-dns.com`, `dns.quad9.net` and
    `dns.nextdns.io` answer GET and POST over HTTP/3 (the first, second and fourth advertise `h3` in Alt-Svc;
    AdGuard and NextDNS answer without one); `doh.opendns.com` and `doh.mullvad.net` do not answer HTTP/3.
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
- D83 (completes D82; amended by D109) The client asks DoH over HTTP/3, `Transport::Https` in `dedens-net::https`. RFC 9114 over a
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

- D79 (amends D69, D78, D83; amended by D94, D115, D117) ODoH over HTTP/3 (RFC 9230 §3, §4), `odoh` feature, off by default: `dedens` asks a target
  through a proxy, `dedensd` serves as a target. `dedens-proto::Transport::Odoh` is the transport, reported `ODoH`.
  - Messages: a client sends the encrypted query by POST to the proxy (RFC 9230 §4.1: media type
    `application/oblivious-dns-message` as content type and accept, `targethost` and `targetpath` in the query of the
    proxy's URI, which `+odoh-proxy=URI` gives as a plain `https://HOST[:PORT][/PATH][#NAME]`); `targetpath` keeps `/`
    unescaped, as the RFC's example, and escapes every other reserved character. Without a proxy (tests, a target
    asked directly) the POST goes to the target's URI. The query is ID 0 (RFC 8484 §4.1; RFC 9230 does not ask for
    it, DoH does, and a target answers the same) and not padded with EDNS: the padding is inside the encryption
    (`query_padding`, `response_padding`, D78), so the message is one block of its own. A response is read only from
    a 2xx of the media type (§4.3); a 3xx is an error (no redirect is followed). The request carries
    `content-length`: Cloudflare's target answers 400 to an HTTP/3 POST without it (found by the live check).
  - Configurations: fetched by GET from `/.well-known/odohconfigs` of the target (a convention, RFC 9230 §5 leaves
    discovery out; Cloudflare, `odoh-rs` and `odoh-go` use it) and kept per target. The fetch goes straight to the
    target, not through the proxy: a proxy relays POSTs of oblivious messages only (§4.1), and public ones relay no
    GET. Cost: the target sees the client's address (never a query, which is all §8 protects) and may link the query
    that follows to it by timing, so the fetch must be rare: the lifetime is `Cache-Control: max-age` less `Age` and
    the age `Date` shows (RFC 9111 §4.2.1), but never under an hour (`MIN_KEPT`) nor over a day (`MAX_KEPT`), whatever
    the target says, `no-store` and `no-cache` without field names included: the configurations are public keys, and
    Cloudflare's `no-cache, no-store` would otherwise cost a fetch per exchange; a skewed clock only shortens the
    lifetime, to the hour. `no-cache="field"` does not forbid keeping. At most 64 targets are kept (expired first,
    then the soonest to expire). A client of one exchange per process (`dedens`) fetches each run anyway: when the
    target forbids keeping and a proxy is used, it prints a warning on stderr (`odoh::Notice::ConfigsNotToBeKept`,
    from `Client::take_odoh_notices`), and `+odoh-config=FILE` (a file of the configurations as the target serves
    them, `Client::pin_odoh_configs`) fetches nothing: pinned ones never expire and are never fetched again, a 401 is
    an error then. Other discovery (through the proxy, SVCB) is in `docs/TODECIDE.md`.
  - Errors: a 401 (the target does not hold the key, §4.3) after configurations kept from the cache fetches them
    again and asks once more, when the target made it: with a proxy, a response
    with a `Proxy-Status` header holding an `error` parameter (RFC 9209) is the proxy's (`OdohError::Proxy`) and ends
    the exchange (a proxy that answers 401 for its own reasons must not make the client leak its address). A response
    that does not decrypt, and any error of the encryption, end it: the configurations are not at fault. After
    configurations fetched for this exchange, or pinned, a 401 ends it too (no loop, no second fetch). The cache is
    the client's own (`Client`, per target address and authority), not shared between `Client`s.
  - Client API: `Client::exchange_oblivious(query, target, proxy, options)` (not `exchange`, which refuses
    `Transport::Odoh` with `ClientError::OdohWithoutProxy`: the proxy is a second server). Randomness is
    `odoh::Entropy`, 64 bytes read from the OS when the exchange starts and wiped when dropped, so an OS failure is
    an error (`OdohError::Random`); `encrypt_query` draws 32 bytes, `encrypt_response` 16 (tested), and a draw beyond
    the 64 gives zeros and fails `Entropy::finish`, which the caller asks after the encryption, so that no draw panics
    and none is silently weak. The proxy URI is a plain one, not an RFC 9230 §4.1 URI Template: one that already
    holds `targethost` or `targetpath` is refused (`OdohError::ProxyVariables`). A message may be a kilobyte over
    a DNS message's cap (`odoh::MAX_BODY`: the header, the encapsulated key, the tag and the padding), at the HTTP
    reader and at `classify`. The HTTP side is sans-IO functions in `dedens-net::odoh` (`request`, `configs_request`, `response`, `configs_lifetime`, `classify`,
    `target_response`, `configs_response`) over `http` types, tested without a socket; the fuzz target
    `read_odoh_http` covers the readers of outside data.
  - CLI: `+odoh-proxy=URI` with an `https://` target server (D83's); usage errors (exit 2) without such a target, with
    `+tcp`, `+tls`, `+quic`, `+https-get` or `+trace`; `+noedns` is accepted (the padding is not EDNS's); a build
    without the feature refuses the option.
  - `dedensd`, feature `odoh`: a section `odoh:` makes each `https://` listener a target at its path (default
    `/dns-query`): a POST of the media type is opened, asked of the pipeline as a query over `Transport::Odoh`
    (padded replies are the encryption's, so the pipeline's EDNS padding is off for it) and answered sealed with
    `Cache-Control: no-cache, no-store` (§4.1); a key that is not the target's is 401 and a message that does not
    open 400 (§4.3, D78). `GET /.well-known/odohconfigs` answers the configurations with `max-age=3600`, unless the
    listener's own path is that one (the listener wins). Plain DoH stays served at the same path. The key is the
    secret of `odoh.key`, a file of 64 hexadecimal digits (`openssl rand -hex 32`; at most 256 bytes, read into a
    buffer wiped on drop; a file others can access is refused and one its group can access warned about on Unix, D115), else a random one made at
    start (so the configurations change at each start). A reload keeps the key and never reads the file again: a
    changed `odoh` section (the key file's path) is ignored with a warning (it takes a restart), and a key file that
    went bad fails no reload. `odoh` without an `https://` listener is an error. Metrics: `dedensd_doh_queries_total`
    gains status 401 and counts no configurations GET (not a `DoH` query). The unauthenticated decapsulation per
    POST is bounded since D117.
  - Not here: HTTP/2. The proxy role is D94's.
  - Checked live (2026-11-01, `dedens @https://TARGET/PATH +odoh-proxy=PROXY example.com A`, the targets and
    relays of `DNSCrypt/dnscrypt-resolvers` `v3/odoh-servers.md` and `odoh-relays.md`): every target below answers
    HTTP/3 and serves, at `/.well-known/odohconfigs`, one config of version 1 with the one suite of D78 (no other
    suite, no unusable config, in any of the five or the dnscry.pt ones): `odoh.cloudflare-dns.com` (`no-cache,
    no-store`, so the warning above; its key is the one of `tests/testdata/odohconfigs-cloudflare.bin`),
    `odoh.crypto.sx`, `doh.tiar.app` (path `/odoh`), `dope.snowstorm.love` and `doh.tiarap.org` (path `/odoh`); the others send `max-age=86400` or no `cache-control`, so no warning. Each answered the CLI asked directly (the target as
    its own proxy) and through `odoh-relay.edgecompute.app` (Fastly, path `/`, HTTP/3: `targethost` and `targetpath`
    with `/odoh` and `/dns-query` accepted), except `doh.tiarap.org`, which this relay refuses (403 for that
    `targethost`, also with a plain `curl`). The other listed relay, `odoh-relay.numa.rs/relay`, advertises `h3` in
    Alt-Svc but answers no QUIC packet from here (`aioquic` too), so every try times out (exit 9); over HTTP/2 it
    answers (`curl`: 400 for a bad message), which waits for step 23. A wrong key (the configurations of another
    target, `+odoh-config=`) is a 401 from Cloudflare and `doh.tiar.app`, direct and through the Fastly relay, so
    the exit is 10 with the 401 and no second fetch, as pinned configurations say. Pinned right ones
    (`+odoh-config=` on the file `curl` saved) fetch nothing and work through the relay, with or without EDNS.
    The responses decrypted every time; those of `odoh.crypto.sx`, `doh.tiar.app` and `doh.tiarap.org` carry their
    own EDNS padding to 132 bytes, the other two none. Checked live later, 2026-11-01 (`just odoh-live`): a key rotation
    cannot be provoked on a real target, but a key it does not hold stands for one: `Client::keep_odoh_configs`
    keeps such configurations as a fetch (pinned ones never refetch), and `odoh.cloudflare-dns.com` and
    `doh.tiar.app` each answered 401, then the real ones were fetched once and the query was answered; pinned,
    the same configurations ended in the 401. Our `dedensd` as a target for a client that is not ours: Cloudflare's
    `odoh-rs` 1.0.5 sealed three captured queries at paddings 0, 17 and 400 to its configurations over HTTP/3
    (`aioquic`) and opened every response; 401 for a key it does not hold, 400 for a damaged ciphertext
    (`tests/interop/odoh.py`). Not checked live: that a target refuses a badly padded query (tests only), and the
    size on the wire of our padded query.
  - Tests: `crates/dedens-net/tests/rfc9230.rs` (the request of §4.2, §4.3's statuses, the captured Cloudflare
    headers and configurations, a loopback target direct and through a loopback proxy, the 401 refetch, and the
    ignored live one), `tests/interop/odoh.py` (by hand: `odoh-rs` against `dedensd`),
    `apps/dedensd/tests/rfc9230.rs` (the real `dedensd` as target), `apps/dedens/tests/odoh.rs` (the command).

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
    block in a new message ID and the same token; the server's smaller block size is followed. The ETag is
    compared across blocks (a change is `Failure::ETagChanged`), and `Params::require_etag` (off by default, the
    RFC only asks the server for one) makes a first block with More set and no ETag `Failure::MissingETag`: without
    it two versions of a body would be put together unseen. A request over `block1_size` goes in Block1 blocks, 2.31 answered by the next one, the server's
    smaller size followed. A follow-up for a Block2 carries the request's payload when the request went whole, as
    a FETCH body is part of the cache key (RFC 8132 §2) and a server keeping nothing needs the query again;
    aiocoap's and libcoap's clients send none, and their servers do not need it (libcoap's
    `coap-server` answers our follow-ups with the body as well). Block1 requests' follow-ups carry none (RFC 7959
    Figure 10).
  - `server::Dedup` remembers the reply to a confirmable request by (endpoint, message ID) for EXCHANGE_LIFETIME
    (247 s), at most a given number of entries, the oldest dropped first, only for a message that is new; a duplicate
    gets the same reply, at most `MAX_RETRANSMIT` times (D105).
  - Fuzz: `parse_coap` reads arbitrary datagrams; `coap_doc` is stateful, an `Exchange` against a model of the
    listener (`doc::query` and `response`, a `Dedup`, the Block1 and Block2 sizes, a body that changes between two
    blocks, retransmission, duplicates, time, bytes of any kind for a reply) holding that a body is one of the
    server's, whole.
  - `docpath` is `SvcParam::DocPath(Vec<Box<[u8]>>)` (RFC 9953 §3.2, key 10): the wire is `alpn`'s with empty
    segments allowed, the text a comma-separated list, no segment the root path. One empty segment prints in the
    `key10="\000"` form, a single empty item being no different from the empty list in the text.
  - Tests read datagrams captured from aiocoap (`capture.py`) and from libcoap 4.3.5b (`capture_libcoap.py`, its
    `coap-server` and `coap-client` through a logging proxy, `tests/testdata/coap/`; the real DNS answers of 2808 and
    1280 bytes it blocks are DoH captures). Checked live against libcoap: our client against `coap-server` (FETCH
    of a stored DNS answer, Block2 in 3 blocks of 1024, Max-Age 60 by default), and `coap-client` against
    `dedensd` (below, D81). Taken from the captures: libcoap's client sends an empty token, Uri-Port and Request-Tag
    on every request; its server blocks at 1024 by itself with ETag and Size2, answers a Block1 PUT 2.31 per block
    then 2.01, sends a separate response as an empty ACK then a CON, a NON request a NON response; a lost request or
    ACK is sent again after 2.4 s. Not checked: DTLS, OSCORE (not built), Observe.
- D81 (completes D80; amended by D95, D105, D109) DoC, DNS over unprotected CoAP over UDP (RFC 9953), behind
  the `doc` feature of `dedens`, `dedensd` and `dedens-net` (D69): the client `Transport::Coap`
  (`dedens_net::doc`), the `dedens` options `@coap://HOST[:PORT][/PATH]` and `+coap` (port 5683, the root path
  unless given), the `dedensd` listener `coap://ADDR[:PORT][/PATH]`. The sans-IO halves are D80's `coap::doc`: the
  client's `request`, the server's `query`, `response`, `error`.
  - Client: one confirmable FETCH per query on a UDP socket of its own, DNS ID 0 (§4.2.2), Content-Format and
    Accept 553, no Uri-Host or Uri-Port (the server is the one named). A response in blocks must carry an ETag
    and keep it (`require_etag`, D80): a server that sends none is refused beyond the first block. The retransmission is CoAP's (RFC 7252
    §4.2), so the DNS tries are 1 (§4.2). The Max-Age of a 2.05, 60 s when absent, is added to each TTL, to at most
    2^31 - 1 (§4.3.2); a response in blocks is put together. A code other than 2.05, another content format and a
    body that is no DNS message are errors of the exchange (§4.3.1), not responses. Over `+trace`, `+tcp`, `+tls`,
    `+quic`, `+https` it is a usage error. Built without `doc`, asking for CoAP is a local error. The report says
    `CoAP`, JSON `coap`; `-v` logs the code, Max-Age and blocks (`tracing` debug).
  - Server: a FETCH, or a POST (RFC 9953 defines FETCH only; accepted as the same query), to the listener's path.
    Codes (§4.3.1): 4.04 another path, 4.05 another method (GET included), 4.15 a content format other than 553 or
    none, 4.06 another one accepted, 4.02 a critical option unknown, a Uri-Query or a bad block, 4.00 no body,
    4.13 a body in Block1 blocks (a server keeps no request state, a query fits one datagram), and from RFC 7252
    §5.7.2, §5.10.8: 5.05 for a Proxy-Uri or Proxy-Scheme (no forward-proxy, and no own names to take a proxy
    request for itself as local), 4.12 for an If-None-Match, or an If-Match with a tag (the resource has no stable
    tag to match; an empty one, any representation, passes). Uri-Host and Uri-Port are accepted, whatever they
    say: one resource tree serves every authority. A DNS failure
    upstream is the pipeline's SERVFAIL in a 2.05 (§4.3.1). The Max-Age is the least TTL, which is taken from every
    TTL (§4.3.2, the RECOMMENDED algorithm). A response over 1024 bytes goes in Block2 blocks of 1024, each cut
    again from a new query (the follow-up carries it, D80), or of the size a request asks; each block carries
    an ETag, the FNV-1a hash (8 bytes, written out so that servers of two versions agree) of the body as cut, so
    TTLs less their least: an answer that changed between two blocks fails the client's transfer (RFC 7959 §2.4),
    its Max-Age, which moves with the clock, not part of it. libcoap's and aiocoap's
    clients send no body with the follow-ups, so a FETCH or POST with no body that asks for a Block2 past the first
    (`doc::Query::Block`) is answered from the response sent in blocks, kept by (endpoint, Request-Tag, RFC 9175
    §3.2; empty if none), 64 per socket (`server::Blocks`), from the first block and not moved by the follow-ups, for
    `EXCHANGE_LIFETIME` at most, and served a bounded number of times (D105): found by libcoap's `coap-client`
    getting 4.00 for the second block of a 2649-byte answer, as the RFCs do not say how a server finds the response
    again. No such response kept is 4.00. CON requests are
    deduplicated (`Dedup`, 4096 entries, `EXCHANGE_LIFETIME`; the NON ones for `NON_LIFETIME`, D105) and answered
    by a piggybacked ACK, never a separate
    response; a NON request gets a NON response, its message ID from a counter that starts at random (RFC 7252
    §4.4); a ping, and a CON message with a format error whose ID can be read (`Message::reject`, §4.2), get a RST;
    a NON one, or one of another version, is dropped. The path is read as written, no
    percent-decoding; `?` and `#` in it are refused at configuration.
  - Unprotected: `dedensd` logs a warning at start for each `coap://` address, NOT RECOMMENDED (§6). DTLS and
    OSCORE are not built; the proxy parts (§9.2 redirects, §9.3 hop limit) are ignored: see `docs/TODECIDE.md`.
  - Checked live: libcoap 4.3.5b's `coap-client` against `dedensd` (`listen: ['coap://127.0.0.1:56840/dns/query']`,
    forwarding to 8.8.8.8): FETCH of a small query (`gmail.com MX`) 2.05 with the content format and a Max-Age;
    a 2649-byte answer (`cloudflare.com TXT`) in 3 blocks of 1024 and with `-b 64`, whole; NON gets NON; a lost
    request (`-l 60%`) is sent again and answered; 4.04 for another path or the root, 4.15 for another content
    format, 4.06 for another accept, 4.05 for GET. A lost ACK (a duplicate) is checked by the test only.
  - Not done: GET with `?dns=`, which the RFC does not define; a `coap://` upstream of the `forward` stage; the
    discovery by SVCB `docpath` (§3.2, D95).
- D95 (amends D81) DoC discovery by `rt=core.dns` in `/.well-known/core` (RFC 9953 §3.1, RFC 6690), the `dedensd`
  listener's answer and `dedens +doc-discover`, behind the `doc` feature:
  - Server (`coap::doc::discovery`, before D81's `query`): a GET of `/.well-known/core` answers 2.05 in Content-Format
    40 with one link, `<PATH>;rt=core.dns;ct=553`, `PATH` the listener's path (a socket has one: one link per DoC
    listener); the root path is `</>`, a path that starts with an empty segment is written after `/.` (else the
    link would read as an authority), and bytes a path cannot hold are percent-encoded. A `rt=` query filters (RFC 6690
    §4.1) on a complete value or a `*` prefix; no match is 2.05 with an empty payload, and any other query is ignored,
    as §4.1 allows. 4.05 for another method, 4.02 for an unknown critical option, 4.06 for an Accept other than 40,
    4.12 as D81 for the preconditions; a NON request gets a NON response; a request with a Proxy-Uri or Proxy-Scheme
    is not the listing and goes on to the forwarding refusal of D81. A listener path of `/.well-known/core`, or with a
    segment `.` or `..` (a Uri-Path is never one, RFC 7252 §5.10.1: no request could reach it), is refused at
    configuration.
  - Client: `Client::discover_doc(server)` sends a GET with Accept 40 and `rt=core.dns` and returns the paths of the
    links to take, in the order listed. `coap::link::parse` reads RFC 6690 §2 (whitespace tolerated around `;`, `,`
    and `=`, as the RFC's own examples need): `rt`, `if`, `sz` and `ct` once, a repeated `rel` takes the first,
    `ct` a u16 or a list of them, other attributes checked and dropped; a syntax error is `DocError::Links`, a payload
    that is not Content-Format 40 `DocError::NotLinks(format)`. A link is taken when it has the type `core.dns`, a
    `ct` with 553 or none, no `anchor` and a `rel` of `hosts` or none. A link's target is resolved against
    `coap://SERVER/.well-known/core` (RFC 3986 §5.2) and taken only when it is a path on the same IP address and port
    (a host name never matches: no lookup); a link to another server is refused, since a forged list must not send
    the queries away, and does not fail the lot when another link is fine. Each segment is percent-decoded after the
    dot segments are removed (RFC 7252 §6.4); a `?`, a `#`, a bad percent-encoding or a decoded `.`/`..` is refused.
    The fuzz target `parse_link_format` reads arbitrary bytes, and the list the server writes for any path back
    to that path: it found the encoding and the empty first segment above.
  - `dedens +doc-discover @coap://HOST[:PORT]` (or `+coap`; option `doc_discover`, `--doc-discover`): before each
    query, the server is asked and the first path is the Uri-Path of the FETCH; the report says `(discovered /PATH)`,
    JSON `doc_path`. Never automatic: §6 allows discovery only from a trusted source, and `dedens` does not tell
    one from another, so the user asks for it for the server they name. It is a usage error with a path in the URI
    (the path is found, not given), with a non-CoAP server or with none (exit 2); a failed discovery, an empty list or
    no resource of that type is an error of the exchange (exit 9).
  - Cut: discovery by SVCB `docpath` (§3.2). The request is built from the ALPN, `coap` for CoAP over TLS (RFC 8323) or `co`
    for CoAP over DTLS (RFC 9952), and the unprotected CoAP of D81 has none: neither is built, so the key stays
    parsed and unused. See `docs/TODECIDE.md`.
  - Checked live: libcoap 4.3.5b's `coap-client -m get coap://127.0.0.1:56840/.well-known/core` against `dedensd`
    (listener `coap://127.0.0.1:56840/dns/query`) gets `</dns/query>;rt=core.dns;ct=553`, with `?rt=core.dns` the
    same and with `?rt=other` an empty payload, 4.05 for `-m post`, 4.06 for `-A 41`; `dedens +doc-discover
    @coap://127.0.0.1:56840 example.com` finds `/dns/query` and gets the answer.
- D105 (amends D81; amended by D113) `dedensd` CoAP server limits (audit S7, S9, L10, E7), as D47 bounds the other listeners:
  - Replays (RFC 7252 §4.5, §4.8): `Dedup` sends the kept reply again at most `MAX_RETRANSMIT` = 4 times per entry
    (`coap::MAX_RETRANSMIT`, shared with the client's `Params`), the retransmissions a client makes, so every one of a
    client's is answered; then the message is still a duplicate (never processed again) but gets silence, until the
    entry expires. A duplicate arriving before the reply is kept is silent and costs none. Without it a spoofed source
    got a ~1 KB reply for each ~40-byte datagram repeated for `EXCHANGE_LIFETIME`; the same CON sent 100 times is now
    answered 5 times at most. NON requests are deduplicated too, for `NON_LIFETIME` (145 s; §4.5 SHOULD, §4.8.2), with
    no reply kept: a duplicate is dropped. Not covered: a message with a new ID, CON or NON, is a new request, so a
    spoofed source is amplified as with plain UDP DNS; D113 limits the rate of a source network, and sends a source over it nothing.
  - Block2 follow-ups (D81): the response kept in `Blocks` is served at most `(1 + MAX_RETRANSMIT)` times its size in
    bytes (`Found::Spent`, then silence), whatever the message IDs, and a follow-up neither stores it again nor moves its
    clock. Bytes, not blocks: the client picks the block size, a 64-byte client of a 2649-byte answer needs 42 requests,
    which a count of blocks at 1024 would cut off. By design (audit L10): a follow-up replays the TTLs of the
    response as it was cut at first, not re-resolved, so the data a client reads may be up to `EXCHANGE_LIFETIME` (247 s)
    old, the time the entry is kept from the first block; the ETag of the blocks stays the same.
  - Parsing: `Message::parse` reads at most `MAX_OPTIONS` = 64 options, past it `ParseError::TooManyOptions`, a format
    error like the others (a CON gets the RST of §4.2). The RFC sets no limit; a DoC request has about ten options. A
    datagram of zeros made ~65 K empty options, a list of 32-byte entries of ~2 MB per datagram (an empty option
    allocates nothing). The client reads responses with the same limit. Not done: the audit's other idea, option
    values as ranges into the datagram.
  - Receive buffer: 2048 bytes (`MAX_REQUEST`), plus one to tell a datagram over it from one that fits. A datagram over
    it is parsed from its first 2048 bytes: a CON or NON request gets 4.13 with Size1 = 1024 (RFC 7959 §2.9.3, §4),
    anything else is dropped. The largest legitimate request is a query of 1024 bytes (`BLOCK_SIZE`; a DNS query is far
    under, EDNS padding included) with 4 bytes of header, 8 of token and options of a few dozen bytes: the other 1024 are
    slack. The server also takes a body of 1025 to ~2030 bytes with no Block1; it advertises 1024. RFC 7252 §4.6 says a
    message SHOULD fit one IP packet, and suggests 1152 bytes for a path of unknown MTU: a bound the 2048 is over.
  - Tasks: 256 requests are answered at once per socket (`Slots`, as D47's TCP connections), so a thread answers at
    most n listeners × 256 (four `coap://` listeners reach its 1024 upstream queries; one is the usual case). The
    `Dedup` is looked up first, so a duplicate is answered from what was kept even with the slots full; a new request
    takes a slot and is noted only then: past 256, it is dropped silently, not noted, and its retransmission is asked.
    Silent, with no 5.03 (a deviation from §4.2, in `coverage.md`), as D47 drops past its limits: answering under
    overload costs more than the request, and a 5.03 still costs a send.
  - E7: the first response is sent, then the buffer `send_to` gives back is kept in `Dedup`: no copy for it. A copy
    of the DNS response goes to `Blocks` only when its block has more after it (`doc::more_blocks`, which reads the
    request as `response` does: a malformed Block2 is no block); the follow-up path copies the kept response once, as
    `response` needs a `Vec` to take the TTLs off.
  - Tests: the trigger datagrams are built by hand from the audit's (zeros after a header, a bare FETCH), not captured:
    they hold no DNS data, and what they check is the server's count and bounds (AGENTS.md's real-data rule is for
    the DNS content, which the existing captures keep). Fuzz: `parse_coap` asserts the options cap, and `coap_doc` the
    replays per message ID and `more_blocks` against the reply.
- D109 (amends D61, D81, D83) The client's QUIC, HTTP/3 and CoAP exchanges are bounded by what the server sends and
  by the query's deadline (audit step 06):
  - DoH over HTTP/3 (RFC 9114 §4.2.2, §7.2.4.1): the client's SETTINGS carry `SETTINGS_MAX_FIELD_SECTION_SIZE` of
    8 KiB (`MAX_RESPONSE_FIELD_SECTION`, `https.rs`), where h3 states none; a response with a larger header section
    is refused as a stream error (`HttpsError::Stream`), the request not sent again. 8 KiB is ten times the largest
    header section of the responses captured from Cloudflare, Google, Quad9 and AdGuard (797 bytes, counted as
    RFC 9114 §4.2.2 does: name, value and 32 per field; `tests/testdata/doh/*.headers`) and what servers commonly
    take of a request; a server that sends more is no DoH server worth asking. The body limit is unchanged, and the
    QUIC receive windows are step 12's.
  - DoQ (RFC 9250 §4.3.3): a response stream that is not one message behind its length closes the connection with
    `DOQ_PROTOCOL_ERROR` (2). The pool does not reuse it (a closed connection is not, D61), and the query is not sent
    again on a new connection (D27's retry is for a connection found closed, not for one closed here): the error is
    the server's.
  - DoC (RFC 7252 §4.8, §5.2.2; RFC 7959 §2.4): the CoAP exchange, with its retransmissions, the wait for a separate
    response after an empty ACK (93 s) and the blocks, ends at the DNS exchange's deadline, as over the other
    transports: `DocError::TimedOut`, which the client turns into the exchange's timeout, `Failure::TimedOut` with
    one send (D81: the DNS tries are 1). A blackholed server holds a query for the timeout, not for 93 s or more.
    The discovery (D95) is not bounded: it has no query deadline, and the CLI asks it once.

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
- D103 Mutation testing (cargo-mutants), outside the gate: `just mutants` for whole packages, local, as it takes
  hours (5510 mutants in the workspace, about 10 s of build each); `just mutants-diff` for what a branch changes,
  also run on each pull request by the `mutants` workflow, informational: the `gate` job does not need it.
  Both test the committed HEAD in a worktree of their own with `--in-place`: the build stays warm from one
  mutant to the next, and a killed run's leftover mutant never reaches the working tree. `--iterate` tests again
  only what the last run did not catch. Tests run under nextest: a warm run of `dedensd`'s took 11.4 s against
  24.2 s with `cargo test`, the other packages within 0.8 s (2026-11-01); nextest runs no doctest, so a mutant
  only a doctest catches shows as missed, the safe direction. A missed mutant no test can observe, or one that
  hangs the tests (240 s each), is skipped in `.cargo/mutants.toml`, with its reason, matched by function and
  change, never by line. Rejected: a
  scheduled whole-workspace run in CI, which would need a dozen shards to fit GitHub's 6 h job limit.
- D22 (amended by D114) Response cache (`dedens-cache`, sans-IO, time passed in as seconds): one cache shared by compio's
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
  validation (`+validate` is refused, D76), no CNAME following. Refused with `@server`, `-f`, `--repeat`, `--search`, `+tls` and `+quic`. The human format
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
- D89 Loopback test servers count queries, not datagrams, and no test frees a port to get a closed one. The system
  hands a port out again as soon as its socket closes, and tests run side by side (in one process, `just check`'s
  other work, other worktrees): a QUIC server keeps sending, after its client exited, to the client's old port, which
  another test's server then holds (seen: a log of three queries with a fourth that was 31 bytes of QUIC), and a
  client of a port freed to be closed is answered by whoever took it (seen: `a_closed_port_exits_9` exit 0). So
  the UDP servers of `apps/dedens/tests/common`, `apps/dedensd/tests/common` and `crates/dedens-net/tests/common`
  and the CoAP one of `rfc9953.rs` skip a datagram that is not a query, and closed-port tests use `127.0.0.1:1`,
  which the system never hands out. Rejected: a retry or a sleep (the stray is not late, it is not ours), a port
  range per test (the stray's sender does not know it). On macOS a datagram is queued without the control data
  (destination address, ECN) of the socket options set after it arrived, and `compio-quic` panics on one
  (`compio-io` 0.10.1 `CMsgIter::new`: `buffer too short`). `dedensd` bound its sockets, logged `serving` and set the
  options when its threads built the QUIC endpoints, so a client at once could kill the process (seen: 6 of 3840
  runs of `s3_the_path_is_the_listeners` under load, `connected: TimedOut`); it now logs `serving` once every
  thread has its endpoints. A datagram that reaches a socket before its owner set the options stays a risk, a
  startup one on macOS only (a restart ends it), and for a client of a test too.

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
- D41 (amended by D43, D46, D111, D114) Server core (`dedens-server`), sans-IO as D26: `Pipeline::query` takes the query's
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
- D42 (amended by D45, D47-D49, D52, D65, D66, D84, D115) `dedensd` I/O around D41: one compio thread per core on Linux, each with its
  own UDP socket and TCP listener on every `listen` address (`SO_REUSEPORT`, the kernel spreading queries), one
  thread elsewhere, where `SO_REUSEPORT` does not spread; IPv6 sockets IPv6-only, so `[::]` and `0.0.0.0` bind
  together. Every socket is bound before any thread starts, so a taken address fails the start. A reply the
  pipeline builds at once goes out from the socket's task; a query for upstream gets a task owning its `Upstream`
  and asks with the thread's `dedens_net::Client`, over the client's transport, with the forward stage's timeout
  and tries (D45). TCP (RFC 7766): queries read in turn, each answered when ready, replies in any order through one
  writer (§6.2.1.1); reading stops after 10 s without a query, the connection closes once pending replies are
  written (§6.2.3). Listeners and upstreams from the configuration (D44). Rejected: one socket shared by all
  threads (contention on one receive queue); a task per query on the cached path (an allocation per hit).
- D43 (amended by D45, D46, D114) Cache stage (D22 in D41's pipeline): `Stage::Cache` looks the query up at `now`,
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
- D44 (amended by D64-D66, D84, D91, D113, D115) `dedensd` configuration, D24 narrowed for the first server: one YAML file (`--config`), as D36's query
  files; `listen` addresses, `pipeline` (stage names in order), `stages` (name to settings
  under `type`: `cache` with `dedens_cache::Config`'s fields, `forward` with `servers`, `IP` meaning port 53),
  `upstream_ca` (D65).
  `${VAR}` is replaced in the text before YAML reads it; a value spanning lines is refused, as it would add YAML.
  Errors: unknown fields, duplicate names, a stage listed and not defined, defined and not listed, listed twice or
  after a forward stage (which answers every query). `dedensd validate` reads the file and builds the pipeline
  without binding; SIGHUP reloads it (D55). Later, with need: a directory merged, `SECRET[..]`, JSON Schema.
- D45 (amended by D115) Upstream patience and the client response timer (RFC 8767 §5), changing D42 and D43: a forward stage
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
- D47 (amended by D64, D91, D113) `dedensd` limits, per thread (RFC 7766 §10, D42 had none): 1024 upstream queries in flight (past them a
  UDP query is dropped, a TCP one answered SERVFAIL), 256 TCP connections (past them a new one is closed at once);
  per connection, 64 queries in flight (reading waits; a bounded channel is the semaphore), 128 KiB of queued
  replies (reading waits), and 10 s for the queue to empty from its first reply (a client that reads slower than
  it asks loses its connection). A query waiting upstream holds no reply buffer until a reply is made. A QUIC
  Initial from an address not yet validated is answered with a Retry (RFC 9000 §8.1.2) and takes no connection
  slot, so forged sources cannot fill them; always on, at the cost of a round trip for a first connection (a
  client holding a token from an earlier one skips it). A QUIC connection (DoQ, HTTP/3) is a TCP one in these
  limits: no new stream within the idle time, whatever pings keep it alive, ends it once the queries asked are
  answered, and a reply not written within the write time is given up with its stream reset: a client granting
  no flow control credit keeps the connection for the write time past the idle time at most, and its slot only
  for the idle time. No per-address cap, for TCP either. Constants for now; configuration with need. Client
  allow and block lists come later (`docs/TODECIDE.md`); per-address caps are the deployment's (D90; UDP is limited per network by D113).
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
- D50 (amended by D108) Upstream UDP queries share a fixed pool of 256 sockets per server and client (`dedens-net::udp`), each opened
  on first use on port 0 and connected, then kept: a query takes one at random and waits for datagrams with its
  ID, which the socket's task receives for every query on it. An off-path attacker guesses the ID and the
  socket: 16 + 8 bits (RFC 5452 §9.2), against about 32 with a socket per query; cookies (RFC 7873) and `0x20`
  stay the way to win more. Matching stays D27's: a datagram goes to each query waiting for its ID (four kept for
  each, D108), and the exchange drops those of another question. A datagram is received whole, up to 65535 bytes, into
  one buffer per socket, whatever size the queries advertised. A socket error goes to the queries that sent on
  it, each counting it as a lost try; errors in a row pause the socket's task 10 ms. Forwarding to a second `dedensd` (`just bench-dnsperf HEAD forward`): about 125k → 127k queries/s,
  the upstream on one core being the limit there. Rejected: renewing sockets on a timer (no attack measured
  against a kept port yet); muxing by question too (the exchange checks it).
- D51 (amended by D107) The io_uring of a serving thread runs completion work cooperatively (`COOP_TASKRUN` and `TASKRUN_FLAG`,
  Linux 5.19, the floor for `io_uring`: older kernels serve on `poll`, with a warning at start, D107): when the thread enters the kernel, instead of interrupting it as a signal does. Forwarding
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
- D108 (amends D27, D50) Bounds on the client's queues and the evidence of a live server. UDP: a query keeps four
  datagrams with its ID until it reads them, a response and the late ones of its tries, and drops the next; the
  socket's one shared inbox of 64 let a query flooded, or slow to read, take the room of the others: the 65th
  concurrent query on a socket lost its response. TCP: a connection queues 1024 messages for its writer, where a
  server that stopped reading held up to 65536 (4 GiB of 64 KiB queries); the query that finds it full goes on a new
  connection, as one that finds every ID taken (D27), and the full one drains and closes. Only a message with the
  ID of a query sent counts as a response read: frames for IDs nobody waits for neither kept the connection from
  idling nor hid a stalled one (D27), so a server could trickle them and never answer. Not done: freeing the ID
  of a query that stopped waiting (RFC 7766 §6.2.1: no reuse of the ID of a query in flight, which a late response
  may still answer; the 65536 IDs and the stall check bound them); waiting for room in a full queue (it holds an ID, freed on every way to give up).
  Not measured: no Linux bench host here; the changes add no work per message on the TCP read path, and UDP's
  per-query lookup replaces the scan of the shared inbox.
- D54 (amended by D64, D110) Plugins (D23's custom stage types, for built-in stages too): `dedens_server::Plugin`, a trait object in
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
    Any class asked (D110). Formats, duplicates and the allowlist in D56.
- D55 (amended by D64, D107) `dedensd` reloads its configuration file on SIGHUP (systemd's `ExecReload=kill -HUP $MAINPID`): the file
  is read and the pipeline built as at start, then swapped in. Each serving thread compares a generation counter
  before each query (one atomic load) and takes the new pipeline under a lock only when it changed (a thread no query reaches takes it when woken by the reload, D107), holding it in
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
- D57 (amended by D64, D104, D115) `dedensd` downloads blocklist and allowlist `urls` (`https://`, or `http://` for a server of one's own)
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
- D58 (amended by D110) A blocklist holds a 64-bit `SipHash` of each name (D110 defines the hash: chained from the
  root over the lowercase wire labels) under a key drawn per `Lists` (std's `RandomState`), in a `HashSet<u64>`
  hashing them no further: 8 bytes a name instead of the name and its allocation. Published lists of 2.29M names:
  110 MB resident instead of 240 MB, read in 0.64 s instead of 0.87 s, lookups as fast (`benches/blocklist.rs`;
  the chain of D110 changed the load time, `docs/benchmarks.md`). A false match needs two names of equal hash
  (D110 gives the odds), and the key, unknown outside the process, keeps a client from aiming at one. The cost: names cannot be listed back, so a blocked name under a blocked parent is no longer
  dropped (2% of those lists, 0.4 MB). Rejected: names in one buffer with offsets (~55 MB, exact, more code); a
  sorted `Vec<u64>` (18 MB instead of the set's 37 MB, a binary search per label); a trie or FST (a dependency,
  slower to build).
- D110 (amends D54, D58) The blocklist blocks a name in any class, and finds a name's suffixes in a walk linear in
  its labels (audit L11, P4).
  Class: it looked up IN queries only, so a query of class ANY (QCLASS 255), NONE, CH or HS for a blocked name
  went to the next stage: the list is a policy on names, and the class is no longer read. `Action::Null` answers A
  and AAAA with records of class IN, so only to questions of class IN or ANY; the other classes get no data.
  Rejected: reading ANY and NONE as IN (CH and HS would still go on).
  Walk: each suffix was hashed from scratch, labels² bytes of `SipHash` for a name of 127 labels. The hash of a name is
  now chained from the root, `h = SipHash(parent ‖ length byte and label)` under the same per-`Lists` key (the
  root's `h` is 0), so a name's walk hashes each label once and each suffix's hash is the one reached on the way.
  The key stays: a client chooses the names it asks, and an unkeyed or weak hash (a rolling hash, FNV) lets it
  aim at collisions (D22's reason for keyed hashing). A set also keeps which label counts its names have, a
  `u128`: a lookup hashes no deeper than the longest name of the lists that can still decide, probes only counts
  present, and does not walk a name with fewer labels than the shortest blocked name. Collision odds: a collision
  at a label carries to the names below it, so two names share a hash with a chance of at most 2^-64 per label,
  about one wrong answer in 10^11 queries of a few labels against 2M names (D58 had 10^12). Rejected: a trie of
  reversed labels (D58 rejected a trie: a node per label, 8 bytes a name becomes tens); label offsets alone (the
  hash of each suffix is still computed from its bytes). What stays linear in the labels is finding where each
  label starts, from the front of the wire name; `docs/TODECIDE.md` asks if that is enough. Measures: `docs/benchmarks.md`.
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
- D64 (amended by D104, D107) Review fixes to D44, D47, D54, D55 and D57.
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
- D104 (amends D57, D64) List downloads, from the audit (S4, S15.a, S15.c, L13, L16):
  - Size: `ureq` is built without `gzip` (`default-features = false`, keeping `rustls` and `platform-verifier`) and
    asks for `Accept-Encoding: identity` (RFC 9110 §12.5.3: no header would let a server send gzip, which is no
    list). The 256 MiB cap counted the compressed bytes, so a gzip body of that size could inflate about a
    thousandfold in memory. Rejected: keeping gzip and capping the decoded body (`take(MAX + 1)` on the decoder).
    Gzip saves bandwidth only, about 4× on a list; without it a 36 MB list within the 30 s timeout needs about
    10 Mbit/s, and a bounded decoder is code to keep. Revisit if a list server needs it. `ureq`'s limit is
    exclusive: a body of exactly 256 MiB is refused.
  - Retry: a pipeline reload that fails after a list was saved is retried. The copy and its `ETag` are saved
    before the reload (D64), so the next fetch is a 304 and nothing else would say the pipeline is behind. The reload
    thread keeps a `pending` flag, set when a fetch changed a list and cleared by a reload that serves (a SIGHUP
    one too, which reads the copies as well); while set, each fetch is followed by a reload, waiting as after a
    failed download: 1 min, doubling up to the refresh interval. A fetch that panics counts as changed too: it may
    have saved a copy, and a reload that finds nothing new is cheap.
  - Logs: a list URL is logged as `scheme://host[:port]path`, parsed as the client parses it (`http::Uri`; a text
    that does not parse shows as `(not a URL)`); credentials, query and fragment may be secrets. A secret in the
    path stays logged. Each `scheme://` token of an error message is redacted the same way, up to the closing quote
    or bracket around it, else to the end of the message: an error may quote a redirect target or a raw `Location`
    header, which can hold spaces. The config error of a mistyped URL is redacted too, and a config error carries
    no YAML snippet (`serde-saphyr`'s `with_snippet` is off), as a snippet could echo the `urls`: line and column
    stay, the field name in the snippet is lost.
  - Files: the `.part` file is created exclusively (`create_new`, by `tempfile`) in the copy's directory, named by
    the copy's file name, a dot and a random part, mode `0o666` less the umask as any new file (a privilege drop,
    S5, would make copies of 0600 unreadable), and removed on failure; the rename stays atomic. The old name, the
    copy's plus `.part`, was predictable, and `File::create` followed a symlink left there. Once at start, before
    the first fetch, the reload thread removes the `.part` files of the copies and tags of the configured URLs that
    a killed process left, the old name included; those of a URL since removed stay.
  - Concurrency: the lists are fetched four at a time, on named scoped threads, no `unsafe`. Four, as the lists in
    memory at once stay within 4 × 256 MiB. One slow server delays the lists queued behind it, no longer all of
    them. A SIGHUP still waits for the fetch in progress, up to ⌈n/4⌉ × 30 s for n lists; SIGHUPs queued meanwhile
    are drained after the reload, as each asks for what it did. A download that panics is caught per URL, logged
    with the redacted URL and counted as an error, and its worker goes on. The configuration keeps each URL once
    (`urls` of `Downloads`): two downloads of one URL would save one copy at once.
  - No draining on SIGTERM, by design: an in-flight download is dropped with the process, and its saved copy and
    `ETag` stay consistent as both are replaced atomically (D64).
- D65 (amends D42) Each upstream server of a forward stage has its own transport, written as in the CLI (D60,
  D61): `IP[:PORT]` over the client's (UDP for a query over UDP, TCP for one over a connection), `tls://` over TLS
  and `quic://` over QUIC, port 853 unless set, `#NAME` for the name the certificate must hold, else the address
  (RFC 8310 §8.1). An address only: a host name would need resolving before `dedensd` can resolve. One stage
  can mix transports, the first server over TLS and the next plain. Upstream certificates are checked against
  the OS trust store, or the PEM file of a top-level `upstream_ca`, which a reload cannot change (each thread's
  `dedens_net::Client` holds it; changing it logs that it takes a restart). `dedens-server` only carries the
  transport and name (`Server`, `Via`), staying sans-IO. Rejected: transport settings per stage (`transport:
  tls`, `tls_name`), which cannot mix servers.
- D66 (amends D42, D44; amended by D115) `dedensd` answers over TLS (RFC 7858) and QUIC (RFC 9250) on `listen` addresses behind
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
- D84 (amends D42, D44, D65; completes D82, D83; amended by D94) `dedensd` serves DNS over HTTPS on HTTP/3 (RFC 8484, RFC 9114) and
  forwards to DoH upstreams. A `listen` address `https://ADDR[:PORT][/PATH]` (port 443, path `/dns-query`; a path
  with a query, a fragment or a template expression is refused) takes UDP, as `quic://` does: the certificate of
  `tls` (D66) is required with it, ALPN `h3`, TLS 1.3 alone, no 0-RTT, the connection counted against the thread's
  TCP ones, idle time and write time D47's (no new request within the idle time ends it, pings or not), 64 request streams and 16 unidirectional ones (control and QPACK, D83) at once, the
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
  Checked against an independent client, aioquic 1.7.1 (2026-11-01, two listeners with a test CA, forwarding to
  8.8.8.8): GET with `dns=` and POST are 200 with `application/dns-message`; `cache-control: max-age=300` on a
  GET of an answer (its TTL), `max-age=1800` on a GET of a no data (the SOA's TTL and MINIMUM), none on a POST; the
  ID is echoed; 415 for a POST of another or no content type, and a content type in other case with a parameter is
  accepted; 400 for garbage or no body, a missing, malformed, padded (RFC 8484 §6 forbids the padding) or
  non-DNS `dns`; 404 for another path, also `/.well-known/odohconfigs` without `odoh`, and for the other listener's
  path; 405 for PUT and DELETE; 413 for a 70000-byte POST. A request the pipeline cannot parse as a query (a wrong
  label length) is 200 with FORMERR (§4.2.1).
- D90 (amends D47, D77; superseded by D113 for UDP and DoC: kept for TCP, TLS, QUIC and HTTPS) Rate limits per client address are the deployment's: nftables `hashlimit` or `dnsdist` in
  front of `dedensd` limits queries and connections per address, for UDP, DoQ and DoT alike (a general reverse
  proxy such as nginx `stream` does TCP only, and a proxy hides the client's address unless PROXY protocol or the
  like carries it). `dedensd` keeps what only it can weigh: the validation cost of one query (256 units) and the
  allowance all queries draw on (D77), and the per-thread connection cap (D47). No per-address query limit and no
  per-address connection cap in `dedensd`. RRL (response rate limiting, a defence against reflection) belongs to
  the authoritative phase, where the server answers from its own data; a stub or forwarder has nothing to
  amplify. The client's address enters the pipeline only for the allow and block lists (`docs/TODECIDE.md`).
- D113 (supersedes D90 for UDP and DoC; amends D47, D91, D105; audit S1) `dedensd` limits the rate of responses over UDP
  and DoC per client network, and gives Server Cookies that exempt a client from the limit. D90 left both to the
  deployment on the ground that a forwarder has nothing to amplify; a cache hit answers a ~40-byte query with up to
  1232 bytes (a 1.2 kB TXT, `benches/server.rs`), to a source address anyone can forge, so a daemon safe by default
  cannot leave the limit to a firewall it may not have. Decided by the user. TCP, TLS, QUIC and HTTPS stay as D90 says:
  the handshake proves the address (QUIC answers Initial with Retry, D47) and a per-address cap stays the deployment's.
  The settings are `rrl` and `cookies` in `apps/dedensd/src/config.rs`, the code `rrl.rs` and `cookie.rs` of
  `dedens-server`; both are on by default.
  - What is limited. A UDP query, before any check but the access lists, so a FORMERR is limited too; a REFUSED of the
    access lists (D91) as well, since the default lists refuse every Internet source and that REFUSED is as spoofable
    as an answer, and past the limit it is dropped, never truncated. A response (QR set) or a header-less datagram is
    dropped before, so forged responses spend no bucket. DoC is limited too: unprotected CoAP over UDP is as spoofable,
    and D105 left the rate of a source to this step. A DoC discovery or DNS query counts; an error does not (it is no
    larger than its request), nor a request for a later block (no body, Block2 number over 0): it follows a query that
    counted and D105 bounds it. CoAP has no TC, so a limited DoC request gets nothing, slip or not.
  - Not limited: connection-oriented transports, as above; sources in `rrl.exempt` (default loopback, which cannot be
    forged from outside; a proxy or a monitor on another address goes in the list, as BIND's `exempt-clients`); a query
    with a valid Server Cookie, which proves the address.
  - Limit. Token bucket per client network, `/24` IPv4 and `/56` IPv6 (BIND `ipv4-prefix-length` and
    `ipv6-prefix-length`, `doc/arm/reference.rst`; Knot's levels, `src/knot/modules/rrl/functions.c`); IPv4-mapped
    IPv6 counts as IPv4 (D91). Every query counts whatever the name: Unbound's `ip-ratelimit` does too, and BIND's
    `responses-per-second` counts identical responses, which its documentation warns hurts recursive servers.
    Defaults, Knot's (`rate-limit` 50 and `instant-limit` 125 per address, `rrl.c`) times its multipliers for those
    prefixes (32 for `/24`, 3 for `/56`, `functions.c`): IPv4 1600 a second, burst 4000; IPv6 150, burst 375. A burst
    left out is 2.5 times the rate; one below the rate is refused at read (the bucket would never fill). BIND and
    Unbound ship it off; here it is on, because this one protects others. A network sending more than 1600 queries a
    second gets slips and falls back to TCP or a cookie: raise `rrl.ipv4.rate`, or turn it off.
  - Slip (BIND `slip`, Knot `slip`). Of the queries over the limit, one in `slip` is answered, the rest dropped. Default
    2 (BIND's; Knot's is 1), 0 to 10. A deterministic count per bucket, not Knot's random roll, so tests are exact. The
    answer is an empty reply with TC=1 (RFC 1035 §4.2.1, never larger than the query), or, for a query with a Client
    Cookie, BADCOOKIE with a fresh Server Cookie (BIND's rule; RFC 7873 §5.2.3): a real client retries with the cookie
    and is no longer limited. A slip is never larger than its query plus the 16 bytes of the Server Cookie (a test
    asserts it): at most 1.4 times a 40-byte query, 0.7 averaged over slip 2, where a hit gives up to 30 times.
  - Table. A fixed array of `table_size` (default 65536, 512 KiB) `AtomicU64` buckets, indexed by a keyed hash of the
    network (random `RandomState` key, as D22 and D58: an attacker cannot aim at a bucket). Memory never grows, whatever
    sources are spoofed (BIND bounds its table, `max-table-size` 20000; Knot's is fixed, `table-size`). Networks sharing a
    slot share a bucket, so a flood from many networks can limit an innocent one at about `table_size` times the rate in
    all. Rejected: a map with eviction (the flood chooses what stays), a lock per bucket (a CAS loop on one word needs
    none and no `unsafe`), key tags (the table would hold more than a word per bucket). A reload keeps the `RateLimit`,
    table and all, while its settings are unchanged: a new one would hand every source a full bucket.
  - Cookies (RFC 7873 §5.2, RFC 9018). A query with a COOKIE option gets a fresh Server Cookie in its reply, on every
    transport, after its own cookie is checked: version 1, SipHash-2-4 (`siphasher`) of the Client Cookie, version,
    reserved bytes, timestamp and client address, so servers of other makes sharing the secret accept it (§4.4;
    Appendix A.1-A.4 are the tests of `tests/rfc9018.rs`). Valid is version 1, 16 bytes, from at most an hour ago and
    five minutes ahead (§4.3), hash matching one of the secrets; reserved bytes are hashed as received (§4.2). Only the
    first COOKIE option of a request counts (RFC 7873 §5.2; `Options` in `dedens-proto` skips the others). A cookie is
    not forwarded upstream.
  - Invalid Server Cookie: answered normally, with a fresh cookie, as a Client Cookie alone (RFC 7873 §5.2.4, §5.2.3
    option 3), not BADCOOKIE: a stub whose cookie went stale (restart, secret change, anycast skew) would get no
    answer without a retry, and BIND does the same by default (`require-server-cookie no`). The cookie only buys the
    exemption from the limit. A bad length stays FORMERR (§5.2.2); a cookie and no question is a request for a cookie
    (§5.4): NOERROR with it, BADCOOKIE if the Server Cookie sent was invalid.
  - Secrets (RFC 9018 §5). `cookies.secret` (32 hexadecimal digits, quoted in YAML, `${VAR}` keeps it out of the file)
    and `cookies.accept` (others accepted) roll as §5 says for anycast: stage 1 secret OLD, accept NEW; stage 2 secret
    NEW, accept OLD; stage 3 secret NEW. Without them, one random secret is drawn at the first read of the
    configuration and kept for the process, so a reload keeps cookies good and a restart makes them invalid once.
    Rejected: a master from which a secret per day is derived (a rotation by itself): a secret that
    changes at restart or by configuration gives no less (a cookie's timestamp bounds its life to an hour) and the
    code is twice as long. `accept` without `secret` is an error. `Secret` is zeroed on drop and prints nothing.
  - Counted: `dedensd_rrl_limited_total{action=slip|drop}` (CoAP counts under `drop`) and
    `dedensd_cookies_total{outcome=none|client_only|invalid|valid}`.
  - Cost (`benches/rrl.rs`, `docs/benchmarks.md`): about 11-20 ns on a cache hit for the limit, 50-60 ns more for a
    cookie; a limited query costs half a hit.
  - Not done: the limit counts queries, not responses by name; cookies are not required (`require-server-cookie`); a
    Server Cookie is made anew for each reply, not kept until half an hour old (§4.3 SHOULD only).
- D93 (amends D77) An answer a validating stage proved insecure is cached a day at most, as keys are (D86), not for
  `max_ttl`'s 7 days: a zone that turns secure gets AD on its answers within a day, as its keys do. The cap is
  `dedens_cache::Config::max_insecure_ttl`, applied by `Response::build` to what `Checked::Insecure` stores, on top
  of `max_ttl` and `max_negative_ttl` (a negative answer is under three hours anyway); `Unchecked` and `Secure`
  keep `max_ttl`, so a secure answer, which the signatures bound, is not shortened. Serve-stale and prefetch see
  the capped TTL as any other. The CD copy of a bogus response is stored `Insecure` and so under the cap too, within
  `bogus_ttl`. The setting is an `Option<u32>`, not a `u32` defaulting to 86400 beside a refusal above `max_ttl`:
  that pair would refuse every configuration with a `max_ttl` under a day that does not also lower the new key
  (`max_ttl: 3600` is a configuration the tests read). `None`, the default, is a day or `max_ttl` if less
  (`Config::insecure_ttl`); a value is refused as `ConfigError::InsecureTtl` when 0 (a response kept for no time) or
  above `max_ttl`. Rejected: capping in `dedens-server`
  (the cache owns every stored TTL); a TTL for secure answers too (nothing asks for it). Tests:
  `dedens-cache/tests/checked.rs`, the configuration tests of `apps/dedensd/src/config.rs`.
- D94 (amends D79, D84, D91; amended by D117) `dedensd` is an Oblivious DoH proxy too (RFC 9230 §4, `odoh` feature): `odoh: {proxy: {targets:
  [HOST[:PORT]], timeout_ms}}` makes each `https://` listener forward the requests that name a target. `targets` is
  required and not empty, a port is 443 unless given; a name is read strictly (UTS 46 with STD3 rules and the label
  and 253-byte limits, as A-labels in lower case, one trailing dot dropped) and a name or port that does not read is
  refused at start; targets are kept sorted and without duplicates. `timeout_ms` (default 5000) bounds a forward: the
  name's resolution, the connection and the response together. A restart applies a change (D79: `odoh` is fixed at
  start). No proxy section, no proxy.
  - Routing: at the listener's path, a request whose query has `targethost` or `targetpath` is the proxy's; any other
    is the target's (D79) or plain DoH's, as before. The query form of §4.1's template is the one served
    (`/dns-query?targethost=H&targetpath=P`, percent-decoded, `+` kept): the path form `/{targethost}/{targetpath}`
    would need a listener path with expressions, which D84 refuses and which would shadow the paths of a DNS
    server. A proxy's request is a POST of the media type with a body (405 with `Allow: POST` (RFC 9110 §15.5.6), 415,
    400, 413 as D79's target), each variable once, `targethost` a `HOST[:PORT]`, `targetpath` an absolute path of
    the characters RFC 3986 allows in a path and a query once decoded (a decoded `é` or DEL is not re-encoded: 400);
    else 400 (§4.1). The body is the same bytes both ways: the proxy never opens it.
  - Policy (§11.2): only listed targets (403 `http_request_denied` with `details`, as §4.1 words it, also for a port
    not listed: the non-standard ports §4.1 allows refusing), and only for the clients D91's access lists allow: one
    they deny, with either action, gets the same 403 and error with `details="client not allowed"` before any
    resolution, counted in `dedensd_access_denied_total{action}` (D91); RFC 9209 §2.3.17 says the intermediary
    rejected the request by its policy and forwarded nothing, which is this, so no token of its own. A `drop`
    client mostly never gets this far: its connection is ignored or closed at accept. A listed IP literal is forwarded as written (the tests'
    loopback target). A name is resolved by the system resolver (D83's client does too: `getaddrinfo` through compio)
    rather than the pipeline, which may block or rewrite it; so a host whose system resolver is `dedensd` itself
    sends the lookup through the pipeline and back, and waits for the forward's time. The first address that is global
    (not in the IANA special-purpose registries, RFC 6890, nor multicast; IPv6 outside 2000::/3, 6to4, documentation;
    mapped and NAT64 addresses judged by the IPv4 inside; the whole of 192.0.0.0/24, which includes 192.0.0.9 and
    192.0.0.10, and 192.88.99.0/24 on purpose) is used, and a name with none is 502 `destination_ip_prohibited`: a
    listed name that points inside the network is not an open door to it. The address a name was checked as is kept
    60 s per thread, so a forward within that time, and any on a connection that is still up, does no lookup.
  - Forward: a new POST to `https://targethost/targetpath` over HTTP/3 through `HttpsPool` (D83), one connection per
    address and name kept 30 s idle and shared by requests (§11.2 recommends it: a connection of a client's own would
    let the target link its queries), checked against `upstream_ca` or the system (D65). The request is built, not
    copied: media type as content type and accept, `content-length`, no `Forwarded`, `Via`, cookie or other header of
    the client (§4.5; the pool adds none), no address. Forwards have their own limit, 256 in flight per thread,
    apart from the resolver's upstream queries (D47), so a target that does not answer cannot starve resolution: one
    more is 503 `connection_limit_reached`. No redirect is followed.
  - Response: the target's status and body, its content type only (a `Location` would send the client to the target
    directly), `Cache-Control: no-cache, no-store` (§4.1) and `Proxy-Status: dedensd; received-status=N` (§4.3; RFC
    9209 §2.1.4). A success of the target with another content type than the media type is 502 `http_protocol_error`
    (§4.3 gives the client no other reading). The client's `proxy_error` (D79) reads only `error`, so a target's 401
    stays the target's and leads to the refetch. A failure is a response of its own with `Proxy-Status: dedensd;
    error=TOKEN` (RFC 9209 §2.1.1, and `details` on a 403) and no body: 400 `http_request_error`; 403
    `http_request_denied`; 502 `dns_error`, `dns_timeout` (§4.1 says 502 for it where RFC 9209 says 504),
    `destination_ip_prohibited`, `connection_refused` (the QUIC `CONNECTION_REFUSED`), `tls_protocol_error` (any TLS
    alert of the handshake, a certificate not trusted included: no finer `tls_certificate_error`),
    `connection_terminated`, `http_protocol_error`, `http_response_body_size` (RFC 9209 §2.3.21); 503
    `connection_limit_reached`; 504 `connection_timeout` while the connection is not up and `http_response_timeout`
    (§2.3.26) once the request is out; 500 `proxy_internal_error`. They live in `dedens_net::odoh::proxy` (`route`,
    `forward_request`, `forwarded`, `failure`, `rejection`, `ProxyError`) over `http` types, tested without a socket,
    as D79's functions, and fuzzed with `read_odoh_http`; the `dedensd` part (`apps/dedensd/src/odoh/proxy.rs`)
    resolves, checks and sends.
  - Privacy: no log line at info or below tells a client address and a target together; a failure logs its `error`
    token at debug, with neither. Stats: `dedensd_odoh_proxied_total{status}`, the status one of those above or
    `other`. No rate limit per client on the forwards: the deployment's (D90; D113 limits UDP only; the target's decapsulations are D117's). The pool keeps
    a slot per address a listed name resolved to (`docs/TODECIDE.md`).
  - Tests: `apps/dedensd/tests/rfc9230.rs` (a real `dedensd` as proxy to a real one, or to a test HTTP/3 server that
    records what it sees: the client's query answered, the proxy answering as a target too, the target's 200 and its
    401 returned with their `received-status`, never cached, two forwards on one connection and no header of the
    client at the target, each of the statuses above with its `Proxy-Status` except `dns_timeout`, which no test can
    make without a resolver that hangs, and the ones for which no port is free to be silent: refused by a QUIC
    server, silent by a UDP socket nobody reads, a target that connects and never answers, untrusted by another
    authority), unit tests of the routing, the target syntax and the address classes.
  - Checked live (2026-11-01): the brief's command needs a proxy certificate a public store trusts, and `dedens` has
    one trust for both hops (`--tls-ca` replaces the store for the target too: `docs/TODECIDE.md`), so a local
    `dedensd` listened on `https://0.0.0.0` (an unprivileged process cannot bind UDP 443 on one address here) with
    a certificate of a throwaway authority and the targets listed, and `dedens --tls-ca CA
    +odoh-proxy=https://127.0.0.1/dns-query +odoh-config=FILE @https://TARGET/PATH example.com A`, the
    configurations fetched with `curl` and pinned, answered NOERROR over ODoH (HTTP/3 200) from
    `odoh.cloudflare-dns.com`, `odoh.crypto.sx` and `doh.tiar.app` (path `/odoh`). `odoh.cloudflare-dns.com:8443`, not
    listed, was 403: the CLI exits 10 with "the proxy answered HTTP status 403". Not checked live: a client other than
    ours against this proxy, `dns_timeout`, a host with one IP family only.

- D91 (amends D44, D90; amended by D94, D113) Client access lists: `dedensd` answers the networks it is told to, so it is no open
  resolver (RFC 5358 §4). The client's address enters `Pipeline::query` with the transport, from every listener
  (UDP, TCP, TLS, QUIC, DoH, DoC, and ODoH where `dedensd` is the target, the proxy's address being the client's
  there), an IPv4-mapped IPv6 address read as its IPv4 one. A `Pipeline` holds an optional `Access`: the library
  and its tests, benches and fuzz targets build none and answer everyone; `dedensd` always builds one, so a reload
  (D55), which rebuilds the pipeline, changes the lists with it. Top-level `access: {allow: [networks], deny:
  [networks], action: refuse|drop}`, `refuse` by default. The longest network holding the address decides, `deny`
  wins a tie, an address in no network is denied. Unset `access` is the loopback (`127.0.0.0/8`, `::1/128`),
  RFC 1918, RFC 4193 (`fc00::/7`) and link-local (`169.254.0.0/16`, `fe80::/10`) networks allowed, so a fresh
  install on a public address answers nobody; `dedensd` warns at start for each listen address outside them. A
  network is `ADDRESS/LENGTH`; the config is refused for text that is none, for bits past the length
  (`192.0.2.1/24`, the error names `192.0.2.0/24`), for an IPv4-mapped IPv6 network (`::ffff:10.0.0.0/104`, the
  error names `10.0.0.0/8`, since clients are read as IPv4), for an IPv6 network that starts in
  `::ffff:0:0/96` and is shorter than /96 (`::ffff:0:0/95`; `::/0` stays valid and holds IPv6 clients only) and for
  an unknown action. A denied query is answered before any stage, from the query in place: `refuse` writes REFUSED
  with EDE 18 (Prohibited, RFC 8914 §4.19) carrying the query's ID and question with `Client::answer`, with no
  `Message` and no allocation (FORMERR's rule: a response, or under 12 bytes, gets nothing; a query with no
  readable question gets the `Client::reply` fallback), `drop` sends nothing. Over DoH a refused query is still 200
  with the REFUSED message (RFC 8484 §4.2.1); a dropped one gets no connection (below), or, on a connection a
  reload found open, 400 without a message, as any query the pipeline does not answer. `Pipeline::drops(from)`
  tells a denial that sends nothing from a protocol drop, and `Pipeline::denial(from)` is the verdict alone,
  uncounted. The transports use them:
  - `drop`: TCP and TLS close the connection at accept, before a connection slot (D47) and the handshake; QUIC
    calls `Incoming::ignore`, before Retry and a slot, so a forged source gets nothing; DoC sends nothing, not
    the 4.00 a protocol drop gets (RFC 9953 §4.3.1).
  - `refuse`: the connection is accepted and every query on it is answered REFUSED, so a denied client costs a
    slot and a handshake. Accepted, because a client that is told it is refused does not retry, and checking
    before the handshake would be `drop` in effect; the deployment's firewall (D90) is what keeps denied clients
    off the slots.
  - ODoH proxy (D94): a request to forward is served only to a client the lists allow, whatever the action
    (`Pipeline::denies`, which counts); a client they drop is closed at accept, as for any request, and on a
    connection a reload found open, or one they refuse, the answer is 403 and nothing goes to the target.
  - DoC Block2 follow-ups (RFC 7959) are served from the kept response only to a client the lists still allow,
    so a reload takes effect on a transfer under way; a confirmable request the duplicate filter replays a reply to
    is not checked, as the filter keeps it for the exchange lifetime only. `breaks_doq` runs before the check: breaking DoQ ends the connection and
    answers nothing, so a denied client gains nothing.

  Warnings: at start and at each reload that succeeds, `dedensd` warns for each listen address outside the local
  networks when `access` is unset, and when `access` is set with an empty `allow` (it answers nobody). Stats
  (D30): `dedensd_access_denied_total{action}`, counted in `dedens-server` behind its `metrics` feature, where the
  verdict is made. The lookup is a longest-prefix tree, never a scanned list: `prefix-trie` 0.10 (`JointPrefixMap`
  over `ipnet::IpNet`; MIT OR Apache-2.0, in `deny.toml`'s list; updated July 2026, 19M downloads in 90 days)
  over `ip_network_table` 0.2 (BSD-2-Clause, which `deny.toml` does not allow; last release in 2021; a forked
  treebitmap underneath). It pulls `array-const-fn-init` (a proc-macro, with the legacy licence `MIT/Apache-2.0`,
  read as either), `either`, `num-traits` and `smallvec`. Cost in `docs/benchmarks.md`: a verdict is 1.4-24 ns in a
  table of 10 000 networks, a denied query 42 ns with no allocation (161 ns and two allocations when built from a
  `Message`). Not here: blocking by answer address (`docs/TODECIDE.md`).
- D107 (amends D51, D55, D64) Runtime fixes of audit step 04.
  - QUIC datagrams (RFC 9221 §3): both the server (`endpoint`) and `Dialer` set `datagram_receive_buffer_size(None)`.
    quinn's default of 1.25 MB made both advertise `max_datagram_frame_size` and buffer DATAGRAM frames nothing
    reads (RFC 9250 uses streams alone). Now a peer sees `max_datagram_size()` as `None`, which the tests check
    (`tests/rfc9221.rs` of `dedens-net` and `dedensd`). That quinn then closes the connection on a DATAGRAM frame
    (PROTOCOL_VIOLATION, as RFC 9221 §3 requires) is its behaviour, not tested here.
  - Driver (amends D51): Linux 5.19 is the floor for `io_uring` (`COOP_TASKRUN` and `TASKRUN_FLAG`), with no retry
    without those flags on EINVAL. compio falls back to `poll` when the ring cannot be made (before 5.19, a
    seccomp filter, `kernel.io_uring_disabled`), with a `warn!` nobody sees, so the "serving" event has a `driver`
    field (`io_uring`, `poll`, or `mixed` if the threads differ), and on Linux a thread on `poll` is a warning at
    start, with the count of threads on it. compio's own logging (its `enable_log` feature) stays off: it
    instruments the driver's hot path, unmeasured. `tests/serve.rs` expects `io_uring` on Linux, unless
    `DEDENS_TEST_ALLOW_POLL` is set (a container whose seccomp filter refuses it); the fallback itself is not
    tested, as it needs a kernel or a filter refusing the ring.
  - UDP receive (amends D64): the pause after a failed receive is per task, and the lock on the socket's stream is
    released before it, so the socket's other tasks keep receiving. A first error is retried at once and a second
    in a row after 100 ms, as D64 has it. `ResourceBusy` (`ENOBUFS`: the pool's 256 buffers, D49, are held by
    datagrams the kernel filled and the tasks have not read) is no failure but a wait for the tasks to read:
    `Receiving`, per task, yields 4 times, then sleeps 1 ms between tries, reset by a datagram. Yielding alone
    spins: on `io_uring` each retry is a submission the kernel refuses at once while the pool is empty.
    `just bench-dnsperf BASE two-sockets` (one core, two UDP ports, the first flooded, the second asked at 2000
    queries/s, `docs/benchmarks.md`) shows no loss and the same latency before and after (0.3 ms on average, 10-13 ms
    at most): the flood never emptied the pool, so it does not reach the case; the unit tests do.
  - A runtime is never dropped (`ManuallyDrop` in the thread's closure, `main.rs`): dropping one on a thread that
    panicked or failed closes the ring and frees the buffers of operations the kernel may still write to, while the
    other threads serve on. The process ends right after the first thread does, and the kernel then closes the
    ring. No `unsafe`: `ManuallyDrop` is safe, a leak being so.
  - Reloads (amends D55, D64): `Current::replace` also wakes each thread, through a `flume` channel of one per
    thread (`Current::follow`, which subscribes before it reads the generation and the pipeline); a `follow` task
    per thread takes the new pipeline on it. An idle thread held the old one, its lists included (about 110 MB with
    the largest), until its next query. The hot path is unchanged: one atomic load of the generation per query, no
    bench needed. Rejected: a periodic check (a wake-up per thread each period for nothing, and the old one held
    till the next).

- D106 (amends D71, D74, D75, D77; amended by D117) Validation cost counts what it costs: the debt of the admission bucket stops at
  one burst and a query in debt asks no more, and NSEC3 hashing is counted in SHA-1 blocks, as the salt and the name
  make them.
  - Debt: `Budgets::charge` (`dedens-server/src/budget.rs`; `Bucket::charge` of `validate.rs` until D117) floors the units at `-burst` (default -20 000). Before,
    2 000 expensive queries admitted together left about -770 000 units and validation shed for about 77 s after the
    flood stopped; now it admits again `burst / per_second + 1` s after (3 s by default: `admit` wants a unit above
    zero, and the clock counts whole seconds). The floor forgives the units above it, so a query is also stopped
    from spending them: `Check::next` charges the step it ran and, if the bucket is then in debt and the query would
    ask another question, ends it with `Progress::Shed`, answered as a query refused at `admit` is: SERVFAIL with
    EDE 14 (Not Ready), nothing held or cached (the response is not at fault, so not `Indeterminate`, which holds
    the failure), counted in `dedens_validations_total{verdict="shed"}` as a refusal is. The real bound: the work
    past the first debt is one validation step of each query in flight at that time, a step at most 130 units (the
    validator's `Budget` of 128 verifications and 8192 blocks, 2 units), and a few units for the common step; the
    floor then forgives it. A query in flight took a unit at `admit`, so they are at most `burst` plus the refill
    while they run. `per_query` bounds one query to within the step that goes over it, as `Check::next` checks
    after the step. Rejected: reserving `per_query` at admission and refunding the rest (the audit's first fix): it
    adds an exit path to each query's life in the pipeline to refund from, and a query that costs 2 units would
    still hold 256 while it runs.
  - NSEC3 blocks: `Budget::nsec3_hash(salt, iterations, owner)` is the one way to hash with a budget: it spends the
    SHA-1 blocks the hash computes (RFC 5155 §5), then hashes (`spend_nsec3_blocks` is private, so no hash is
    unpaid): `blocks(owner wire length + salt length) + iterations * blocks(20 + salt length)`, with `blocks(n) =
    ceil((n + 9) / 64)`, the 9 being SHA-1's `0x80` and 64-bit length (FIPS 180-4 §5.1.1). The first computation
    hashes the owner name, the later ones a 20-octet hash, so a long name costs on the first only: `(iterations + 1)
    * blocks(max(owner, 20) + salt)` is an upper bound of this, and charges a name's first block to every
    iteration. A name with 55 octets or fewer with its salt, and a salt of 35 or fewer, cost one block a
    computation, `iterations + 1`, as before: that is every zone that follows RFC 9276 §3.1 (empty salt). The
    limits keep their numbers and change their unit, blocks: `Budget::DEFAULT_NSEC3_BLOCKS` 8192 (D71),
    `BLOCKS_PER_UNIT` 4096 an `Allowance` unit (D77), `Cost::nsec3_blocks` (D75), `Nsec3Blocks`. So 8192 blocks
    cover 54 names at 150 iterations and no salt as before, but 10 with a salt of 255 octets (755 blocks each): a
    salt is no longer a free multiplier of 5 on the CPU a response costs. `Unproven::UnsupportedHash` (D74) is gone:
    the chain keeps only SHA-1 records (RFC 5155 §8.1), so nothing made it. A block takes 93 ns at no salt, a little
    above the 90 ns the defaults were sized with, and less with a long salt (`docs/benchmarks.md`): 8192 blocks are
    0.8 ms and a unit 0.4 ms, kept. Rejected: refusing a salt over 64 octets as insecure (the audit's alternative):
    RFC 9276 §3.1 only tells zone operators to use none, RFC 5155 §3.1.4 allows 255, and refusing would change the
    verdict of zones that validate today, where counting changes only what a response may cost. Each chased CNAME
    name starts a validation with a fresh `Budget` (D77), so one query may spend 9 of them (the first and
    `MAX_CHASES`), 73 728 blocks, 18 units, 6.6 ms of hashing at most; the `Allowance` charges it as it goes.
  - Tests: `the_debt_of_a_flood_stops_at_one_burst` and `the_bucket_is_in_debt_only_below_zero` in `budget.rs`,
    `the_debt_of_queries_in_flight_is_at_most_a_burst` and `a_flood_in_flight_asks_no_more_than_the_burst_allows` in
    `dedens-server/tests/limits.rs` (captured chains), `a_long_salt_costs_the_blocks_it_makes` in
    `dedens-dnssec/tests/rfc5155.rs` (RFC 5155 Appendix A's records, salt rewritten) and the unit tests of
    `crypto/budget.rs` (block boundaries, the paid hash).

- D111 (amends D41) `Pipeline::receive` checks each upstream response against the question sent, as `dedens-net`
  does (D27, D50; RFC 5452 §9.1), so the core is safe on its own, driven by a transport of tomorrow or a test: QR
  set, opcode QUERY, exactly one question, equal to the one sent with its name in any case (RFC 4343 §4; `0x20` is
  the transport's, the core never sees the case sent). The question sent is the validator's while one of its
  questions is upstream (D77), the client's otherwise. A response failing a check is that server failing, as a
  timeout or SERVFAIL: the next server is asked, and after the last the failure is held (D43); nothing is stored
  from it. The ID is not checked: the transport picks it (D27), the core never knows it. Through `dedensd` this is
  the second check: the transport already drops such a datagram and goes on waiting. No new parsing, the decoded
  message is read: `miss` bench a/mx/txt_large 0.67-0.72/1.25-1.30/1.88-1.92 µs against 0.71/1.26/2.00 µs before,
  15 allocations in both. Rejected: leaving the check to `dedens-net` (the audit's L1: an unchecked transport
  sends uncached replies out as they came).

- D114 (amends D22, D27, D31, D41, D43, D77) Checks on what answers carry (audit step 15; L2, L3, S1.2):
  - AD is ours alone (L2): set only on data our validator checked secure, which is `dnssec: validate` (D77); RFC 6840
    §5.8, RFC 4035 §3.2.3. A forward stage without a validator clears upstream's AD in `Pipeline::receive`, over any
    transport, and the cache keeps such a response as `Checked::Unchecked`, which serves AD clear like `Insecure`
    (its TTL stays uncapped, D93). RFC 4035 §4.9.3 lets a stub trust AD from a trusted recursive server over a
    secure channel; rejected here, as the configuration says nothing of which servers are trusted, a stage may mix
    plain and encrypted ones, and the cache would then serve one server's AD for another's data. Migration: a
    forward to `tls://9.9.9.9` with `dnssec: off` no longer passes AD; set `dnssec: validate`. An opt-in
    `trust_upstream_ad` is in `docs/TODECIDE.md`.
  - Fallbacks (L3). A query changed by a fallback (TC to TCP, EDNS dropped, BADCOOKIE) goes with another ID (RFC
    5452 §9.2); it was the next one, which a forger that saw one ID guessed. `Exchange::start` takes four spare IDs
    from the caller, the most such changes in one exchange, and `Client` draws them at random with the first ID, so the
    exchange stays sans-IO (D31). A spare ID equal to the one before is not used. EDNS is dropped (RFC 6891 §7) only
    on a FORMERR or NOTIMP that has the question and no OPT, and never once a response of the exchange had an OPT
    (`EdnsState`). A FORMERR or NOTIMP without the question is the response: no downgrade, no second query. This
    does not make the downgrade unforgeable: a forger still needs the ID and the port (RFC 5452 §9 is the defence),
    and now the question too, in its case when `0x20` is on, which a question-less response spared it. Cost: a legacy
    server that answers an EDNS query with FORMERR and no question is no longer asked again without EDNS; its
    FORMERR is the result, and `+noedns` asks without.
  - ANY (S1.2): a query of QTYPE ANY over UDP or CoAP is answered by the forward stage, after the plugins (which
    keep their local answers) and the RD check, with NOERROR, TC set and no record: the question and our OPT, so
    never larger than the query. No upstream query, no cache read or write: the cache key has no transport, so
    the entry a TCP client stored would answer UDP clients in full. The client asks again over TCP (RFC 7766 §3).
    Over TCP, TLS, QUIC, HTTPS and ODoH ANY is answered as any query, from upstream or the cache: RFC 8482 §4.4
    lets a responder differ per transport, and those transports show the source address. The class is not
    looked at: ANY of QCLASS CH or ANY is truncated like one of IN. An empty, truncated response is not one of
    the modes of RFC 8482 §4.1-4.3, only a use of §4.4's freedom with RFC 7766's retry.
  - ANY, limits: a client that does not retry over TCP, such as DoC over CoAP (D81, no TCP), gets no ANY answer
    at all; ANY to a resolver is a diagnostic, and over TCP it works.
  - ANY, rejected: §4.2, a synthesized HINFO (or §4.1, one cached RRset): it needs a record for names that do not
    exist or are CNAMEs, a signature for DO, and a TTL, each a new claim by a forwarder that does not know the zone;
    §4.3, a guess: needs upstream. Truncation says nothing about the data.
  Tests: `dedens-server/tests/{rfc6840,rfc8482}.rs`, `dedens-net/tests/{rfc5452,rfc6891}.rs`,
  `dedens-cache/tests/checked.rs`.
- D115 (amends D42, D44, D45, D57, D66, D79) Configuration bounds, from the audit (L14, L15, E5): what the file
  says is held to what the server can bear, and what a variable holds cannot become configuration.
  - Key files. One check, `config::guard_key`, on the open file (no swap between check and read), for the TLS key
    and the ODoH key (D79, which warned on any group or other bit): a key others can access (`& 0o007`) is refused,
    at start and at a reload, which then serves the previous configuration on (D55, D66); one its group can access
    (`& 0o070`) is read with a warning, for a key shared through a group (Debian's `ssl-cert`). `ssh` and PostgreSQL
    refuse a key others can access; PostgreSQL allows its group on a root-owned key. Nothing is checked off Unix.
    A Kubernetes Secret volume is 0644 by default: set `defaultMode` 0400 (or 0440 with `fsGroup`).
  - Patience (D45). A forward stage's `timeout_ms` is at most 30000 and `tries` at most 5; above, the file is
    refused. 30 s is the cap of the system resolver's `timeout` (`resolv.conf(5)`), between the 4 s a BIND stub
    resolver starts at and the 45 s ceiling of BIND's backoff (RFC 1536 §1); 5 is the cap of its `attempts` and
    Unbound's `outbound-msg-retry` default. A query waits at most servers × `tries` × `timeout_ms` and holds its
    slot (D47) all that time; a typo (`timeout_ms: 300000000`, 3.5 days, or `tries: 255`) held it for good.
    The ODoH proxy's `timeout_ms` (D94) is not capped here.
  - Variables (D44). A `${VAR}` value is one YAML value, never YAML. A plain value (ASCII letters and digits,
    `_./:@+=%~#-`, not starting with `#`, `@` or `%` or a document marker, not ending in `:`) stays as it is, so
    ports, addresses, URLs and paths work anywhere, in a number or beside text. Any other value must stand alone
    as a value (after `key:`, `-`, `[`, `,`, `{`, before the end, a comment, `,`, `]`, `}`) and is written in single
    quotes, or sit between quotes of the template, and is escaped for them; elsewhere it is refused. A control
    character or line break is refused. `${VAR:-default}` text is the template's and stays as written. Rejected:
    quoting every value (breaks a number and a value inside the template's own quotes) and substituting in the
    parsed tree (loses the line numbers of errors and numbers' types).
  - Saved lists (D57, D104). A copy that does not exist yet is an empty list, so a blocklist fails open until the
    first fetch; a copy that is no list is warned about and left out. A copy that exists and cannot be read
    (permissions, a directory) refuses the start or the reload, as before: serving without the list would not mend
    when the next fetch runs. Now tested and documented.
  - `threads` (D42). Serving threads, 1 to 1024, fixed at start (a reload warns, as for `listen`). Default as before:
    one per core on Linux, one elsewhere; above 1 off Linux is refused, where `SO_REUSEPORT` spreads nothing and a
    second thread would serve no query. Each thread costs about 1 MiB of buffers, 64 KiB of scratch and a 4 MiB
    receive buffer per UDP socket, so fewer threads than cores serve a small host; 1024 stops a typo.
  - Tests: `a_key_readable_by_others_is_refused` (`tests/listeners.rs`: refused, kept on a reload, group warned),
    `a_long_key_file_is_refused_and_an_exposed_one_too` (`odoh.rs`), `forward_patience_is_bounded`,
    `a_variable_cannot_inject_yaml`, `a_value_is_the_text_it_stands_for` (every text of up to three characters
    from an alphabet of YAML's syntax, in five templates: read back as that text or refused, which stands for a
    fuzz target, `dedensd` being a binary), `an_unreadable_saved_list_refuses_the_start`, `threads_are_bounded`,
    `threads_default_to_the_cores_on_linux` (`config.rs`), `threads_set_the_serving_threads` (`tests/serve.rs`).
    Test and bench key files are written 0600 (`common::write_key`). No hot path touched, no bench.

- D117 (amends D77, D79, D94, D106; builds on D91, D113) Client budgets, from the audit (S3, S14): what one client can
  spend of a shared limit is bounded before the shared limit is. Two places had one budget for all: the validation
  allowance (D77) and the ODoH target's decapsulations (D79).
  - One keyed table (`Budgets`, `dedens-server/src/budget.rs`) for both: a client's key is its network, a /24 of
    IPv4 and a /48 of IPv6 (an IPv4-mapped address counts as IPv4), hashed with a random key into a fixed table
    of 2^16 words (512 KiB). Memory does not grow with the clients; two networks that collide share a bucket, as
    in D113. A word is one `AtomicU64`, the last second and the debt of D106; no lock, and a refusal that changes
    nothing writes nothing, so a flood does not make the cores fight for the line. The global allowance is the
    same type with one slot, so D106's debt is one piece of code. The prefix is /48 where D113's is /56: a site is
    given a /48, and a holder of one would otherwise have 256 buckets of work; D113 limits answers, which a
    holder of many /56 does not gain from the same way.
  - The key has a proven bit: a connection or a valid Server Cookie (D113) cannot be spoofed, so those queries
    have a bucket of their own and a flood from spoofed UDP sources of a network does not shed them.
  - Validation (S3). `Pipeline::query` passes the source (address, proven bit) and its `now` (the cache's clock,
    D43, monotonic; the validator keeps reading the wall clock for signatures) to `Validating::admit`, which takes
    one unit of the network's share, then one of the global allowance, and gives the first back if the second
    refuses. `Check::next` charges both with what the validation spent (D106) and sheds when either is in debt:
    SERVFAIL with EDE 14, nothing held, counted `verdict="shed_share"` for the share and `verdict="shed"` for
    the allowance. Cache hits, CD and classes other than IN cost neither, as before. A source on D113's
    `rrl.exempt` list has no share and still spends the allowance. `client_share: {rate, burst}` on the forward
    stage, default 1000 and 2000, a tenth of the allowance, so that ten networks at their share spend all of it
    and no one network can: 2000 units are about 160 cold validations (`docs/benchmarks.md`). A reload keeps the
    key cache and restarts the shares only when the setting changed.
  - ODoH (S14). Before `ObliviousDoHMessage::parse` and the HPKE open, `Target::open` takes one unit of the
    client network's budget (`odoh.client_budget`, default 1000 and 2000: 3.5% of a core at 34.6 µs a
    decapsulation) and one of the global one (`odoh.budget`, default 10 000 and 20 000: a third of a core), and
    gives the first back if the second refuses. A QUIC peer completed its handshake: its address is proven.
    Exempt sources pay no network unit. Past a budget the request is 503 (RFC 9230 §4.3 leaves errors to DoH's),
    counted `dedensd_odoh_limited_total{budget}` and logged at debug, whatever the body: the refusal says nothing
    about the message. Read at start with the rest of `odoh` (D79). A target sees its proxy's address, not the
    client's (D91), and the pipeline its source address likewise: all the clients of one proxy spend one network
    budget and one validation share, so a target behind a busy proxy raises them, or lists the proxy in
    `rrl.exempt`.
  - Why these numbers: a decapsulation is 34.6 µs, a cold validation 12 units of about 10 µs, and taking a unit
    from the table a few ns (`docs/benchmarks.md`): the check costs thousands of times less than what it guards.
  - Rejected: a map of clients with eviction (an attacker evicts); tables per thread (a client spreading over
    threads gets the budget of each); a budget per connection (a connection is cheap to open); places per thread
    for decapsulations held through the exchange (the open is synchronous on the thread, so places bound the
    exchanges in flight and not the CPU, and a global budget bounds the CPU; the upstream queries in flight have
    their own slots); no exemption for validation shares either way (a proxy hiding clients is in `rrl.exempt`, as
    D113 says).
  - Limits are in `docs/TODECIDE.md`. Tests: `a_client_over_its_share_cannot_shed_another_client`,
    `a_proven_client_is_not_shed_by_the_unproven_ones_of_its_network`, `an_exempt_source_has_no_share`
    (`dedens-server/tests/limits.rs`, the first written first), `a_query_the_allowance_refuses_keeps_its_unit_of_the_share`
    (`validate.rs`), the unit tests of `budget.rs`, `a_flood_from_one_network_does_not_stop_the_others`,
    `many_networks_open_no_more_than_the_global_budget`, `an_exempt_source_pays_only_the_global_budget`
    (`odoh.rs`), `d117_a_flood_of_posts_past_a_budget_is_503_before_it_is_opened` (`tests/rfc9230.rs`),
    `a_client_share_is_set_per_stage_and_reload_keeps_the_keys`, `an_odoh_target_has_limits` (`config.rs`). No
    fuzz target: the key is an address; the ODoH parser has its own. Benches: `serve_shed_share`, `serve_cold`,
    `serve_warm`, `serve_shed` (`dnssec.rs`), `budget_admit`, `budget_refuse`, `budget_refuse_one_network`,
    `decrypt_query_message` (`odoh.rs`).

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
