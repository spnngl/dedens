# dedens-resolver

The recursive resolver. Sans-IO: the caller passes the time and the random source, so tests drive both. The
rustdoc holds the rules; D191 the iteration's choices, D192 the scrubber's, D193 the `RRset` cache's, D194 the
infra cache's.

The caches keep their entries in `dedens_cache::Store` (D193): its sharding, byte budget and S3-FIFO are
`dedens-cache`'s, tested there. Feature `metrics` (D30): counters in `src/metrics.rs`, tested in `tests/metrics.rs`.
The integration tests are one binary, `tests/tests.rs` (D162), but for `memory.rs`, which sets the process's
`#[global_allocator]`.

## Invariants

- Nothing reaches a cache or a client but through `scrub`: it alone knows the zone a server was asked as, which
  bounds what the server is trusted with (RFC 2181 §6.1). `Scrubbed::ranked` is what `insert` takes: its `RRsets`,
  each with its signatures and `Rank` (one type, `src/rank.rs`), which the cache's replacement reads.
- A rule of `scrub` changes with D192 and a test in `tests/scrub.rs`; a bound is a named constant with its Unbound
  value, and a test reaches it.
- `scrub` is total: any message, any zone, no panic. The fuzz target `scrub_response` checks that what it keeps is
  within the zone and parses, that every record of the response is kept or dropped, once, and that each kept is in
  an `RRset` of its rank; its seeds are the captures of `testdata/recursion`. A record no `RRset` holds (a meta
  type) is dropped, not kept, and an RRSIG question's signatures are `Outcome::Signatures`, outside `ranked` and
  `records` (D176): grouping loses nothing.
- A scrubbed `Lame` or `Unusable` keeps and drops nothing: the iteration asks another server, nothing is logged per
  record.
- A value's `Cost` counts the bytes asked for every allocation it owns (`Rrset::cost`: the `Arc`, the owner name,
  the RDATA slices, each RDATA); `tests/memory.rs` checks it against the allocator's count. The allocator's rounding
  and headers are not counted: up to 1.5 times more on glue (D193). A new owned field means a new term.
- `insert` trusts its rank: the input is scrubbed (step 05), in bailiwick. Only answer non-authoritative and
  above, or secure data, may answer a client (RFC 2181 §5.4.1); `get` returns every rank.
- Replacement follows Unbound's `need_to_update_rrset` but for three choices of D193: verdicts on the same data,
  an NS `RRset` bounded whatever its trust, and an address over glue pinned whatever its TTL and across a verdict
  (`Cached::pins`). A change there goes to D193 and `tests/rrset_cache.rs`.
- Keys are the owner name in lowercase (RFC 4343): a lookup lowers its name the same way, through `key_of`.
- The infra cache's lame keys lower the zone the same way, through `lame_key`; its `Cost` is 0: its entries own no
  allocation, the key and slot are the store's.
- The infra cache's random draw takes a `CryptoRng` (RFC 5452 §4.4): the server asked must not be predictable.
- The value is an enum (`Entry`) so that negative entries (step 12) share the `RRset` cache's key space: add a
  variant, not a second store.
- Time is `u32` seconds from any origin (a `Duration` in `Resolution`, its seconds to the caches) and may go back:
  use saturating arithmetic.
- `Resolution::receive` reads a response only through `scrub`, whose `Outcome` alone picks the next move. The infra
  cache credits the transport's `rtt` only for an outcome serving the question; REFUSED, SERVFAIL and an undecodable
  response leave the server as it was: its entry is keyed by address alone, a back-off would shut it out of every
  zone (D191).
- The transport owns the wire: ID, DO, `0x20`, TC then TCP, EDNS fallback and the matching (D190). `Query` stays
  typed, without bytes. A `Reply::LocalError` is ours: it never touches the infra cache.
- Every CNAME hop counts against `Limits::restarts`, through `Resolution::hops`, from the cache or a response.
- Every query leaves through `Resolution::send`, which checks `Limits::queries`. A new bound is a `Limits` field
  with its number and prior art, in D191, and a test in `tests/iteration.rs`.
- `tests/iteration.rs` replays the captures by steering the infra cache's draw (`steer`: every other address
  lame): a capture refreshed may change the server followed, not the test.
- The metric names are public: Prometheus series.

## Traps

- `Rank::AnswerNonAuthoritative` is never a non-AA answer: a response without AA but a referral is `Lame` (D192, a
  deviation from Unbound). It is the chain past an AA answer's first owner.
- A DS is the parent's (RFC 4035 §3.1.4.1): `closest` starts above the name for one, and a DS question referred to
  the name asked is not followed. Its proof (NSEC or NSEC3) is in the referral, the validator's to read (step 10):
  the child's answer would be NODATA from the wrong side of the cut. A server above the parent serving the child
  too still gives such a NODATA, taken as the denial: `docs/TODECIDE.md`, for step 10.
- NSEC and NSEC3 records are not capped by count (a proof needs what it needs): the validator bounds their cost
  (KeyTrap, CVE-2023-50387 and CVE-2023-50868).
- Names keep the case the server sent: `Name`'s equality folds case, so `scrub` matches a `0x20` question, and
  nothing restores the client's case. The cache and the server must.
- The budgets against NXNS and TsuNAME (fetches per resolution, cycles between delegations) are the iteration's:
  `scrub` sees one response.
