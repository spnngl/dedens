# dedens-cache

The response cache of `dedensd`: one cache shared by all server threads, split into locked shards, storing whole
responses as bytes and answering a hit by copying them and patching a few fields. It follows RFC 2308 (negative
caching), RFC 8767 (serve-stale) and RFC 9520 (resolution failures). It does no I/O and reads no clock: the
caller passes the time in seconds, from any monotonic origin.

The reasons behind the design are in [`docs/decisions.md`](../../docs/decisions.md) (D22, and D43 for the server's
cache stage); measured speed is in [`docs/benchmarks.md`](../../docs/benchmarks.md).

## API

| Item | Role |
|------|------|
| `Cache::new(Config)` | An empty cache; refuses a `Config` that `Config::validate` rejects. |
| `Cache::lookup(query, now, stale, out)` | Writes the response for `query` into `out`, returns a `Lookup`. |
| `Cache::insert(query, response, now)` | Stores the decoded `response` to the client's `query`, or says why not (`NotCached`). |
| `Cache::fail(key, now)` | Records a failed resolution of `key`, returns the seconds it is held. |
| `Key::of(query)` | The key of a query, or `None` when the cache never answers such a query. |
| `len`, `used`, `is_empty` | Entries and bytes, summed over the shards (locks each one). |

`Lookup` is one of:

- `Hit(Hit { len, freshness, truncated })`: `out[..len]` is the response. `freshness` is `Fresh { prefetch }` or
  `Stale` (add EDE 3, Stale Answer). `truncated` when it did not fit `out`.
- `Failed`: a failure hold is on (RFC 9520 §3.2): answer SERVFAIL without asking upstream.
- `Miss`: resolve.
- `Expired`: resolve; expired data is kept, and `StalePolicy::Always` would serve it once the client response
  timer (RFC 8767 §5, 1.8 s) runs out.

`StalePolicy` says when expired data may answer: `Never`, `IfFailing` (a failure hold is on), `Always`.

## Key

Built on the stack, at most 260 bytes, compared and hashed as bytes:

```
lowercased wire name (≤ 255) | QTYPE (2) | QCLASS (2) | flags (1): DO = 1, CD = 2
```

- The name is lowercased (RFC 4343); the client's case comes back in the reply (see "Serving a hit").
- DO (RFC 3225) and CD (RFC 4035 §3.2.2) are part of the key, so an answer with signatures, or unchecked, only
  goes to clients that asked for it. The caller asks upstream with the client's DO and CD.
- Only standard queries have a key: QR clear and opcode QUERY. QTYPE 0, OPT, 128 to 255 (IXFR, AXFR, MAILB,
  MAILA, TSIG, TKEY…) and 65535 have none (RFC 6895 §3.1); ANY (RFC 8482) has one.
- Only the first question counts.

## Layout

```
Cache
├── hasher: RandomState              keyed SipHash, one hash per operation
└── shards: [Mutex<Shard>; shards]   picked by bits 40.. of the hash
    └── Shard
        ├── index: HashMap<hash, slot>   the hash passes through (no second hashing)
        ├── slab:  Vec<Option<Entry>>    plus a free list of slots
        ├── small, main: VecDeque<slot>  S3-FIFO queues
        ├── ghosts                       hashes recently evicted from small
        └── budget = capacity / shards   bytes
Entry
├── key: Box<[u8]>
├── response: Option<Response>      None while only failures are known
├── freq (0..=3), queue, prefetched
└── failures, hold_until            RFC 9520 state
Response
├── shared: Arc<[u8]>               wire bytes, then the TTL offsets (2 bytes each), one allocation
├── ttl                             lifetime given at insert
├── expires = now + ttl
└── stale_until = expires + max_stale
```

The index is keyed by the 64-bit hash only. The entry's key is compared on every `get`, so a collision never
returns another name's answer; a second key with the same hash replaces the first. SipHash is keyed per process,
so clients cannot aim at collisions or at one shard.

## Insert

`insert` takes the response the forwarder already decoded and never decodes it again. It stores it only if:

| Rule | Refused as |
|------|------------|
| The query has a key | `NotCached::Query` |
| No protocol violation found by the decoder | `Violations` |
| QR set, opcode QUERY | `NotResponse` |
| TC clear: the full answer comes over TCP (RFC 2181 §9) | `Truncated` |
| Exactly the query's question | `OtherQuestion` |
| RCODE NOERROR or NXDOMAIN; failures go through `fail` | `Rcode` |
| No client subnet option with a scope above 0 (RFC 7871 §7.3.1) | `ClientSubnet` |
| A negative answer has an SOA at or above the name its CNAME chain ends at (RFC 2308 §2, §5) | `NoSoa` |
| Its lifetime is above 0 (RFC 1035 §3.2.1) | `ZeroTtl` |
| The entry fits a shard's budget alone | `TooLarge` |

The lifetime is the smallest TTL of all records, capped by `max_ttl`. A negative answer (NXDOMAIN, or NOERROR
without a record of the type asked, both maybe after a CNAME chain) is also capped by its SOA's TTL and MINIMUM
and by `max_negative_ttl`.

The response is then encoded once without its OPT record (the server adds its own to each reply), and the offsets
of its TTL fields are appended to the same allocation. Storing resets the key's failure count and hold.

## Serving a hit

Under the shard's lock, a hit that fits `out` is copied, then patched:

- ID of the query.
- Flags: AA and Z cleared, RA set, RD and CD as the query has them, AD kept only if the query set AD or DO
  (RFC 6840 §5.8).
- The question name in the query's case, so 0x20 mixed case survives.
- Every TTL set to one value: the seconds left of the lifetime when fresh, `stale_answer_ttl` (30 s) when stale.
  Records never get more than the TTL stored.

No decoding and no allocation. A response larger than `out` (a client's small UDP size) takes the slow path: the
`Arc` is cloned under the lock, and after the lock is released the bytes are copied, decoded and encoded again
truncated (RFC 2181 §9: TC set only when answer or authority records were dropped).

`out` must hold at least `Cache::MIN_OUT` bytes (a header, the longest question and `Cache::STALE_ROOM`) and be as
long as the reply may be, less the room the caller keeps for its OPT record. A stale hit leaves its last
`Cache::STALE_ROOM` bytes (6) free for the EDE option the caller adds (RFC 8914 §2).

`Cache::stored` serves the response `insert` just stored, as a fresh hit, without counting a use: no `freq` raised,
no prefetch asked, no lookup in the metrics. A server answering a miss from the cache calls it, so a name asked once
stays the first evicted.

## Time

| State | When | Lookup gives |
|-------|------|--------------|
| Fresh | `now < expires` | `Hit`, `prefetch` once when under `prefetch_percent` of the lifetime is left |
| Stale | `expires <= now < stale_until` | `Hit` (stale) if the policy allows, else `Failed` while held, else `Expired` |
| Gone | `now >= stale_until` | `Miss`, or `Failed` while held |

Failure holds (RFC 9520 §3.2): the first failure holds the key `failure_min` seconds (5), doubled on each failure in
a row, up to `failure_max` (300). With stale data to answer meanwhile, a hold lasts at least `stale_recheck` (30,
RFC 8767 §5). A failure reported during a hold does not count: it comes from a resolution started before. Failures
stop being in a row once more than `failure_max` has passed since the last hold ended.

The clock may go back: the seconds left are never above the lifetime, and a hold further ahead than `failure_max`
counts as over.

## Eviction: S3-FIFO

Each shard keeps its entries within its byte budget with S3-FIFO (Yang et al., SOSP 2023):

1. A new key enters `small`, a FIFO taking about a tenth of the budget.
2. Each hit raises the entry's `freq`, up to 3.
3. Evicting from `small`: an entry hit while there moves to `main`; the others leave, and their hash goes to the
   ghost queue.
4. A key inserted while its hash is a ghost goes straight to `main`.
5. Evicting from `main`: an entry with `freq > 0` loses one and goes back to the end; one with 0 leaves.

Eviction takes from `small` while it holds more than a tenth of the budget, else from `main`. The entry just
inserted or changed is never evicted by its own insert. One-time names, most of DNS's long tail, leave from
`small` without pushing popular names out of `main`.

## Memory

An entry costs `128 + key length + response bytes + 2 × records` bytes against its shard's budget (128 estimates its
slab, index and queue slots). `used()` is at most `capacity`. Outside the budget:

- Ghosts: at most one per live entry of the shard, with up to two queue places each before stale places are
  dropped.
- The slab, index and queues keep their peak size: freed slots are reused, never returned.

## Complexity

Sizes: `n` the query name (≤ 255 bytes), `k` the key (≤ 260), `b` the stored response (≤ 65535), `r` its records,
`s` the shards, `e` the entries of one shard, `g` its ghosts (≤ `e`). Hash-map operations are expected O(1): the
hash is keyed SipHash, so clients cannot pile keys on one bucket; a map that grows rehashes in O(`e`), amortized
O(1). `lookup` and `insert` build the key from the query, O(`n`); every operation on a key hashes it, O(`k`).

### Public operations

| Operation | Time | Under the shard lock | Allocations |
|-----------|------|----------------------|-------------|
| `Cache::new` | O(`s`) | none taken | the shard array; shards start empty |
| `Cache::config`, `Key::as_bytes` | O(1) | none taken | none |
| `Config::default`, `Config::validate` | O(1) | none taken | none |
| `Key::of` | O(`n`); O(1) for a query without a key | none taken | none (built on the stack) |
| `lookup`, query without a key | O(1) | none taken | none |
| `lookup`, `Miss`, `Failed`, `Expired` | O(`n` + `k`) | one probe, one key compare: O(`k`) | none |
| `lookup`, hit that fits | O(`n` + `k` + `b`) | probe, copy O(`b`), patch O(`n` + `r`) | none |
| `lookup`, hit too large | O(`k` + `b` + `r`·`n`) | probe, `Arc` clone O(1) | after the lock: a copy, the decoded message, nothing for the output |
| `insert` | O(`b` + `r`·`n`) to check and encode, then expected amortized O(1) | probe, entry change O(`k`), eviction | encoded bytes (512 bytes, grown up to 4 times for larger responses), TTL offsets, the shared buffer; the key of a new entry |
| `fail` | O(`k`), then expected amortized O(1) | probe, entry change, eviction | the key of a new entry |
| `len`, `used`, `is_empty` | O(`s`) | each shard in turn, O(1) inside | none |

Other costs: each metrics counter is one call to the installed recorder (an atomic add for the usual ones),
nothing without the `metrics` feature. Replacing a response frees the old one under the lock, unless a
slow-path hit still holds its `Arc`.

### Steps

| Step | Time | Notes |
|------|------|-------|
| Hash and shard pick | O(`k`) | SipHash over the key bytes; the shard from bits 40 and up |
| `Shard::get` | expected O(1) + O(`k`) | index probe by hash, then the stored key compared |
| `Response::build` | O(`b` + `r`·`n`) | checks O(1); lifetime O(`r`); CNAME chain and SOA search compare names, O(`n`) each |
| Encoding without OPT | expected O(`b` + `r`·`n`) | each name looks its suffixes up in a fixed-size compression table, O(`n`); a buffer too small is encoded again 4 times larger, a constant factor more in all |
| TTL offsets | O(`b`) | one walk of the encoded bytes |
| `Response::serve` | O(`b` + `n` + `r`) | copy, then ID and flags O(1), question case O(`n`), TTLs O(`r`) |
| `Shared::serve_truncated` | O(`b` + `r`·`n`) | copy, decode, encode up to the client's size |
| `Response::ending`, `left`, `Cache::held` | O(1) | |
| `Shard::update` | expected O(1) + O(`k`) + eviction | probe, a new entry's key copied, byte counts adjusted |
| `Shard::evict` | amortized O(1), worst O(`e`) | see below |
| Ghost `take` | expected O(1) | |
| Ghost `remember` | amortized O(1), worst O(`g`) | stale places dropped in bulk once they outnumber the live ones |

Eviction: each entry popped from a queue is evicted, moved from `small` to `main` (at most once per stay in `small`),
or spends one of its hits (`freq`, raised by hits, at most 3 kept). So the pops are paid for by inserts and hits:
amortized O(1) each. A single insert can still walk the whole shard, when every entry was hit recently.

Ghost places: after a bulk drop the queue holds only live places, and the next drop comes once it holds twice as
many as the live ones, so each drop is paid for by the `remember` calls since the last one.

Memory is O(`e`) per shard, the entries' bytes bounded by the budget (see "Memory").

Threads contend only on the shard a key hashes to, and only for the copy-and-patch of a hit or the bookkeeping of
an insert. A poisoned lock is still used: a shard is consistent between calls.

## Configuration

`Config::default()` follows the RFCs; with the `serde` feature it is read from `dedensd`'s configuration under the
same field names, each defaulting.

| Field | Default | Meaning |
|-------|---------|---------|
| `capacity` | 64 MiB | Byte budget, split evenly between shards |
| `shards` | 64 | Power of two up to 65536, a few per thread |
| `max_ttl` | 7 days | Cap on a positive lifetime (RFC 8767 §4) |
| `max_negative_ttl` | 3 hours | Cap on a negative lifetime (RFC 2308 §5) |
| `stale_answer_ttl` | 30 s | TTL of records in a stale answer, above 0 (RFC 8767 §4) |
| `max_stale` | 3 days | How long expired data is kept (RFC 8767 §5) |
| `failure_min` | 5 s | First hold after a failure, at least 1 s |
| `failure_max` | 300 s | Longest hold, at most 300 s (RFC 9520 §3.2) |
| `stale_recheck` | 30 s | Shortest hold while stale data answers, at most `failure_max` |
| `prefetch_percent` | 10 | Lifetime percent left under which a hit asks for prefetch |
| `stale_answer_after_ms` | 1800 | Client response timer, run by the caller; 0 waits for resolution |

`validate` also requires each shard's share of `capacity` to hold one failure record of the longest key.

## Features

- `metrics`: counters through the `metrics` facade, compiled away without it: `dedens_cache_lookups_total{outcome}`
  (`hit`, `stale`, `failed`, `miss`), `dedens_cache_prefetches_total`, `dedens_cache_inserts_total`,
  `dedens_cache_evictions_total`. Install the recorder before building the cache.
- `serde`: `Config` deserializes, unknown fields refused.

## Not done

- One TTL for every record of a response, not one per RRset.
- Whole responses only: no RRset cache, which comes with the recursive resolver.
- No key on the client subnet (RFC 7871): such answers are not stored.
- No DNSSEC validation: AD is passed through as the upstream set it.

## Tests and benches

- `tests/rfc2308.rs`, `tests/rfc8767.rs`, `tests/rfc9520.rs`: the RFC rules, each in its file.
- `tests/cache.rs`: keys, patching, truncation, bounds, concurrency; `tests/metrics.rs`: the counters.
- `src/shard.rs` unit tests: a proptest checks byte accounting and queue membership after random operations.
- `crates/dedens-bench/benches/cache.rs`: `hit`, `insert`, and `hit_hot` / `hit_spread` on 8 threads;
  `benches/server.rs` measures the cache inside the server pipeline.
