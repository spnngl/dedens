# dedens-cache

The response cache of `dedensd`. Its design and the RFC rules it follows are in [`docs/decisions.md`](../../docs/decisions.md)
(D22, and D43 for the server's cache stage), its API, key, insert rules, hit patching, time states, settings and
S3-FIFO eviction in the crate's rustdoc, measured speed in [`docs/benchmarks.md`](../../docs/benchmarks.md). This
file holds only what those do not: the memory an entry costs and the complexity of each operation.

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
