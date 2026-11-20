# Benchmarks

Measurements behind the performance decisions (`decisions/`). Apple M-series, divan medians of one run unless
stated; `just bench` reruns them. `a`, `mx`, `txt_large` are the captured responses of 72, 161 and 1187 bytes.

Medians swing up to 2x between runs (threads move between P and E cores): compare a change on instructions and
cycles retired (`/usr/bin/time -l`) over a fixed iteration count, or within one run. Every encoder measured
compresses names.

## Codec (D14, D7a)

Nanoseconds, `a`/`mx`/`txt_large`.

| Measure | dedens | hickory-proto | `domain` | miekg/dns |
|---|---|---|---|---|
| Owned decode (before D7a) | 208/552/1437 | 250/708/1791 | 146/297/620 | 281/766/2170 |
| Borrowed decode | 73/153/289 | | 94/191/432 | |
| Borrowed decode, then `into_owned()` | 138/378/743 | | | |
| `decode_reusing` (warm, no allocation) | 77/174/325 | | | |
| Encode, reused buffer | 73/330/461 | | | 162/637/1056 |
| Encode, fresh buffer | 88/317/718 | 416/1291/1697 | 198/666/771 | 177/667/1135 |

- The owned decode allocated 7 times (328 B) for `a` and 15 times (779 B) for `mx`; `domain` none. Borrowed:
  3 allocations, the section `Vec`s.
- Re-encoding a borrowed message costs 13-33% more than an owned one (60/302/351 vs 53/227/305): a name with
  pointers is copied run by run on the stack unless it has one run.
- Parse pass of phase 2, cycles for all three captures: `decode_reusing` 4323 → 3706 (`domain` 3517, with
  more instructions: 17325 vs 15615), `MessageIndex::read` (removed by D28) 3301 → 2896, view 5456 → 4618.
  Gains: a 24-byte `Name` (16-bit offset), records built in place, fixed fields read with one bounds check.
- Truncation keeping whole additional `RRsets` (D10), `encode_truncated_dedens`: 3000 additional records of
  distinct owners into 16 KiB. Looking up each kept record's `RRset` among all the records was quadratic: 3.97 ms;
  one hash per record: 253 µs (same session).
- Fixed layouts as `zerocopy` structs (D59), fastest of 3000 samples, base and new alternated in one session:
  `decode_reusing` 42-83/219/432-445 -> 42-83/211/429-437 (`a` swings between two values in both),
  `Query::read` 41.7-44.7 -> 37.1-39.8, `encode` 56-58/330-344/183-187 -> 52-53/349-359/177-181 (`mx` moves
  5% between runs of one binary), `to_vec` 88-94/88-90/105-109 -> 84-86/83-87/101-105, server `hit`
  87-88/88-92/105-111 -> 83-87/82-86/97-101.
- Checking an OPT record's option framing before reading it (D9), so a broken one is a violation, not an error:
  `query_dedens` (a query with a client cookie) 42.1-42.4 -> 40.2-42.1, `query_decode_dedens` 61-67 -> 57-65,
  fastest of 100 samples, base and new alternated in one session: no change past the noise.
- Tried and dropped: `get_unchecked` in `Reader` (no faster), labels from a re-sliced window (2% fewer
  instructions, same cycles), `#[inline]` hints (no change); `to_vec` going from 512 bytes straight to 65535
  instead of growing 4 times: zeroing and freeing 64 KiB made `txt_large` 496 → 869-1745 ns.

## Name table and name hash (D112)

`benches/message.rs`, on an Apple M5 running other jobs (noise 30%). `encode_64k`: the most CNAME and MX records,
alternating, that 64 KiB holds, so both ends of a record are compressed names, of six shapes: `spread` (hosts of a
zone of 64 names) and five hostile ones: `collisions` (a first label and a length in common, differing one label
further: what the first table hashed), `chains` (100 one-byte labels before a differing one), `flips` (first labels
of 63 bytes that differ by bits that cancel in a multiplicative hash of the words, whatever the seed), `deep_fresh`
(9 labels of their own before 100 one-byte labels and `com`) and `deep_hit` (1 label of its own before them). A bench
encodes the message its own build fills, so a build that compresses better fits more records. The build before
(504a2e8) and the build after were run alternately from copies of the binaries of `cargo bench --no-run`, 5 or 6
rounds each, the lowest median of the rounds (`encode_64k` in µs, the rest in ns):

| Measure | Before | After |
|---|---|---|
| `encode_64k` `spread` | 290 | 181 |
| `encode_64k` `collisions` | 2702 | 183 |
| `encode_64k` `chains` | 162 600 | 169 |
| `encode_64k` `flips` | 698 | 251 |
| `encode_64k` `deep_fresh` | 17 300-23 300 | 3400-4000 |
| `encode_64k` `deep_hit` | 1630-1810 | 2650-2750 |
| `encode_dedens_to_vec` `a`/`mx`/`txt_large` | 64/375/483 | 71/451/421 |
| `encode_dedens_owned` `a`/`mx`/`txt_large` | 52/265/179 | 58/323/179 |

Instructions retired for an encode, steadier than time (`time -l`, an iteration of `encode_dedens_owned` and
`encode_dedens_to_vec`): `mx` 8108 to 9520 (+17%), `a` 2718 to 2955 (+9%), `txt_large` 13 582 to 13 884 (+2%).

`collisions`, `chains` and `flips` are within 2x of `spread` after the change (1.0x, 0.9x, 1.4x). `deep_*` have
names of 102 labels, to hash and search: 3.4-4.0 and 2.7 ms for 64 KiB. Before, `deep_fresh` was 5x slower and
`deep_hit` 1.6x faster: hashing every suffix of a name is what `deep_hit` pays. On a served response the price is the
same hash, which names of 3 to 5 labels do not save with a lookup that ends early: `mx` (6 names) costs 46-58 ns more
(+17%), about 1% of the 4.6 µs of a warm validation, and `a` (2 names) 6 ns. Tried and dropped, same runs:

- Names keyed by (label, offset of the rest), looked up from the root, one probe a label, no seed: `chains` 74,
  `collisions` 131, `flips` 36 µs, `deep_fresh` 2.6 ms, but `deep_hit` 5.2-5.8 ms (3.5x before: a probe for each of
  the 101 labels) and `mx` 9951 instructions (+23%: 5 probes for a name of 5 labels, 2 with the longest first).
- A table of 512 slots: fewer long probes, but small encodes 12-25% slower to clear it. A table of 128 names: the
  hostile shapes within 2x, a third fewer names kept. Labels hashed apart and joined with a rotation: no faster.
- A seed alone (the first version of the change): bits of two words flipped to cancel in the multiplication, whatever
  the seed, gave 128 labels one hash and `flips` 1.5 ms against 0.25 now. A hash that folds the 128-bit product and a
  cap on the comparisons of a lookup close that.

`name_hash` (`RandomState::hash_one`, ns, short/long/packed) and `name_map_get` (a `HashMap<Name, _>` hit, short/long)
close P3 of the audit as measured: hashing label by label, lowercasing in a 63-byte buffer as it goes, skips the copy
of 255 bytes and is slower. The variant, as `impl Hash for Name`, against the committed code, 5 rounds:

```rust
for label in self.labels() {
    let mut lower = [0_u8; 63];
    let lower = lower.get_mut(..label.len()).unwrap_or_default();
    lower.copy_from_slice(label);
    lower.make_ascii_lowercase();
    state.write_u8(u8::try_from(label.len()).unwrap_or_default());
    state.write(lower);
}
state.write_u8(0);
```

| Measure | `Hash` of D7 | Label by label |
|---|---|---|
| `name_hash` | 14.9/39.5/18.2 | 31.7/59.3/32.6 |
| `name_map_get` | 23.2/53.2 | 36.8/75.5 |

The `Hash` stays (D7 unchanged). The key cache (D86, D92) asks two tables, `name_map_get` (23 to 53 ns each) against
4.6 µs for a warm validation: it stays at two lookups.

### The table in a file of its own

`NameTable` and its hash moved from `wire.rs` to `wire/name_table.rs` (D159), code unchanged: kept, as no bench
that writes names got slower beyond its noise. The base (422d20d) and the moved tree, `message` and `server` built by
`cargo bench --no-run` and linked by Apple's `cc`, not the repo's lld (the release build is codegen's, D150), run
alternately from copies of the binaries, 10 rounds each, the order swapped each round, on an otherwise idle Apple M5.
The median of the 10 runs' medians (`encode_64k` and `encode_truncated_dedens` in µs, the rest in ns); the delta in
%; the noise, the larger of the two builds' (max − min) / median over the runs, in %:

| Measure | Before | After | Delta | Noise |
|---|---|---|---|---|
| `encode_64k` `spread`/`collisions`/`chains`/`flips` | 165/150/163/257 | 169/151/160/259 | +2.5/+0.8/-2.1/+0.8 | 18/21/24/13 |
| `encode_64k` `deep_fresh`/`deep_hit` | 2994/2414 | 3018/2411 | +0.8/-0.1 | 18/12 |
| `encode_truncated_dedens` | 106 | 108 | +1.6 | 6 |
| `encode_dedens` `a`/`mx`/`txt_large` | 58.2/409/178 | 57.6/405/180 | -1.1/-1.0/+1.1 | 8/6/10 |
| `encode_dedens_owned` `a`/`mx`/`txt_large` | 51.5/299/174 | 51.7/301/175 | +0.3/+0.4/+0.7 | 10/10/14 |
| `encode_dedens_to_vec` `a`/`mx`/`txt_large` | 64.9/412/383 | 65.1/409/384 | +0.3/-0.6/+0.3 | 8/7/6 |
| server `miss` `a`/`mx`/`txt_large` | 760/1249/1581 | 760/1234/1571 | 0.0/-1.2/-0.7 | 6/8/5 |
| server `plugin` | 56.3 | 55.8 | -0.9 | 7 |

### The suffix search by `partition_point`

The hand-written binary search of `Writer::put_name_found` for the longest suffix held, replaced by `partition_point`
and one lookup of the suffix at its index: dropped. Measured as above, the base 9eb4376, 10 rounds, linked by
Apple's `ld` (D166), beside another agent's build (load 12 to 23 on 10 cores): `encode_64k` `deep_fresh` 3302 to
4136 µs (+25%, noise 15%, every round of the change slower than every round of the base); the other measures of the
table above within their noise. `partition_point` always narrows to one suffix and then compares it, and the suffix
at its index is looked up again: 9 lookups for a `deep_fresh` name of 110 labels, against 7.

### Name equality, the bytes first

`impl PartialEq for Name` on two names without pointers compares the bytes, then, only when they differ, without
case: kept. Equal names nearly always have the same case, and `==` on bytes is a `memcmp` where
`eq_ignore_ascii_case` folds each byte. The base b6141d4 and the change, `message` built by `cargo bench --no-run`,
run alternately from copies of the binaries, 2 rounds each, under a load of 90 on 10 cores (times noisy): instructions
retired (`time -l`) for the run of 2 million `name_map_get` lookups, 1819.7/1815.2 M to 1674.7/1672.1 M (-8%, about
72 a lookup); the medians short/long 24.6-25.1/53.8-55.9 to 23.1-23.8/51.5-51.7 ns. Tried and dropped, same runs:
`impl Hash for Name` lowercasing a flat name straight from its bytes, skipping the 255-byte buffer it unpacks into:
`name_hash` 4004-4009 M to 3982 M instructions for 3 million hashes (-0.5%), times within their noise.

## Unbound (D14)

Unbound 1.26.2, `just bench-unbound` (`-O2`, median of 101 samples), next to `cargo bench -p dedens-bench` in
the same session. Nanoseconds, `a`/`mx`/`txt_large`; this session ran slower than the table above.

| Measure | dedens | Unbound |
|---|---|---|
| Structure check, records located: `decode_dedens_reusing` / `parse_packet` | 117/227/510 | 98/193/415 |
| Owned decode: `decode_dedens_owned` / `reply_info_parse` | 188/460/975 | 143/376/594 |
| Encode, reused buffer: `encode_dedens` / `reply_info_encode` with OPT | 64/333/362 | 44/312/109 |
| Zone, 100 006 records | 7.7 ms | 94.9 ms |

- `parse_packet` does not read RDATA; `decode_reusing` checks every RDATA and EDNS option.
- `reply_info_parse` keeps RDATA as wire bytes, only decompressing names.
- The TXT encode gap is not RDATA: once dedens copied RDATA bytes too (D28), it stayed at 359 ns. A profile
  puts it in owner names: `put_name_compressed`, its table lookups and `Name::to_wire`, once per record.
  Unbound writes an RRset's owner once and a pointer to it for each further record; dedens now does too (D10):
  `encode_dedens` 65/396/367 → 55/351/170, `encode_dedens_owned` 56/325/307 → 49/278/158 (same session, three
  runs).
- Zone: `sldns_fp2wire_rr_buf` reads a `FILE` token by token, as Unbound's auth-zone does.

## RDATA as bytes (D28)

Before and after, same session, ns `a`/`mx`/`txt_large`: no measurable change, except `into_owned` on the TXT
answer (954 → 1047).

| Measure | typed records | bytes |
|---|---|---|
| `decode_dedens_reusing` | 125/260/573 | 125/260/568 |
| `decode_dedens_owned` | 192/621/954 | 194/631/1047 |
| `encode_dedens`, reused buffer | 65/406/354 | 66/409/364 |
| `decode_typed_dedens`: decode, then `data()` on every record | | 146/341/729 |
| `decode_domain` | | 99/218/492 |

Checking RDATA (D9) is most of decoding and stays; reading it as its type again costs 15-30% more. The
removed `MessageView` read every record in 178/505/1093 ns.

## Cache (D22)

- Hit including `Query::read`: 84/159/185 ns.
- Insert of the message the forwarder decoded (no second decode): 226/682/843 ns; it was 362/927/1426 ns
  decoding the bytes again.
- Insert encoding without the OPT record instead of a copy of the message without it, wire bytes and TTL offsets
  behind one `Arc`: 667/750/1322 → 625/667/854 ns (same session).
- 8 threads, medians: one hot name 364 ns (one shard lock), 10 000 names 448 ns (each thread walks the names
  from its own start, buffers made outside the timing).
- Counters (D30), `just bench` features of `dedens-bench`, 10 million hits under `/usr/bin/time -l`: feature off,
  none; `metrics` without a recorder, +8 instructions a hit; `recorder` (atomic counters, as an exporter's),
  +16 (`a`) to +30 (`txt_large`) instructions. Cycles differ within noise, single-threaded and on 8 threads
  (hot name and 10 000 names, ±30% between runs).
- Each shard lock padded to 128 bytes (`#[repr(align(128))]`, no two shards on one cache line), `hit_spread`,
  five alternating runs of 3000 samples each, medians: 4 threads 150-396 ns padded against 151-229 ns; 8 threads
  182-542 against 172-281. No gain: a shard is already larger than a line, so neighbours share one line at its
  edge, and threads meet on a shard's own lock far more often. Not kept.

### Audit step 18 (D116)

Apple M5, `benches/cache.rs`, the load average about 5 from other work on the machine. Three binaries alternated,
6 rounds of 100 samples each: `before` is `fix/phase4-hardening` with the new benches, `after` the final tree. Fastest
sample and, in parentheses, the median of the rounds' medians, in ns.

| Bench | before | after |
|---|---|---|
| `hit` a | 73.3 (76.6) | 76.0 (79.5) |
| `hit` mx | 72.7 (76.6) | 74.7 (79.9) |
| `hit` txt_large | 81.8 (90.3) | 86.4 (91.3) |
| `hit_hot`, 1 thread | 71.4 (78.5) | 74.0 (78.6) |
| `hit_truncated` (`txt_large`, 512-byte buffer) | 679.9 (752.6) | 83.8 (98.1) |
| `insert` a | 181.2 (196.9) | 168.3 (182.4) |
| `insert` mx | 622.5 (659.2) | 575.6 (607.1) |
| `insert` txt_large | 959.6 (1001) | 631.7 (678.6) |
| `insert_evicting_hot` (3 000 hot entries in a full shard) | 34 890 (38 600) | 1 689 (3 313) |

- Truncated hit: 3 allocations (copy, decode, encode) → none, within 1.1x of the hit of the same response that
  fits whole (the audit asked for 2x). Kept: the offsets stored with the response cost 2 bytes a record and one bit
  a record of the additional section.
- Insert: the response is one `Box<[u8]>`, not an `Arc`.
- Hit: 2-3 ns (3-4%) more on one thread; 4 and 8 threads, with swings of 2x, show no difference. Nothing on the
  path changed but the layout of `Config` and `Shard`, and `serve` splitting off the offsets before it tests
  whether the response fits.
- `insert_evicting_hot`: one insert into a new cache each sample, 300 samples. Without the bound the first eviction
  passes over every entry three times under the shard lock. Once the bound is spent the eviction takes from small
  when it holds other entries (D116), so main's hot entries stay: 1.7 µs is the 32 passes, 0.5-0.7 µs when it
  took main's first entry instead (the tree before the review).
- Rotations allowed per eviction (`MAX_ROTATIONS`), `examples/hit_ratio.rs`: hit ratio of one shard, entries of
  one size, 1000 and 10 000 entries, names drawn from 20x as many by Zipf's law (exponent, entries), 100 requests
  an entry, the first third not counted:

  | K | 0.7, 1000 | 0.9, 1000 | 1.1, 1000 | 0.7, 10 000 | 0.9, 10 000 | 1.1, 10 000 |
  |---|---|---|---|---|---|---|
  | 0 | 0.2887 | 0.5225 | 0.7591 | 0.3044 | 0.5680 | 0.8271 |
  | 1 | 0.3376 | 0.5661 | 0.7896 | 0.3522 | 0.6094 | 0.8493 |
  | 8, 16, 32, 64, unbounded | 0.3375 | 0.5660 | 0.7895 | 0.3521 | 0.6094 | 0.8493 |

  Any K from 1 gives the ratio of an unbounded eviction to four digits. The names are synthetic.
- Entry counted: a response of one address under a 14-byte name, 200 bytes → 344 bytes; a shard of the same
  capacity holds 42% fewer of them. A response of 1.2 KB: about 10% fewer.
- Memory held (`tests/memory.rs`, 1 MiB over 4 shards, counted by the allocator between operations), most held in
  each of the workloads, as thousandths of the capacity: small responses 828, responses of every size 967, small
  then large 982, failure records 704, failures then large 986 (it holds 295 entries; the slab never compacted held
  24). Before: small, every size, small then large, failures: 1810, 1060, 2060, 1470. The old accounting left the
  slab, the index, the queues and the ghosts out.

### Read lock (D137), not kept

`RwLock` per shard, a hit writing two atomics (`freq: AtomicU8`, `prefetched: AtomicBool`), against the `Mutex`.
Same two binaries of `benches/cache.rs` alternated, `before` at the tree with the `insert_under_hits` bench, `after`
the read-lock tree; one machine's load average 8-9 from other work (Apple M5, `Timer precision` 41 ns) and an idle
Linux VPS (6 vCPU, AlmaLinux 10.2, `rust:1` container, 24 ns). Command: `benches/cache.rs --bench --sample-count N
--color never <filter>` of each binary in turn, one run of each per round. Fastest sample over all rounds and, in
parentheses, the median of the rounds' medians; then the lowest-highest of those medians, in ns. `hit_hot`: 30
rounds of 300 samples; the others 10 rounds of 100.

| Bench | M5 before | M5 after | VPS before | VPS after |
|---|---|---|---|---|
| `hit` a | 75.9 (124.7; 80-125) | 41.7 (124.7; 79-125) | 206.0 (261.9; 220-285) | 249.6 (261.6; 253-422) |
| `hit` mx | 79.2 (87.7; 82-91) | 75.3 (85.7; 78-91) | 211.1 (235.6; 233-256) | 228.9 (236.3; 230-245) |
| `hit` txt_large | 86.4 (96.6; 90-104) | 86.4 (96.9; 89-101) | 243.7 (273.4; 271-287) | 250.7 (262.4; 254-270) |
| `hit_hot`, 1 thread | 73.3 (86.0; 81-157) | 72.0 (81.1; 76-167) | 219.6 (264.6; 255-392) | 224.2 (261.1; 233-445) |
| `hit_hot`, 4 threads | 82.7 (208.4; 109-592) | 79.2 (162.2; 114-353) | 254.6 (587.9; 328-832) | 260.5 (490.9; 375-864) |
| `hit_hot`, 8 threads | 82.8 (257.5; 146-866) | 81.8 (215.2; 135-873) | 252.2 (566.1; 392-870) | 249.0 (518.9; 316-875) |
| `hit_spread`, 4 threads | 145.6 (314.8; 198-958) | 153.3 (666.4; 218-1228) | 461.6 (1512; 1080-2172) | 522.6 (1372; 1172-1512) |
| `hit_spread`, 8 threads | 161.2 (541.2; 219-791) | 140.3 (609.2; 281-729) | 600.6 (1488; 1244-2400) | 744.6 (1634; 1475-2072) |
| `insert_under_hits` (a store, 7 threads hitting its shard) | 199.3 (1622; 242-3692) | 160.8 (586.2; 367-1389) | 643.4 (934.2; 855-1254) | 646.4 (1179; 875-1785) |

The other benches (`insert`, `insert_evicting_hot`, `hit_truncated`) are equal on both machines.

- `hit_hot` at 4 and 8 threads: the medians of the rounds differ by 5-20%, the rounds themselves by 3-5x (4
  threads, M5 109-592 ns), so the gain is inside the spread. Counting rounds in which `after` beat `before`: M5 16
  and 15 of 30, VPS 22 and 19 of 30; median ratio of the pairs 0.90 and 0.99 (M5), 0.92 and 0.93 (VPS).
- Why: a read lock still writes the lock word (on Linux `std`'s reader is a CAS, then a `fetch_sub`), so the
  line moves between cores as the mutex's did; what a hit avoids is the wait, not the transfer. Bringing 8 threads
  near one thread's time needs a read path that writes no shared line.
- `hit` on one thread: equal within the spread on both machines (VPS paired: 6-10 of 10 rounds to `after`).
- `insert_under_hits`: M5 faster, VPS slower (1 of 10 rounds to `after`, median ratio 1.27): the writer waits for
  overlapping readers, and `std`'s `RwLock` does not favour it on either. No result to rely on.
- `just bench-dnsperf`'s UDP hits, one name, queries/s over four rounds (VPS, the server on cores 0-2 (3 threads),
  dnsperf `-c 8 -T 4 -q 500` on 3-5, 10 s a run; the script as in the repository but for those cores and the one
  name, kept on the VPS): `before` 394 275, 324 018, 411 768, 336 044 (median 365 160); `after` 400 703, 414 404,
  380 410, 280 403 (median 390 557). Rounds range 324-412 k against 280-414 k: no difference.

## Resolver `RRset` cache (D193)

`crates/dedens-bench/benches/rrset_cache.rs`, Apple M5, macOS 27.2.1, one shard, on a machine shared with other
builds (load 8 to 30): nanoseconds, median of the medians of 5 runs (3 for `group` after). `a` is `example.com.` A
(2 records), `ns` `example.com.` NS (2), `root_ns` `com.` NS from a root referral (13).

| Measure | `a` | `ns` | `root_ns` |
|---|---|---|---|
| `hit`: `get`, an `Arc` cloned, no allocation | 37 | 40 | 39 |
| `insert` into an empty cache, the `RRset` already grouped | 91 | 110 | 314 |
| `replace`: other data of the key held at a lesser rank | 88 | 181 | 193 |
| `evict`: `a` renamed, into a full 256 KiB cache | 142 | | |

A hit is a lock, a hash and an `Arc` clone, the same for any `RRset` size.

`Rrset::group`, before (`f137ae65`: each record looked for among the `RRsets` so far) and after (an index by owner,
type and class, sized to the records); `group_many` is the captured `a` record renamed to distinct owners:

| Records | before | after |
|---|---|---|
| RFC 4035 Appendix A zone | 4 074 | 4 269 |
| RFC 5155 Appendix A zone | 4 566 | 4 754 |
| `group_many` 16 | 778 | 1 072 |
| `group_many` 128 | 17 930 | 14 610 |
| `group_many` 2048, a 64 KiB response | 3 921 000 | 102 500 |

Linear, not quadratic, at the price of 300 ns on a small response. The index grown from empty cost 1.5 times on the
zones and 2.5 times on 16 records; sized to the records, 1.05 and 1.4. Hashing a name copies and lowers it (`Name`'s
`Hash`): most of what is left.

Duplicates and equality among RDATA folding the same, before (`1fc80be5`: each RDATA looked for among those of its
run) and after (by hash, when a run is longer than one); `case_variants` n is `google.com.`'s first TXT record with
the case of its first 12 letters varied, n records of one run, as an attacker may send. The two builds alternated,
5 runs each, load 8 to 30: median of the medians, fastest sample in brackets (the medians swing with the load).

| Measure | before | after |
|---|---|---|
| `group`, RFC 4035 Appendix A zone | 4 908 (4 137) | 4 550 (4 168) |
| `group`, RFC 5155 Appendix A zone | 4 799 (4 580) | 5 182 (4 670) |
| `group_many` 16 / 128 | 1 112 (977) / 8 236 (7 349) | 1 122 (937) / 7 633 (6 052) |
| `group_many` 2048 | 115 100 (99 620) | 158 500 (99 970) |
| `group_case_variants` 16 | 3 516 (3 246) | 1 951 (1 782) |
| `group_case_variants` 128 | 222 900 (135 300) | 20 270 (13 240) |
| `group_case_variants` 2048 | 55 840 000 (34 700 000) | 318 000 (205 800) |
| `eq_case_variants` 16 | 3 082 (2 790) | 3 955 (1 622) |
| `eq_case_variants` 128 | 241 000 (132 000) | 13 580 (12 870) |
| `eq_case_variants` 2048 | 170 700 000 (35 780 000) | 509 600 (209 900) |

Linear but for the sort: 16 times the variants, 15.5 times the time (fastest), where it was 256 times. Elsewhere
no change, but for one that is not made: a `HashSet` for every `RRset` cost the zones about twice the time, so only a run longer than one is
hashed; and `into_boxed_slice` on the `Vec` grown by pushes, a shrinking `realloc`, cost them a sixth more than
moving the RDATA into a slice of its size, as before (fastest 4 744 and 5 410).

The response cache before (`origin/main`, `17be9b20`) and after the store's extraction into `Store<V>`,
`crates/dedens-bench/benches/cache.rs`, runs alternated, fastest sample in brackets. `SLOT_COST`: 272 bytes before
and after. The generic `Entry<Stored>` had padded a slot to 96 bytes, 288 with the slot's tables; `failures` as a
`u16` (it saturates, and the hold reaches its cap long before) brings it back to 88 and 272.

| Measure | before | after |
|---|---|---|
| `hit` a / mx / txt_large | 125 (77) / 155 (77) / 185 (93) | 125 (81) / 83 (78) / 186 (88) |
| `hit_hot` t=1 / 4 / 8 | 155 / 271 / 289 | 155 / 229 / 198 |
| `hit_spread` t=1 / 4 / 8 | 604 / 708 / 750 | 693 / 812 / 667 |
| `hit_truncated` | 105 (86) | 107 (85) |
| `insert` a / mx / txt_large | 497 (232) / 1 429 (696) / 1 788 (855) | 229 (213) / 721 (690) / 866 (814) |
| `insert_evicting_hot` | 3 690 (1 940) | 3 813 (2 022) |
| `insert_under_hits` | 1 221 (222) | 867 (200) |

The fastest samples agree within 5 % (`hit_spread` aside, whose medians move both ways from run to run): no change
measured. The medians' gaps, both ways, are the load's.

## Server hit path (D23, D43)

- `benches/server.rs` `hit`: `Pipeline::query` reading a query with EDNS and answering it from the cache stage
  into a 1232-byte buffer, a/mx/txt_large: 204/143/163 ns and one 192-byte allocation a hit (the stale option
  pushed to size the reply, the upstream query built for nothing) → 97/97/118 ns, none (same session).
- `hit_secure` (D77): the same hit for a client with DO on a response stored as validated, AD set from the verdict,
  against `hit_dnssec_ok`, stored unchecked: a/mx/txt_large 127/127/134 ns against 126/126/140 ns fastest of 100
  samples (medians 132/131/139 against 131/131/145 ns), no allocation: within noise. A validating stage changes
  only the miss path.
- `miss`: the query sent upstream, then the response stored and answered: 0.8/1.7/2.0 µs and 15 allocations
  (8 kept by the cache entry, 7 temporary), sockets aside. The entry in one allocation (wire and TTL offsets)
  and the reply served from it as a hit, not encoded again: a/mx/txt_large 0.67-0.74 → 0.59-0.63, 1.53 →
  1.09, 1.71-1.82 → 1.77-1.82 µs (fastest of 3000 samples, same session); 6 allocations kept, 5 of them the
  empty cache's first insert, which a fresh pipeline per sample counts. With the request the client sends: built
  when the query goes upstream, then copied by `Client::exchange`, 17 allocations → built for each server and
  taken by `Client::exchange`, 15; a/mx/txt_large 0.62/1.09-1.17/1.67-1.75 → 0.63/1.10-1.13/1.71-1.80 µs
  (fastest of 5000 samples, before and after alternated, same session; medians 0.71-0.75 → 0.71 µs).
  `Pipeline::receive` checking QR, opcode and question of the response (D111), on the message it decodes anyway:
  a/mx/txt_large 0.71/1.26/2.00 µs before, 0.72/1.25/1.88 and 0.67/1.30/1.92 µs after (fastest of 100 samples,
  before between two runs after, same session), 15 allocations before and after: within noise.
- `hit_guarded` (D121): `hit` inside the `catch_unwind` `dedensd` puts around each UDP datagram's step: a/mx/txt_large
  medians of `hit` against `hit_guarded`: 104/103/121 against 104/103/122 ns, 104/103/119 against 103/104/117, 114/114/129
  against 109/112/131 (three runs of both, same session), no allocation: a landing pad costs nothing until a panic.
- `plugin` (D54): a plugin stage answering two A records it holds, into a 1232-byte buffer: the reply built
  as an empty `Message` and the records moved in after the question, 116 ns and one 128-byte allocation (the
  question list) → header, question and records copied from the query and the plugin: 83-125 ns, none.

## Blocklist (D56, D58, D118, D120)

- `dedensd validate` reading 4 published lists (stevenblack, hagezi light, two hagezi wildcard; 44 MB, 2.29M
  names) and an allowlist, `/usr/bin/time -l`: names as boxed byte strings, 240 MB resident, 0.87 s → their
  keyed 64-bit hashes, 110 MB, 0.64 s; running server 236 → 110 MB (`ps` RSS), heap 131 → 39 MB (`heap`).
- `benches/blocklist.rs` `query` on the test heads of those lists, median of 3000: blocked under a listed
  parent 110 → 116 ns, allowed 140 → 136 ns, in no list (sent upstream) 156 → 195 ns (noise ±30%); a blocked
  name allocates nothing.
- A download checked before it is saved: `read` into throwaway lists (2.29M names: a 37 MB set, its hashes
  buffered first) → `Lists::check`, names counted, not hashed or stored. `benches/blocklist.rs` `check` on the
  three block heads: 15.7 µs fastest, at most 98 B held at once; `read` of the same heads and the allowlist,
  15-16 µs fastest of 1000 samples both before and after `read` and `check` shared their line reader. D120
  replaced `Lists::check` by `Names::check` on names the download parses once (`parse`, below).
- Suffix walk (D110, audit P4), `benches/blocklist.rs` on the test heads, names of `a.` labels in no list unless
  said. The old and the new bench binaries built from the same tree, run alternately 5 times, 100 samples each:
  the fastest sample of all runs, and in parentheses the median of the runs' medians, in ns. `lookup` is
  `Blocklist::answer` on a query read once; `query_labels` is the whole `Pipeline::query` (decoding included).

  | Bench, labels | before | after |
  |---|---|---|
  | `lookup` 1 | 14.6 (15.7) | 9.0 (10.2) |
  | `lookup` 3 | 27.8 (30.4) | 39.5 (41.4) |
  | `lookup` 10 | 75.3 (77.9) | 55.7 (60.6) |
  | `lookup` 127 | 3082 (3166) | 203 (245) |
  | `lookup_blocked`, under `adform.net.`, 10 | 148 (156) | 83 (102) |
  | `lookup_blocked`, under `adform.net.`, 123 | 6249 (6416) | 252 (278) |
  | `lookup_empty` (no names) 1 / 3 / 10 / 127 | 12 / 27 / 70 / 2978 | 7.7 / 8.6 / 8.2 / 15.6 |
  | `query_labels` 1 | 77.6 (120) | 77.6 (120) |
  | `query_labels` 3 | 96.1 (106) | 98.6 (114) |
  | `query_labels` 10 | 148 (160) | 125 (135) |
  | `query_labels` 127 | 3244 (3369) | 411 (492) |

  A 127-label name: 15 times faster, linear now (the lookup of 123 labels under a listed parent, which also
  looks the allowlist up, 25 times). P4's "Done when" (127 labels under 3 times a 3-label name) is not met: 5.1
  times (fastest; 5.9 on medians). Below the hashes, finding where each label starts costs ~1.3 ns a label
  (a name is read from its front, each length byte giving the next): `lookup` 127 less its 5 hashes is ~150 ns.
  A 3-label name is 11 ns slower, a real loss: the chained hashes wait for each other where the suffixes hashed
  separately ran side by side; the whole query at 3 labels is the same within noise (96 → 99 ns, ±30%). Open
  question in `docs/TODECIDE.md`.
- Loading, `Lists::read` of the published lists (43.8 MB, 2.4M lines) as one block list, best of 7 reads in one
  process, 5 runs alternated: before 0.45-0.85 s, median 0.60 s; after 0.49-0.71 s, median 0.66 s (+10%: a name's
  hash is now a chain of its labels' hashes, not one hash). Memory the same, a set gaining 16 bytes. `read` on
  the test heads, fastest of 5 alternated runs: 16.6-17.7 → 18.1-19.4 µs.
- Response review (D118), `benches/blocklist.rs` `review` and `hit` on the test heads, after the rebase onto the cache of
  D116 (the mark is a field of the stored response). Apple M5, macOS 27.2, rustc 1.99.1 (Homebrew), release profile
  with debuginfo, a laptop in use (load average 8.5 at the start, 10.7 at the end of the runs). 5 rounds of one bench
  binary run one after the other, `hit` (the two pipelines alternating inside it) and `review` in each, 3000
  samples: fastest sample of all rounds, and in parentheses the median of the rounds' medians, in ns. The load made
  the means 1.3-2x the medians (outliers of 5-180 µs), and the medians of rounds 2-4 wander by up to 2x; the fastest
  samples are the figures to compare.
  - `review` of a response whose chain of 1 / 4 / 16 CNAME records points to unlisted names, the allowlist
    asked first for the query name: 102.6 (114.3) / 294 (330.5) / 1020 (1124). ~60 ns a hop (the CNAME of the name
    reached, its target looked up in the lists), ~40 ns once for the allowlist. Each hop reads on from where the
    last was found: a first version read the whole section at each hop, 1.5 to 2.2 µs for 16 hops (quadratic).
    Nothing is allocated. The same as before the rebase (98.1 / 278 / 989 fastest, at a lighter load).
  - `hit`, `Pipeline::query` on a cache hit of the captured `www.ripe.net. A` (two CNAME, their RRSIG, two
    addresses, 5 records): without a blocklist 82.8 (124.7), with one before the cache 145.6 (163.8). The
    ~40-60 ns difference is the plugin's lookup of the query name; the entry carries this pipeline's mark, so the
    reply is not decoded. Before the rebase: 100.6 (106.5) and 140.4 (150.8), so the difference is the same and the
    cache itself moved (D116) by more than the noise of this load allows to say. Before the mark, every such hit
    decoded the reply and reviewed it: 549 (601) ns, as measured in an earlier round of this work. A hit after a
    reload (another mark) pays that once per entry. A response from upstream pays the review once, before it is
    stored, on top of the decoding it already has.
- Lists read once, kept across reloads (D120, audit step 19, E3). Apple M5, macOS, release `dedensd`, the old one
  built from ef75a5b. Six published lists (StevenBlack hosts 2.4 MB, hagezi pro-onlydomains 4.1, light 1.7, multi
  3.6, ultimate 5.7, TIF 32.7 MB; 49.9 MB, 2.68M lines, 2.14M names, 542k of them listed twice), fetched from
  their public URLs for the run, not kept in the repo, as the saved copies of the `urls` of one blocklist stage.
  `ps` RSS sampled every ~20 ms during the reload, `/usr/bin/time -l` maximum resident set. A SIGHUP after the
  copy of one list (hagezi pro) got a line appended, 3 runs each, old and new alternated; the answers and the
  logged counts are the same (2 135 862 names, 542 425 duplicates):

  | | before | after |
  |---|---|---|
  | lists parsed by that reload | 6 | 1 |
  | the reload (SIGHUP to `reloaded`) | 0.71-0.77 s | 0.14-0.18 s |
  | peak RSS over the reload | 119 → 171 MB (+52) | 110 → 148 MB (+37) |
  | RSS once started | 119 MB | 110 MB |
  | `validate`, max resident | 120.2 MB, 0.74 s | 111.3 MB, 0.79-0.95 s |

  After, the peak is the new merged set (38 MB: 2^22 buckets of 9 B) built while the old one serves; the store
  holds 8 B a name of each source (21 MB for these) beside it. Before, the reload read the six copies again (the
  largest, 32.7 MB, into one `String`). Some runs of the new binary
  started at 71-73 MB: macOS had compressed its pages; those are left out. A list downloaded (TIF over loopback, a
  fresh start, measured on the first pass of this step): parsed twice before (to check it, then by the reload that
  follows, 0.39-0.45 s later) and once now, the reload after the download taking 0.1 ms. The parses and merges are
  logged (`list parsed`, `lists merged`) and counted by `a_reload_reads_the_lists_that_changed_only` and
  `a_downloaded_list_is_read_once` (`apps/dedensd/tests`).
- A stage of many sources, 50 sources of 200 000 random names (`h<16 hex>.example`, 10M names, generated for the
  run, not kept; a throwaway test, release): parsing all 50 1.86 s; `Merged::new` of the 50 0.29 s; a reload with
  one source replaced (parse 200k, merge the 50) 0.35 s. A first version looked each source up in turn and
  counted the names held by earlier sources at every add: 2.1 s for the same 50 sources (measured in the review of
  that version), and lookups of 0.2-1.5 µs a suffix with 20 large sources (D120, rejected).
- `benches/blocklist.rs` before (`ef75a5b`) and after, the bench binaries built each, run alternately 3 times, 100
  samples, the fastest sample, ns (the lists are the 1 KB heads of three block lists and one allow list, so their
  sets sit in the cache: they say the lookup code is D110's, not what a large stage costs): `lookup` 1 / 3 / 10 /
  127 labels 9.0 / 39.5 / 56.1 / 225 → 9.0 / 38.5 / 56.1 / 218.5; `lookup_blocked` 10 / 123 90.3 / 257.5 → 90.3 /
  254.9; `query` `www.example.com.` 119.6 → 120.9; `review` 1 / 4 / 16 hops 101 / 284 / 979 → 100 / 289 / 1031;
  `hit` 99.4 / 143 → 100 / 144. `read` of the heads 17.6 → 18.7 µs (+6%: the hashes are sorted and deduplicated
  on the way). `check` (the download's check, 11 µs) is now `parse` (13.7-14.1 µs: it hashes the names, which the
  reload's second read did); `merge` of the heads into one side 0.47-0.50 µs.
- The read as `user` after the drop (D122, audit 4 of `dedensd`). Apple M5, macOS, release, a throwaway test of
  `lib.rs` (the drop itself is Linux only): a blocklist stage of one `file`, 2M generated names (`h<16 hex>.example`,
  not kept), `build` once as root then once more as the start does after the drop, 3 runs. Before, the second read
  had a fresh `Store`; after, the first one's, and the first pipeline as `previous`. `ps` RSS with both reads held,
  as `main` held them (the first `Config` and `Store` lived as long as it), 2 runs:

  | | before | after |
  |---|---|---|
  | first read | 0.58-0.67 s | same |
  | second read | 0.59-0.69 s | 0.2-3.1 ms |
  | RSS, one read | 77 MB | 79 MB |
  | RSS, both held | 136-143 MB | 79 MB |

## DoH core (D82)

`benches/doh.rs`, medians in nanoseconds for `a`/`mx`/`txt_large`, one run. The HTTP layers (`h3`, `h2`) are
not measured: the core only makes and reads `http` types.

| Measure | ns |
|---|---|
| `request`, GET (query to base64url in the URI) | 359/336/328 |
| `request`, POST | 295/295/290 |
| `response`, TTLs untouched | 135/238/442 |
| `response`, `Age: 10`, every TTL lowered | 132/236/475 |
| `server_request`, GET (one allocation, the query) | 24/20/19 |
| `server_response`, GET (decodes to find the TTLs, copies the body) | 174/282/514 |

- A request or response costs about what decoding the message does (73/153/289, Codec above): the HTTP
  headers are a few hundred nanoseconds, so a DoH exchange is bound by the HTTP and TLS layers.

## DoH over HTTP/3 and DoQ (D83)

`cargo bench -p dedens-net --bench transports`: queries a second of one `Client` against loopback servers
(`benches/transports.rs`), client and servers on one thread, 3 s a row, one run, the connection warm. Each query is
`example.com. A`, padded to 128 bytes, and the response is that query echoed with QR and RA set. `in flight` loops ask
one after another over one connection.

| Transport | in flight | queries/s |
|---|---|---|
| DoQ | 1 | 9395 |
| DoQ | 32 | 202875 |
| DoH3, GET | 1 | 8598 |
| DoH3, GET | 32 | 95376 |
| DoH3, POST | 1 | 8769 |
| DoH3, POST | 32 | 124747 |

- One query at a time DoH3 is 8% slower than DoQ (QPACK and HTTP framing on top of the same QUIC stream); with 32
  at once 0.47x (GET) and 0.61x (POST) of DoQ's rate, the one thread running both ends. A GET builds a URI with the
  query in base64url and its server parses it; POST sends the query as a body.
- The silent-try close (D61, D83) reads the reused connection's received datagrams and the clock before each
  request, a lock of the connection's state. Three rounds alternating `origin/main` (7dc4be80) and the change, the
  same bench binaries, on an Apple M5 (10 cores) under load (load average 3 to 9, other agents' builds running),
  medians in queries/s:

  | Transport | in flight | before | after |
  |---|---|---|---|
  | DoQ | 1 | 9750 | 9746 |
  | DoQ | 32 | 214280 | 212807 |
  | DoH3, GET | 1 | 9049 | 9039 |
  | DoH3, GET | 32 | 100636 | 100140 |
  | DoH3, POST | 1 | 9247 | 9250 |
  | DoH3, POST | 32 | 121088 | 120621 |

  Within 1% each way, under the spread between rounds (up to 5%): no cost to measure.

## Client UDP and TCP pools

`cargo bench -p dedens-net --bench pools`: queries a second of one `Client` over its UDP socket pool (D50) and its one
TCP connection (D27) against loopback servers (`benches/pools.rs`), client and servers on one thread, 3 s a row, the
sockets and the connection warm. The query is `example.com. A`, the response that query echoed with QR and RA set.
`in flight` loops ask one after another. Three runs in a row on an Apple M5 (10 cores) under load (load average 9, other builds running), so about 20% of noise between runs:

| Transport | in flight | run 1 | run 2 | run 3 |
|---|---|---|---|---|
| UDP | 1 | 25267 | 28651 | 27914 |
| UDP | 32 | 86741 | 90251 | 70316 |
| TCP | 1 | 28742 | 28508 | 24569 |
| TCP | 32 | 248517 | 242478 | 222508 |

### After the seam (D134)

The bench executables of the tree before the seam and after it (`Client<Compio>`: `UdpPool`, `TcpPool` and `Client`
generic over `Io`, `Compio` zero-sized) run alternately, four rounds each, the median of the four, on the machine and
the load above. The rounds of one build range over 1.4x, so this rules out only a regression of more than about 40%:

| Transport | in flight | before | after |
|---|---|---|---|
| UDP | 1 | 23737 | 23327 |
| UDP | 32 | 72219 | 74758 |
| TCP | 1 | 23152 | 26210 |
| TCP | 32 | 214429 | 216932 |

The queries waiting on a TCP connection in a `BTreeMap` rather than a `HashMap` (D134, determinism): TCP, 32 in flight,
four alternating rounds under load average 12-15, medians 196077 (`BTreeMap`) and 194622 (`HashMap`) queries/s, the
rounds over 2x apart: no difference that shows.

### Build and binary (D134)

`cargo build --release -p dedensd -p dedens --timings` from a clean target directory, before and after, on the same
machine under load (load average 11-13: the wall times, 2m01s and 2m45s, are not comparable, the builds not running
alone):

| | before | after |
|---|---|---|
| `dedens-net` compile | 3.8 s | 2.8 s |
| `dedensd` compile (codegen) | 59.4 s | 61.2 s |
| `dedens` compile (codegen) | 59.0 s | 59.5 s |
| `dedensd` size | 6,235,984 bytes | 6,153,184 bytes (-1.3%) |
| `dedens` size | 5,107,920 bytes | 5,107,872 bytes |

The generics stop at `Client<Compio>`: `dedensd` and `dedens` name `Client` and get the `Compio` default, one
instance of each pool. `dedensd`'s `__text` is 73,792 bytes smaller (-1.6%), not from code the seam removed: the
symbols of the binary built unstripped (`CARGO_PROFILE_RELEASE_STRIP=false`) show fat LTO inlining differently
across crates, the largest `ReadExact` over a TLS read half (`futures_util`, 16,136 to 1,384 bytes), then `core`
(-12,844), `compio-net` and `compio-driver` (-17,056) and `rustls` (-11,500). The client's own functions, into which
the pools' code is inlined, move by a few percent:

| Function (`dedens-net`) | before | after |
|---|---|---|
| `Client::step` (UDP and TCP queries inlined) | 23,500 | 24,760 |
| `Client::run` | 17,856 | 18,368 |
| `udp::receive`'s task | 4,712 | 5,844 |
| `TcpPool::connection` | 4,072 | 4,100 |
| `TcpPool::exchange`'s timeout | 2,552 | 2,616 |
| `tcp::run` and its timeout | 28,160 | 25,396 |

`cargo-show-asm` was not installed: these are symbol sizes in bytes, not instructions.

## dedensd serving DoH over HTTP/3 (D84)

`cargo bench -p dedensd --bench doh3`: the release `dedensd` on a macOS host (one serving thread) answers one name from
its cache behind an `https://` listener; a `dedens-net` `Client` of the bench process, on one thread, asks it over
loopback, 3 s a row, one run, the connection and the cache warm.

| Method | in flight | queries/s |
|---|---|---|
| GET | 1 | 9031 |
| GET | 32 | 73189 |
| POST | 1 | 9087 |
| POST | 32 | 77608 |

- One at a time the rate is that of the echo server of D83 above (8.6k-8.8k): the round trip, not `dedensd`, is the
  limit. With 32 at once 0.77x (GET) and 0.62x (POST) of that server's, the client and `dedensd` each on one
  core and `dedensd` also decoding, looking in its cache and encoding.

### The windows and the byte budget (D119)

`cargo bench -p dedensd --bench doh3` and `-p dedens-net --bench transports`, the bench executables of the tree before
D119 (7d88de1) and after run alternately, five rounds each, the median of the five. Apple M5, macOS 27.2, rustc 1.99.1
(Homebrew), a laptop in use, load average 6-10 from other work: single rounds range over 1.5x, so only a difference
larger than that would show.

| Row | in flight | before | after | after, `BUDGET` not reached |
|---|---|---|---|---|
| `doh3` GET | 1 | 6231 | 6306 | 6681 |
| `doh3` GET | 32 | 67091 | 63749 | 73045 |
| `doh3` POST | 1 | 6466 | 6829 | 6469 |
| `doh3` POST | 32 | 73331 | 75908 | 74825 |
| `transports` DoQ | 1 | 7616 | 7198 | |
| `transports` DoQ | 32 | 163701 | 150061 | |
| `transports` DoH3 GET | 1 | 6745 | 6700 | |
| `transports` DoH3 GET | 32 | 74069 | 69909 | |
| `transports` DoH3 POST | 1 | 6724 | 6823 | |
| `transports` DoH3 POST | 32 | 84437 | 84533 | |

- No difference beyond the noise. The last column is `doh3` with `BUDGET` raised to 2^40 (one run of five rounds): at
  75 000 queries a second a 3 s row sends about 40 MiB, so the connection is rotated ten times: GET with 32 in flight
  is 13% slower with rotation (63.7k against 73.0k), POST is equal, the spread of single rounds larger than both. The sweeper's idle cost was not measured apart: one
  wake-up every 20 ms a thread.

## dedensd serving UDP (D121)

`cargo bench -p dedensd --bench udp`: the release `dedensd` on one thread answers one name from its cache over loopback to
sockets of the bench process (one thread), 3 s a row; the bench executables of the tree before D121 (09220db) and after,
run alternately, four rounds each. Apple M5, macOS, `poll` driver, a laptop in use: single rounds range over 2.4x.

| in flight | before: median (fastest) | after: median (fastest) |
|---|---|---|
| 1 | 35347 (43867) | 30713 (42250) |
| 32 | 87600 (128907) | 82252 (104998) |

- Within the noise: the rounds of both overlap, the medians differ by 6-13% against a spread of 2.4x, and no round order
  explains it. A difference under 10% is not shown; io_uring on Linux was not measured (no Linux host), where `just
  bench-dnsperf` is the check to run.

### Behind the seam (D182)

The same bench, the executables of the tree before D182 (440e39dd) and after (`Thread<Compio>`: `udp`, `tcp`,
`answer` and `supervise` generic over `Io`), run alternately, eight rounds each, the order of the pair swapped after
four. Apple M5, macOS, `poll` driver, load average 14-16 from other builds: single rounds range over 3.7x.

| in flight | before: median (fastest) | after: median (fastest) |
|---|---|---|
| 1 | 20756 (29771) | 16193 (22340) |
| 32 | 65050 (91618) | 60122 (72739) |

- No conclusion either way: the rounds of both overlap from end to end, and the code on a datagram's path is the same
  calls through one `#[inline]` forwarder each.

On Linux: the VPS of "UDP send queue and `io_uring` flags" below, `DEDENS_CONTAINER=podman DEDENS_BACK_CPU=2
DEDENS_LOAD_CPUS=3-5 DEDENS_ROUNDS=<n> just bench-dnsperf 440e39dd <mode>`, base and tree alternating, no query lost
in any run. Queries/s, min-max (median):

| mode | before (440e39dd) | `timeout_at` forwarded | `Deadline` (kept) |
| --- | --- | --- | --- |
| `tcp` | 742k-807k (776k) | 656k-696k (665k) | 822k-883k (852k) |
| `udp` | 190k-198k (194k) | 184k-195k (194k) | 184k-200k (192k) |
| `forward` | 34.1k-36.8k (35.7k) | 40.5k-46.3k (44.6k) | 43.1k-48.0k (45.2k) |
| `forward-tcp` | 48.1k-55.5k (53.7k) | 63.9k-68.5k (68.2k) | 73.3k-76.6k (73.6k) |

- Six rounds for `tcp` forwarded, three for `udp`, five for forwarding; four in the `Deadline` column, six for its
  `udp` (a four-round run before it had one round at 160k, its base none: a neighbour); each column's base runs
  beside it, pooled here.
- A/A control: the base against itself, `forward`, three rounds: 36.2k-36.9k against 35.6k-36.7k. The harness has no
  bias of its own.
- TCP 14% slower with `timeout_at` forwarded: a `perf` profile (`DEDENS_PERF=1`) showed `memmove` at 10% of the
  server's time against 2.5% before, the reads' and writes' futures moved through compio's two nested `async fn` and
  ours; the clock (vDSO) at 5.9% against 3.7%. `Deadline` polls them in place, one clock read: 10% faster than the
  base.
- Forwarding gains 25-35% under both: not explained. The client's exchange was on the seam already (D134); the
  front server's queries now spawn through `Io::detach` and read one clock. No query lost, every reply NOERROR.

## dedensd under dnsperf (D48-D53)

`just bench-dnsperf [base] [mode]`: Docker on an Apple M-series host (Linux arm64 VM, io_uring), `dedensd` on
one core answering four names from its cache, dnsperf on six, 10 s a run, two rounds.

- One UDP task a socket → four: 304k-334k → 381k-432k queries/s, average latency 1.5 → 1.2 ms.
- TCP (`tcp`), one write a reply → queued replies written together: 176k-191k → 1.79M-1.83M queries/s,
  average latency 2.7 → 0.22 ms. Copying each reply twice instead of once: no change (176k-188k).
- UDP, a receive asked per datagram → one multishot receive into a pool of 256 4-KiB buffers (D49): 402k-428k
  → 478k-480k queries/s, average latency 1.2 → 1.0 ms. 16 tasks a socket instead of 4: 475k-516k, within noise.
- Forwarding (`forward`): `dedensd` without a cache, every query sent over UDP to a second `dedensd` on its own
  core answering from its cache. A socket per upstream query → a pool of 256 muxed sockets (D50): 124.6k-124.9k
  → 126.5k-127.7k queries/s, no loss, average latency 4.0 → 3.9 ms. The front `dedensd` is the limit, at 99% of
  its core against 31% for the upstream one, most of it in the kernel (loopback sends, wakeups). Its local
  address asked once a socket, not once a query (`getsockname` was 2.4% of the profile): 124.7k → 129.3k-129.9k.
  Cooperative io_uring task work (D51; signal-like task work was 7.3% of the profile): 135.0k-135.4k →
  158.0k-158.2k, average latency 3.7 → 3.1 ms; UDP and TCP from the cache unchanged (506k-516k, 1.86M-1.93M).
  `SQPOLL` instead: cache hits over UDP 475k → 230k, forwarding 155k → 82k.
  Registered file descriptors (io_uring fixed files, a compio prototype: the listening socket registered, its
  multishot receive and sends given its index), cache hits over UDP: 488k-513k → 501k-517k, +1%, within noise.
  At 44ea2ce, 160k-163k: the front `dedensd` spends 58% of its core in the kernel (17.5% waking the
  receiver of each loopback datagram), 30% in its own code with no function above 2% (encoding the reply,
  decoding the response, timers, the compio driver), 8% in libc (allocation), 4% reading the clock. TCP is twice
  as fast because replies and upstream queries go out several per write (D53); UDP has one datagram per send.
- Forwarding over TCP (`forward-tcp`), the same against itself: 84.5k-88.6k. A 65535-byte reply buffer zeroed
  for each query → kept per thread and reused (D52): 83.9k → 90.1k-92.3k unzeroed; zeroed on reuse, the default:
  79.4k-87.6k against 87.1k-90.0k unzeroed in the same run. Upstream queries queued meanwhile written together
  (D53), up to 65535 bytes, as replies to clients are: 86.4k-88.3k → 273.5k-278.3k, average latency 5.7 → 1.8 ms.
  Replies made in one buffer per thread and copied out (D63), against spare buffers zeroed on reuse:
  230.3k-269.5k → 303.4k-305.3k, average latency 2.1-1.8 → 1.6 ms; forwarding over UDP 152.8k-155.4k →
  150.9k-157.7k and TCP from the cache 1.77M-2.06M → 1.46M-2.09M, both within noise (the base too fell to 1.29M
  once).
  The front `dedensd` is at 100% of its core: 27% in kernel wakeups, 9% reading the clock.
- Two sockets (`two-sockets`, D107): one core, one cache, two UDP ports; the first flooded (eight clients, dnsperf
  on five cores), the second asked at 2000 queries/s by one client for 10 s. Before (59db4d0, the pause held the
  socket's lock) → after (UDP receive errors paused per task, `ResourceBusy` backed off, reload wake-up): the
  second socket's average latency 0.30-1.04 ms → 0.28-0.31 ms, maximum 13-101 ms → 10-12 ms, no query lost on
  either socket in any run (four runs: two rounds each). The flood never emptied the pool of 256 buffers, so no
  `ENOBUFS` happened and the change shows only as noise: the first base run's 101 ms maximum was its warm-up,
  not repeated in round 2. The scenario cannot show the U2 gain; the unit tests (`serve/udp.rs`) do, with a stream
  that fails on every poll.

### UDP send queue and `io_uring` flags (D123, D51)

Machine: a VPS with six Haswell vCPUs shared with other tenants (a Grafana runs there), AlmaLinux 10.2, Linux 6.12 with
`kernel.io_uring_disabled` set to 0 for the sessions, podman rootless; every run's log says `"driver":"io_uring"`.
`dedensd` on core 0, dnsperf (`-c 8 -T 4 -q 500`) on cores 2-5 (3-5 forwarding, the second `dedensd` on 2), 8 s a
run, five rounds, the variants alternating within each round, no query lost in any run. `io_uring_enter` a query
comes from an ftrace histogram on `syscalls:sys_enter_io_uring_enter` over the server's threads (`perf` and
`strace` are not installed). The noise is 3-5% on a path a change does not touch (TCP, forwarding over TCP), larger
on the others (a round of the UDP base in the ring session fell to 139.9k). `run.sh` alternates base and tree as
well, so the first claim reruns with `DEDENS_CONTAINER=podman DEDENS_BACK_CPU=2 DEDENS_LOAD_CPUS=3-5
DEDENS_ROUNDS=5 just bench-dnsperf 8ce176f udp` (and `forward`); the other variants took environment switches that
are not in the tree.

Queries/s, min-max (median), and `io_uring_enter` a query, `8ce176f` (before) against the queue with two
receiving tasks and 256 queued (the kept 64: the `UDP_SENDS` table below), one session:

| mode | before | after | enters before → after |
| --- | --- | --- | --- |
| `udp` | 151.2k-169.5k (163.1k) | 171.3k-197.2k (190.8k) | 0.255 → 0.006 |
| `forward` | 33.1k-36.7k (35.5k) | 39.0k-42.3k (41.0k) | 0.082 → 0.066 |
| `tcp` | 793k-811k (803k) | 727k-822k (779k) | 0.0046 → 0.0046 |
| `forward-tcp` | 56.1k-59.4k (57.4k) | 56.1k-60.9k (56.8k) | 0.0374 → 0.0374 |

Average latency over UDP 3.0 → 2.5 ms, forwarding 14.1 → 12.1 ms. Over UDP the medians rose 11-17% and forwarding
10-17% in four sessions: the one above and three earlier ones, `d215d31` against the queue with four receiving tasks
(169.9k → 193.0k, 171.3k → 191.5k, 172.0k → 191.6k over UDP; 35.8k → 41.9k, 36.0k → 39.7k, 35.7k → 39.4k
forwarding), against 163.1k → 190.8k and 35.5k → 41.0k above. A detached
task for each reply instead of the queue (`spawn`, `d215d31` base): 0.033 enters a query over UDP, 160.2k-187.0k
(180.9k), forwarding 31.6k-35.5k (32.7k) against 30.4k-36.1k (33.2k) for the base in that session.

Tasks receiving on a socket, with the queue (`UDP_RECEIVES`), UDP over eleven rounds and forwarding over five:

| tasks | `udp` | `forward` |
| --- | --- | --- |
| 1 | 164.4k-204.2k (197.1k) | 35.3k-41.7k (39.5k) |
| 2 | 185.1k-199.8k (194.3k) | 38.6k-42.0k (41.3k) |
| 4 | 181.7k-194.8k (189.6k) | 36.9k-41.8k (41.2k) |

Equal within noise; two are kept (D123). Without the queue D48 measured 1 task at 310k and 4 at 415k: a task waited
for its send then.

Replies queued for the sender, `UDP_SENDS`, with the queue and two tasks, in a session of its own:

| queued | `udp` | enters | `forward` | enters |
| --- | --- | --- | --- | --- |
| 16 | 174.2k-185.9k (180.0k) | 0.063 | 33.7k-36.8k (36.0k) | 0.084 |
| 32 | 182.1k-197.1k (185.0k) | 0.032 | 36.4k-38.2k (36.5k) | 0.083 |
| 64 | 179.3k-197.6k (192.4k) | 0.016 | 35.2k-39.3k (37.4k) | 0.082 |
| 256 | 189.3k-197.5k (196.0k) | 0.006 | 34.3k-41.8k (37.9k) | 0.066 |

Only 256 keeps the forwarding gain (the other session's 256: 41.0k). 64 is the one kept, for the latency below
(D123).

Two sockets (`two-sockets`, D107), `8ce176f` and the final code, four rounds of each in `run.sh`, the first socket
flooded by eight clients on cores 2-5, the second asked at 2000 queries/s on core 1 (`DEDENS_BACK_CPU=1`, which
the mode leaves free); then four rounds of the same by a script, with `UDP_SENDS` 64 and 16. Two ranges in a cell:
`run.sh`, script.

| | second socket, average latency | its maximum | flood, queries/s (script) |
| --- | --- | --- | --- |
| `8ce176f` | 0.10-0.37 ms; 0.10-0.70 ms | 3.7-124 ms; 7.4-90 ms | 153k-166k |
| 256 queued | 1.19-1.42 ms; 1.23-2.09 ms | 11-85 ms; 10-97 ms | 176k-194k |
| 64 | 0.53-1.28 ms | 11-141 ms | 169k-196k |
| 16 | 0.21-0.30 ms | 7-158 ms | 155k-184k |

No query lost on either socket in any run. The second socket's average latency rises about tenfold with the queue
(the flood's sends go out in batches of up to 256 ahead of its reply in the same submission); the maximum does not.
64 is kept: it halves that latency, keeps most of the UDP gain and gives the forwarding gain away (D123).

The rings, medians over five rounds, without the queue (`await`) → with it (4 receiving tasks, 256 queued), in
queries/s:

| ring | `udp` | `forward` | `tcp` | `forward-tcp` |
| --- | --- | --- | --- | --- |
| `COOP_TASKRUN` (D51) | 171.3k → 191.5k | 36.0k → 39.7k | 803k → 808k | 56.8k → 56.8k |
| `SINGLE_ISSUER` + `DEFER_TASKRUN` | 173.8k → 193.4k | 35.2k → 39.7k | 784k → 770k | 57.1k → 58.7k |
| the same + `COOP_TASKRUN` | 166.5k → 196.0k | 34.8k → 38.9k | 788k → 777k | 58.3k → 58.6k |
| `SQPOLL`, thread on the server's core | 96.3k → 161.8k | 23.3k → 24.0k | 457k → 450k | 28.0k → 27.5k |
| `SQPOLL`, thread on core 1 | 200.0k → 250.5k | 54.7k → 58.7k | 975k → 1.08M | 65.7k → 65.4k |
| two serving threads, cores 0-1 (no `SQPOLL`) | 279.7k → 306.5k | 75.9k → 71.1k | 995k → 1.13M | 113.8k → 118.6k |

`DEFER_TASKRUN` is within noise of `COOP_TASKRUN` and no fewer enters. `SQPOLL` on a core of its own gains over
one core, but two serving threads gain more with the same two cores, and an `SQPOLL` thread spins its core
while idle (1 s here); on the server's core it halves the rates. The first full run of this matrix was
discarded: a server left running by a failed run had been using the VPS's cores.

The flags again on the final code (`1d6d02c`: two receiving tasks, 64 queued), the same method, five rounds with the
order of the three rings rotating each round, no query lost and `"driver":"io_uring"` in all 60 runs. The rings
were set by an environment variable read where the runtime is built (not committed); `TASKRUN_FLAG` stayed on in all
three, and the second `dedensd` of the forwarding modes kept `COOP_TASKRUN`. The enters come from one run each
with the histogram on (the front server's thread told from the second one's by its thread ids). Queries/s,
min-max (median), and `io_uring_enter` a query:

| ring | `udp` | enters | `forward` | enters |
| --- | --- | --- | --- | --- |
| `COOP_TASKRUN` (D51) | 185.8k-193.1k (189.2k) | 0.0158 | 37.3k-40.4k (39.3k) | 0.0824 |
| `SINGLE_ISSUER` + `DEFER_TASKRUN` | 184.7k-191.6k (190.3k) | 0.0160 | 37.3k-42.0k (39.6k) | 0.0824 |
| the same + `COOP_TASKRUN` | 175.2k-200.7k (189.4k) | 0.0160 | 38.3k-40.1k (39.5k) | 0.0824 |

| ring | `tcp` | enters | `forward-tcp` | enters |
| --- | --- | --- | --- | --- |
| `COOP_TASKRUN` (D51) | 774k-829k (807k) | 0.0045 | 57.2k-59.9k (58.4k) | 0.0374 |
| `SINGLE_ISSUER` + `DEFER_TASKRUN` | 792k-838k (808k) | 0.0083 | 55.3k-61.1k (58.2k) | 0.0370 |
| the same + `COOP_TASKRUN` | 738k-826k (811k) | 0.0084 | 56.9k-60.7k (58.4k) | 0.0371 |

The medians differ by at most 0.6% in every mode, far inside the ranges: `DEFER_TASKRUN` gains nothing. It
costs nearly twice the enters over TCP and saves none over UDP or when forwarding. `COOP_TASKRUN` stays (D51, D123).

## Zone files (D25)

A generated 100 000-record zone: dedens 7.3-7.5 ms, `domain` 9.8 ms, hickory-proto 54 ms (it also builds record
sets). A lazy lexer cost 17% until a byte table skipped plain token text. Taking `\#` hex as the wire RDATA
once checked, instead of encoding it twice more, does not show: the generated zone has no such record.
Reading numbers and code mnemonics from the token bytes, instead of checking them as UTF-8 for `FromStr`:
9.6 → 9.05 ms in the same session (6%); `from_utf8` went from 9.5% to 5.5% of the profile, the rest being
IP addresses, whose byte parser (`parse_ascii`) is not stable yet. Scanning token text 8 bytes at a time in a
`u64` (bit tricks, no `unsafe`) instead of the byte table was 9% slower (9.05 → 9.9 ms): most tokens are
shorter than 8 bytes, so the word test only adds work before the byte loop.

## DNSSEC crypto (D71)

`benches/dnssec.rs`, one call on the RFC example each (`ring`; keys of 1024 bits where RSA's size is not said).
Microseconds unless stated.

| Measure | Median |
|---|---|
| Verify RSASHA1 (5), 1024 bits | 1.7 |
| Verify RSASHA256 (8), 1024 bits | 3.3 |
| Verify RSASHA256 (8), 2048 bits | 10.7 |
| Verify RSASHA512 (10), 1024 bits | 3.4 |
| Verify ECDSAP256SHA256 (13) | 27.3 |
| Verify ECDSAP384SHA384 (14) | 341 |
| Verify Ed25519 (15) | 19.6 |
| DS digest SHA-1 / SHA-256 / SHA-384, ns | 334 / 125 / 173 |
| NSEC3 hash at 0 / 12 / 150 iterations | 0.11 / 1.2 / 13.6 |
| NSEC3 hash at 150 iterations, salt of 0 / 64 / 255 octets (151 / 302 / 755 SHA-1 blocks) | 14.9 / 27.0 / 61.6 |

RSA with a public exponent of 65537 is the cheapest to check and P-384 the dearest, 17 times Ed25519's cost.
`Budget`'s defaults come from the worst: 64 verifications of P-384 are 22 ms, and 8192 SHA-1 blocks of NSEC3
hashing 0.8 ms. The budget counts blocks, not hashes (D106). A block takes 99 / 89 / 82 ns at a salt of 0 / 64 /
255 octets (the medians above over the blocks; the fastest of 2000 samples, which repeats to 1% across runs, gives
93 / 86 / 77 ns): above the 90 ns the defaults were sized with at no salt, below it with a long one, as each hash has
a fixed part a block has not. So a long salt is charged at least what it costs. The medians are the
lowest of six runs on a machine at a load of 48 (other jobs running), the others of an earlier, quieter one: read
the ratios, not the digits. A validation of a name five zones deep verifies about 20 signatures, and the denial
proof of a name ten labels deep hashes about a dozen names, 1800 blocks at 150 iterations and no salt. Without a
cap, a response that makes the validator check every signature against every key of one tag (KeyTrap,
CVE-2023-50387) costs it seconds.

`trusted_keys_one_tag`: `trusted_keys` on 8 and 64 DNSKEYs of one tag, each with a SHA-256 and a SHA-384 DS, no
signature (2026-11-14, a machine shared with other builds). Digesting each key against each DS record of its tag
took 10.8 / 640 µs, quadratic: a zone of a thousand keys and DS records of one tag, which a 64 KiB response
holds, was hundreds of milliseconds no budget counted. One digest per key and digest type, searched among the
sorted DS records (D73): 2.1 / 18.8 µs.

## Oblivious DoH (D78)

`benches/odoh.rs`, one call each on the captured response `a` (and `mx`, `txt_large` for the responses), padded
to 128 and 468 bytes (RFC 8467); median, with fixed bytes for the ephemeral key and the response nonce. HPKE is the
`hpke` crate (RustCrypto, X25519 and AES-128-GCM); the response's HKDF is one HMAC of `ring`, its AES-GCM `ring`'s.

| Measure | Median |
|---|---|
| Encrypt a query (client: HPKE seal) | 51.6 µs |
| Decrypt a query (target: HPKE open) | 34.6 µs |
| Encrypt a response, 3 captures | 1.11-1.30 µs |
| Decrypt a response, 3 captures | 0.95-1.00 µs |
| Derive a target key (`DeriveKeyPair`, public key, key ID) | 17.0 µs |

Deriving a key is one X25519 multiplication, so a query is three of them for the client and two for the target (the
ratios of the times are 3.0 and 2.0), and they are the whole of its cost. The response is one HKDF and one AES-GCM of
under 1 KB, a thirtieth of the target's side: the target answers from the context of its query, with no public-key
operation. An ODoH exchange adds about 88 µs of CPU across both parties to a DNS over HTTPS one, small next to the
extra hop. Three runs on a quiet machine agree within 1%.

The response path once made 9 allocations and 9 reallocations to encrypt, 7 and 5 to decrypt: the DNS message
copied into a `MessagePlaintext`, a plaintext grown from empty, a second copy to seal, the AAD and the HKDF input
on the heap. The plaintext is now written once, sized for the tag, and sealed in place; the AAD is an array and
the HKDF an HMAC context: 3 allocations each way, no reallocation, and no copy of the query plaintext left by a
reallocation. Fastest of two interleaved runs of the old and the new binary on a loaded machine (2026-11-20; the
medians there are noise), `a`, `mx`, `txt_large`:

| Measure | Before | After |
|---|---|---|
| Encrypt a response | 1.12 / 1.13 / 1.25 µs | 0.74 / 0.76 / 0.86 µs |
| Decrypt a response | 0.99 / 0.99 / 1.04 µs | 0.85 / 0.82 / 0.89 µs |

The query side, under HPKE, is unchanged within noise.

## DNSCrypt (D97)

`benches/dnscrypt.rs`, one call each, on the captured responses `a`, `mx` and `txt_large` (72, 161 and 1187 bytes), for both
classical systems; the query is padded as a UDP query of the draft's "Padding For Client Queries Over UDP" (256 bytes at
least), the response for TCP; median, with fixed bytes for the nonces (Apple M5, three runs on a quiet machine, the
range of their medians when it is wider than 2%). A response's padding is a function of the shared key and the client
nonce, so a fixed nonce would seal one message to different lengths under the two systems: the benches pick, for each
system and capture, the first client nonce of 64 whose response has no extra block of padding, and assert it, so both
systems encrypt and decrypt the same plaintext (128, 192 and 1216 bytes padded). X25519 is `x25519-dalek`, the ciphers
`chacha20`, `salsa20` and `poly1305` (RustCrypto), the Ed25519 verification and the response padding's HMAC `ring`.

| Measure | XChaCha20-Poly1305 | XSalsa20-Poly1305 |
|---|---|---|
| Parse a certificate (Ed25519 verification) | 19 µs | (the same) |
| Open a session (client: public key and shared key) | 36.7-38.7 µs | 36.7-38.8 µs |
| Decrypt a query (resolver: shared key and open) | 19.1-20.2 µs | 18.9-19.2 µs |
| Decrypt a query, shared key kept (`decrypt_query_with`) | 0.67-0.69 µs | 0.49 µs |
| Encrypt a query (client, session open) | 0.63-0.67 µs | 0.52-0.55 µs |
| Encrypt a response: `a`, `mx`, `txt_large` | 0.59, 0.68, 1.67-1.75 µs | 0.49-0.51, 0.58, 2.02 µs |
| Decrypt a response: `a`, `mx`, `txt_large` | 0.67-0.70, 0.86-0.92, 2.0 µs | 0.48, 0.67-0.70, 2.28-2.45 µs |

The public-key work is the whole of the cost, as for ODoH: a session is two X25519 multiplications (the public key, then
the shared key), a resolver's first packet from a client one (19 µs), and every other packet is a keystream, a
Poly1305 and an allocation, 0.5-2.5 µs for the sizes here. A resolver that keeps the shared key of a client
(`decrypt_query_with`) pays the multiplication once: 28 times less for a packet of the same client. The two systems
differ by the stream cipher alone, and on equal plaintexts the gap is small and changes sign with the size: XChaCha20
costs 0.1-0.2 µs more on 128 and 192 bytes (15-40%, cause not investigated) and 10-20% less on 1216. One run of three
had `decrypt_query_with` for XChaCha20 at 1.27 µs, a disturbed machine.

The packets were once built from copies: a query sealed in its own buffer, then copied after a head built in a
third, a response sealed in a buffer grown from empty and copied into the packet, a decrypted response copied out of
its plaintext. Each is now padded and sealed in the packet it goes out in, and the response handed back in its
plaintext buffer: 6 allocations to 4 to encrypt a query, 2 and a reallocation to 1 to encrypt a response, 5 to 4 to
decrypt one (the rest is `Message::decode`). The time is the cipher's: fastest of five interleaved runs of the old
and the new binary, 300 samples each, on a loaded machine (2026-11-20), 2-7% less on 72 to 161 bytes and 1-2% on
1187 (encrypt a query, XChaCha20 0.61 to 0.57 µs and XSalsa20 0.52 to 0.49; encrypt a response `mx` 0.67 to 0.63
and 0.58 to 0.54; decrypt a response `a` 0.65 to 0.62 and 0.48 to 0.46).

## PQDNSCrypt (D101)

`benches/dnscrypt.rs`, the `pq_*` benches, one call each on the captured response `a` (72 bytes), with fixed bytes for the
randomness. A full query is the client's encapsulation to the resolver's `X-Wing` key and the sealing (a 1220-byte
packet: the 1120-byte ciphertext replaces the 32-byte client key, no 256-byte floor); the resolver decapsulates with
its secret key and opens. A resumed query carries the 130-byte ticket (424 bytes with the 256-byte padding) and needs
no public-key operation. Apple M5, **one run on a loaded machine** (another worker was building and testing at the
same time), so the numbers are an order of magnitude, not a ranking; the X25519 figures are D97's, the same run.

| Measure | X-Wing (`0x0003`) | X25519 (`0x0002`) |
|---|---|---|
| Parse a certificate (Ed25519 verification) | 23.7 µs | 20.6 µs |
| Full query, client (key agreement, sealing) | 67.8 µs | 39.9 µs |
| Full query, resolver (key agreement, opening) | 101.4 µs | 20.8 µs |
| Resumed query, client (sealing) | 1.1 µs | |
| Resumed query, resolver (ticket and key derivation, opening) | 1.7 µs | |
| Response with a ticket (resolver, 72-byte answer) | 1.7 µs | |

Post-quantum key agreement costs the client about 1.7 times an X25519 session and the resolver about five times, 100 µs of
a core a query: a resolver at 10,000 full PQ queries a second spends a core on decapsulation. That is why the draft has
tickets: a resumed query costs the resolver 1.7 µs, 60 times less, and the client 1.1 µs. A certificate is 1320 bytes, a
full query 1220 and a resumed one 424. `dedensd` bounds the decapsulations with D117's budgets, not D113's rate limit
(a pipeline stage, after the opening): 250 a second for a client network, 2500 for all, 2.5 % and 25 % of a core at 101 µs
(D101; the global one is a bound, no measure).

## DNSCrypt in `dedensd` (D99)

Queries per second over UDP on loopback, one `dedensd` thread (macOS has no `SO_REUSEPORT` spreading, so `threads: 1`), a
`hosts` stage answering `example.test A`, release build, a throwaway client of N threads each sending 16 queries and
reading 16 answers for five seconds (not committed: `dnsperf` speaks no DNSCrypt, and `just bench-dnsperf` needs
Linux). DNSCrypt is XChaCha20-Poly1305, a query padded to 256 bytes. Apple M5, one run each, the machine not
quiet (another build ran on it): the shape holds, the digits do not.

| Client threads | plain UDP | DNSCrypt, one client key | DNSCrypt, a new client key per query |
|---|---|---|---|
| 1 | 93,500 | 69,400 | 20,200 |
| 2 | 109,500 | 80,100 | 23,200 |
| 4 | 115,300 | 89,600 | 26,600 |

A client that keeps its key costs `dedensd` 25% of the plain rate, which the sealing and the client's own work account
for; a new key per query (as `dedens` does, D98) pays the X25519 multiplication at every packet (D97's 19 µs): 3.4 times
fewer queries. The per-thread cache of shared keys (D99) is what separates the two columns: without it every client
would be in the right-hand one. The cache fills only from a packet whose tag verified, holds 1024 keys and is cleared
when full.

## DNSSEC `RRset` verification (D73)

`benches/dnssec.rs`, `verify_rrset`: one `rrsig::verify` of a captured `RRset` (`testdata/dnssec`)
with its RRSIG and key: the checks of RFC 4035 §5.3.1, the canonical form and order of the RDATA, the signed data
and the signature. Microseconds.

| Capture | Algorithm | Median |
|---|---|---|
| `alg7_soa` | RSASHA1-NSEC3-SHA1 (7) | 3.5 |
| `alg8_a` | RSASHA256 (8) | 3.2 |
| `alg10_soa` | RSASHA512 (10) | 6.0 |
| `alg13_a` | ECDSAP256SHA256 (13) | 27.7 |
| `alg14_a` (11 addresses) | ECDSAP384SHA384 (14) | 347 |
| `alg15_a` | Ed25519 (15) | 19.2 |

The signature is the cost of the curves (P-256: 27.7 here, 27.3 for the bare check above), so the `Budget` of D71
stands as sized. RSA with a short exponent is cheap enough for the rest of the work to show: canonical form,
sorting and building the signed data take a few microseconds.

## DNSSEC key cache (D86)

`benches/dnssec.rs`, `validate_cold` and `validate_warm`: a whole validation of the captured `alg8_a` answer (RSASHA256
under `.`, `nl`, `nlnetlabs.nl`) at the time of the capture, with the captures as the caller. Cold, a validator that
knows no zone: 5 questions, the keys of three zones verified. Warm, one whose key cache holds the chain: no question,
the answer's signature alone. Each `t=N` runs N threads, each its own iterations: the cold ones share nothing, the warm
ones share one `Validator`, so one `Mutex`. Microseconds per validation, median of one run.

| Threads | Cold | Warm |
|---|---|---|
| 1 | 106 | 4.6 |
| 2 | 129 | 6.9 |
| 4 | 140 | 9.3 |
| 8 | 235 | 22.9 |

The cache takes a validation from 106 to 4.6 µs, which is the answer's one signature check (3.2 µs, above) and little
else. (The first figures of this section, 168 and 54 µs, included the read of the `captured_at` file the bench made
for each validation: 50 µs; the bench reads it once now.) The lock is held for one lookup and clones an `Arc` and a
name, never across a check. From one thread to eight the warm validation slows 5x, the cold one, with nothing shared,
2.2x: at 4.6 µs a validation, eight threads in a tight loop ask the one lock all the time, which a real caller's
validations, spread over time and far fewer than one per cache miss, do not. Part of the slowdown is the machine's
(cores of two kinds, one allocator).

D92 drops the bogus table (two tables, not three). The machine drifts too much between runs to compare against the
figures above: five runs after the change gave 1-thread warm medians of 5 to 13 µs and 8-thread cold ones of 126 to
330 µs, and `serve_warm` is bimodal, 6.7 or 17.5 µs per query, from one run to the next. So the build before and
the build after were run alternately, four runs of each, from the same directory. Medians over the four runs, µs:

| Measure | Before D92 | After |
|---|---|---|
| `validate_cold` t=1 | 113.6 | 112.4 |
| `validate_cold` t=8 | 309 | 313 |
| `validate_warm` t=1 | 13.2 | 13.1 |
| `validate_warm` t=8 | 17.5 | 17.6 |

The two builds are within 1.5% of each other and each within the spread of its own runs, so the change costs
nothing measurable. The absolute figures are those of a slow state of the machine, which is why they differ from the
table above (4.6 µs warm); that table is the figure of a quiet machine and is not redone. `serve_warm` did the same:
both builds showed the two modes.

`validate_wildcard_name`: the captured `wildcard_answer` (`wildcard-test.sidnlabs.nl` MX, a wildcard expansion
under `sidnlabs.nl`, ECDSAP256SHA256, one NSEC3 proving the next closer name absent) by a validator whose key cache
holds the chain (`sidnlabs_nl_dnskey` validated first, out of the timing), each sample a fresh validator: the shape
of the comparison's `dnssec` mode, a name never seen under a wildcard of a zone whose keys are known. Before D75's
shortcut, the walk asked the DS of `wildcard-test.sidnlabs.nl` and checked its denial (SOA and three NSEC3, each
signed); after, the answer's own NSEC3 proves the name absent and no cut: two checks, no question. The builds before
and after, copied out of `cargo bench --no-run`, alternated three rounds each in one session (2026-11-15, the
machine busy with other builds). µs:

| Measure | Before | After |
|---|---|---|
| `validate_wildcard_name` fastest, 3 rounds | 178.2-179.2 | 59.5-60.4 |
| `validate_wildcard_name` median, 3 rounds | 188-446 | 60.7-69.0 |
| `validate_cold` t=1 fastest, 2 rounds | 109.3, 111.0 | 107.4, 111.4 |
| `validate_warm` t=1 fastest, 2 rounds | 4.67, 13.2 | 13.2, 4.58 |

A third of the time, the two signatures of the answer and the NSEC3 at about 27 µs each (D71's table) and the rest
little; the medians of the build before swing with the machine, its fastest samples do not. `validate_cold` and
`validate_warm` (`alg8_a`, no denial in the answer) do not move: the shortcut reads the authority section only when
it holds a denial. On the VPS's Haswell a P-256 check is about 80 µs, so the name goes from about 530 µs of checks to
160.

### The memo of signatures verified

D86's memo keeps the digest of each check that succeeded. `validate_wildcard_name_again`: as
`validate_wildcard_name`, but the validator validated `wildcard_answer` first (out of the timing) and the sample is
`a.b.wildcard-test.sidnlabs.nl` under the same wildcard, as the comparison's `dnssec` mode asks name after name: the
signed data are the same, the wildcard's `RRset` and the NSEC3's. Base `21806bba` and the tree alternated two
rounds in one session (2026-11-16, M5), µs, medians:

| Measure | Before | After |
|---|---|---|
| `validate_wildcard_name_again` | 63.8, 64.0 | 8.9, 13.7 |
| `validate_wildcard_name` | 66.5, 63.3 | 63.5, 67.2 |
| `validate_warm` t=1 | 5.0, 5.1 | 1.8, 1.9 |
| `validate_warm` t=8 | 14.2, 8.0 | 6.7, 7.1 |
| `validate_cold` t=1 | 109.2, 113.3 | 108.7, 115.3 |

A validation that finds both checks in the memo costs the digests and the walk; `validate_warm` (one check of
`alg8_a`'s answer, held) falls by its RSA check. A name never seen and a cold validator do not move: the digests do
not show beside checks of 27 to 80 µs each.

## DNSSEC cost limits (D77)

`benches/dnssec.rs`, `serve_cold`, `serve_warm` and `serve_shed`: one uncached client query of the captured `alg8_a`
answer through `Pipeline::query` and `receive` of a validating forward stage with no cache stage, the captures as the
upstream, so each run validates or is shed. Cold: a validator that knows no zone, five questions and the keys of three
zones verified; warm: its key cache holds the chain; shed: `Allowance::burst` 0, so the allowance refuses the query
before anything is sent. `t=N` threads share one pipeline in warm and shed, so one allowance and one `Mutex`; the
cold ones build their own. Median per query, one run. The benches ran on one thread whatever `t=N` (divan's
`bench_local` does): the rows are four runs of one thread, and [Threads in the serve benches](#threads-in-the-serve-benches)
has the threads.

| Threads | Cold | Warm | Shed |
|---|---|---|---|
| 1 | 115 µs | 6.2 µs | 0.12 µs |
| 2 | 110 µs | 6.2 µs | 0.12 µs |
| 4 | 113 µs | 6.2 µs | 0.12 µs |
| 8 | 106 µs | 6.2 µs | 0.11 µs |

Admitting and charging a query costs a few atomic updates (D117; two critical sections of a `Mutex` before), not seen against the 6 µs
of a warm one. A shed query costs 0.1 µs (0.15 µs since D117): a flood of uncached queries past
the allowance asks nothing upstream and decodes nothing. A unit (`Allowance`) is about 10 µs at the cold figure (five
questions and some seven checks, 12 units, 115 µs, no network), 3 µs for an RSA check, 27 µs for ECDSA P-256 and
340 µs for P-384, the worst case the default `per_second` (10 000, so 0.1 core on the common algorithms, 3.4 on
P-384 alone) is set against (TODECIDE has the weighting by algorithm). Hits take a write lock (they
move the entry in the recency order), so the readers do not run in parallel as an `RwLock` would let them; sharding
the tables by name or an `RwLock` is for a measured need (TODECIDE). Not measured: the cost of a miss at the bounds
(a `BTreeMap` pop, logarithmic, under the lock).

## CoAP (D80)

`benches/coap.rs`, medians in nanoseconds, one run, on the datagrams of `testdata/coap/fetch_doc.txt`: aiocoap's
FETCH for the quad9 MX query (38 B payload) and the real response (161 B payload). `exchange` starts the request
and reads the response through `Exchange`, copying the request in.

| Measure | ns |
|---|---|
| `parse`, request/response | 125/78 |
| `write`, request/response | 50/36 |
| `exchange` (start, receive) | 256 |

## Access lists (D91)

`benches/access.rs`, medians of one run, in a table of 10 000 networks (8 000 IPv4 `/24` of `10.0.0.0/8`, 2 000 IPv6 `/48` of
`2001:db8::/32`, every tenth denied), `prefix-trie`'s `JointPrefixMap`. `permits` is the verdict on an address; `denied_query` is
`Pipeline::query` for a denied client, REFUSED with EDE 18 (an EDNS query) built before any stage, from the query in place: no allocation. Before, through `Client::reply` and a `Message`, it took 161 ns and 2 allocations (320 B).

| Measure | ns |
|---|---|
| `permits`, IPv4 allowed / denied in the table | 4.3 / 4.4 |
| `permits`, IPv4 in no network | 1.4 |
| `permits`, IPv6 in the table | 24.0 |
| `permits`, IPv4-mapped IPv6 in the table | 5.4 |
| `denied_query` | 42 |

## Root hints and TLD list (D126)

`benches/roots.rs`, medians of one run: reading the bundled `named.root` and `tlds.json` (1603 TLDs, cut by
`just roots` to 0.9 MB), and `Tlds::get` in the table read. Reading the list keeps 1.6 MB in 28 170 allocations.

| Measure | Median |
|---|---|
| `read_hints` | 12.6 µs |
| `read_tlds` | 1.9 ms |
| `get`, `fr.` / `WWW.EXAMPLE.FR.` / `example.nosuchtld.` | 33 / 38 / 37 ns |

The rejected alternative, measured once with a scratch generator (not in the tree): the list written by `jq` as
Rust static tables (addresses kept as strings), the same binary search over them. Nothing is read at start; `get`
runs in 28 / 41 / 41 ns (medians, at the timer's precision of 41 ns): the same as from the table read.

## Signed root anchors (D127)

`benches/anchors.rs`, medians of one run, Apple M5, macOS 27.2: `TrustAnchors::verified` on the captured pair, and
on the captured `.p7s` grown with digest algorithms in decreasing DER order (196, 708 and 1732 of them), which
`der` sorts by insertion as it decodes. Time grows with their square: what bounds the `.p7s` to `MAX_P7S`.

| Measure | Median |
|---|---|
| `verified`, the captured 2 523 bytes | 40.5 µs |
| `verified_grown`, 4 / 8 / 16 KiB | 0.37 / 4.7 / 29.2 ms |

## Rate limiting and Server Cookies (D113)

`benches/rrl.rs`: `Pipeline::query` over UDP from `198.51.100.7` (not loopback, which the limit skips) for the cached
response `a` with EDNS, in a 1232-byte buffer. The hit is the cheapest path a query takes, so the added cost is the largest
share of it. Machine: Apple M5, macOS 27.2, rustc 1.99.1 (Homebrew), release profile with debuginfo, a laptop in use.
Command: `cargo bench -p dedens-bench --bench rrl -- --sample-count 1000 --sample-size 2000`, run 3 times; each cell is the
range over the runs, in nanoseconds, of the fastest sample and of the median (the fastest is the less noisy; the median is
what a loaded machine sees).

- `limited`: the limit on, the source within its rate (one keyed hash, one atomic update).
- `client_cookie`: a Server Cookie is made (clock read, SipHash-2-4 of 28 bytes) and written in the reply.
- `valid_cookie`: the cookie is checked, the limit skipped, and a fresh one made.
- `over_the_rate`: the source's bucket is spent, `slip` 0 (dropped) or 2 (every second one a TC reply).
- `over_the_rate_with_client_cookie`: the same with cookies on and a Client Cookie not yet valid: it is checked first,
  then dropped or (every second one) BADCOOKIE with a fresh Server Cookie.

| Measure | fastest ns | median ns |
|---|---|---|
| `baseline`, no limit, no cookies | 98.0-98.2 | 147.8-148.9 |
| `limited` | 109.0-110.7 | 166.8-169.0 |
| `client_cookie` | 148.1-160.1 | 223.0-231.0 |
| `limit_and_client_cookie` | 165.8-178.2 | 257.4-270.8 |
| `valid_cookie` (with the limit on) | 183.9-197.2 | 270.7-271.5 |
| `over_the_rate`, slip 0 | 46.7-47.6 | 70.6-72.7 |
| `over_the_rate`, slip 2 | 74.6-76.2 | 115.4-116.8 |
| `over_the_rate_with_client_cookie`, slip 0 | 67.5-68.0 | 100.6-101.8 |
| `over_the_rate_with_client_cookie`, slip 2 | 124.2-136.6 | 190.3-208.5 |

The limit adds about 11-20 ns to a hit. A query with a Client Cookie costs about 1.5x a cookie-less one, the clock read of
`SystemTime::now` and the hash being most of it. A query over its rate is answered in half the time of a hit, and a
spoofed flood costs the server no allocation with `slip` 0. A slipped reply allocates once (divan's allocation column:
64 bytes for a TC reply, 160 for BADCOOKIE, which holds the cookie option); no other path allocates.

D136 (`subtle`'s compare of the hash), `valid_cookie` back to back, same command, 3 runs each, 2026-11-02: before
176.9-184.7 fastest, 186.8-190.9 median; after 179.7-185.6, 190.3-191.2. Within noise.

## Client budgets (D117)

Machine: Apple M5, macOS 27.2, rustc 1.99.1 (Homebrew), release profile with debuginfo, a laptop in use, load average 4-7
over the runs. Rounds interleave, 4 of them, each running in turn `cargo bench -p dedens-bench --bench dnssec -- serve_` on the
tree before D117 (commit 1346075, in a copy with its own `target`), the same on this one, then `--bench odoh -- query_message`
on this one and `-- budget`, then `-- query_message` on the first. The cells are the mean of the middle two of the 4 rounds' medians.

`benches/dnssec.rs`, the benches of D77's section with the network's share on the path (cold, warm and shed give the share an
unlimited rate, so the fixed clock measures what they did and not the share's sheds); `serve_shed_share` is a query shed by its
network's share (burst 0) with the global allowance unlimited.

| Threads | Cold before / after | Warm before / after | Shed before / after | Shed by the share |
|---|---|---|---|---|
| 1 | 107.5 / 106.9 µs | 5.95 / 6.15 µs | 0.166 / 0.167 µs | 0.155 µs |
| 2 | 106.3 / 106.4 µs | 6.21 / 6.14 µs | 0.120 / 0.146 µs | 0.133 µs |
| 4 | 106.2 / 105.9 µs | 6.23 / 6.09 µs | 0.117 / 0.148 µs | 0.131 µs |
| 8 | 105.3 / 105.3 µs | 5.96 / 6.02 µs | 0.119 / 0.146 µs | 0.129 µs |

Cold and warm do not move. A shed query costs about 25 ns more: the share's slot hashed and its word read before the
allowance's. The allowance's `Mutex` is gone: a query takes no lock. The rows ran on one thread, as those above.

### Threads in the serve benches

The `serve_` benches of `benches/dnssec.rs` called `bench_local`, which runs one thread whatever the bench's `threads`:
the `t=N` rows of the tables of this section and of D186's are runs of one thread each. They now use `bench_refs`, each
thread with its output buffer. 2026-11-20, Apple M5 (4 performance cores, 6 efficiency ones), macOS 27.2.1, rustc
1.100.0, other builds on the machine; 4 runs of `cargo bench -p dedens-bench --bench dnssec -- serve_`, the mean of the
middle two medians. A cell is the time of one query on one thread with the others running.

| Threads | Cold | Warm | Shed | Shed by the share |
|---|---|---|---|---|
| 1 | 108 µs | 3.19 µs | 0.250 µs | 0.166 µs |
| 2 | 129 µs | 6.87 µs | 0.604 µs | 0.220 µs |
| 4 | 148 µs | 8.24 µs | 0.776 µs | 0.296 µs |
| 8 | 196 µs | 12.9 µs | 0.838 µs | 0.424 µs |

The threads of a warm query share the validator's key cache, whose hits take a write lock: a second thread doubles a
query's time, where a cold one, sharing nothing of the pipeline, takes 19 % more. A shed query (the allowance's word,
shared) takes 2.4 times as long with two threads; one shed by the share 1.3 times. Past 4 threads some run on efficiency cores, which the cold column's growth includes. The one-thread warm query
takes half the time of the tables above, unexplained here.

`benches/odoh.rs`: `decrypt_query_message` is the HPKE open of a query, the cost a flood of posts asks of the target:
36.7 µs median before and after (34.4-34.7 µs fastest; one round at 52 µs while the machine was busy). `budget_admit` is what
`odoh::Service::open` does first for a client outside loopback, the network keyed and hashed and a unit taken, `budget_refuse` the same with
the budget spent, each thread on a network of its own: 7.1 ns and 6.1 ns with 1 thread, 7.3 ns and 6.5 ns with 4 (fastest
6.5 ns and 5.6 ns; a round or two at 20-40 ns while the machine was busy), the table of 2^16 words in the cache of every core.
`budget_refuse_one_network` has all the threads refused on one network's word, 5.6 ns with 1 thread and 6.2 ns with 4: a refusal
writes nothing, so the cores do not fight for its line. A refused post costs the target that and its `503`, three orders
of magnitude below a decapsulation.

`budget_admit_within` is the whole admission, `Budgets::admit_within`: the network's unit, then the global
allowance's, whose one word all threads share. Written when the three copies of that order (`Validating::admit`,
`odoh::Service::open`, DNSCrypt's `Decapsulations::admit`) became the one method; measured against the copied code as a
bench beside it, 4 interleaved rounds of `cargo bench -p dedens-bench --bench odoh -- budget_admit` (Apple M5, macOS
27.2.1, rustc 1.99.1 (Homebrew), the machine busy with two other builds, so the samples of 100 iterations sit at the timer's 41 ns
floor and only those of 12 800 or more count): 14.8 ns median with 1 thread against 14.0 ns for the copy, 14.7 ns with 4
against 35.7-59.6 ns. Fat LTO inlines the method; the difference is the machine's noise.

A unit of D77 is about 10 µs, so the defaults (`client_share` 1000 a second, burst 2000; `odoh.client_budget` the same) let a
network spend 1 % of a core on validations (about 80 cold ones a second, 160 in a burst) and 3.7 % of a core on
decapsulations (1000 a second, 2000 in a burst); the global `odoh.budget` (10 000 a second, burst 20 000) caps all clients at
37 % of a core. A network's budget is a tenth of the global one for both.

## Waiting for the validation allowance (D186)

Machine: Apple M5, macOS 27.2.1, rustc 1.99.1 (Homebrew), the laptop busy with other builds. Rounds interleave, 4 of them,
each running `cargo bench -p dedens-bench --bench dnssec -- serve_` on the tree before D186 (commit 9972ad5, a worktree with
its own `target`), then on this one. The cells are the mean of the middle two of the 4 rounds' medians. Each row ran on
one thread ([Threads in the serve benches](#threads-in-the-serve-benches)).

`serve_shed` is now a query the allowance refuses, parked, then given up at once as one past its wait (`Pipeline::shed`):
what a query costs the pipeline beyond the line, without the wait.

| Threads | Cold before / after | Warm before / after | Shed before / after | Shed by the share before / after |
|---|---|---|---|---|
| 1 | 109.3 / 109.0 µs | 6.23 / 6.44 µs | 0.167 / 0.270 µs | 0.166 / 0.167 µs |
| 2 | 108.2 / 108.7 µs | 6.27 / 6.25 µs | 0.142 / 0.235 µs | 0.132 / 0.136 µs |
| 4 | 108.3 / 107.6 µs | 6.15 / 6.23 µs | 0.140 / 0.226 µs | 0.130 / 0.137 µs |
| 8 | 107.7 / 107.1 µs | 6.19 / 6.37 µs | 0.140 / 0.231 µs | 0.127 / 0.128 µs |

Cold, warm and the share's shed do not move: an admitted query takes the same path through the pipeline (`dedensd`
adds a look at its thread's line, `Parking::waiting`, a `RefCell` borrow).
A query given up costs 90 ns more, the upstream question built and boxed before it waits, then dropped: nothing next to
the second it waits. A parked query holds its boxed `Upstream` and one of the thread's 1024 upstream places (D47).

## Benches that time what they name (2026-11-20)

Three benches timed something other than their name. `benches/cache.rs` `insert` replaced the entry it had stored
before the timing: it now stores a new one into a cache, made outside the timing, that holds 1 000 others (some 16 a
shard, the tables made). `benches/dnssec.rs` `validate_cold` built its `Validator` in the timing: it is now an
input. The `serve_*` benches asserted a reply, which a shed query gets too: each run now reads the reply's header,
NOERROR and AD for `serve_cold` and `serve_warm`, SERVFAIL for the sheds, which are checked once beforehand to carry
EDE 14, Not Ready (D186). Apple M5, the build before (`2d2a152c`) and after alternated, three rounds for `insert`,
two for the others; medians, fastest samples in brackets, one thread:

| Bench | before | after |
|---|---|---|
| `insert` a / mx / txt_large, medians | 284-575 / 721-1 492 / 855-1 845 ns | 375-555 / 989-1 286 / 1 257-1 614 ns |
| `insert` a / mx / txt_large, fastest | 242-492 / 700-1 459 / 824-1 823 ns | 303-324 / 845-907 / 1 030-1 113 ns |
| `validate_cold` | 159.1, 186.1 µs (112.1, 105.4) | 111.1, 107.2 µs (109.7, 104.5) |
| `serve_cold` / `serve_warm` | 170.6, 298 / 3.87, 3.62 µs | 137.7, 112.6 / 3.58, 3.37 µs |
| `serve_shed` / `serve_shed_share` | 250, 250 / 333, 167 ns | 237, 229 / 147, 138 ns |

- `insert`: a new entry costs what the replacement did, within the machine's swings (the build before was bimodal,
  0.7 or 1.5 µs for mx); the table grows in about one store of two of txt_large (divan's `grow` 1.5 against 1).
- `validate_cold`: the validator's making did not show; the medians' swing was the machine's, the fastest samples
  are equal.
- The header read is a few bytes: the serve rows do not move beyond their noise. The sheds' medians before are of
  one iteration a sample, at the timer's precision.

## Profiles (D138)

Where the time goes, from samples; no result to compare. 2026-11-03, `dedensd` and the benches at 4db3114 plus this change.
Inlined frames fold into the function that holds them.

### A cache hit on macOS

`just profile server 'hit::'`: the `hit` bench of `benches/server.rs`, a/mx/txt_large five seconds each, samply 0.13.1 at 1 kHz,
14 979 samples. Apple M5, macOS 27.2, rustc 1.99.1 (Homebrew), bench profile (release with line tables), a laptop under load
from other workers (load average 17, 13, 11): read the shares, not the times. Tabulated from a second run of the same command
with `--unstable-presymbolicate`; divan's own loop is the other 2.4% of the samples.

| Function | Self | With callees |
|---|---|---|
| `Pipeline::query` (the bench's call) | 7.2% | 97.6% |
| `dedens_server::cache::look` | 3.1% | 57.5% |
| `Cache::find` | 8.5% | 46.5% |
| `Query::read` (its closure, 8.5% self, included) | 8.7% | 28.1% |
| `_platform_memmove` | 16.0% | 16.0% |
| `Key::new` (`DefaultHasher::write` 4.2%) | 5.1% | 8.2% |
| `Cache::shard` | 3.5% | 7.7% |
| `response::patch` | 2.5% | 5.9% |
| `Client::append_opt` (`Client::pad` 1.7%) | 1.6% | 5.8% |
| `Record::read_raw` | 3.0% | 4.4% |
| `Name::decode` | 4.4% | 4.4% |
| `Edns::encode` | 3.7% | 3.7% |
| `Options::read` | 3.6% | |
| `pthread_mutex_lock` and `_unlock` | 0.8%, 1.1% | |

Reading the query takes 28% of a hit, the key's hash and shard 16%, and the `memmove` (the reply copied out of the entry) 16%.

### `dedensd` under dnsperf on Linux

`DEDENS_CONTAINER=podman DEDENS_BACK_CPU=2 DEDENS_LOAD_CPUS=3-5 DEDENS_PERF=1 just bench-dnsperf HEAD udp` (and `forward`).
A VPS with six vCPUs shared with other tenants, load average 0.6-1.0 right after the runs, AlmaLinux 10.2, Linux
6.12.0-211.69.1.el10_2.x86_64, podman rootless, `rust:1` with Debian's `linux-perf`. `dedensd` on core 0 under `perf record -F
999 --call-graph dwarf` (event `task-clock`: the VM has no PMU), dnsperf `-c 8 -T 4 -q 500` on cores 3-5, one 10 s round, 9-10k
samples. For the run `kernel.io_uring_disabled` was 0, `kernel.perf_event_paranoid` 1 and `kernel.kptr_restrict` 0 (perf reads
`/proc/kallsyms` as an unprivileged user; at 1 the kernel functions are bare addresses), restored to 2, 2 and 1 after.

Profiled, the server answered 186k queries/s from its cache and 37k forwarding (one round each): dwarf unwinding copies a stack for each
sample, so these are not the rates of `dedensd` (sections above). Sampling by `task-clock` lands where interrupts are enabled
again, so `_raw_spin_unlock_irqrestore` probably over-counts. A table lists the functions above 0.5% of the samples.

`udp`, from the cache (four names): 66% of the samples are inside syscalls (`io_uring_enter`; `Driver::submit_auto` 65.8%
with its callees), of the rest 16% in `udp_queries` and 14% in `send_replies`; the cache hit, `Pipeline::query`, is 7.3%.
The functions in the table add up to 39% in the kernel, 16% in `dedensd` and 2% in libc: a flat profile, no function of
`dedensd` above 6% of its own.

| Function | Self | With callees |
|---|---|---|
| kernel `_raw_spin_unlock_irqrestore` | 8.1% | 8.1% |
| `dedensd::serve::send_replies` | 5.6% | 14.1% |
| `dedensd::serve::udp_queries` | 3.2% | 16.2% |
| kernel `udp_sendmsg` (a reply sent) | 1.9% | 28.5% |
| kernel `process_backlog` (loopback receive, in softirq) | 0.3% | 16.0% |
| kernel `io_recvmsg` (multishot receive) | 0.2% | 11.2% |
| `Cache::find` | 1.3% | |
| `Outbox::push` | 1.2% | |
| libc `malloc` | 1.2% | |
| `Query::read` | 0.9% | |

`forward`, the front `dedensd` (no cache) sending every query over UDP to the second one: 30% of the samples in syscalls,
33% in `compio_runtime::Runtime::run`.

| Function | Self | With callees |
|---|---|---|
| libc `0x162b87`: the `rep movsb` of glibc's `memmove` (no symbol) | 18.1% | 18.1% |
| kernel `_raw_spin_unlock_irqrestore` | 3.3% | |
| `TaskAlloc<Origin::run<udp_queries …>>` | 2.0% | 24.4% |
| `compio_runtime::Runtime::run` | 1.6% | 32.8% |
| kernel `rep_movs_alternative` | 1.6% | |
| `send_replies` | 1.4% | |
| `dedens_net::client::Client::run` | 1.2% | 6.1% |
| libc `malloc`, `cfree` | 1.2%, 1.1% | |
| `Writer::put_name_found` | 1.1% | |
| `Client::step` | 1.1% | 9.6% |

The `memmove` stands out: nearly a fifth of the front server's samples copying bytes, with no caller in the stacks (dwarf
unwinding stops at a libc leaf without CFI). Whether it is a reply buffer of D52 or D63, or the response copied out of the
upstream socket, is not known; the report keeps no `perf.data` to ask.

## UDP buffers of 4240 bytes (D49)

The pool's buffers grew from 4096 to 16 + 128 + 4096 = 4240 bytes so that a query of 4096 bytes is read whole: 1.04 MiB a
thread instead of 1.00. The receive path is the same, so the claim is that nothing moved.

`just bench-dnsperf HEAD udp` and `DEDENS_ROUNDS=5 just bench-dnsperf HEAD udp` (base is the commit before, in a clone of
the tree, as the worktree's `.git` is not visible in the container). Docker Desktop on an Apple M-series host (Linux 7.0.14
arm64 VM, 10 CPUs, `io_uring`), `dedensd` on one core, dnsperf on six, 10 s a round; the host ran other builds, load average
15-30. Seven rounds each, base alternating with tree, no query lost:

| | Median | Range |
|---|---|---|
| base (4096-byte buffers) | 305.8k queries/s | 217.5k-345.4k |
| tree (4240-byte buffers) | 312.8k queries/s | 248.8k-335.2k |

The two ranges overlap throughout and the medians differ by 2%: noise, as the range inside one side is 40%. The VPS run
(`just bench-dnsperf origin/main udp`, six vCPUs, quiet) is the one to read the 480k figure of D49 from.

`cargo bench -p dedensd --bench udp` (D121) on macOS, where the pool is read by the poll driver, the executables of both
trees alternating, load average 30-50 from other workers: 12 rounds, median queries/s at one query in flight 17.7k (base) and
13.9k (tree), at 32 in flight 30.2k and 36.3k. The same bench with the base executable run against a copy of itself (12
rounds) gave 16.4k and 14.9k at one in flight, 29.4k and 23.7k at 32: the gap between two identical executables is as
large as the one between the trees, so the bench shows no change, and says nothing finer on a loaded laptop.

## Linker (D150, D166)

lld, Rust's own (`.cargo/config.toml`), against the platform's linker, for `dedensd`. Paired rounds, the two
variants alternated in one session; `L` is lld (Linux: rustc's default; macOS: `.cargo/lld-cc`), `B` the platform's linker.

- Linux: x86_64, 6 vCPUs, AlmaLinux 10.2 (kernel 6.12.0-211.73.1), the `rust:1` container under rootless
  podman, rustc 1.99.1, shared host (load average 3.5 before the run), 2026-11-05. `B` is
  `RUSTFLAGS=-Clinker-features=-lld`, which gives GNU ld 2.44 (through gcc 14).
- macOS: Apple M5, 10 cores, macOS 27.2, rustc 1.99.1, load average 4.7 at the start, 2026-11-06. `B` is
  `CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=cc` (Apple's `ld`); `L` runs with `SDKROOT` of the 26.5 SDK, as
  stable's lld cannot read the 27 SDK.
- Debug relink: `touch apps/dedensd/src/main.rs; cargo build -q -p dedensd` after a warm build, 10 rounds.
  Release: the same touch and `cargo build -q --release -p dedensd` (fat LTO, one codegen unit), 4 rounds.

Seconds, min / median / max over the rounds.

| Build | Linux `L` | Linux `B` | macOS `L` | macOS `B` |
|---|---|---|---|---|
| Debug relink | 1.88 / 1.98 / 2.34 | 6.83 / 7.06 / 7.66 | 1.03 / 1.07 / 1.68 | 0.82 / 0.86 / 1.16 |
| `B`/`L` per round, median (range) | 3.57 (3.26-3.72) | | 0.79 (0.69-0.96) | |
| Release | 107.5 / 108.5 / 115.1 | 106.9 / 108.5 / 109.0 | 34.7 / 34.8 / 35.1 | 34.6 / 36.3 / 38.5 |
| `B`/`L` per round, median (range) | 0.995 (0.95-1.00) | | 1.04 (0.99-1.11) | |

- On Linux lld relinks the debug build 3.6 times faster, in every round; on macOS Apple's `ld` is 0.2 s faster,
  in every round. The release build is codegen's, not the linker's: equal within the noise on both.

Hardening of the release `dedensd` and `dedens`, `L` against `B` (`readelf -hlWd`; `otool -hv`): unchanged.

| Property | Linux `L` and `B` | macOS `L` and `B` |
|---|---|---|
| Position independent | `Type: DYN`, `FLAGS_1 PIE` | `PIE` in the header flags |
| RELRO, BIND_NOW | `GNU_RELRO`, `FLAGS BIND_NOW`, `FLAGS_1 NOW` | `__DATA_CONST` segment, `DYLDLINK TWOLEVEL` |
| Non-executable stack | `GNU_STACK` `RW` | none to set |

- Size, `dedensd`/`dedens`, bytes: Linux `L` 7,495,736/6,191,544, `B` 7,502,616/6,194,496; macOS `L`
  6,136,512/5,107,760, `B` 6,153,168/5,107,856. Linux links `libgcc_s.so.1` and `libc.so.6` either way.
- What differs: lld records itself, even stripped (ELF `.comment` `Linker: LLD`; Mach-O `LC_BUILD_VERSION` tool 4
  against Apple's 3); it writes no `LC_SOURCE_VERSION` and, on Linux, a `GNU_STACK` of alignment 0 instead of 0x10.
- The debug `dedens` and `dedensd` of `x86_64-unknown-linux-musl` (cross, Debian with `musl-tools`) are static-PIE:
  no `INTERP`, `FLAGS BIND_NOW`, `FLAGS_1 NOW PIE`. The release musl readout waits for step 01.

## Test binaries (D162)

A test binary per file (`tests/rfcNNNN.rs`, main at 786c2e6) against one per package (`tests/tests.rs`), the same
1897 tests. Apple M5, 10 cores, macOS 27.2, rustc 1.99.1, Apple's `ld` (`CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=cc`),
a shared machine (load average up to 10), 2026-11-08; each tree a `git archive` with an empty target directory,
one run.

| Measure | A binary per file | One per package |
|---|---|---|
| `cargo test --workspace --no-run`, cold | 43 s | 29 s |
| The same after `touch crates/dedens-proto/src/lib.rs`, 3 rounds | 16 / 17 / 17 s | 5 / 5 / 6 s |
| `target/` | 5.7 GB | 3.7 GB |
| `target/debug/deps` | 3.5 GB | 2.3 GB |
| Test executables | 129 | 14 |

- The incremental build is the link's: each binary linked its crate's dependencies again. 14 is a binary per
  package with tests, plus `dedens-cache`'s two that set their own `#[global_allocator]`.

## Parallel frontend (D187)

The builds of the pinned nightly at `RUSTFLAGS="-Zunstable-options --jobs-frontend=N"`, against the nightly's
default of 2 frontend threads (`RUSTFLAGS` unset). Apple M5, 10 cores (4 performance, 6 efficiency), 24 GB, macOS
27.2.1, rustc 1.102.0-nightly (5df8c02af 2026-11-16) of nightly-2026-11-17, 2026-11-17. A shared machine: a virtual
machine and another agent's builds kept the load average between 17 and 70. Each build cold: its target directory
(and for `careful` the careful sysroot) removed before it; the four variants in a different order each round.

- `check`: `cargo check --workspace --all-features`, 5 rounds.
- `careful`: `cargo careful test -p dedens-proto --all-features --no-run`, the careful std sysroot built first,
  5 rounds.
- `fuzz`: `cargo fuzz build` in `fuzz/` (release, every target), 4 rounds.

Seconds, min / median / max over the rounds; CPU is user plus system seconds, median; memory the peak resident
set of the largest process, the most over the rounds.

| Build | `N`=1 | default (2) | `N`=4 | `N`=8 |
|---|---|---|---|---|
| `check` | 13.1 / 14.3 / 23.0 | 13.6 / 16.3 / 23.1 | 13.4 / 16.8 / 27.2 | 13.2 / 14.7 / 15.6 |
| `check` CPU, memory | 81 s, 0.48 GB | 88 s, 0.50 GB | 90 s, 0.52 GB | 90 s, 0.53 GB |
| `careful` | 20.3 / 22.0 / 27.7 | 17.3 / 22.0 / 38.1 | 16.3 / 17.2 / 30.3 | 15.1 / 15.2 / 15.9 |
| `careful` CPU, memory | 26 s, 0.51 GB | 31 s, 0.51 GB | 32 s, 0.52 GB | 32 s, 0.55 GB |
| `fuzz` | 129 / 154 / 191 | 94 / 109 / 167 | 102 / 152 / 158 | 94 / 135 / 169 |
| `fuzz` CPU, memory | 497 s, 2.53 GB | 471 s, 2.48 GB | 490 s, 2.58 GB | 484 s, 2.53 GB |

- By the minimum, the round least disturbed by the load, no `N` beats the default by more than the noise (1.15):
  `check` 1.01 to 1.04, `fuzz` 0.73 to 1.00, `careful` 1.146 at 8 threads. The workspace's crates are many and
  small: Cargo already keeps the cores busy, and a frontend thread adds CPU time (`check` 81 s at 1, 90 s at 8).
- `careful` at 8 threads is the steadiest (15.1 to 15.9 s against 17.3 to 38.1 s): more threads take a larger share
  of a loaded machine. The package's own build (Cargo's `Finished`) is 6 to 8 s in 16 rounds of 20, at every
  `N`; the rest is the std sysroot, which a workstation keeps per nightly and each CI job builds
  (under AddressSanitizer there, without it here). The memory grows by 10% at most.
- CI's runners have 4 vCPUs (Linux) and 3 (macOS), fewer than the 4 threads where a gain starts here; not measured.

## Simulation time (D133, D164)

`just sim-time`: wall time of each family of `dedens-sim`'s `tests` binary run alone, then of the binary whole, in
`just check`'s build (debug, `--workspace --all-features`) under the fixed seeds. Apple M5, 10 cores, macOS 27.2,
rustc 1.99.1, a shared machine (another worktree building; each round waits for a 1-minute load average under 4),
2026-11-08. Seconds, median of 3 rounds; before is main at ac8ccd0, after the cut of `dnssec`'s shed seeds (D164).

| Family | before | after |
|---|---|---|
| `baseline` | 1.30 | 1.30 |
| `crash` | 1.62 | 1.65 |
| `dnssec` | 3.23 | 1.88 |
| `forged` | 1.10 | 1.12 |
| `limits` | 1.23 | 1.21 |
| `loss` | 1.36 | 1.35 |
| `partition` | 0.80 | 0.81 |
| `pools` | 0.59 | 0.58 |
| `replay` | 0.06 | 0.06 |
| The binary | 7.18 | 6.65 |

- `dnssec` alone, the two builds alternated over 5 rounds: 3.26 s before, 1.91 s after. Its client-share scenario
  took 2.79 s before (3 seeds), 0.92 s after (1); its allowance one 1.75 s, then 0.59 s. Its slowest tests are now
  at one seed: `a_validating_run_replays_in_two_processes` 1.09 s alone, 1.3 to 1.5 s beside the 15 others.
- One seed less for the property test `whatever_the_validators_questions_suffer_the_verdict_stands_or_servfails`
  (`FEW` to `ONE`) took `dnssec` from 1.91 to 1.83 s: not done, the module's time is its longest tests'.
- The first run of a binary just linked takes 0.5 to 0.7 s more (macOS checks it): `baseline` timed 2.03 s first.
  `just sim-time` runs `--list` before timing.

`cargo bench -p dedens-sim --bench driver` (`benches/driver.rs`): one client asks `example.com. A` of the resolver over
UDP, seed 0, the topology built inside the timed run. `answered`: the upstream answers with the capture `a`, 54
simulated milliseconds. `silent`: the upstream never answers, the resolver tries until it gives up, 6.01 simulated
seconds. Divan medians, 100 samples; 3 runs of the release bench, then one of `--profile dev`, the tests' build.

| Run | release, run 1 | run 2 | run 3 | dev |
|---|---|---|---|---|
| `answered` | 286 µs | 207 µs | 162 µs | 1.34 ms |
| `silent` | 8.14 ms | 8.18 ms | 8.16 ms | 110 ms |

- A simulated second costs 1.36 ms in release, 18 ms in the tests' debug build: a family's 2 s buys about 110
  simulated seconds of one-host scenarios on one thread. The idle steps dominate, turmoil's tick being 1 ms.
- `answered` moves 1.8x between runs (setup under the load's noise); `silent`, 1%, is the number to compare.

## Allocators

Which global allocator a static musl `dedensd` (D151) should carry: musl's mallocng (the default, no crate), mimalloc
(three hardening levels) or jemalloc. Branch `build/alloc-experiment` (from `main` 83ca20f, never merged); the code
measured is the commit tagged `alloc-experiment-2026-11-06`. Features `alloc-mimalloc`, `alloc-mimalloc-secure` and
`alloc-jemalloc` of `dedensd` and `dedens-bench` select one `#[global_allocator]` (two at once do not compile); the
benches wrap it in divan's `AllocProfiler`. The ranking by security is step 03's; the choice, step 04's.

- Machine: the VPS, x86_64, 6 vCPUs (Intel Haswell, no TSX), 11.7 GiB, AlmaLinux 10.2, kernel 6.12.0-211.73.1, rootless
  podman 5.8.2, shared host. THP `enabled` is `always` (`defrag` `madvise`); there is no cpufreq governor in the VM.
  `kernel.io_uring_disabled` is 2 there, so each session set it to 0 and restored 2 at the end; every log of every
  run says `"driver":"io_uring"`.
- Candidates, defaults, nothing tuned. Binaries: `x86_64-unknown-linux-musl` static PIE from `rust:1.99.1-alpine`
  (Alpine's gcc builds the C allocators); references: dynamic glibc 2.41 from `rust:1` (Debian 13). Release profile.

| Name | Allocator |
|---|---|
| `ng` | musl 1.2's mallocng, no crate |
| `mi` | `mimalloc` 0.1.52 (mimalloc v3.3.2), `alloc-mimalloc` |
| `mi-min` | `alloc-mimalloc` with `CFLAGS=-DMI_SECURE=1` (reaches the C build: `CFLAGS = Some(-DMI_SECURE=1)` in its log; the binary differs from `mi`'s) |
| `mi-sec` | `alloc-mimalloc-secure` (`MI_SECURE=4`: guard pages, randomised, encoded free lists) |
| `je` | `tikv-jemallocator` 0.7.0 (jemalloc 5.3.1), `alloc-jemalloc` |
| `g` | reference: glibc's malloc |
| `g-mi` | reference: mimalloc on glibc |

- Session, files of the tag `alloc-experiment-2026-11-06` only (`alloc.sh` is on `alloc-security-2026-11-06` too),
  not of `main`: `crates/dedens-bench/dnsperf/alloc-vps/` (`build.sh`, `inner.sh`, `session.sh`, run from `~/alloc`
  beside a copy of the repository in `src/`), `crates/dedens-bench/dnsperf/alloc.sh` (in the `dedens-abench` image:
  `rust:1` and `dnsperf` 2.14.0), tables from `crates/dedens-bench/dnsperf/alloc-report.nu`. `session.sh <dir> startup rounds divan churn` was the first session
  (08:59-10:25); the divan session (30 rounds) and the soak followed on the same build, one session at a time.
- Rounds: 8 per cell, a cell being a mode (`udp`, `tcp`, `forward`, `forward-tcp`) and 1 or 3 serving threads. In a round
  every binary runs once per cell, in a shuffled order, 8 s each, `dnsperf -c 8 -T 4 -q 500` on its own cores
  (one thread: server 0, back server 1, `dnsperf` 2-5; three: server 0-2, back 3, `dnsperf` 3-5, or 4-5 forwarding).
  The back server, the same `ng` binary for every run, answers locally (a blocklist). `forward*` forward every query,
  the others hit the cache. Load average at the start of the rounds: 0.55 (5-6 while the generators run). No query
  was lost.
- A ratio is a binary's queries/s over the round's fastest in that cell; latencies likewise over the round's lowest. A
  cell is the median over the rounds. p99 is the upper edge of the `dnsperf` histogram bucket that holds the 99th
  percentile, so it moves in bucket steps.

### Build

One clean `cargo build --release -p dedensd` each, nothing else running (the musl builds in `rust:1.99.1-alpine`, the
glibc ones in `rust:1`, so compare within a libc).

| Name     | Build, s | `dedensd`, bytes | vs `ng` or `g` |
| -------- | -------- | ---------------- | -------------- |
| `ng`     | 266      | 7,620,640        |                |
| `mi`     | 265      | 7,806,592        | +2.4 %         |
| `mi-min` | 268      | 7,806,848        | +2.4 %         |
| `mi-sec` | 268      | 7,813,056        | +2.5 %         |
| `je`     | 292      | 8,114,272        | +6.5 %         |
| `g`      | 148      | 7,494,456        |                |
| `g-mi`   | 156      | 7,676,168        | +2.4 %         |

### Throughput and latency

Queries/s over the round's fastest, median (range):

| cell          | ng               | mi               | mi-min           | mi-sec           | je               | g                | g-mi             |
| ------------- | ---------------- | ---------------- | ---------------- | ---------------- | ---------------- | ---------------- | ---------------- |
| udp 1         | 0.6 (0.58-0.64)  | 0.93 (0.9-0.99)  | 0.93 (0.9-1.0)   | 0.89 (0.85-0.95) | 0.92 (0.87-0.99) | 0.96 (0.91-1.0)  | 1.0 (0.98-1.0)   |
| tcp 1         | 0.67 (0.65-0.75) | 0.9 (0.81-0.92)  | 0.87 (0.85-0.89) | 0.83 (0.78-0.86) | 0.87 (0.82-0.89) | 0.99 (0.93-1.0)  | 1.0 (0.77-1.0)   |
| forward 1     | 0.77 (0.75-0.83) | 0.98 (0.88-1.0)  | 0.91 (0.89-1.0)  | 0.91 (0.82-0.99) | 0.89 (0.85-0.98) | 0.87 (0.83-0.93) | 1.0 (0.9-1.0)    |
| forward-tcp 1 | 0.8 (0.75-0.84)  | 0.91 (0.88-0.96) | 0.91 (0.88-0.98) | 0.84 (0.79-0.9)  | 0.87 (0.82-0.89) | 0.89 (0.85-0.92) | 1.0 (1.0-1.0)    |
| udp 3         | 0.62 (0.34-0.81) | 0.86 (0.59-1.0)  | 0.88 (0.71-1.0)  | 0.97 (0.69-1.0)  | 0.89 (0.63-0.96) | 0.92 (0.81-1.0)  | 0.95 (0.65-1.0)  |
| tcp 3         | 0.7 (0.5-0.87)   | 0.93 (0.76-0.97) | 0.96 (0.81-1.0)  | 0.95 (0.8-1.0)   | 0.95 (0.78-1.0)  | 0.97 (0.82-1.0)  | 0.93 (0.84-0.94) |
| forward 3     | 0.76 (0.55-0.88) | 0.95 (0.67-1.0)  | 0.89 (0.71-1.0)  | 0.96 (0.61-1.0)  | 0.99 (0.67-1.0)  | 0.93 (0.65-0.99) | 0.94 (0.65-0.96) |
| forward-tcp 3 | 0.53 (0.41-0.62) | 0.95 (0.59-1.0)  | 0.85 (0.6-0.98)  | 0.81 (0.67-0.94) | 0.81 (0.57-1.0)  | 0.84 (0.61-1.0)  | 1.0 (0.56-1.0)   |

p99, ms, median (median ratio to the round's lowest):

| cell          | ng           | mi           | mi-min       | mi-sec       | je           | g            | g-mi         |
| ------------- | ------------ | ------------ | ------------ | ------------ | ------------ | ------------ | ------------ |
| udp 1         | 6.14 (1.71)  | 4.1 (1.16)   | 3.97 (1.15)  | 4.03 (1.15)  | 4.1 (1.2)    | 4.03 (1.16)  | 3.84 (1.03)  |
| tcp 1         | 1.28 (1.52)  | 0.93 (1.11)  | 0.95 (1.14)  | 0.99 (1.22)  | 0.94 (1.13)  | 0.86 (1.0)   | 0.86 (1.02)  |
| forward 1     | 21.5 (1.36)  | 17.15 (1.03) | 18.69 (1.17) | 19.2 (1.13)  | 18.18 (1.15) | 18.43 (1.16) | 17.15 (1.04) |
| forward-tcp 1 | 12.8 (1.31)  | 10.75 (1.09) | 11.14 (1.12) | 11.9 (1.25)  | 11.9 (1.17)  | 11.65 (1.17) | 10.11 (1.0)  |
| udp 3         | 6.14 (1.9)   | 3.74 (1.27)  | 3.68 (1.27)  | 3.52 (1.28)  | 3.46 (1.21)  | 3.14 (1.13)  | 3.68 (1.13)  |
| tcp 3         | 1.78 (2.59)  | 0.83 (1.27)  | 0.75 (1.16)  | 1.0 (1.45)   | 0.9 (1.29)   | 0.75 (1.07)  | 0.9 (1.28)   |
| forward 3     | 16.77 (1.75) | 13.7 (1.41)  | 14.59 (1.44) | 14.72 (1.57) | 11.65 (1.17) | 13.7 (1.27)  | 12.8 (1.29)  |
| forward-tcp 3 | 11.65 (2.36) | 6.59 (1.25)  | 6.91 (1.36)  | 7.04 (1.35)  | 6.85 (1.34)  | 6.78 (1.29)  | 6.59 (1.19)  |

Average latency, ms, median (median ratio to the round's lowest):

| cell          | ng           | mi           | mi-min      | mi-sec      | je           | g            | g-mi        |
| ------------- | ------------ | ------------ | ----------- | ----------- | ------------ | ------------ | ----------- |
| udp 1         | 3.9 (1.68)   | 2.53 (1.06)  | 2.52 (1.08) | 2.6 (1.12)  | 2.57 (1.1)   | 2.46 (1.05)  | 2.34 (1.0)  |
| tcp 1         | 3.66 (1.03)  | 4.06 (1.18)  | 3.81 (1.19) | 3.59 (1.1)  | 4.09 (1.24)  | 3.72 (1.1)   | 4.46 (1.29) |
| forward 1     | 13.82 (1.29) | 11.15 (1.02) | 11.65 (1.1) | 11.98 (1.1) | 11.85 (1.12) | 12.28 (1.15) | 10.92 (1.0) |
| forward-tcp 1 | 3.42 (1.02)  | 4.08 (1.23)  | 3.88 (1.23) | 3.95 (1.22) | 3.66 (1.09)  | 3.77 (1.14)  | 3.85 (1.2)  |
| udp 3         | 1.78 (2.72)  | 1.02 (1.69)  | 0.95 (1.75) | 0.69 (1.24) | 0.92 (1.63)  | 0.84 (1.17)  | 0.78 (1.07) |
| tcp 3         | 4.38 (1.32)  | 4.02 (1.14)  | 3.95 (1.11) | 3.99 (1.11) | 4.67 (1.25)  | 4.21 (1.07)  | 3.9 (1.05)  |
| forward 3     | 6.19 (1.33)  | 4.96 (1.06)  | 5.4 (1.14)  | 4.86 (1.04) | 4.78 (1.01)  | 5.08 (1.08)  | 5.08 (1.06) |
| forward-tcp 3 | 3.68 (1.11)  | 3.58 (1.09)  | 3.82 (1.14) | 3.95 (1.19) | 3.85 (1.19)  | 3.51 (1.03)  | 3.66 (1.08) |

Queries/s, median:

| cell          | ng     | mi     | mi-min | mi-sec | je     | g      | g-mi   |
| ------------- | ------ | ------ | ------ | ------ | ------ | ------ | ------ |
| udp 1         | 124076 | 190589 | 191063 | 185170 | 188729 | 195722 | 205550 |
| tcp 1         | 571271 | 746832 | 732008 | 693535 | 736783 | 832630 | 838413 |
| forward 1     | 35882  | 44406  | 42581  | 41315  | 41804  | 40369  | 45331  |
| forward-tcp 1 | 55236  | 62082  | 62343  | 58152  | 58650  | 60838  | 68028  |
| udp 3         | 255105 | 371605 | 381135 | 419376 | 387025 | 405507 | 394563 |
| tcp 3         | 647798 | 866596 | 870853 | 862990 | 879172 | 892596 | 863177 |
| forward 3     | 79363  | 98225  | 91173  | 99885  | 100969 | 95852  | 95838  |
| forward-tcp 3 | 91798  | 168527 | 153267 | 142160 | 142178 | 149730 | 169304 |

Per binary: geometric mean of the cells' median ratios (queries/s), cells of 8 with a median ratio of 0.90 or more, cells of 8 with a median p99 ratio of 1.25 or less:

| binary | geomean | at_090 | p99_within_125 |
| ------ | ------- | ------ | -------------- |
| ng     | 0.677   | 0      | 0              |
| mi     | 0.924   | 6      | 4              |
| mi-min | 0.898   | 4      | 5              |
| mi-sec | 0.892   | 4      | 4              |
| je     | 0.897   | 3      | 6              |
| g      | 0.919   | 5      | 6              |
| g-mi   | 0.977   | 8      | 6              |

Queries lost: 0. Drivers: io_uring.

### Benches

divan on core 2 of the idle machine (load average 0.4), 30 rounds of 100 samples, every binary in each round; the
benches are `server`, `cache` (insert) and `message` (owned decode) of `dedens-bench`.

divan medians, ns, median over the rounds (median ratio to the round's fastest):

| key                                    | ng              | mi            | mi-min        | mi-sec        | je            | g             | g-mi          |
| -------------------------------------- | --------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
| cache::insert/a                        | 10790.0 (15.72) | 879.9 (1.28)  | 902.9 (1.32)  | 1005.5 (1.46) | 890.2 (1.3)   | 691.4 (1.01)  | 689.7 (1.0)   |
| cache::insert/mx                       | 2825.0 (1.41)   | 2541.0 (1.27) | 2565.5 (1.28) | 2662.0 (1.33) | 2551.0 (1.27) | 2002.5 (1.0)  | 2007.0 (1.0)  |
| cache::insert/txt_large                | 17480.0 (7.06)  | 3205.0 (1.3)  | 3220.0 (1.3)  | 3474.5 (1.41) | 3168.0 (1.28) | 2525.5 (1.02) | 2474.5 (1.0)  |
| message::decode_dedens_owned/a         | 956.6 (1.66)    | 712.8 (1.22)  | 715.6 (1.23)  | 766.8 (1.31)  | 643.3 (1.11)  | 581.8 (1.0)   | 610.6 (1.05)  |
| message::decode_dedens_owned/mx        | 7097.0 (4.01)   | 2393.0 (1.36) | 2397.0 (1.36) | 2530.0 (1.43) | 2295.0 (1.29) | 1781.0 (1.0)  | 1790.0 (1.01) |
| message::decode_dedens_owned/txt_large | 4057.0 (1.5)    | 3207.0 (1.18) | 3195.5 (1.18) | 3651.0 (1.35) | 3062.5 (1.13) | 2733.5 (1.0)  | 2716.0 (1.0)  |
| server::hit/a                          | 442.6 (1.23)    | 444.4 (1.24)  | 441.6 (1.23)  | 441.6 (1.23)  | 441.6 (1.23)  | 361.1 (1.01)  | 357.6 (1.0)   |
| server::hit/mx                         | 433.1 (1.3)     | 433.6 (1.31)  | 430.5 (1.3)   | 432.2 (1.3)   | 429.2 (1.3)   | 336.2 (1.01)  | 332.6 (1.0)   |
| server::hit/txt_large                  | 443.5 (1.25)    | 442.2 (1.24)  | 440.0 (1.24)  | 438.5 (1.24)  | 440.2 (1.24)  | 360.3 (1.01)  | 355.8 (1.0)   |
| server::miss/a                         | 4280.5 (1.88)   | 2644.0 (1.17) | 2681.5 (1.18) | 3222.0 (1.42) | 2517.5 (1.11) | 2305.5 (1.0)  | 2300.0 (1.01) |
| server::miss/mx                        | 5267.0 (1.31)   | 4747.5 (1.18) | 4818.0 (1.2)  | 5220.0 (1.3)  | 4628.0 (1.16) | 4022.0 (1.0)  | 4040.5 (1.0)  |
| server::miss/txt_large                 | 25365.0 (4.41)  | 6602.0 (1.15) | 6675.0 (1.16) | 7202.0 (1.25) | 6403.0 (1.11) | 5824.5 (1.01) | 5733.0 (1.0)  |

### Memory

Startup: `VmRSS` 2 s after the start, three runs. Churn: 120 s of 1 million distinct names (`nN.churn.test`, looped)
at 30,000 queries/s offered, three threads on the default 64 MiB cache, `VmRSS` sampled every second (`VmHWM` is the
peak), then 20 s of rest. The soak is the same for 3,600 s.

Startup RSS, MiB, median of three:

| threads | ng   | mi   | mi-min | mi-sec | je   | g   | g-mi |
| ------- | ---- | ---- | ------ | ------ | ---- | --- | ---- |
| 1       | 8.1  | 14.8 | 14.8   | 13.2   | 12.9 | 7.5 | 16.3 |
| 3       | 10.8 | 19.2 | 19.2   | 19.6   | 37.1 | 9.9 | 20.8 |

Churn, MiB: VmHWM, RSS at the end of the load, RSS 20 s later, and the queries/s dnsperf got (30,000 offered):

| binary | peak  | end_of_load | after_20s | qps   |
| ------ | ----- | ----------- | --------- | ----- |
| ng     | 94.4  | 82.1        | 82.0      | 29854 |
| mi     | 160.8 | 146.1       | 154.7     | 29294 |
| mi-min | 153.8 | 140.6       | 140.6     | 29913 |
| mi-sec | 183.5 | 177.7       | 179.3     | 29808 |
| je     | 159.8 | 140.1       | 139.9     | 29738 |
| g      | 101.1 | 100.1       | 99.4      | 29065 |
| g-mi   | 157.1 | 147.9       | 141.9     | 29471 |

### Soak

Soak, MiB: VmHWM, RSS at 10 and 30 minutes, at the end of the load (60), 20 s later, and the queries/s dnsperf got:

| binary | peak  | rss_600s | rss_1800s | end_of_load | after_20s | qps   |
| ------ | ----- | -------- | --------- | ----------- | --------- | ----- |
| mi     | 144.1 | 122.5    | 131.8     | 131.3       | 131.3     | 29863 |
| mi-min | 165.8 | 155.2    | 144.9     | 156.0       | 151.1     | 29802 |

### Reading

- Speed: no musl candidate holds 0.90 of the fastest in every cell. `ng` is the slowest everywhere (0.53-0.80), the
  crates 0.81-0.99 (`mi` 6 cells of 8 at 0.90 or more, `mi-min` 4, `mi-sec` 4, `je` 3); between them the cells differ by
  less than the 10 % noise, apart from `mi-min`, `mi-sec` and `je` in `forward-tcp 3` (0.81-0.85, 0.1 below `mi`). The
  three-core ranges reach 0.34-0.6 on the shared host; one-core ones stay within 0.1.
- Latency: `ng` has the highest p99 in every cell (1.3-2.6 times the lowest; `tcp 3` 1.78 ms against 0.75-1.0); the crates
  sit within 1.0-1.57 of it. The average latency does not follow queries/s in the TCP cells (`ng` has the lowest
  average in `forward-tcp 1`).
- The cost of `mi-sec` against `mi` is on the allocating paths: +22 % `server::miss/a`, +14 % `cache::insert/a`, +14 %
  `message::decode_dedens_owned/txt_large`, and +14 % of the peak RSS in the churn (+19 % over `mi-min`). `mi-min`
  is `mi` within 2-5 %.
- mallocng costs 1.3 to 16 times per allocating operation: `cache::insert/a` 10.8 µs against 0.7-1.0 µs,
  `server::miss/txt_large` 25 µs against 5.8-7.2 µs. `server::hit`, which allocates nothing, is 23-30 % slower on
  every musl build than on glibc (440 against 360 ns): the libc, not the allocator.
- Memory: `ng` holds the least of the musl builds (churn peak 94 MiB against 154-184 MiB, startup 8-11 against
  13-20 MiB), as glibc's malloc does (101 MiB). `je` reaches 37 MiB at start on three threads (arenas). In the 1 h soak neither
  `mi` nor `mi-min` grows (peak 144 and 166 MiB; the 120 s churn ordered them the other way round: noise of about 10 %).
- Soak candidates: the two best by speed and RSS only, for now. By rank sum (speed rank by the geometric mean over
  cells, RSS rank by the churn peak, among the five musl builds) `mi-min` (4) and `mi` (5) lead, then `ng` and `je`
  (6), `mi-sec` (9). `ng` was not soaked: no 1 h baseline for it. Step 03's security rank is not applied.
- Against the plan's verdict rule (queries/s 0.90 and p99 within 25 % of the fastest in every cell, peak RSS within
  25 % of the lowest): `ng` fails the speed, every crate fails the RSS (+63 % to +94 % over `ng`). The choice is step 04's.
- One session on one shared host; a ratio below 1.1 between two builds is not a difference.


## `0x20` (D184)

`DEDENS_ROUNDS=<n> just bench-dnsperf 0373ffe0 forward` on an Apple M-series host (Docker, Linux arm64 VM), base and
tree alternating, every query NOERROR, none lost: the front `dedensd` forwards each query over UDP to a second one
answering from its cache, so each upstream query now draws 32 bytes for `0x20`, copies the question's name and writes
it back into the response.

| Run | base (0373ffe0), k/s | tree, k/s |
|---|---|---|
| 4 rounds | 108.9, 122.8, 127.0, 127.9 | 99.3, 127.4, 122.9, 112.3 |
| 8 rounds | 152.7, 143.6, 126.5, 146.5, 152.2, 79.1, 74.6, 77.6 | 147.2, 146.6, 135.0, 147.5, 83.0, 74.1, 77.2, 79.8 |

- The tree won 6 of 12 paired rounds; the host's rate halved from the fifth round of the second run, for both.
  Within the noise, as expected of a draw from the IDs' buffer and a name copied twice against some 7 µs a query.

## Against TelltaleDNS, Unbound and CoreDNS (D183)

`DEDENS_CONTAINER=podman DEDENS_ROUNDS=5 bash crates/dedens-bench/dnsperf/compare.sh <mode> <cores>` (`just
bench-compare`), every mode at 1 and 3 server cores, then an A/A run, a broken server and TelltaleDNS's own smoke
bench. The JSON of each run is in [`comparison/results/`](comparison/results/); the method is D183's, the features
[`comparison/`](comparison/README.md)'s.

Host: a VPS with six vCPUs (Intel Haswell, shared with other tenants), 11 GiB, AlmaLinux 10.2, Linux
6.12.0-211.74.2.el10_2.x86_64, podman 5.8.2 rootless, host networking, `kernel.io_uring_disabled` 0 for the runs and
2 after. Rootless podman has no `cpuset` controller: each container pins its process with `taskset` (the JSON's
`pinning`). Servers on cores 0 (1 core) or 0-2 (3 cores), dnsperf on the cores up to 4, Knot on 5.

| Server | Version | Lean / shipped |
|---|---|---|
| `dedensd` | `main` at 7dc4be80 | one file: cache, forward, DNSSEC validation in `dnssec` |
| TelltaleDNS | 0.6.0 (940f136b), built from source | a thread per core; shipped adds its metrics and API listeners |
| Unbound | 1.26.2 | `num-threads` = cores, its defaults otherwise; one file |
| CoreDNS | 1.15.0 (Go 1.27.3) | `cache` and `forward`; shipped is kubeadm's Corefile (`cache 30`, `errors`, `prometheus`, `loadbalance`, ...); no validator, no blocklist |
| Knot DNS (upstream) | 3.6.2 | a wildcard root zone, signed (ECDSA P-256, NSEC3) for `dnssec` |

dnsperf `-c 8 -q 500`, 10 s runs; the cache-hot corpus (200 000 lines, 10 000 names), miss-heavy (500 000 unique
names under the root's wildcard) and blocked corpora are TelltaleDNS's `bench/corpus.py` output, the blocklist the
first million names of HaGeZi's TIF. Each table: per server the median of its valid saturation runs and their range,
latency and CPU per query at the common rate (half the slowest server's median), latency at half its own rate,
memory idle and loaded (the cgroup's anonymous memory), time to the first answer.

Saturation, thousands of queries a second, lean configurations: median (range) of the valid runs, and the void
ones (rules in D183). `dnssec` is the miss-heavy corpus against the signed zone, validated; CoreDNS has no
validator and no blocklist. The `dnssec` rows here and below are a later run of the three servers, 2 rounds,
`dedensd` at c9c7be7a: D75's walk shortcut, D77's allowance by the threads, D186's wait for it and D86's memo of
the signatures verified (`2026-11-16T211358Z` and `211917Z`; the runs before them are beside them).

| Mode | `dedensd` | TelltaleDNS | Unbound | CoreDNS |
|---|---|---|---|---|
| 1 core: `udp` | 85.4 (81.2–86.3) | 77.1 (76.5–79.3) | 72.2 (67.9–80.1), 2 void | 24.9 (24.4–25.4) |
| `tcp` | 486.8 (481.3–496.6) | 62.4 (61.9–62.8) | 43.2 (41.3–44.9) | 36.1 (33.9–36.9) |
| `dot` | 392.1 (386.0–399.9) | 67.1 (64.9–70.5) | 26.5 (25.4–28.8) | 38.9 (38.0–39.8) |
| `forward` | 67.9 (63.0–69.9) | 48.1 (45.6–50.2), 1 void | 52.6 (50.3–55.8) | 22.0 (21.3–22.8) |
| `forward-tcp` | 291.2 (271.0–301.5) | 54.9 (49.8–55.2) | 37.2 (34.7–39.4), 1 void | 32.8 (31.0–33.7) |
| `miss` | 16.2 (16.1–16.6) | 6.7 (6.5–6.9) | 8.3 (8.3–8.4), 5 void | 6.7 (6.4–7.2), 5 void |
| `dnssec` | 5.6 (5.6–5.6) | 1.5 (1.5–1.6) | 3.1 (3.1–3.1), 2 void | – |
| `blocked` | 87.5 (85.5–89.9) | 58.3 (56.9–59.5) | 66.5 (64.6–67.9) | – |
| 3 cores: `udp` | 137.7 (97.8–141.8) | 141.9 (130.7–146.3) | 137.2 (109.4–144.1) | 52.9 (45.5–53.5) |
| `tcp` | 570.1 (566.4–617.8) | 149.3 (146.5–152.4) | 100.7 (95.0–107.9) | 105.1 (102.8–105.6) |
| `dot` | 257.9 (241.3–274.3) | 143.8 (128.9–147.2) | 59.6 (41.6–76.3) | 105.4 (97.6–108.7) |
| `forward` | 105.0 (102.2–124.4) | 110.6 (99.0–117.2) | 102.4 (100.0–108.2) | 48.7 (46.5–49.7) |
| `forward-tcp` | 390.8 (376.1–466.3) | 120.9 (114.2–128.6) | 119.9 (55.9–141.3) | 83.7 (77.0–89.5) |
| `miss` | 43.4 (34.4–48.1) | 22.6 (20.7–23.9), 1 void | 25.5 (21.5–26.9), 2 void | 25.7 (24.0–26.7), 1 void |
| `dnssec` | 11.1 (11.0–11.2) | 4.8 (4.8–4.8) | 5.9 (5.9–5.9), 3 void | – |
| `blocked` | 134.7 (119.4–150.6) | 141.0 (137.3–152.6) | 125.6 (97.7–144.8), 1 void | – |

At the common rate (thousands a second), average / p99 latency in ms and CPU µs a query, lean:

| Mode | Rate | `dedensd` | TelltaleDNS | Unbound | CoreDNS |
|---|---|---|---|---|---|
| 1 core: `udp` | 10.9 | 0.10 / 0.61, 19 | 0.10 / 0.77, 16 | 0.08 / 0.44, 17 | 0.21 / 1.66, 45 |
| `tcp` | 14.8 | 0.09 / 0.48, 23 | 0.13 / 1.34, 24 | 0.57 / 0.99, 16 | 0.32 / 4.86, 38 |
| `dot` | 13.2 | 0.12 / 0.75, 26 | 0.12 / 0.94, 27 | 0.16 / 1.44, 33 | 0.20 / 1.89, 36 |
| `forward` | 10.1 | 0.21 / 1.69, 26 | 0.25 / 1.73, 24 | 0.13 / 0.85, 22 | 0.33 / 4.03, 49 |
| `forward-tcp` | 13.8 | 0.39 / 6.53, 24 | 0.35 / 6.66, 24 | 0.64 / 2.43, 20 | 0.35 / 5.63, 39 |
| `miss` | 3.0 | 0.42 / 1.38, 76 | 0.53 / 1.21, 95 | 0.49 / 1.05, 96 | 0.63 / 1.95, 132 |
| `dnssec` | 0.8 | 0.69 / 1.89, 180 | 1.76 / 3.52, 515 | 0.89 / 2.24, 311 | – |
| `blocked` | 27.4 | 0.17 / 2.05, 17 | 0.37 / 3.01, 21 | 0.38 / 3.97, 14 | – |
| 3 cores: `udp` | 21.4 | 0.15 / 2.11, 24 | 0.24 / 2.30, 19 | 0.23 / 3.01, 20 | 1.07 / 14.34, 55 |
| `tcp` | 42.6 | 0.24 / 2.43, 21 | 0.40 / 3.46, 23 | 0.67 / 4.35, 15 | 0.48 / 4.73, 32 |
| `dot` | 29.8 | 0.40 / 2.75, 32 | 0.52 / 3.07, 33 | 1.85 / 29.18, 37 | 0.50 / 3.71, 43 |
| `forward` | 18.7 | 0.28 / 2.69, 32 | 0.28 / 2.56, 27 | 0.18 / 2.11, 25 | 0.48 / 6.91, 66 |
| `forward-tcp` | 35.8 | 0.49 / 3.90, 20 | 0.46 / 4.35, 29 | 0.60 / 4.73, 21 | 0.36 / 3.39, 36 |
| `miss` | 10.8 | 0.77 / 19.97, 72 | 0.94 / 24.06, 106 | 0.70 / 17.92, 85 | 0.67 / 10.50, 119 |
| `dnssec` | 2.4 | 0.43 / 2.11, 188 | 1.23 / 6.02, 566 | 0.64 / 2.81, 327 | – |
| `blocked` | 62.8 | 0.36 / 2.81, 17 | 0.44 / 3.14, 22 | 0.40 / 2.94, 15 | – |

Memory (MiB, the cgroup's anonymous memory idle, then loaded after the runs) and the time to a first answer:

| Run | `dedensd` | TelltaleDNS | Unbound | CoreDNS |
|---|---|---|---|---|
| 1 core `udp` | 11 / 36, 8 ms | 25 / 32, 14 ms | 4 / 10, 20 ms | 10 / 25, 47 ms |
| 3 cores `miss` | 17 / 160 | 38 / 90 | 5 / 23 | 11 / 85 |
| 1 core `blocked` | 69 / 40, 878 ms | 97 / 46, 7216 ms | 419 / 419, 3227 ms | – |
| 3 cores `blocked` | 69 / 49, 875 ms | 113 / 64, 3596 ms | 420 / 420, 3116 ms | – |

What the 160 MiB of 3-core `miss` hold, and `dedensd` with an 8 MiB cache: "Where the memory goes", below.

Shipped configurations (the JSON has their tables): TelltaleDNS at 0.86 to 0.99 of its lean rate, CoreDNS at 0.77
to 0.92; `dedensd` and Unbound have one configuration. Every table's numbers are in the JSON with the half-rate
latencies and memory peaks.

### Spread and void runs

- A/A (`udp`, 1 core, lean, each server twice in one session): medians 87.9k and 87.8k for `dedensd` (0.1%),
  77.8k and 79.2k for TelltaleDNS (1.8%), 76.1k and 76.0k for Unbound (0.1%), 25.8k and 25.9k for CoreDNS (0.6%);
  one void run of 88. One server's runs spread up to 12% (Unbound 71.7k to 80.5k): a gap under 1.15 between two
  servers is not one. The A/A session's `udp` medians are 3-6% above the series' own, three hours earlier.
- Void runs, by the rules of D183: Unbound and CoreDNS lose about 1% of their queries at saturation in most runs
  of `miss` (5 of 16 each at 1 core) and in Unbound's `dnssec`, and are measured at 90% of that rate instead;
  before D186, `dedensd`'s `dnssec` saturation runs were void, its answers SERVFAIL past its validation allowance
  (below).
- `broken` (a CoreDNS forwarding to nowhere) exits 1: "rcode SERVFAIL for 10 s, not NOERROR". TelltaleDNS's own
  smoke bench against `dedensd` (`crosscheck`): cache-hot 85 624 queries/s, p50 2.2 ms and p99 4.2 ms at saturation,
  p50 48 µs at half; miss-heavy at its fixed 2000 a second, p50 343 µs, p99 655 µs, none lost.
- dnsperf, at 1 core on four cores, is at most 49% busy in a saturation run, so the servers are measured. At 3
  cores it has two cores, busy 82-86% while `dedensd` serves TCP and DoT: those two rates are a floor. Knot is
  at most 36% busy (3-core `miss`).

### What limits each

One server at a time at 1 core, between the two sessions (07:40 to 08:30 UTC; `dot` at 12:55): the split of the server's core from
`/proc/stat` at saturation, `strace -f -c` at a fixed rate, and `perf record -e cpu-clock:u -F 999 --call-graph
dwarf` from a `rust:1` image with Debian's `linux-perf` (user space only: `perf_event_paranoid` stayed 2). Each
server rebuilt with symbols for it (`dedensd` and TelltaleDNS `strip = false`, CoreDNS without `-s -w`; Unbound's
OpenSSL has none). Knot's `mod-stats` counted the questions each server asked for 5000 cold queries.

- `udp`, from the cache: the kernel's loopback path. At saturation the core is user 13%, system 48%, softirq 38%
  for `dedensd` (82k/s), 22/43/34 for TelltaleDNS (79k/s), 12/42/34 for Unbound (78k/s): sending and receiving a
  datagram costs more than answering it, so the three stay within 20% of one another. For 300 000 queries (the
  priming pass included) `dedensd` made 57 500 `io_uring_enter` calls, TelltaleDNS 253 000 `sendmsg` and 88 000
  `recvmmsg`, Unbound 224 000 `sendto` and 247 000 `recvfrom`.
- CoreDNS, every mode: Go's runtime, 46% of its core in user space at `udp` saturation. Its profile is led by
  goroutine stack growth (`runtime.step` 9.1%, `runtime.pcvalue` 8.6%, `getStackMap` 4.0%, `adjustframe`: a
  goroutine per query outgrows its first stack and is copied) and the garbage collector; `miekg/dns` packing is
  under 2%.
- `tcp` and `dot`: `dedensd` writes the replies of a connection together (D53) and reads what a connection has
  queued at once, so the kernel's cost is paid per batch, not per query: 183 000 `io_uring_enter` for 300 000
  queries, the core user 41%, system 32%, softirq 26% at 504k/s. TelltaleDNS made 409 000 `recvfrom` and 197 000
  `sendto`, Unbound 444 000 `recvfrom` and 177 000 `writev` (softirq 48% of its core), CoreDNS 370 000 `read` and
  180 000 `write`: two reads and a write per query. At the common rate, CPU per query is alike (16 to 38 µs);
  the gap is at saturation only, where many queries wait on each connection.
- `dot` the same, one TLS record per batch: `dedensd` made 83 000 `io_uring_enter` for 300 000 queries and its CPU
  falls from 25 µs a query at 13 000/s to 2.2 µs at saturation (361k/s, user 53% of the core). TelltaleDNS
  writes each reply with its own `writev` (256 000), CoreDNS 239 000 `write` and 151 000 `read`. Unbound reads
  each query with its own `read` (290 000 for 283 000 queries) and writes every second one (145 000), its core
  user 21%, system 40%, softirq 39% at 28k/s: the 2.5× behind TelltaleDNS is its system calls and records, not
  its crypto (`libcrypto` and `libssl` 15% of its user-space samples, a fifth of its core).
- `forward` and `forward-tcp`: a single pass over the cache-hot corpus from a cold start, so 10 000 names go
  upstream and 190 000 hit the cache; the rates follow `udp` and `tcp`. `dedensd`'s `forward-tcp` run takes under
  a second.
- `miss`: every query goes upstream. TelltaleDNS and Unbound open a socket for each upstream question (a random
  source port): for 25 000 queries TelltaleDNS made 24 900 `socket`, `bind`, `connect` and `close` and 49 800
  `epoll_ctl`, Unbound 27 000 `socket` and 54 000 `fcntl`; system time is 50% of TelltaleDNS's core at saturation.
  `dedensd` sends through its pool of 256 connected sockets (D50, 256 `connect` for 30 000 queries), and at
  saturation `io_uring` batches the rest: 38 µs of CPU a query at 16.5k/s against 85 µs at 3300/s. CoreDNS keeps
  its upstream sockets too, and pays its runtime. All four ask Knot exactly one question a query.
- `blocked`, memory and start: `dedensd` keeps a keyed 64-bit hash of each name (D58), Unbound a `local-zone` per
  name in its tree, from a million-line `include` (6 times the memory, 3 times the start); TelltaleDNS parses the
  list into its own set. The answer itself costs about what a cache hit does.
- Losses: Unbound and CoreDNS lose about 1% of a saturation run (CoreDNS 1390 queries in every mode) with 10-12% of
  their core idle, so their saturation run is retried at 90% of its rate (D183); the cause is not known.

### Where the time goes at the common rate

The gaps of the table above at a fixed rate, 2026-11-16, `main` at 21806bba against Unbound: three rounds
alternating unless said, the server's CPU from its cgroup, `strace -f -c` and the voluntary context switches of
each thread (`/proc/<pid>/task`) per query, `perf record -e cpu-clock --call-graph dwarf` with the kernel's symbols
(`perf_event_paranoid` 1 for the session, back to 2 after). Per query, `dedensd` makes fewer system calls than
Unbound and wakes as often: no cost of its own, a system call or a wake-up a query, stands above the kernel's.

| Mode at the common rate | `dedensd` µs/query | Unbound | `dedensd`'s calls a query | Unbound's |
|---|---|---|---|---|
| 1 core `udp`, 10 887/s (2 rounds) | 18.8, 23.9 | 17.6, 19.3 | 0.86 `io_uring_enter` | `sendto` 1, `recvfrom` 1 |
| 3 cores `udp`, 21 371/s (1 round) | 25.5 | 22.2 | 1.07 | `sendto` 1, `recvfrom` 1.14 |
| 1 core `tcp`, 14 808/s | 22.0 (21.9-23.5) | 16.7 (16.4-17.8) | 0.51 | `writev` 1, `recvfrom` 2 |
| 1 core `forward`, 10 139/s | 27.0 (24.4-28.4) | 21.6 (21.5-23.3) | 0.54 | `sendto` 1.1, `recvfrom` 1.1, a socket 0.11 |
| 3 cores `forward`, 18 723/s | 28.5 (27.8-32.9) | 22.9 (22.7-24.0) | 1.33 | `sendto` 1.06, `recvfrom` 1.14, a socket 0.06 |
| 1 core `miss`, 3032/s | 69.1 (67.1-75.1) | 94.5 (86.9-99.7) | – | – |
| 3 cores `miss`, 10 800/s | 77.9 (76.2-79.4) | 87.5 (84.7-94.8) | – | – |

- `udp`: both spend about half their samples in the kernel (`dedensd` 48%, Unbound 54%), 11% of them in
  `_raw_spin_unlock_irqrestore` waking dnsperf's thread on its core (the hypervisor's interrupt). `dedensd`'s own
  are spread: `memcpy` 3.4%, `send_replies` 3.3%, `udp_queries` 2.7%, the cache's `Shard::get` 1.7%,
  `Outbox::push` 1.2%. 0.27 to 0.42 voluntary switches a query against Unbound's 0.39 to 0.63. At 3 cores the
  kernel's `SO_REUSEPORT` hash loads the threads unevenly (13.9, 4.3 and 7.3 µs a query each).
- `tcp`: Unbound's 1.3× is the kernel's. The server's user time is alike (11-14% of the cores against 10-13%), its
  system time 26-28% against 16-19% and softirq 14-16% against 1-2%: `tcp_sendmsg` is 50% of `dedensd`'s samples
  with what it calls, 30% of them delivering the segment to dnsperf's socket in the same softirq, against 12% for
  Unbound. Both send two segments a query (`Tcp.OutSegs`). Unbound leaves Nagle on for plain TCP
  (`listen_dnsport.c` sets `TCP_NODELAY` for TLS and HTTP/2 only), so a reply waits for the ACK of the previous
  one and leaves from dnsperf's core: 0.57 ms a query against 0.09. A `dedensd` without `TCP_NODELAY` spent the same
  21.9 µs (21.0-22.8) with latency up to 0.69 ms: RFC 7766 §10's no-delay stays.
- `forward`: from a cold server, run once, 5% of the names go upstream; the gap is mostly in the other 95%
  ("First and second pass", below). 3.5-5.4% of `dedensd`'s
  samples are `clear_page_erms`, the kernel zeroing the transparent huge pages `mimalloc` first touches for tasks
  (the upstream sockets' receive tasks, the queries'); neither `MIMALLOC_PURGE_DELAY=-1` (28.4) nor
  `MIMALLOC_ALLOW_THP=0` (31.5) moves it past the base's spread (30.2). The upstream query's task was 23 KiB, its 8
  KiB future held three times by D121's catch; held once (D121), 1 core `forward` spends 23.6 µs (23.0-23.7)
  against 27.0, 3 cores 29.5 (29.4-30.7) against 28.5, `miss` 68.1 and 74.7 against 69.1 and 77.9: the 1-core
  gain only is past the spread. Latency at 1 core stays 0.22-0.25 / 1.1-1.4 ms against Unbound's 0.12-0.13 /
  0.64-0.82, not explained.
- `dnssec`: below, the memo of signatures verified (D86).

First and second pass (`forward`, 2026-11-16, `main` at c9c7be7a against Unbound, three rounds alternating): each
server started cold, then the corpus sent twice at the common rate with no restart, Knot counting the questions it
gets (`mod-stats`). The first pass is the table's run; in the second every name is in the cache and none goes
upstream. Median (range) of the CPU a query, avg / p99 ms, and Knot's questions:

| Run | Pass | `dedensd` µs/query, ms | Unbound | Knot: `dedensd` / Unbound |
|---|---|---|---|---|
| 1 core, 10 139/s, 8501 distinct questions | first | 26.8 (25.0-27.6), 0.17 / 0.94 | 23.0 (22.3-24.1), 0.12 / 0.82 | 8524 (8521-8534) / 8501, 1.003 |
| | second | 20.2 (19.5-20.4), 0.11 / 0.38 | 16.8 (16.4-19.3), 0.10 / 0.43 | 0 / 0 |
| 3 cores, 18 723/s, 9539 distinct | first | 28.4 (27.8-29.1), 0.28 / 2.82 | 26.0 (24.9-26.6), 0.14 / 1.89 | 9653 (9629-9674) / 9544 (9542-9544), 1.011 |
| | second | 25.3 (25.1-28.3), 0.16 / 2.18 | 21.6 (21.5-23.6), 0.15 / 1.95 | 0 / 0 |

- The gap is on the cache hits: 1.20× at 1 core and 1.17× at 3 in the second pass, where nothing goes upstream,
  against 1.17× and 1.09× in the first. What the first pass adds over the second, the 5% upstream, is alike: 6.6
  µs a query for `dedensd` and 6.2 for Unbound at 1 core, 3.1 and 4.4 at 3. At the harness's common rate, 2.4
  times higher at 1 core, a hit costs the two the same (`dedensd-8mib` table below: 16.9 and 16.6 µs): the cost is
  per wake-up, paid at a low rate: two turns of the runtime a wake-up, below.
- Unbound asks Knot once per distinct question, coalescing the identical ones in flight (its mesh); `dedensd` asks
  0.3% more at 1 core and 1.1% at 3, the duplicates a thread sends while the first is in flight. Coalescing would
  save no more than that.

The cost of a hit (2026-11-17, `main` at 6b692e9c against the tree of D123's reply sent at once, VPS of above,
one core at the common rate, five rounds alternating): the CPU from the server's cgroup, and system calls,
switches and `io_uring` events counted by the host's `perf stat` on the server's process (one run each). Median
(range) µs a query; calls a query; the second pass of `forward` as above, `udp` primed:

| Run | `main` | tree | Unbound | `main`'s calls | the tree's | Unbound's |
|---|---|---|---|---|---|---|
| `forward` second pass, 10 139/s | 21.3 (18.6-25.4) | 18.1 (15.6-19.6) | 18.3 (16.8-18.5) | 0.82 `io_uring_enter`, 0.26 switches | 0.57 `io_uring_enter` + 1 `sendto`, 0.31 | `sendto` 1, `recvfrom` 1.26, `pselect6` 0.26, 0.26 |
| `udp`, 10 887/s | 22.3 (18.0-24.0) | 18.2 (16.2-21.4) | 17.5 (17.4-18.4) | 1.31, 0.51 | 0.76 + 1 `sendto`, 0.66 | 1, 1.67, 0.67 |

- Where the 3.4 µs went: two turns of the runtime a wake-up, where Unbound sleeps once in `pselect6` and reads
  until `EAGAIN`. `main` made 2.2 to 2.5 `io_uring_enter` a wake-up (calls over switches). A reply sent on the
  ring completes during the enter that submits it, and its completion ends the next wait at once: a second enter
  and a second turn. Two wake-ups of a task by itself made the task hot, which compio follows with an enter that
  does not wait: `flume` waking the sender, joined in the answering task (D123), and the lock over the socket's
  datagrams waking the second receiving task of D48. Kernel time a query was alike (12.4 µs against Unbound's
  12.6 in `udp`, the first table's profile, most of it delivering the reply to dnsperf over loopback); the rest
  was the user and `io_uring` time of the extra turns. No timer, futex or allocation a query; the cache's hit is 0.2 µs (`server` bench).
- Tried, in order, each against `main` in the same session: the queue without `flume` alone, 22.2 against 21.7
  (noise); the `block_on` future made a task (compio polls it every turn), 24.1 against 24.1, dropped; a lone
  reply by `sendto`, 20.4-20.7; with one receiving task, 19.8-20.0; every reply by `sendto` while none is in flight
  on the ring, 18.1, kept (D123). `forward` is 0.99 times Unbound's, `udp` 1.04, both within noise.
- Left: the tree makes 1.9 enters a wake-up in `forward` against 1.2 in `udp`, not explained; within noise of
  Unbound, not followed.

At saturation, the same session, `main` → tree, medians (range), queries/s; the compare harness three rounds
(`udp` five), its CPU at the common rate within noise of the table above:

| Mode | 1 core | 3 cores |
|---|---|---|
| `udp` | 84.3k (83.1-88.1) → 92.4k (91.4-95.4) | 125.5k (113.3-145.8) → 134.9k (106.4-144.2) |
| `forward` | 66.2k (65.9-66.9) → 69.5k (66.0-70.6) | 103.6k (101.0-134.9) → 119.1k (115.8-126.0) |
| `tcp` | 516k (486-516) → 527k (518-528) | 524k (510-537) → 510k (509-554) |

`just bench-dnsperf 6b692e9c <mode>` (D123's harness, `DEDENS_BACK_CPU=2 DEDENS_LOAD_CPUS=3-5`, three rounds):
`udp` 194.8k-196.8k (196.0k) → 225.0k-228.6k (225.9k), average latency 2.46 → 2.14 ms; `forward` 49.6k-50.6k
(50.5k) → 51.0k-52.7k (51.3k); `two-sockets`, the second socket's average latency 0.52-0.55 → 0.42-0.48 ms, its
maximum 4-13 → 8-135 ms (3.7-158 in D123's runs); no query lost. One `sendto` a reply under a flood costs less than D123's batches on the
ring, and a reply no longer waits behind a batch.

### Where the memory goes

3-core `miss` loaded (`main` at c9c7be7a, 2026-11-16): one saturation pass of the corpus from a cold start, two
rounds alternating; the cgroup's `memory.stat`, `smaps_rollup`, and `mimalloc`'s statistics at exit
(`MIMALLOC_SHOW_STATS=1`). Each cause is taken out once: transparent huge pages (`MIMALLOC_ALLOW_THP=0`), the
upstream receive buffers (a build reading 4 KiB instead of 64 KiB, for this only: it truncates larger answers),
the cache (8 MiB instead of 64). Anonymous MiB, the huge pages' share in brackets:

| `dedensd`, 3 cores | THP as shipped | `MIMALLOC_ALLOW_THP=0` |
|---|---|---|
| 64 MiB cache, 64 KiB receive buffers | 168 (98) | 103 (101-104), (0) |
| 64 MiB cache, 4 KiB receive buffers | 115 (113-117), (54-60) | 83 (83-83) |
| 8 MiB cache, 64 KiB receive buffers | 100 (68) | 41 |
| Unbound | 26 (26-26) | |

- Huge pages, 65 MiB: `mimalloc` commits 175-179 MiB at its peak either way; with THP the kernel backs a whole 2
  MiB page under memory never touched, without it only what is.
- The upstream receive buffers (D50), 20 MiB without THP and 53 with: each of the 256 pool sockets of a thread
  holds its own 64 KiB buffer, 48 MiB for three threads, most of it never written but resident under THP. In
  `udp` (from the cache, the pool idle after priming) `dedensd` holds 91 MiB loaded at 3 cores, 29 without THP, 30
  with 4 KiB buffers and 18 with both.
- The cache, 58 MiB without THP (103 to 41): its 64 MiB filled by the 450 000 new names.
- The rest, about 25 MiB (83 less the cache), is Unbound's 26. Outside the anonymous memory `dedensd` holds 3 MiB
  of socket buffers and 2 of slab.

`dedensd` with an 8 MiB cache, Unbound's order of size (`DEDENS_SERVERS="dedensd dedensd-8mib unbound"`, lean, 2
rounds, `2026-11-16T203527Z` to `205800Z`): saturation (k q/s), CPU µs a query at the common rate, MiB idle /
loaded, for `dedensd`, `dedensd-8mib` and Unbound:

| Run | Saturation | CPU at the common rate | MiB |
|---|---|---|---|
| 1 core `udp` | 82.5 / 85.0 / 71.9, 1 void | 16.0 / 14.9 / – | 11 / 36, 11 / 36, 4 / 10 |
| 1 core `forward` | 67.1 / 67.7 / 48.9 | 16.9 / 18.0 / 16.6 | 11 / 36, 11 / 36, 4 / 10 |
| 1 core `miss` | 16.3 / 16.1 / 8.1, 3 void | 76.9 / 75.4 / 94.0 | 11 / 64, 11 / 42, 4 / 14 |
| 3 cores `udp` | 147.5 / 136.5 / 139.4 | 17.9 / 17.8 / 14.4 | 19 / 90, 19 / 90, 5 / 12 |
| 3 cores `forward` | 132.2 / 113.9 / 107.6 | 21.5 / 19.4 / 20.2 | 19 / 90, 19 / 89, 5 / 12 |
| 3 cores `miss` | 48.7 / 40.2 / 27.5 | 67.7 / 70.5 / 91.2 | 19 / 149, 19 / 97, 5 / 23 |

The cache's size shows where the cache fills, `miss`: 64 to 42 MiB at 1 core, 149 to 97 at 3. Elsewhere the two
hold the same, and at 3 cores that is the receive buffers under THP. The rates are within the runs' spread but
3-core `miss`, 1.21× lower with the full 8 MiB cache evicting (ranges 44.6-52.9 and 39.5-40.9), not measured
further.

### One receive buffer per pool (D50)

The upstream pool's sockets now wait for readiness and receive into one 64 KiB buffer of the pool's, Unbound's
`outnet->udp_buff`, instead of each holding its own. `main` at c9c7be7a against `perf/unbound-2` on the VPS, the
median of 3 (memory) or 4 (CPU) runs alternating, ranges in brackets. Memory: anonymous MiB after the 3-core
`miss` corpus from cold at saturation, shipped and with `MIMALLOC_ALLOW_THP=0`. CPU: µs a query and average /
p99 ms on the first pass from cold at the common rate, every query of `miss` and 5% of `forward` going upstream:

| Run | `main` | one buffer |
|---|---|---|
| 3 cores `miss`, MiB | 170 (167-171) | 105 (104-107) |
| 3 cores `miss`, MiB, no THP | 103 (102-103) | 88 (87-89) |
| 1 core `miss` at 3032/s | 70.2 (68.5-71.6), 0.51 / 1.52 | 66.4 (65.9-74.5), 0.49 / 1.10 |
| 3 cores `miss` at 10 800/s | 76.8 (71.7-79.7), 0.48 / 8.32 | 76.2 (74.0-80.5), 0.47 / 4.06 |
| 1 core `forward` at 10 139/s | 26.2 (25.9-27.5), 0.21 / 1.50 | 26.2 (23.8-28.9), 0.21 / 1.25 |
| 3 cores `forward` at 18 723/s | 31.1 (29.2-33.1), 0.47 / 5.09 | 29.5 (28.0-32.3), 0.28 / 2.56 |

The loaded memory falls 65 MiB, 1.6×, the buffers' share under THP (53) and some of what THP rounded up near
them; 14 without THP, of the 20 the 4 KiB build saved. The readiness wait and the `recv` call per datagram cost
nothing the runs can see. `cargo bench -p dedens-net --bench pools` on the M5 (kqueue, 4 rounds alternating, the
first under load): UDP 1 in flight 28801 → 28207, 32 in flight 91174 → 88217 queries a second, medians, within
the rounds' spread (27921-29776, 83076-97149).

### Transparent huge pages off (D154)

`dedensd` sets `PR_SET_THP_DISABLE` first thing in `main`. `main` at 0c746b60 against `perf/thp-off` on the VPS (THP
`always`), `just bench-compare`'s musl binaries, lean configurations, the A/A pair `main`, `main#2`. Memory:
anonymous MiB after the 3-core `miss` corpus from cold at saturation, median of 3 alternating, huge-page MiB in it
after the slash:

| Run | `main` | THP off |
|---|---|---|
| shipped | 106 (106-107) / 46-54 | 89 (85-92) / 2 |
| `MIMALLOC_ALLOW_THP=0` | 88 (83-88) / 0 | |
| `MIMALLOC_ALLOW_THP=1` | | 103 (100-108) / 28-56 |

The loaded memory falls 17.5 MiB, what mimalloc's switch saved; the variable still turns them back on. The 2 MiB
left huge is one page faulted before `main`. Idle / loaded MiB of the comparisons: 1 core 11 / 15 → 5 / 10, 3 cores
19 / 27 → 9 / 18. CPU: µs a query and average / p99 ms at the common rate, median of 6 alternating:

| Run | `main` | THP off | `main#2` |
|---|---|---|---|
| 1 core `udp` at 43 160/s | 13.5 (13.0-13.9), 0.20 / 2.46 | 13.7 (13.0-14.2), 0.18 / 2.21 | 13.1 (12.5-13.9), 0.27 / 4.45 |
| 3 cores `udp` at 69 412/s | 17.0 (16.2-19.0), 0.48 / 3.87 | 17.4 (16.8-17.8), 0.45 / 3.13 | 16.9 (15.9-18.5), 0.47 / 3.58 |
| 1 core `forward` at 33 252/s | 15.6 (14.6-17.2), 0.88 / 16.89 | 15.9 (14.2-16.7), 0.79 / 15.87 | 15.4 (15.2-16.6), 0.78 / 16.26 |
| 3 cores `forward` at 60 584/s | 19.2 (15.3-21.4), 0.63 / 8.83 | 19.8 (16.8-21.3), 0.78 / 14.98 | 19.0 (16.8-20.6), 0.69 / 10.37 |
| 3 cores `miss` at 16 882/s | 62.3 (56.3-64.1), 0.62 / 10.24 | 62.8 (51.6-67.2), 0.64 / 11.01 | 63.4 (62.5-65.1), 0.62 / 8.77 |

Saturation, thousand queries a second, medians of `bench-compare` (4 rounds, or 6 where two series):

| Mode | `main` | THP off | `main#2` |
|---|---|---|---|
| 1 core `udp` | 87.1 | 86.3 | 87.0 |
| 3 cores `udp` | 146.9; 148.2 (131.7-152.9) | 142.0; 148.6 (135.9-153.9) | 138.8; 146.1 (127.8-151.8) |
| 1 core `forward` | 67.7 | 67.3 | 66.5 |
| 3 cores `forward` | 130.2; 132.3 (125.9-140.4) | 121.2; 126.6 (109.7-135.1) | 130.7; 132.1 (119.6-142.6) |
| 3 cores `miss` | 33.8 | 46.5 | 38.1 |

No mode loses more than its A/A pair spreads. 3 cores `forward` sits 4-7% under `main` in both series, its slow
runs the first rounds'; a third series with the roles swapped (THP off twice, `main` between, 6 rounds) puts it
2% under, 130.7 and 130.6 against 133.4 (94.1-140.9), under the 1.15× the comparisons call noise.

### `dnssec`: `dedensd` validates what its allowance admits

In `dnssec` every query is a new name under the signed wildcard, so each one is validated cold. The first run (5
rounds, `main` at 7dc4be80, `2026-11-15T102337Z` and `120500Z`) found `dedensd`'s saturation runs void, every one:
past about 1300 validations a second it answered the rest SERVFAIL (EDE 14, not ready), at 1 and 3 cores alike, and
at the 3-core common rate of 2478 a second 1351 NOERROR and 1127 SERVFAIL a second. Two causes, one on the other,
both since fixed:

- The validation allowance (D77): 10 000 units a second whatever the threads, one unit per question upstream and
  per signature checked. D77 priced a unit at 10 µs from the M5's 27 µs P-256 check; on this Haswell a check takes
  about 80 µs, so the allowance was one core's validations and two of three cores stayed idle. Loopback is exempt
  from the client shares (D117), so the global allowance alone sheds. Now 10 000 units for every two serving
  threads (`Allowance::serving`).
- The cost of each cold query. Knot counted, per client query, one `A` for every server, plus 1.34 `DS` for
  `dedensd`, 2.0 `DNSKEY` for TelltaleDNS (hickory's validator), nothing more for Unbound. `dedensd` walked the
  chain of trust down to the owner name, one `DS` question per label below the last zone it knew (D75), each
  answered by a wildcard NODATA of three NSEC3. Under `perf` (1 core, saturation) 76% of its samples were in P-256
  (`ring`'s `ecp_nistz256`), 57% under `Validation::cut` (the walk): about 530 µs of signature checks a query, six
  to seven checks, against TelltaleDNS's 245 µs and Unbound's 165 µs, which validates the wildcard answer and its
  NSEC3 against the root's cached keys only. Now the walk ends where the answer's own NSEC3 proves the next closer
  name absent (D75), and Knot counts one `A` a query and nothing else.

After both (`2026-11-15T150430Z` and `151114Z`): at the common rate `dedensd`'s CPU a query went from 815 to 372 µs
at 1 core, its latency from 8.28 / 102.40 ms to 1.07 / 2.69 (the cold start's tail was the `DS` question of each
top-level name), and at 3 cores it answers all, 0.71 / 2.94 ms at 385 µs, against Unbound's 321 µs and
TelltaleDNS's 547. At saturation it still shed past its allowance rather than queue, so a run that offered more than
it may validate was void: about 2870 validations a second at 1 core (28 500 to 28 700 NOERROR each 10 s, the core
busy: user 73%, system 16%, softirq 9%), 5700 at 3 cores (56 300 to 57 100), where the run offered 4933 a second was
valid. That is about 3.5 units a name (the client's question, two checks and the NSEC3 hashes), and at the 294 µs a
validated name costs at saturation, the 20 000 units of three threads are 1.7 of the three cores (D77 leaves the
rest to the cache). TelltaleDNS queues instead, at 1500 and 4800 a second; Unbound validates 3000 and 7800.

With D186 (`2026-11-15T202244Z` and `203007Z`, commit e70c093d, run as 6f59f69 before its rebase) a query past the allowance waits for it on its
thread, up to 1.8 s and 512 a thread: no saturation run is void and none is answered SERVFAIL. The rate is the
allowance's, as the NOERROR counts were: 2753 to 2804 a second at 1 core (28 500 to 28 750 each 10 s) and 5488 to
5522 at 3 cores (55 800 to 58 000), above TelltaleDNS's 1500 and 4800, below Unbound's 3000 and 8400 (whose runs
lose queries, void 3 of 10 and 4 of 8). The 500 queries dnsperf keeps outstanding wait their turn: 177 ms on average
at 1 core (p99 410 to 442 ms, their count over the rate), 80 to 89 ms at 3 cores (p99 270 to 573 ms); the 3-core
runs lost 23, 43 and 278 queries of 56 000 (under D183's 1%, cause not known: no query waits past 1.8 s, and a
shed one is answered). At the common rate and at half its own nothing waits: 1.16 / 2.56 ms at 378 µs at 1 core,
0.83 / 3.39 ms at 364 µs at 3 cores, as before within the runs' spread. Memory loaded 56 to 58 MiB at 1 core and
123 to 136 MiB at 3 cores, as before (56 and 118 to 128).

Where the time went at the common rate (`perf` at 746 a second, 1 core, `main` at 21806bba): `ring`'s P-256 was half
of `dedensd`'s samples, about 2.3 checks a query at 81 µs each on this Haswell (`verify_signature/p256`), the NSEC3's
under `Validation::cut` and the wildcard answer's; Unbound's `EVP_DigestVerifyFinal` was 37% of its samples, about
1.2 checks at 99 µs (`openssl speed ecdsap256`): its checks are slower than `ring`'s, and fewer. Unbound keeps an
`RRset`'s security with the `RRset` in its cache and verifies an identical one no more (`rrset_check_sec_status`),
and every name of this mode is answered by the same wildcard `RRset` and the same NSEC3. D86's memo of signatures
verified does that for `dedensd` (`perf(dnssec): keep a memo of the signatures verified`, three rounds of base and
tree alternating with Unbound, 2026-11-16):

| Common rate | Base: avg / p99 ms, µs/query | Memo | Unbound |
|---|---|---|---|
| 1 core, 746/s | 1.04 / 2.56, 373 (367-377) | 0.61 / 1.66, 179 (176-194) | 0.75 / 1.79, 315 (310-318) |
| 3 cores, 2376/s | 0.75 / 3.33, 373 (371-376) | 0.43 / 1.54, 185 (184-186) | 0.58 / 1.82, 315 (306-322) |

The allowance's units fall with the checks (a check the memo holds is not charged, D77). With the memo
(`2026-11-16T211358Z` and `211917Z`, 2 rounds) `dedensd` saturates at 5588 a second (5587-5589) at 1 core and 11 111
(10 990-11 232) at 3, twice its rate before, no run void, 44 and 112 MiB loaded; Unbound at 3095 and 5869, void 2
of 7 and 3 of 6 (its 3-core range was 7.0k to 9.7k the day before), TelltaleDNS at 1547 and 4807. At the common
rate: 0.69 / 1.89 ms at 180 µs at 1 core, 0.43 / 2.11 ms at 188 µs at 3, against Unbound's 311 and 327 µs.

### Not counted

- A first session (03:37 to 07:38 UTC, 4 h) measured `dedensd` on `poll`: podman's default seccomp filter refuses
  `io_uring`, and `dedensd` only logs its fallback (D107). Its numbers are not kept: `udp` at 1 core gave 72k
  queries/s at 31 µs a query at the common rate where `io_uring` gives 85k and 19 µs; the harness now runs every container without the
  filter and fails a `dedensd` that is not on `io_uring` (D183).
