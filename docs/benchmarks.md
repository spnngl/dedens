# Benchmarks

Measurements behind the performance decisions (`decisions.md`). Apple M-series, divan medians of one run unless
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
  not repeated in round 2. The scenario cannot show the U2 gain; the unit tests (`serve.rs`) do, with a stream
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

## DNSSEC `RRset` verification (D73)

`benches/dnssec.rs`, `verify_rrset`: one `rrsig::verify` of a captured `RRset` (`crates/dedens-dnssec/tests/testdata`)
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

## DNSSEC cost limits (D77)

`benches/dnssec.rs`, `serve_cold`, `serve_warm` and `serve_shed`: one uncached client query of the captured `alg8_a`
answer through `Pipeline::query` and `receive` of a validating forward stage with no cache stage, the captures as the
upstream, so each run validates or is shed. Cold: a validator that knows no zone, five questions and the keys of three
zones verified; warm: its key cache holds the chain; shed: `Allowance::burst` 0, so the allowance refuses the query
before anything is sent. `t=N` threads share one pipeline in warm and shed, so one allowance and one `Mutex`; the
cold ones build their own. Median per query, one run.

| Threads | Cold | Warm | Shed |
|---|---|---|---|
| 1 | 115 µs | 6.2 µs | 0.12 µs |
| 2 | 110 µs | 6.2 µs | 0.12 µs |
| 4 | 113 µs | 6.2 µs | 0.12 µs |
| 8 | 106 µs | 6.2 µs | 0.11 µs |

Admitting and charging a query costs a few atomic updates (D117; two critical sections of a `Mutex` before), not seen against the 6 µs
of a warm one, and eight threads do not slow it. A shed query costs 0.1 µs (0.15 µs since D117): a flood of uncached queries past
the allowance asks nothing upstream and decodes nothing. A unit (`Allowance`) is about 10 µs at the cold figure (five
questions and some seven checks, 12 units, 115 µs, no network), 3 µs for an RSA check, 27 µs for ECDSA P-256 and
340 µs for P-384, the worst case the default `per_second` (10 000, so 0.1 core on the common algorithms, 3.4 on
P-384 alone) is set against (TODECIDE has the weighting by algorithm). Hits take a write lock (they
move the entry in the recency order), so the readers do not run in parallel as an `RwLock` would let them; sharding
the tables by name or an `RwLock` is for a measured need (TODECIDE). Not measured: the cost of a miss at the bounds
(a `BTreeMap` pop, logarithmic, under the lock).

## CoAP (D80)

`benches/coap.rs`, medians in nanoseconds, one run, on the datagrams of `tests/testdata/coap/fetch_doc.txt`: aiocoap's
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

Cold and warm do not move. A shed query costs about 25 ns more with 2 threads or more (none with 1, where the noise is
larger than the difference): the share's slot hashed and its word read before the allowance's. The allowance's `Mutex`
is gone: a query takes no lock.

`benches/odoh.rs`: `decrypt_query_message` is the HPKE open of a query, the cost a flood of posts asks of the target:
36.7 µs median before and after (34.4-34.7 µs fastest; one round at 52 µs while the machine was busy). `budget_admit` is what
`Target::open` does first for a client outside loopback, the network keyed and hashed and a unit taken, `budget_refuse` the same with
the budget spent, each thread on a network of its own: 7.1 ns and 6.1 ns with 1 thread, 7.3 ns and 6.5 ns with 4 (fastest
6.5 ns and 5.6 ns; a round or two at 20-40 ns while the machine was busy), the table of 2^16 words in the cache of every core.
`budget_refuse_one_network` has all the threads refused on one network's word, 5.6 ns with 1 thread and 6.2 ns with 4: a refusal
writes nothing, so the cores do not fight for its line. A refused post costs the target that and its `503`, three orders
of magnitude below a decapsulation.

A unit of D77 is about 10 µs, so the defaults (`client_share` 1000 a second, burst 2000; `odoh.client_budget` the same) let a
network spend 1 % of a core on validations (about 80 cold ones a second, 160 in a burst) and 3.7 % of a core on
decapsulations (1000 a second, 2000 in a burst); the global `odoh.budget` (10 000 a second, burst 20 000) caps all clients at
37 % of a core. A network's budget is a tenth of the global one for both.
