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
  more instructions: 17325 vs 15615), `MessageIndex::read` 3301 → 2896, view 5456 → 4618. Gains: a 24-byte
  `Name` (16-bit offset), records built in place, fixed fields read with one bounds check.
- Tried and dropped: `get_unchecked` in `Reader` (no faster), labels from a re-sliced window (2% fewer
  instructions, same cycles), `#[inline]` hints (no change).

## Unbound (D14)

Unbound 1.26.2, `just bench-unbound` (`-O2`, median of 101 samples), next to `cargo bench -p dedens-bench` in
the same session. Nanoseconds, `a`/`mx`/`txt_large`; this session ran slower than the table above.

| Measure | dedens | Unbound |
|---|---|---|
| Structure check, records located: `MessageIndex::read` and first question / `parse_packet` | 84/191/401 | 98/193/415 |
| Owned decode: `decode_owned` / `reply_info_parse` | 188/460/975 | 143/376/594 |
| Encode, reused buffer: `encode` / `reply_info_encode` with OPT | 64/333/362 | 44/312/109 |
| Zone, 100 006 records | 7.7 ms | 94.9 ms |

- `parse_packet` does not read RDATA; `MessageIndex::read` checks every RDATA and EDNS option.
- `reply_info_parse` keeps RDATA as wire bytes, only decompressing names; dedens types every record. The
  encoder then copies those bytes back, hence 109 ns for the TXT answer that dedens rebuilds from its strings.
- Zone: `sldns_fp2wire_rr_buf` reads a `FILE` token by token, as Unbound's auth-zone does.

## In-place reading (D20, D21)

`MessageIndex::read` costs 65-80% of a full decode: parsing names and RDATA, not building records, is most of
decoding. Check plus first question 136/322/702 ns, every record read 178/505/1093 ns.

## Cache (D22)

- Hit including `Query::read`: 147/149/170 ns.
- Insert: 0.9/1.5/2.5 µs.
- 8 threads: one hot name 312 ns (one shard lock), 10 000 names 333 ns.

## Zone files (D25)

A generated 100 000-record zone: dedens 7.3-7.5 ms, `domain` 9.8 ms, hickory-proto 54 ms (it also builds record
sets). A lazy lexer cost 17% until a byte table skipped plain token text.
