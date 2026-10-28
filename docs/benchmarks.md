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
- Tried and dropped: `get_unchecked` in `Reader` (no faster), labels from a re-sliced window (2% fewer
  instructions, same cycles), `#[inline]` hints (no change).

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
  `encode_dedens` 65/396/367 → 55/351/170, `encode_dedens_owned` 56/325/307 → 49/278/158 (same session, three runs).
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
- 8 threads, medians: one hot name 364 ns (one shard lock), 10 000 names 448 ns (each thread walks the names
  from its own start, buffers made outside the timing).
- Counters (D30), `just bench` features of `dedens-bench`, 10 million hits under `/usr/bin/time -l`: feature off,
  none; `metrics` without a recorder, +8 instructions a hit; `recorder` (atomic counters, as an exporter's),
  +16 (`a`) to +30 (`txt_large`) instructions. Cycles differ within noise, single-threaded and on 8 threads
  (hot name and 10 000 names, ±30% between runs).

## Zone files (D25)

A generated 100 000-record zone: dedens 7.3-7.5 ms, `domain` 9.8 ms, hickory-proto 54 ms (it also builds record
sets). A lazy lexer cost 17% until a byte table skipped plain token text.
