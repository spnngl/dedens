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

## Server hit path (D23, D43)

- `benches/server.rs` `hit`: `Pipeline::query` reading a query with EDNS and answering it from the cache stage
  into a 1232-byte buffer, a/mx/txt_large: 204/143/163 ns and one 192-byte allocation a hit (the stale option
  pushed to size the reply, the upstream query built for nothing) → 97/97/118 ns, none (same session).
- `miss`: the query sent upstream, then the response stored and answered: 0.8/1.7/2.0 µs and 15 allocations
  (8 kept by the cache entry, 7 temporary), sockets aside. The entry in one allocation (wire and TTL offsets)
  and the reply served from it as a hit, not encoded again: a/mx/txt_large 0.67-0.74 → 0.59-0.63, 1.53 →
  1.09, 1.71-1.82 → 1.77-1.82 µs (fastest of 3000 samples, same session); 6 allocations kept, 5 of them the
  empty cache's first insert, which a fresh pipeline per sample counts. With the request the client sends: built
  when the query goes upstream, then copied by `Client::exchange`, 17 allocations → built for each server and
  taken by `Client::exchange`, 15; a/mx/txt_large 0.62/1.09-1.17/1.67-1.75 → 0.63/1.10-1.13/1.71-1.80 µs
  (fastest of 5000 samples, before and after alternated, same session; medians 0.71-0.75 → 0.71 µs).
- `plugin` (D54): a plugin stage answering two A records it holds, into a 1232-byte buffer: the reply built
  as an empty `Message` and the records moved in after the question, 116 ns and one 128-byte allocation (the
  question list) → header, question and records copied from the query and the plugin: 83-125 ns, none.

## Blocklist (D56, D58)

- `dedensd validate` reading 4 published lists (stevenblack, hagezi light, two hagezi wildcard; 44 MB, 2.29M
  names) and an allowlist, `/usr/bin/time -l`: names as boxed byte strings, 240 MB resident, 0.87 s → their
  keyed 64-bit hashes, 110 MB, 0.64 s; running server 236 → 110 MB (`ps` RSS), heap 131 → 39 MB (`heap`).
- `benches/blocklist.rs` `query` on the test heads of those lists, median of 3000: blocked under a listed
  parent 110 → 116 ns, allowed 140 → 136 ns, in no list (sent upstream) 156 → 195 ns (noise ±30%); a blocked
  name allocates nothing.
- A download checked before it is saved: `read` into throwaway lists (2.29M names: a 37 MB set, its hashes
  buffered first) → `Lists::check`, names counted, not hashed or stored. `benches/blocklist.rs` `check` on the
  three block heads: 15.7 µs fastest, at most 98 B held at once; `read` of the same heads and the allowlist,
  15-16 µs fastest of 1000 samples both before and after `read` and `check` shared their line reader.

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

RSA with a public exponent of 65537 is the cheapest to check and P-384 the dearest, 17 times Ed25519's cost.
`Budget`'s defaults come from the worst: 64 verifications of P-384 are 22 ms, and 8192 NSEC3 hashes (about 90 ns
each) 0.75 ms. A validation of a name five zones deep verifies about 20 signatures, and the denial proof of a
name ten labels deep hashes about a dozen names, 1800 hashes at 150 iterations. Without a cap, a response that
makes the validator check every signature against every key of one tag (KeyTrap, CVE-2023-50387) costs it
seconds.
