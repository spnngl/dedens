# Allocator security

What each allocator candidate catches, adds to the attack surface and costs the build, and its security rank under
the verdict rule's step 1. Measured on the experiment tag `alloc-experiment-2026-11-06` (features `alloc-mimalloc`,
`alloc-mimalloc-secure`, `alloc-jemalloc` of `dedensd`); each claim is read from the vendored source or measured.
The probe is `crates/dedens-bench/alloc-probe/` (`AGENTS.md` there), a cargo project outside the workspace: it
needs `unsafe` (D15).

## Candidates

| Build | Crate (Cargo.lock) | C compiled | How it is built |
|---|---|---|---|
| musl mallocng | none | musl 1.2.5, the `libc.a` rustc links (`self-contained`) | the default |
| mimalloc | `mimalloc` 0.1.52, `libmimalloc-sys` 0.1.49 | v3.3.2 (`include/mimalloc.h:11`: 30302) | feature `alloc-mimalloc` |
| mimalloc minimal | the same | the same | `alloc-mimalloc` and `CFLAGS=-DMI_SECURE=1` (the crate defines `MI_SECURE` for feature `secure` only: `build.rs:81`) |
| mimalloc secure | the same | the same | `alloc-mimalloc-secure`: `MI_SECURE=4` |
| jemalloc | `tikv-jemallocator` 0.7.0, `tikv-jemalloc-sys` 0.7.1 | jemalloc 5.3.1 | `alloc-jemalloc`, no `malloc_conf`, no `--enable-opt-safety-checks`, no `--enable-uaf-detection` |
| glibc malloc, glibc mimalloc | as above | glibc 2.41 (Debian 13) | references, not candidates |

dedensd's musl build links rustc's musl 1.2.5, not Alpine's package (1.2.6 at the time): the mallocng read here is
`musl-1.2.5/src/malloc/mallocng/`.

## Probe

Each case runs in a fresh child process 20 times. `crates/dedens-bench/alloc-probe/probe.sh` builds the probe the way `just musl`
builds `dedensd` and runs it in the same container (`rust:1.99.1-alpine`, lld through `.cargo/lld-cc` and `.cargo/config.toml`,
`Cargo.lock` versions, `--release` with fat LTO, the same features and `CFLAGS`; `make` added for jemalloc). It ran on aarch64 (Docker on a Mac); the strace and thread
gates below ran on the x86_64 VPS. What an allocator checks does not depend on the architecture.

Memory goes through `std::alloc`, so the path is `dedensd`'s. Cases:

| Case | Misuse |
|---|---|
| `double_free`, `double_free_gap` | `free(p); free(p)`, and with a free of another block between |
| `interior_free_1`, `interior_free_16` | `free(p+1)`, `free(p+16)` of a 64-byte block |
| `overflow_slack_N` | 100-byte block, `N` bytes (1, 8, 64) written past byte 100, then freed (the block holds slack in every allocator) |
| `overflow_exact_N` | the same on a block of the allocator's usable size, `N` bytes past it |
| `overflow_first_1` | like `overflow_slack_1`, on the first block rather than the 41st of 64 |
| `uaf_write_16`, `uaf_write_64` | free a block, write the address of a static over it, allocate 100000 blocks of the size |

Each case then states what the attack gained: `dup` two live blocks at one address (double free), `overlap` an
allocation inside a live block, `hijack` an allocation at the address written into the freed block. Cell of the
table: `stop N` the process ended (abort, segfault) in `N` of 20 runs; `N dup|overlap|hijack` the attacker gained in `N`
of 20; `-` neither (the misuse was neutralised, or undetected for an overflow). `control` (no misuse) survives in
every build. Every case gave the same result in all 20 runs, so each cell is 0 or 20.

| case | musl mallocng | mimalloc | mimalloc minimal | mimalloc secure | jemalloc | glibc malloc | glibc mimalloc |
|---|---|---|---|---|---|---|---|
| `double_free` | stop 20 | 20 dup | 20 dup | - | 20 dup | stop 20 | 20 dup |
| `double_free_gap` | stop 20 | 20 dup | 20 dup | - | 20 dup | stop 20 | 20 dup |
| `interior_free_1` | stop 20 | - | - | - | 20 overlap | stop 20 | - |
| `interior_free_16` | stop 20 | 20 overlap | - | - | 20 overlap | stop 20 | 20 overlap |
| `overflow_slack_1` | stop 20 | - | - | - | - | - | - |
| `overflow_slack_8` | stop 20 | - | - | stop 20 | - | stop 20 | - |
| `overflow_slack_64` | stop 20 | - | - | stop 20 | - | stop 20 | - |
| `overflow_exact_1` | stop 20 | - | - | - | - | - | - |
| `overflow_exact_8` | stop 20 | - | - | stop 20 | - | stop 20 | - |
| `overflow_exact_64` | stop 20 | - | - | stop 20 | - | stop 20 | - |
| `uaf_write_16` | - | 20 hijack | 20 hijack | stop 20 | - | - | 20 hijack |
| `uaf_write_64` | - | 20 hijack | 20 hijack | stop 20 | - | - | 20 hijack |
| `overflow_first_1` | stop 20 | - | - | stop 20 | - | - | - |

What the messages and sources say:

- mallocng stops a double free, a free of an interior pointer and every overflow, down to one byte: each is an
  `assert`, which `glue.h:33` makes `a_crash()` (SIGSEGV) in every build. An overflow of 1 or 8 bytes past 1 to 256
  requested bytes is stopped for all 256 sizes. A write after free hijacks nothing: the freed slot holds no free-list
  pointer (the group's `meta` sits in a separate area).
- mimalloc secure detects the double free (`mi_check_is_double_free`, `src/free.c:458-492`) and then returns from
  `free` (`free.c:30`): no abort, no message unless `MIMALLOC_SHOW_ERRORS=1`, nothing gained. The overflow check reads
  padding after the block (`free.c:568-604`): 8 and 64 bytes abort (`mimalloc: error: buffer overflow in theap
  block`), and 1 byte is missed for 65 of 256 sizes, 8 bytes for 7. Dumping the 41st 100-byte block's tail shows why:
  its usable size is 107 and the `0xDE` fill starts at byte 107 (zeros in 100 to 106), while the first block of the
  size has usable size 100 and fill at 100; `overflow_first_1` is stopped, `overflow_slack_1` is not. The corrupted
  free list entry of `uaf_write` aborts (`mimalloc: error: corrupted free list entry`).
- mimalloc (level 0) and minimal (level 1) catch nothing in the table and hijack a freed block: free lists are
  plain pointers. Level 1 differs only by unaligning interior pointers (`free.c:124-130`): `interior_free_16`.
- jemalloc frees interior pointers by their size (`sdallocx`): `overlap`. The tcache stack is out of band, so a
  written freed block hijacks nothing.
- glibc malloc catches a double free with the tcache key and an invalid pointer, and an overflow of 8 or more bytes
  when `free` reaches the next chunk's size field (`free(): invalid next size (fast)`), not 1 byte: the 8-byte
  sweep stops 105 of 256 sizes. With 16 blocks instead of 64 around the victim the tcache absorbed the free and no
  overflow was caught: the probe frees 64 blocks to fill it.

Usable size of a request of 16, 64, 100, 1000 bytes: mallocng `16 64 100 1000`; mimalloc `16 64 112 1024`;
mimalloc secure `16 71 100 1000` (first block); jemalloc `16 64 112 1024`; glibc `24 72 104 1000`.

Randomisation (distinct values over 20 runs of the same program; the kernel's ASLR gives every build a new address
of the first block each run):

| Measure | mallocng | mimalloc, minimal, glibc mimalloc | mimalloc secure | jemalloc | glibc malloc |
|---|---|---|---|---|---|
| 4 MiB block's distance to the kernel's mappings | 1 | 20 | 20 | 20 | 1 |
| offsets of 16 consecutive 64-byte blocks | 2 | 1 | 20 | 1 | 1 |

Only mimalloc secure randomises the order of blocks in a page (`src/page.c:533-540`, `:618`, `:866`); mimalloc and
jemalloc randomise the distance to the kernel's mappings; mallocng cycles the offset of a block in its slot
(`meta.h:196-215`, "facilitate trapping double-free").

## Hardening at the version built

| Feature | Source | In the build |
|---|---|---|
| mallocng: `assert` always on, ends in `a_crash` | `glue.h:33` | yes |
| mallocng: secret from `AT_RANDOM` in each meta area's header, checked on `free` | `glue.h:44-50`, `malloc.c:50`, `:103`, `meta.h:146` | yes |
| mallocng: `free` checks alignment, group-to-meta link, `avail`/`freed` masks (double free), offset in size class | `meta.h:131-154`, `free.c:134` | yes |
| mallocng: zero byte after the nominal size and one after the slot, checked on `free` | `meta.h:169-171` | yes (catches non-zero writes only) |
| mallocng: slot offset cycles between reuses | `meta.h:196-215`, `malloc.c:255`, `:330` | yes |
| mimalloc 1: guard pages around meta data, random arena start, abort on corrupted meta data, interior pointers unaligned | `arena-meta.c:84`, `os.c:140`, `:168-207`, `options.c:592-596`, `free.c:124-130` | minimal, secure |
| mimalloc 2: randomised free-list extension | `page.c:533`, `:618-619`, `:677`, `:866` | secure |
| mimalloc 3: encoded free lists, overflow padding (canary, `0xDE` fill of at most 16 bytes) | `types.h:96-111`, `alloc.c:96-116`, `free.c:568-604` | secure |
| mimalloc 4: double-free check (the double free is ignored) | `free.c:458-492` | secure |
| mimalloc 5: guard page per page | `arena.c:837`, `:1070`, `prim/unix/prim.c:455` | no (`MI_SECURE=4`) |
| jemalloc `opt.junk`, `opt.zero` | `jemalloc.c:81-100`: junk "false" outside debug | no effect |
| jemalloc safety checks, use-after-free detection | `configure.ac:1836`, `:1870` (default off), `jemalloc_preamble.h.in:197-225` | no: `tikv-jemalloc-sys` passes neither |

Paths: musl under `musl-1.2.5/src/malloc/mallocng/`, mimalloc under `libmimalloc-sys-0.1.49/c_src/mimalloc/v3/`
(`include/mimalloc/types.h`, `src/`), jemalloc under `tikv-jemalloc-sys-0.7.1/jemalloc/`.

## Gates

Landlock rows: `strace -f -ttt -e trace=%file,clone,clone3` from the launch of the release `dedensd` of each build, on the
x86_64 VPS (`crates/dedens-bench/alloc-probe/strace.sh`: `cache` then forward to an untraced back server, 2 worker
threads, 300 UDP and TCP queries then 1200 more, `kernel.io_uring_disabled=0` during the run and restored to 2). `strace`
was not installed: `sudo dnf install -y --transient strace` (the host is bootc, read-only; the overlay resets at reboot).
No file call follows the first query in any of the seven builds, and each starts the same 4 threads (`clone`), `dedensd`'s
own: the allocators start none. The opens before the first query are `dedensd`'s own (configuration, `/proc/self/cgroup`,
`cpu.max`, `/var/cache/dedensd`) plus the allocator's, listed in the last row. They all happen once, before `dedensd` binds a
Landlock ruleset, as long as that ruleset binds after the first allocation of every thread. Arena growth under memory
pressure was not traced; mimalloc and jemalloc cache what they read at start in the sources cited. glibc builds also open
the loader's files (`ld.so.cache`, `libc.so.6`, `libgcc_s.so.1`).

| Gate | mallocng | mimalloc, minimal, secure | jemalloc |
|---|---|---|---|
| Builds static-PIE on both musl targets with lld | pass | pass | pass: needs `make` in the image (`just musl` installs `git lld procps-ng` only: add `make`) |
| `cargo test -p dedensd` with its feature (aarch64) | pass | pass: all three builds | pass |
| `cargo test --workspace --all-features` | pass | fails: three `#[global_allocator]` (E0428) | fails: the same |
| Upstream maintained | musl 1.2.6 released; mallocng fixes since 1.2.5 touch alignments of 2^35 bytes and over, and linkage | `libmimalloc-sys` 0.1.49 (2026-05-22); vendored v3.3.2, upstream v3.6.1 (2026-10-30) | `tikv-jemalloc-sys` 0.7.1 (2026-05-25); vendored 5.3.1, upstream 5.4.0 (2026-09-17) |
| Landlock-safe: files opened after the first query | none | none | none |
| Landlock-safe: threads the allocator starts | 0 | 0 | 0 |
| Landlock-safe: files opened at start by the allocator | none | `/proc/sys/vm/overcommit_memory`, `/sys/kernel/mm/transparent_hugepage/enabled` (`prim.c:125`, `:151`), `access(/sys/devices/system/node/node1)` (`prim.c:630`, count cached at `os.c:839-853`) | `/proc/sys/vm/overcommit_memory`, `/sys/kernel/mm/transparent_hugepage/enabled` (`pages.c:760`, `:833`), `/etc/_rjem_malloc.conf` (`jemalloc.c:880`) |
| Licence of the C compiled | MIT (musl `COPYRIGHT`) | MIT (`v3/LICENSE`) | BSD-2-Clause (`jemalloc/COPYING`): not in the `deny.toml` allow list (Apache-2.0, BSD-3-Clause, CDLA-Permissive-2.0, ISC, MIT, Unicode-3.0, Zlib); the crates say MIT/Apache-2.0, so `cargo deny` passes while the C is not allowed |

`cargo test --workspace --all-features` cannot pass on the experiment tag: its features are exclusive (`apps/dedensd/src/alloc.rs:5-9`)
and `--all-features` (`justfile:35,37,70,145`, `just musl`'s default at `:216`, `cargo hack --feature-powerset` at `:56`) turns all
of them on. The gate holds for the final design below. The test column ran `cargo test --locked --no-fail-fast -p dedensd` in
`rust:1.99.1-alpine` (aarch64) with `git lld make procps-ng`: the `rfc7766` tests read `ps -o time=`, which busybox lacks.

## Attack surface

| | mallocng | mimalloc | jemalloc |
|---|---|---|---|
| C compiled into `dedensd` | 1,084 lines in `libc.a`, which rustc ships: no C of the build's own | 15,837 lines of `.c` in one translation unit (`src/static.c` includes 21 files), 4,314 lines of headers | 35,982 lines in 67 `.c` files, 22,145 lines of internal headers |
| Tools the build runs | none | `cc` (`cc` crate, honours `CFLAGS`) | `sh`, `make`, `cc`: `./configure` (shipped, no autoconf) then `make` |
| Upstream CI | none in the tree (`libc-test` apart) | `.github/workflows/test.yaml` (release, debug and `MI_SECURE=ON` ctest), `azure-pipelines.yml` | `.github/workflows/linux-ci.yml` (matrix incl. `--enable-opt-safety-checks`, `make check`), static analysis |
| Upstream fuzzing | none found | none found | none found |
| Advisories | none on malloc (OSV, NVD, musl's page; 14 CVEs in iconv, regcomp, dns, math) | RUSTSEC-2022-0094 (informational, alignment, patched since 0.1.39); NVD: none | OSV: none for the crates; NVD: 6 CVEs, FreeBSD, Firefox, Redis, bRPC, none on 5.x |

None of the three is in `google/oss-fuzz/projects`. Lines are `wc -l` of the files the build names (jemalloc from `cargo build -vv`,
mimalloc from the `#include` list of `static.c`, mallocng from `src/malloc/mallocng/`: `aligned_alloc.c` 60, `donate.c` 39,
`free.c` 151, `glue.h` 95, `malloc_usable_size.c` 13, `malloc.c` 387, `meta.h` 288, `realloc.c` 51).

## Other builds keep the system allocator

On the tag the allocator comes from Cargo features only (`apps/dedensd/src/alloc.rs:5-17`; dependencies at
`apps/dedensd/Cargo.toml:27,32`, features at `:47-49`; `crates/dedens-bench/Cargo.toml:17-19` repeats them), and no `cfg(target_env)` is
involved: any build with a feature, on any target, gets that allocator. `just careful` (`justfile:206`) and `just test`
run with `--all-features`, so they would not even compile.

The suite's builds keep the system allocator when all of this holds in the final design:

- The allocator crate sits under `[target.'cfg(target_env = "musl")'.dependencies]` of `apps/dedensd` and the `static` under
  `#[cfg(target_env = "musl")]`. No feature selects it, so `--all-features` and `cargo hack --feature-powerset` compile.
- `cargo careful` (AddressSanitizer does not link on musl, D141), Miri (not run in CI: no `unsafe`, D15), `cargo fuzz`, `just loom`
  (`justfile:187-193`) and `cargo kani -p dedens-proto` (`justfile:356`) build for a glibc or macOS host target, where
  `target_env` is not `musl`: the system allocator stays. A run of any of them with `--target *-musl` would not.
- `fuzz/` is its own workspace and depends on the libraries, not on `dedensd` (`fuzz/Cargo.toml`); `dedens-proto` (Kani) has no
  allocator. The experiment's `alloc-*` features of `dedens-bench` go with the experiment.
- `just musl` keeps testing under the musl build, so its tests run with the chosen allocator.

## Security rank

Step 1 of the verdict rule, among the candidates passing every gate (jemalloc fails the licence gate, and the
all-features gate fails for all three on the tag: see Gates). Cases are the 12 of the plan (4 double free and interior
free, 6 overflow, 2 write after free; `overflow_first_1` is extra). Every case gave 0 or 20 of 20: no probabilistic case.

| Build | Cases stopped in 20 of 20 | Cases where the attacker gained | Overflows undetected | Block order randomised | Hardening confirmed | Rank |
|---|---|---|---|---|---|---|
| musl mallocng | 10 | 0 | 0 | no | 5 (asserts, secret, meta checks, zero bytes, offset cycling) | 1 |
| mimalloc secure | 6 | 0 | 2 of 6 (1 byte) | yes, 20 of 20 | levels 1 to 4 | 2 |
| mimalloc minimal | 0 | 4 (2 double free, 2 write after free) | 6 of 6 | no | level 1 | 3 |
| mimalloc | 0 | 5 | 6 of 6 | no | random hint only (`os.c:140`) | 4 |
| jemalloc (fails licence) | 0 | 4 (2 double free, 2 interior) | 6 of 6 | no | none | out |
| glibc malloc (reference) | 8 | 0 | 2 of 6 (1 byte) | no | tcache key, size checks | |
| glibc mimalloc (reference) | 0 | 5 | 6 of 6 | no | none | |

mimalloc secure's "stopped" count is 6, mallocng's 10, because secure ignores a double free and an interior free without
stopping: nothing is gained either way.
