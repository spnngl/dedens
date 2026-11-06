//! What each allocator catches: misuse of the heap, 20 runs of each case in a fresh process.
//!
//! `alloc-probe` runs every case `RUNS` times as a child of itself and prints Markdown tables (cases, usable sizes,
//! randomisation, overflow sizes); `alloc-probe case <name>` is one run. Memory goes through `std::alloc`, so the
//! path is dedensd's: the global allocator the feature selects (none: the libc's malloc).
//!
//! A child ends in one of three ways, read by the parent:
//! - stopped: killed by a signal (or a non-zero exit): the allocator, or the fault it provoked, ended the process;
//! - reported: exit 0 with a message on stderr: detected, and the process went on;
//! - survived: exit 0, silent.
//!
//! A child that survives states what the attack gained (`stdout`, before anything else runs): `dup=1` two live
//! blocks at one address, `hijack=1` an allocation returned the address the attacker wrote into a freed block,
//! `overlap=1` an allocation returned an address inside a live block; `drain` allocates until the first gain.
//! `misuse=done` is printed right after the bad `free`: a later stop is `late`, the misuse itself went unseen.
#![allow(unsafe_code)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation
)]

use std::alloc::{Layout, alloc, dealloc};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::ptr;

#[cfg(any(feature = "alloc-mimalloc", feature = "alloc-mimalloc-secure"))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "alloc-jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const RUNS: usize = 20;
/// A size with slack in every allocator's classes (glibc 104, mimalloc 104 or 112, jemalloc 112, mallocng 108).
const SLACK_SIZE: usize = 100;
/// Blocks of the size classes the cases use.
const SMALL: usize = 64;
/// Blocks of an overflow case: the victim is freed after enough frees to fill any allocator's thread cache.
const NEIGHBOURS: usize = 64;
const VICTIM: usize = 40;
/// Neighbours whose offsets the layout case prints.
const SEQ: usize = 16;

fn layout(n: usize) -> Layout {
    Layout::from_size_align(n, 8).expect("a valid layout")
}

/// A block of `n` bytes, not yet written.
unsafe fn raw(n: usize) -> *mut u8 {
    // SAFETY: `n` is non-zero.
    let p = unsafe { alloc(layout(n)) };
    assert!(!p.is_null(), "out of memory");
    p
}

/// A block of `n` bytes, all of them set to a known byte, as a program uses its memory.
unsafe fn get(n: usize) -> *mut u8 {
    // SAFETY: `p` has `n` bytes.
    unsafe {
        let p = raw(n);
        ptr::write_bytes(p, 0x11, n);
        p
    }
}

unsafe fn put(p: *mut u8, n: usize) {
    // SAFETY: the callers' point: a case may pass a pointer the allocator did not return, or one freed already.
    unsafe { dealloc(p, layout(n)) };
}

/// The allocator's own size of `p`: what an overflow that no allocator can see (slack) is measured against.
unsafe fn usable(p: *mut u8) -> usize {
    #[cfg(any(feature = "alloc-mimalloc", feature = "alloc-mimalloc-secure"))]
    {
        unsafe extern "C" {
            fn mi_usable_size(p: *const libc::c_void) -> usize;
        }
        // SAFETY: `p` came from mimalloc.
        unsafe { mi_usable_size(p.cast()) }
    }
    #[cfg(feature = "alloc-jemalloc")]
    {
        // SAFETY: `p` came from jemalloc.
        unsafe { tikv_jemalloc_sys::malloc_usable_size(p.cast()) }
    }
    #[cfg(not(any(
        feature = "alloc-mimalloc",
        feature = "alloc-mimalloc-secure",
        feature = "alloc-jemalloc"
    )))]
    {
        // SAFETY: `p` came from the libc's malloc (the System allocator).
        unsafe { libc::malloc_usable_size(p.cast()) }
    }
}

/// The size a block of `n` bytes really holds, so that `n + 1` bytes written is one byte past the block.
unsafe fn exact_size(n: usize) -> usize {
    // SAFETY: allocated and freed here.
    unsafe {
        let p = get(n);
        let u = usable(p);
        put(p, n);
        u
    }
}

/// A fixed buffer to format the child's report into: no allocation after the heap is corrupted.
struct Out {
    bytes: [u8; 2048],
    len: usize,
}

impl std::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        let dst = self.bytes.get_mut(self.len..end).ok_or(std::fmt::Error)?;
        dst.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn say(out: &Out) -> ! {
    // SAFETY: a plain write of the buffer, then `_exit`: nothing runs after the corrupted heap.
    unsafe {
        libc::write(1, out.bytes.as_ptr().cast(), out.len);
        libc::_exit(0)
    }
}

fn out() -> Out {
    Out {
        bytes: [0; 2048],
        len: 0,
    }
}

static mut TARGET: [u64; 512] = [0; 512];
const DRAIN: usize = 100_000;
const SLOTS: usize = 1 << 18;
static mut SEEN: [usize; SLOTS] = [0; SLOTS];

/// The child's report, at once: a later fault must not lose it.
fn state(text: &str) {
    // SAFETY: a plain write.
    unsafe { libc::write(1, text.as_ptr().cast(), text.len()) };
}

/// What the attack gained, seen by allocating: up to `DRAIN` blocks of `n` (enough to use up a page of fresh
/// blocks, so that a freed block is reused), the first gain ending the run at once, before the program writes to
/// the block. `dup=1`: a block at an address already live; `hijack=1`: a block inside `TARGET`; `overlap=1`: a
/// block inside `live`, a block of `live_n` bytes still live.
unsafe fn drain(n: usize, live: *mut u8, live_n: usize) -> ! {
    let target = ptr::addr_of_mut!(TARGET) as usize;
    let target_end = target + size_of::<[u64; 512]>();
    // SAFETY: `SEEN` is used by this function alone, once, in the child process.
    let seen =
        unsafe { std::slice::from_raw_parts_mut(ptr::addr_of_mut!(SEEN).cast::<usize>(), SLOTS) };
    for _ in 0..DRAIN {
        // SAFETY: allocation, then the write the program would make into its own block.
        let p = unsafe { raw(n) };
        let a = p as usize;
        if (target..target_end).contains(&a) {
            state("hijack=1");
            unsafe { libc::_exit(0) }
        }
        if !live.is_null() && a > live as usize && a < live as usize + live_n {
            state("overlap=1");
            unsafe { libc::_exit(0) }
        }
        let mut i = (a >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (usize::BITS - 18);
        while seen[i] != 0 {
            if seen[i] == a {
                state("dup=1");
                unsafe { libc::_exit(0) }
            }
            i = (i + 1) % SLOTS;
        }
        seen[i] = a;
        // SAFETY: `p` has `n` bytes.
        unsafe { ptr::write_bytes(p, 0x11, n) };
    }
    state("gain=0");
    unsafe { libc::_exit(0) }
}

/// `NEIGHBOURS` blocks, block number `victim` written past its end by `over` bytes (0x41), then freed with all
/// the others in allocation order, and the same number allocated again.
unsafe fn overflow(size: usize, over: usize, victim: usize) -> ! {
    // SAFETY: the overflow is the point; it writes into the neighbouring memory of the allocator.
    unsafe {
        let mut blocks = [ptr::null_mut::<u8>(); NEIGHBOURS];
        for b in &mut blocks {
            *b = get(size);
        }
        let victim = blocks[victim];
        for i in 0..over {
            ptr::write_volatile(victim.add(size + i), 0x41);
        }
        for b in blocks {
            put(b, size);
        }
        let mut again = [ptr::null_mut::<u8>(); NEIGHBOURS];
        for b in &mut again {
            *b = get(size);
        }
        for b in again {
            put(b, size);
        }
    }
    let mut o = out();
    let _ = write!(o, "ok=1");
    say(&o)
}

/// After a double free: said, then what it gained.
unsafe fn misused() -> ! {
    state("misuse=done ");
    // SAFETY: allocations only.
    unsafe { drain(SMALL, ptr::null_mut(), 0) }
}

/// A free of an address inside a live block (not the one the allocator returned), then allocations.
unsafe fn interior(offset: usize) -> ! {
    // SAFETY: the bad free is the point.
    unsafe {
        let p = get(SMALL);
        put(p.add(offset), SMALL);
        state("misuse=done ");
        drain(SMALL, p, SMALL)
    }
}

/// Free a block, write the address of `TARGET` over all of it (as a freed block's first words are written by a
/// use-after-free), then allocate: does the allocator hand out `TARGET`?
unsafe fn uaf_write(size: usize) -> ! {
    // SAFETY: the write after free is the point.
    unsafe {
        let p = get(size);
        put(p, size);
        let target = ptr::addr_of_mut!(TARGET) as usize as u64;
        for i in 0..size / 8 {
            ptr::write_volatile(p.cast::<u64>().add(i), target);
        }
        drain(size, ptr::null_mut(), 0)
    }
}

/// Addresses of several sizes, the offsets of sixteen neighbours, and a 4 MiB block's distance to the kernel's
/// own anonymous mappings: what randomisation the allocator adds to the kernel's.
unsafe fn layout_case() -> ! {
    let mut o = out();
    // SAFETY: allocations and anonymous mappings, none freed.
    unsafe {
        let map = || {
            libc::mmap(
                ptr::null_mut(),
                4 << 20,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ) as usize
        };
        let before = map();
        let big = get(4 << 20) as usize;
        let after = map();
        let first = get(16) as usize;
        let _ = write!(
            o,
            "a16={first} a64={} a1000={} a65536={} big_before={} big_after={} seq=",
            get(64) as usize,
            get(1000) as usize,
            get(65536) as usize,
            (big as i64).wrapping_sub(before as i64),
            (big as i64).wrapping_sub(after as i64),
        );
        let base = get(SMALL) as usize;
        for _ in 0..SEQ - 1 {
            let _ = write!(
                o,
                "{},",
                (get(SMALL) as usize as i64).wrapping_sub(base as i64)
            );
        }
    }
    say(&o)
}

fn case(name: &str) {
    // SAFETY: each case is memory misuse by design; it ends in `say`, which `_exit`s.
    unsafe {
        match name {
            "double_free" => {
                let p = get(SMALL);
                put(p, SMALL);
                put(p, SMALL);
                misused()
            }
            "double_free_gap" => {
                let (p, q) = (get(SMALL), get(SMALL));
                put(p, SMALL);
                put(q, SMALL);
                put(p, SMALL);
                misused()
            }
            "interior_free_1" => interior(1),
            "interior_free_16" => interior(16),
            "uaf_write_16" => uaf_write(16),
            "uaf_write_64" => uaf_write(64),
            "layout" => layout_case(),
            "control" => overflow(SLACK_SIZE, 0, VICTIM),
            "usable" => {
                let mut o = out();
                for n in [16, 64, SLACK_SIZE, 1000] {
                    let _ = write!(o, "{n}:{} ", usable(get(n)));
                }
                say(&o)
            }
            other => {
                // overflow_{slack,first,exact,<size>}_<bytes>
                let mut parts = other.split('_');
                let (Some("overflow"), Some(kind), Some(over)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    eprintln!("unknown case {other}");
                    std::process::exit(2)
                };
                let over: usize = over.parse().expect("a byte count");
                let victim = if kind == "first" { 0 } else { VICTIM };
                let size = match kind {
                    "slack" | "first" => SLACK_SIZE,
                    "exact" => exact_size(SLACK_SIZE),
                    n => n.parse().expect("slack, exact or a size"),
                };
                overflow(size, over, victim)
            }
        }
    }
}

const CASES: &[(&str, &str)] = &[
    (
        "control",
        "100-byte block, no overflow, then free: must survive",
    ),
    ("double_free", "free(p); free(p)"),
    ("double_free_gap", "free(p); free(q); free(p)"),
    ("interior_free_1", "free(p+1) of a 64-byte block"),
    ("interior_free_16", "free(p+16) of a 64-byte block"),
    (
        "overflow_slack_1",
        "100-byte block (slack), 1 byte past 100, then free",
    ),
    (
        "overflow_slack_8",
        "100-byte block (slack), 8 bytes past 100, then free",
    ),
    (
        "overflow_slack_64",
        "100-byte block (slack), 64 bytes past 100, then free",
    ),
    (
        "overflow_first_1",
        "the first 100-byte block, 1 byte past 100, then free",
    ),
    (
        "overflow_exact_1",
        "block of its usable size, 1 byte past it, then free",
    ),
    (
        "overflow_exact_8",
        "block of its usable size, 8 bytes past it, then free",
    ),
    (
        "overflow_exact_64",
        "block of its usable size, 64 bytes past it, then free",
    ),
    (
        "uaf_write_16",
        "write TARGET over a freed 16-byte block, allocate 100000",
    ),
    (
        "uaf_write_64",
        "write TARGET over a freed 64-byte block, allocate 100000",
    ),
];

struct Run {
    /// The signal or exit code that ended the child, if it did not exit 0.
    stopped: Option<String>,
    /// The first line of its stderr, if any.
    message: Option<String>,
    stdout: String,
}

fn child(name: &str) -> Run {
    let exe = std::env::current_exe().expect("own path");
    let output = Command::new(exe)
        .args(["case", name])
        .stdin(Stdio::null())
        .output()
        .expect("spawn a child");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.chars().take(70).collect());
    let stopped = match (output.status.signal(), output.status.code()) {
        (Some(s), _) => Some(signal_name(s)),
        (None, Some(0)) => None,
        (None, Some(c)) => Some(format!("exit {c}")),
        (None, None) => Some("?".to_owned()),
    };
    Run {
        stopped,
        message,
        stdout,
    }
}

fn signal_name(s: i32) -> String {
    match s {
        libc::SIGABRT => "SIGABRT".into(),
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGBUS => "SIGBUS".into(),
        libc::SIGILL => "SIGILL".into(),
        libc::SIGTRAP => "SIGTRAP".into(),
        other => format!("signal {other}"),
    }
}

fn field(stdout: &str, key: &str) -> Option<String> {
    stdout.split_whitespace().find_map(|w| {
        w.strip_prefix(key)
            .and_then(|v| v.strip_prefix('='))
            .map(str::to_owned)
    })
}

fn cases_table() {
    println!("| case | what | stopped | late | reported | gained | clean | evidence |");
    println!("|---|---|---|---|---|---|---|---|");
    for (name, what) in CASES {
        let (mut stopped, mut late, mut reported, mut clean) = (0, 0, 0, 0);
        let mut gained = Vec::new();
        let mut evidence = BTreeSet::new();
        for _ in 0..RUNS {
            let run = child(name);
            if let Some(m) = &run.message {
                evidence.insert(m.clone());
            }
            if let Some(s) = run.stopped {
                stopped += 1;
                late += usize::from(run.stdout.contains("misuse=done"));
                evidence.insert(s);
                continue;
            }
            reported += usize::from(run.message.is_some());
            match ["dup", "hijack", "overlap"]
                .into_iter()
                .find(|k| field(&run.stdout, k).as_deref() == Some("1"))
            {
                Some(k) => gained.push(k),
                None => clean += 1,
            }
        }
        let gained = match gained.first() {
            Some(k) => format!("{} {k}", gained.len()),
            None => "-".to_owned(),
        };
        let evidence = evidence
            .into_iter()
            .map(|e| format!("`{e}`"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "| `{name}` | {what} | {stopped}/{RUNS} | {late} | {reported} | {gained} | {clean} | {evidence} |"
        );
    }
}

/// Distinct values over the runs, and the lowest bit that varies between them.
fn spread(values: &[i64]) -> String {
    let distinct = values.iter().collect::<BTreeSet<_>>().len();
    let varying = values.iter().fold(0_i64, |acc, v| acc | (v ^ values[0]));
    let low = if varying == 0 {
        "-".to_owned()
    } else {
        varying.trailing_zeros().to_string()
    };
    format!("{distinct}/{} (low bit {low})", values.len())
}

fn layout_table() {
    let mut keys: Vec<(&str, Vec<i64>)> =
        ["a16", "a64", "a1000", "a65536", "big_before", "big_after"]
            .iter()
            .map(|k| (*k, Vec::new()))
            .collect();
    let mut seqs = Vec::new();
    let mut page_offsets = Vec::new();
    for _ in 0..RUNS {
        let run = child("layout");
        for (k, v) in &mut keys {
            if let Some(x) = field(&run.stdout, k).and_then(|s| s.parse().ok()) {
                v.push(x);
            }
        }
        if let Some(s) = field(&run.stdout, "seq") {
            seqs.push(s);
        }
        if let Some(a) = field(&run.stdout, "a64").and_then(|s| s.parse::<i64>().ok()) {
            page_offsets.push(a & 0xfff);
        }
    }
    println!("| measure | distinct over {RUNS} runs |");
    println!("|---|---|");
    for (k, v) in &keys {
        println!(
            "| `{k}` | {} |",
            if v.is_empty() {
                "no data".to_owned()
            } else {
                spread(v)
            }
        );
    }
    if !page_offsets.is_empty() {
        println!("| `a64 mod 4096` | {} |", spread(&page_offsets));
    }
    let distinct = seqs.iter().collect::<BTreeSet<_>>().len();
    println!(
        "| offsets of 16 neighbours of 64 bytes | {distinct}/{} |",
        seqs.len()
    );
    if let Some(first) = seqs.first() {
        println!("\nneighbour offsets of the first run: `{first}`");
    }
}

/// Overflows of 1 and of 8 bytes past requests of 1 to 256 bytes, one run each (the cases are deterministic):
/// the sizes for which the process stopped.
fn sweep() {
    for over in [1, 8] {
        let caught: Vec<usize> = (1..=256)
            .filter(|size| child(&format!("overflow_{size}_{over}")).stopped.is_some())
            .collect();
        println!(
            "- {over} byte(s) past the request: stopped for {} of 256 sizes",
            caught.len()
        );
        let missed: Vec<String> = (1..=256)
            .filter(|s| !caught.contains(s))
            .take(24)
            .map(|s| s.to_string())
            .collect();
        if !caught.is_empty() && caught.len() < 256 {
            println!("  - first sizes not stopped: {}", missed.join(", "));
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let [_, c, name] = args.as_slice() {
        if c == "case" {
            case(name);
            return;
        }
    }
    println!("## cases ({RUNS} runs each)\n");
    cases_table();
    println!(
        "\nusable size of a block of 16, 64, 100, 1000 bytes: `{}`",
        child("usable").stdout.trim()
    );
    println!("\n## layout\n");
    layout_table();
    println!("\n## sizes\n");
    sweep();
}
