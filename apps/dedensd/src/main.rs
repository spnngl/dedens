//! The `dedensd` binary: [`dedensd::main`], with the allocator of a musl build.

#![forbid(unsafe_code)]

// D154: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    huge_pages_off();
    dedensd::main()
}

/// D154: no transparent huge pages under the heap, unless `MIMALLOC_ALLOW_THP` is set, in any case, as mimalloc
/// reads it: then mimalloc, which read it before `main`, does as it says. `PR_SET_THP_DISABLE` is the process's,
/// every thread's, and holds for the later faults of what was mapped before it; a kernel without it (before 3.15)
/// keeps them.
#[cfg(all(target_os = "linux", target_env = "musl"))]
fn huge_pages_off() {
    let set = std::env::vars_os().any(|(name, _)| name.eq_ignore_ascii_case("MIMALLOC_ALLOW_THP"));
    if !set {
        let _ = nix::sys::prctl::set_thp_disable(true);
    }
}
