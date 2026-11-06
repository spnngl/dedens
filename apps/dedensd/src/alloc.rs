//! The allocator under test (D152, the experiment branch): one of the crates by feature, the libc'"'"'s by default.
//! Two at once do not build.

#[cfg(any(
    all(feature = "alloc-mimalloc", feature = "alloc-mimalloc-secure"),
    all(feature = "alloc-mimalloc", feature = "alloc-jemalloc"),
    all(feature = "alloc-mimalloc-secure", feature = "alloc-jemalloc"),
))]
compile_error!("select one allocator: alloc-mimalloc, alloc-mimalloc-secure or alloc-jemalloc");

#[cfg(any(feature = "alloc-mimalloc", feature = "alloc-mimalloc-secure"))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "alloc-jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
