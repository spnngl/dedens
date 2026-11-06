//! The allocator under test (D152, the experiment branch): one of the crates by feature, the libc'"'"'s by default.
//! Two at once do not build.

#[cfg(any(
    all(feature = "alloc-mimalloc", feature = "alloc-mimalloc-secure"),
    all(feature = "alloc-mimalloc", feature = "alloc-jemalloc"),
    all(feature = "alloc-mimalloc-secure", feature = "alloc-jemalloc"),
))]
compile_error!("select one allocator: alloc-mimalloc, alloc-mimalloc-secure or alloc-jemalloc");

/// The selected allocator.
#[cfg(any(feature = "alloc-mimalloc", feature = "alloc-mimalloc-secure"))]
pub type Selected = mimalloc::MiMalloc;
/// The selected allocator.
#[cfg(feature = "alloc-jemalloc")]
pub type Selected = tikv_jemallocator::Jemalloc;
/// The selected allocator.
#[cfg(not(any(
    feature = "alloc-mimalloc",
    feature = "alloc-mimalloc-secure",
    feature = "alloc-jemalloc"
)))]
pub type Selected = std::alloc::System;

/// The selected allocator under divan'"'"'s `AllocProfiler`, for the benches'"'"' `#[global_allocator]`.
pub type Profiled = divan::AllocProfiler<Selected>;

/// A `Profiled` around the selected allocator.
#[must_use]
pub const fn profiled() -> Profiled {
    divan::AllocProfiler::new(Selected {})
}
