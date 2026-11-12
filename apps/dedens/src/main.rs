//! The `dedens` binary: [`dedens::main`], with the allocator of a musl build.

#![forbid(unsafe_code)]

// D154: on musl, mimalloc in its secure mode replaces musl's allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
    dedens::main()
}
