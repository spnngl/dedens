//! The workspace's shared test data (D161): the real responses, example zones and files of the root `testdata/`,
//! for the tests, benches, fuzz targets and simulations of every crate.
//!
//! A dev-dependency, but a dependency of `dedens-sim` and `dedens-bench`, whose library code reads the data.

use std::path::PathBuf;

/// The file or directory `relative` of the root `testdata/`, as `proto/a.bin` or `zones/`.
#[must_use]
pub fn path(relative: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata")).join(relative)
}
