//! Captures `testdata/authoritative/` (D203), run by `just capture-authoritative`: zones transferred from public
//! servers, the answers Knot and NSD give on the same zones, and the transfers, NOTIFY and UPDATE messages Knot's tools
//! exchange with Knot through a recording proxy.
//!
//! Usage: `capture_authoritative <dir> <stage>...` where `dir` is `testdata/authoritative` and a stage is
//!
//! - `sources`: AXFR the root zone and `zonetransfer.me` from public servers into `zones/` and `recordings/`
//!   (RFC 5936 §2.2), and the Wayback Machine's older copy of the root zone into `zones/root-previous.zone`.
//! - `answers`: Knot and NSD each serve each zone of [`zones::ZONES`] and answer the queries of [`queries`], into
//!   `answers/`.
//! - `exchanges`: TSIG-signed and unsigned AXFR, IXFR, NOTIFY and UPDATE between Knot's tools and Knot, into
//!   `recordings/` ([`scenarios`]).
//! - `root-ixfr`: Knot loads `root-previous.zone`, reloads `root.zone` as a difference, and the IXFR from the
//!   first serial is recorded.
//!
//! Needs the container engine of the `just` variable `container` (`DEDENS_CONTAINER`) with the images of
//! `testdata/authoritative/Containerfile`, `just authoritative-images` builds them.

mod engine;
mod proxy;
mod queries;
mod scenarios;
mod servers;
mod transfer;
mod zones;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The Unix time now.
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Writes `contents` to `path` through a temporary name, so that an interrupted run leaves the old file.
fn write(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("part");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    eprintln!("{}", path.display());
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .ok_or("usage: capture_authoritative <dir> <stage>...")?,
    );
    let stages: Vec<String> = args.collect();
    if stages.is_empty() {
        return Err("usage: capture_authoritative <dir> <stage>...".into());
    }
    for stage in &stages {
        match stage.as_str() {
            "sources" => transfer::sources(&dir)?,
            "answers" => servers::answers(&dir)?,
            "exchanges" => scenarios::exchanges(&dir)?,
            "root-ixfr" => scenarios::root_ixfr(&dir)?,
            other => return Err(format!("no stage {other}").into()),
        }
    }
    Ok(())
}
