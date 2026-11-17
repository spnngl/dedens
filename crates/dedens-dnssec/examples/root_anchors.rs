//! `just roots`: the root's DS records of IANA's `root-anchors.xml` valid now, once its `.p7s` signature
//! is checked against ICANN's bundled CA (RFC 9718 §3.2, D127), written to stdout as `src/root.ds` holds them.
//!
//! Usage: `root_anchors <root-anchors.xml> <root-anchors.p7s>`.

use std::io::Write as _;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_dnssec::TrustAnchors;
use dedens_proto::Name;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "root_anchors: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(xml), Some(p7s), None) = (args.next(), args.next(), args.next()) else {
        return Err("usage: root_anchors <root-anchors.xml> <root-anchors.p7s>".into());
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let anchors = TrustAnchors::verified(&std::fs::read(xml)?, &std::fs::read(p7s)?, now)?;
    let (_, root) = anchors
        .closest(&Name::root())
        .ok_or("root-anchors.xml anchors another zone than the root")?;
    let mut out = std::io::stdout().lock();
    for ds in root.ds() {
        writeln!(out, ". IN DS {ds}")?;
    }
    Ok(())
}
