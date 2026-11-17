//! `just roots`: the root's DS records of IANA's `root-anchors.xml` valid now, once its `.p7s` signature
//! is checked against ICANN's bundled CA (RFC 9718 §3.2, D127), written to stdout as `src/root.ds` holds them;
//! its signing time, in seconds since 1970, written to `<signed_at>` as `src/root.signed_at` holds it.
//!
//! Usage: `root_anchors <root-anchors.xml> <root-anchors.p7s> <signed_at>`.

use std::io::Write as _;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_dnssec::TrustAnchors;
use dedens_proto::Name;

/// The line above the signing time in `src/root.signed_at`, a Rust comment: the file is `include!`d.
const SIGNED_AT_HEADER: &str = "// The signingTime of root-anchors.xml in seconds since 1970: written by `just roots`, never by hand.\n";

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
    let (Some(xml), Some(p7s), Some(signed_at), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        return Err("usage: root_anchors <root-anchors.xml> <root-anchors.p7s> <signed_at>".into());
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let signed = TrustAnchors::verified(&std::fs::read(xml)?, &std::fs::read(p7s)?, now, None)?;
    let (_, root) = signed
        .anchors()
        .closest(&Name::root())
        .expect("the XML reader refuses a Zone other than the root");
    let mut out = std::io::stdout().lock();
    for ds in root.ds() {
        writeln!(out, ". IN DS {ds}")?;
    }
    std::fs::write(
        signed_at,
        format!("{SIGNED_AT_HEADER}{}\n", signed.signed_at()),
    )?;
    Ok(())
}
