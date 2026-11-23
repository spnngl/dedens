//! What the tests share: zone text with a valid apex to add to, and loading with or without `$INCLUDE`s.

use std::fs;

use dedens_proto::Ttl;
use dedens_testkit::dns;
use dedens_zone::{ErrorKind, Include, Limits, Loaded, Report, Source, Zone};

/// A zone with all it needs, to which a test adds what it checks: five lines, the SOA and NS of the apex first.
pub(crate) const APEX: &str =
    "$ORIGIN example.\n$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\n@ NS ns\nns A 192.0.2.1\n";

/// The line the first line after [`APEX`] has.
pub(crate) const NEXT_LINE: usize = 6;

/// The text of a zone file of `testdata/zones/`.
pub(crate) fn zone_file(name: &str) -> String {
    fs::read_to_string(dedens_testkit::path("zones").join(name)).expect("a zone file")
}

/// The text of the zone of RFC 4035 appendix A with names added between `b.example.` and `ns1.example.`: the NSEC of
/// `b.example.` leads to `first`, and `added` is the lines of the new names, the last NSEC leading to
/// `ns1.example.`. Each name of an NSEC chain has its NSEC (RFC 4035 §2.3); the signatures of the new ones are left
/// out, which a load does not check (D209).
pub(crate) fn with_names_after_b(text: &str, first: &str, added: &str) -> String {
    let relinked = text.replace(
        "3600 NSEC   ns1.example. NS RRSIG NSEC",
        &format!("3600 NSEC   {first} NS RRSIG NSEC"),
    );
    format!("{relinked}{added}")
}

/// Loads `text` as the zone `origin`, with the files of `$INCLUDE` given by `files`: pairs of the name as written and
/// the text.
pub(crate) fn load_files(
    origin: &str,
    text: &str,
    default_ttl: Option<Ttl>,
    files: &[(&str, &str)],
    limits: &Limits,
) -> Result<Loaded, Report> {
    let mut include: Box<Include<'_>> = Box::new(|name: &str| {
        files
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, text)| text.as_bytes().to_vec())
            .ok_or_else(|| "no such file".to_owned())
    });
    let source = Source {
        name: "zone.db",
        text: text.as_bytes(),
        default_ttl,
    };
    Zone::load(dns(origin), source, &mut include, limits)
}

/// Loads `text` as the zone `example.`, with the default limits.
pub(crate) fn load(text: &str) -> Result<Loaded, Report> {
    load_with(text, &Limits::default())
}

/// Loads `text` as the zone `example.`.
pub(crate) fn load_with(text: &str, limits: &Limits) -> Result<Loaded, Report> {
    load_files("example.", text, None, &[], limits)
}

/// [`APEX`] and `extra` loaded, the report's errors if it is refused.
pub(crate) fn load_extra(extra: &str) -> Result<Loaded, Report> {
    load(&format!("{APEX}{extra}"))
}

/// The error kinds of a refused load, with their lines.
pub(crate) fn refused(extra: &str) -> Vec<(Option<usize>, ErrorKind)> {
    errors(load_extra(extra).expect_err("a refused zone"))
}

/// The lines and kinds of the errors of `report`.
pub(crate) fn errors(report: Report) -> Vec<(Option<usize>, ErrorKind)> {
    report
        .errors
        .into_iter()
        .map(|e| (e.at.map(|at| at.line), e.kind))
        .collect()
}
