//! [`Zone::load`]: zone text, `$INCLUDE` followed, into a checked [`Zone`] (D204); [`Zone::from_records`]: the
//! records of a transfer, checked the same way (D210).

use dedens_proto::{DecodedRecord, Name, Record, Ttl, ZoneEntry, ZoneReader};

use crate::builder::Builder;
use crate::{Bound, ErrorKind, Limits, Place, Report, Zone};

/// The zone file to read.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    /// What reports call the file, as a path.
    pub name: &'a str,
    /// The text (RFC 1035 §5.1).
    pub text: &'a [u8],
    /// The TTL of a record before any `$TTL` or TTL of its own; without it such a record is an error
    /// (RFC 2308 §4).
    pub default_ttl: Option<Ttl>,
}

/// A zone that passed every check, and what it is still served with.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    /// The zone.
    pub zone: Zone,
    /// The files read and the warnings; no errors.
    pub report: Report,
}

/// The text of a `$INCLUDE`d file, or why the caller cannot give it. The only I/O of a load: the caller says
/// where a name is read from, and what it may read.
pub type Include<'a> = dyn FnMut(&str) -> Result<Vec<u8>, String> + 'a;

impl Zone {
    /// Reads the zone of `origin` from `source`, and checks it (RFC 1035 §5.2, RFC 2181 §5, §10.1, RFC 6672 §2.3,
    /// §2.4); `include` gives the files of `$INCLUDE`, each read as the zone file is.
    ///
    /// Every error found is reported, up to [`Limits::errors`]; a text error ends its file only.
    ///
    /// # Errors
    ///
    /// The [`Report`] of every error, with the place of each.
    pub fn load(
        origin: Name<'static>,
        source: Source<'_>,
        include: &mut Include<'_>,
        limits: &Limits,
    ) -> Result<Loaded, Report> {
        let mut builder = Builder::new(origin.clone(), source.name.to_owned(), limits);
        let mut reader = ZoneReader::new(source.text, Some(origin));
        if let Some(ttl) = source.default_ttl {
            reader = reader.with_ttl(ttl);
        }
        read(&mut builder, &mut reader, 0, 0, include);
        builder
            .finish()
            .map(|(zone, report)| Loaded { zone, report })
    }

    /// Builds the zone of `apex` from `records`, those of a transfer in the order received, the closing SOA left
    /// out (RFC 5936 §2.2), with every check of [`Zone::load`]; a place's line is the record's number in
    /// `records`, from 1, in the file `transfer`. A record outside the zone is dropped with a warning, not
    /// refused (D210).
    ///
    /// # Errors
    ///
    /// The [`Report`] of every error, as [`Zone::load`] gives it.
    pub fn from_records(
        apex: Name<'static>,
        records: impl IntoIterator<Item = Record<'static>>,
        limits: &Limits,
    ) -> Result<Loaded, Report> {
        let mut builder = Builder::new(apex, "transfer".to_owned(), limits).dropping_outside_zone();
        for (n, record) in records.into_iter().enumerate() {
            if builder.stopped() {
                break;
            }
            let at = Place {
                file: 0,
                line: n + 1,
                column: 1,
            };
            builder.add(
                at,
                DecodedRecord {
                    record,
                    invalid_rdata: None,
                },
            );
        }
        builder
            .finish()
            .map(|(zone, report)| Loaded { zone, report })
    }
}

/// The entries of `reader`, the file of index `file` at `depth` levels of `$INCLUDE`.
fn read(
    builder: &mut Builder<'_>,
    reader: &mut ZoneReader<'_>,
    file: usize,
    depth: usize,
    include: &mut Include<'_>,
) {
    while !builder.stopped() {
        let Some(entry) = reader.next() else { return };
        let (line, column) = reader.at();
        let at = Place { file, line, column };
        match entry {
            Ok(ZoneEntry::Record(record)) => builder.add(at, record),
            Ok(ZoneEntry::Include { file: name, origin }) => {
                if depth >= builder.include_depth() {
                    builder.limit(Some(at), Bound::IncludeDepth);
                    continue;
                }
                match include(&name) {
                    Ok(text) => {
                        let index = builder.file(name);
                        read(
                            builder,
                            &mut reader.include(&text, origin),
                            index,
                            depth + 1,
                            include,
                        );
                    }
                    Err(reason) => {
                        builder.error(Some(at), ErrorKind::Include { file: name, reason });
                    }
                }
            }
            // `ZoneEntry` is non-exhaustive: an entry of a kind this version does not know carries no record.
            Ok(_) => {}
            Err(e) => {
                let at = Place {
                    file,
                    line: e.line,
                    column: e.column,
                };
                builder.error(Some(at), ErrorKind::Text(e.kind));
                return;
            }
        }
    }
}
