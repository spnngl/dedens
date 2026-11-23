//! The zones the servers serve: where each is, and its text in the one form both servers read.

use std::path::Path;

use dedens_proto::{Name, Record, Ttl, ZoneEntry, ZoneReader};

use crate::Result;

/// A zone served to Knot and NSD.
pub(crate) struct Zone {
    /// The name of the zone's file in `answers/`.
    pub(crate) id: &'static str,
    /// The zone's file, relative to `testdata/`.
    pub(crate) file: &'static str,
    /// The origin the file starts with.
    pub(crate) origin: &'static str,
    /// The TTL of the records without one, RFC 1035 §5.1's missing `$TTL`.
    pub(crate) default_ttl: Option<u32>,
    /// The files its `$INCLUDE`s name, with their files relative to `testdata/`.
    pub(crate) includes: &'static [(&'static str, &'static str)],
}

/// The zones, each served by one run of each server.
pub(crate) const ZONES: &[Zone] = &[
    Zone {
        id: "rfc1035_isi",
        file: "zones/rfc1035_isi.zone",
        origin: "ISI.EDU.",
        default_ttl: Some(3600),
        includes: &[(
            "<SUBSYS>ISI-MAILBOXES.TXT",
            "zones/rfc1035_isi_mailboxes.zone",
        )],
    },
    Zone {
        id: "rfc4035_appendix_a",
        file: "zones/rfc4035_appendix_a.zone",
        origin: "example.",
        default_ttl: None,
        includes: &[],
    },
    Zone {
        id: "rfc5155_appendix_a",
        file: "zones/rfc5155_appendix_a.zone",
        origin: "example.",
        default_ttl: None,
        includes: &[],
    },
    Zone {
        id: "zonetransfer.me",
        file: "authoritative/zones/zonetransfer.me.zone",
        origin: "zonetransfer.me.",
        default_ttl: None,
        includes: &[],
    },
    SIGNED,
    Zone {
        id: "root",
        file: "authoritative/zones/root.zone",
        origin: ".",
        default_ttl: None,
        includes: &[],
    },
];

/// The zone Knot signed in the `signed` stage, served by both servers as a pre-signed zone (D209).
pub(crate) const SIGNED: Zone = Zone {
    id: "nsec3_signed",
    file: "authoritative/zones/nsec3_signed.zone",
    origin: "example.",
    default_ttl: None,
    includes: &[],
};

/// The unsigned zone Knot signs into [`SIGNED`].
pub(crate) const UNSIGNED: Zone = Zone {
    id: "nsec3_source",
    file: "zones/nsec3_source.zone",
    origin: "example.",
    default_ttl: None,
    includes: &[],
};

/// The root zone as the Wayback Machine archived it, before [`ZONES`]' root: where the IXFR of `root-ixfr` starts.
pub(crate) const PREVIOUS_ROOT: Zone = Zone {
    id: "root-previous",
    file: "authoritative/zones/root-previous.zone",
    origin: ".",
    default_ttl: None,
    includes: &[],
};

impl Zone {
    /// The apex.
    pub(crate) fn apex(&self) -> Result<Name<'static>> {
        Ok(self.origin.parse()?)
    }

    /// The zone's records, `$INCLUDE`s followed.
    pub(crate) fn load(&self, testdata: &Path) -> Result<Vec<Record<'static>>> {
        let text = std::fs::read(testdata.join(self.file))?;
        let mut reader = ZoneReader::new(&text, Some(self.apex()?));
        if let Some(secs) = self.default_ttl {
            reader = reader.with_ttl(Ttl::new(secs).ok_or("TTL out of range")?);
        }
        self.read(testdata, &mut reader)
    }

    fn read(&self, testdata: &Path, reader: &mut ZoneReader<'_>) -> Result<Vec<Record<'static>>> {
        let mut records = Vec::new();
        while let Some(entry) = reader.next() {
            match entry? {
                ZoneEntry::Record(decoded) => records.push(decoded.record),
                ZoneEntry::Include { file, origin } => {
                    let (_, local) = self
                        .includes
                        .iter()
                        .find(|(name, _)| *name == file)
                        .ok_or_else(|| format!("{}: unknown include {file}", self.file))?;
                    let text = std::fs::read(testdata.join(local))?;
                    records.extend(self.read(testdata, &mut reader.include(&text, origin))?);
                }
                _ => return Err("a zone entry that is no record".into()),
            }
        }
        Ok(records)
    }
}

/// The text of `records`, one record a line with its TTL, the form both servers read, under `comment`.
pub(crate) fn render(records: &[Record<'_>], comment: &str) -> String {
    let mut text = format!("; {comment}\n");
    for record in records {
        text.push_str(&record.to_string());
        text.push('\n');
    }
    text
}
