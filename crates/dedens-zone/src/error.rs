//! What a load reports: errors that refuse the zone and warnings that do not, each with its place (D204).

use core::fmt;

use dedens_proto::{
    Class, DecodeError, Name, Nsec3HashAlgorithm, RecordType, Serial, TextErrorKind,
};

/// Where a record starts: the line and column, from 1, in the file of that index in [`Report::files`].
///
/// A record of a zone that [`Zone::apply`](crate::Zone::apply) changes has no line: `line` and `column` are 0, and
/// `file` is 0. A record of the changeset is its number, from 1, removals first, as the `line`. A record of
/// [`Zone::from_records`](crate::Zone::from_records) is its number, from 1, as the `line`, at column 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Place {
    /// Index in [`Report::files`]; 0 is the zone file.
    pub file: usize,
    /// Line, from 1; 0 for a record the zone had before a change.
    pub line: usize,
    /// Column, from 1, in bytes; 0 as `line`.
    pub column: usize,
}

/// A limit of [`Limits`](crate::Limits) a load reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// [`Limits::records`](crate::Limits::records).
    Records,
    /// [`Limits::names`](crate::Limits::names).
    Names,
    /// [`Limits::records_per_rrset`](crate::Limits::records_per_rrset).
    RecordsPerRrset,
    /// [`Limits::rrsets_per_name`](crate::Limits::rrsets_per_name).
    RrsetsPerName,
    /// [`Limits::rdata_bytes`](crate::Limits::rdata_bytes).
    RdataBytes,
    /// [`Limits::include_depth`](crate::Limits::include_depth).
    IncludeDepth,
    /// [`Limits::nsec3_iterations`](crate::Limits::nsec3_iterations).
    Nsec3Iterations,
}

impl fmt::Display for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Records => "records in the zone",
            Self::Names => "names in the zone",
            Self::RecordsPerRrset => "records in an RRset",
            Self::RrsetsPerName => "RRsets at a name",
            Self::RdataBytes => "bytes of RDATA in the zone",
            Self::IncludeDepth => "levels of $INCLUDE",
            Self::Nsec3Iterations => "NSEC3 iterations (RFC 5155 §10.3)",
        })
    }
}

/// Why a load refuses a zone. Each variant names the RFC section it enforces.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The zone text is wrong (RFC 1035 §5.1); the rest of that file is not read.
    #[error("{0}")]
    Text(TextErrorKind),
    /// The callback could not give a `$INCLUDE`d file.
    #[error("cannot read $INCLUDE {file}: {reason}")]
    Include {
        /// The file, as written.
        file: String,
        /// What the callback said.
        reason: String,
    },
    /// A bound of [`Limits`](crate::Limits) is reached.
    #[error("more than {limit} {bound}")]
    Limit {
        /// Which bound.
        bound: Bound,
        /// Its value.
        limit: usize,
    },
    /// A record of another class than the zone's (RFC 1035 §5.2: a zone holds one class).
    #[error("class {found} in a zone of class {zone} (RFC 1035 §5.2)")]
    ClassMismatch {
        /// The class of the record.
        found: Class,
        /// The class of the zone: that of its first record.
        zone: Class,
    },
    /// RDATA written as `\# length hex` that is not valid for its type (RFC 3597 §5): a server must not publish
    /// what it cannot read.
    #[error("RDATA invalid for its type: {0} (RFC 3597 §5)")]
    InvalidRdata(DecodeError),
    /// An owner at neither the apex nor below it (RFC 1035 §5.2, RFC 1034 §4.2.1: a zone holds the names at or
    /// below its apex).
    #[error("{owner} is outside the zone (RFC 1035 §5.2)")]
    OutsideZone {
        /// The owner of the record.
        owner: Name<'static>,
    },
    /// A record of a type or class that is no data: OPT, TSIG, TKEY, a QTYPE or another meta type, a QCLASS or
    /// meta class (RFC 6895 §3.1, §3.2). Zone text cannot write one; the records of a transfer or a changeset can
    /// carry it.
    #[error("a record of type {rtype} and class {class} is no data (RFC 6895 §3.1, §3.2)")]
    NotData {
        /// The type of the record.
        rtype: RecordType,
        /// Its class.
        class: Class,
    },
    /// An SOA that is not at the apex (RFC 1035 §5.2: exactly one SOA, at the top of the zone).
    #[error("SOA below the apex (RFC 1035 §5.2)")]
    SoaNotAtApex,
    /// A second, different SOA (RFC 1035 §5.2).
    #[error("more than one SOA (RFC 1035 §5.2)")]
    MultipleSoa,
    /// No SOA at the apex (RFC 1035 §5.2).
    #[error("no SOA at the apex (RFC 1035 §5.2)")]
    NoSoa,
    /// No NS at the apex (RFC 1035 §5.2: at least one NS at the top of the zone).
    #[error("no NS at the apex (RFC 1035 §5.2)")]
    NoApexNs,
    /// A CNAME at a name that holds another type, DNSSEC's NSEC and RRSIG aside (RFC 2181 §10.1).
    #[error("CNAME beside {other} (RFC 2181 §10.1)")]
    CnameWithOtherData {
        /// A type beside it, the lowest.
        other: RecordType,
    },
    /// A second, different CNAME at a name (RFC 2181 §10.1).
    #[error("more than one CNAME at a name (RFC 2181 §10.1)")]
    MultipleCname,
    /// A second, different DNAME at a name (RFC 6672 §2.4).
    #[error("more than one DNAME at a name (RFC 6672 §2.4)")]
    MultipleDname,
    /// A CNAME and a DNAME at one name (RFC 6672 §2.4, RFC 2181 §10.1).
    #[error("CNAME and DNAME at one name (RFC 6672 §2.4)")]
    CnameWithDname,
    /// A DNAME and an NS at a name that is not the apex (RFC 6672 §2.3: a DNAME and a delegation at one name
    /// would both cut the tree).
    #[error("DNAME beside NS below the apex (RFC 6672 §2.3)")]
    DnameWithNs,
    /// A record to remove that the zone does not have (RFC 1995 §4: each deleted record is one of the old version).
    #[error("{owner} {rtype} record to remove is not in the zone (RFC 1995 §4)")]
    RemoveAbsent {
        /// The owner of the record.
        owner: Name<'static>,
        /// Its type.
        rtype: RecordType,
    },
    /// A changeset that starts at another version than the zone's (RFC 1995 §4: the differences are from the
    /// version the old SOA names).
    #[error("the changeset starts at serial {changeset}, the zone is at {zone} (RFC 1995 §4)")]
    WrongVersion {
        /// The serial of the zone.
        zone: Serial,
        /// The serial the changeset starts from.
        changeset: Serial,
    },
    /// An NSEC or NSEC3 record whose next name is not the owner that follows it in its chain, in canonical or
    /// hash order: the chain does not close, and an answer would prove what the zone holds absent (RFC 4034
    /// §4.1.1, RFC 5155 §7.1).
    #[error(
        "the {rtype} record of {owner} does not lead to the next name of its chain (RFC 4034 §4.1.1, RFC 5155 §7.1)"
    )]
    BrokenChain {
        /// NSEC or NSEC3.
        rtype: RecordType,
        /// The owner of the record.
        owner: Name<'static>,
    },
    /// A name with authoritative data or a delegation point NS that has no NSEC, in a zone that proves absence by
    /// NSEC (RFC 4035 §2.3): the NSEC that covers it would prove it absent, while its answer is data.
    #[error("{owner} has no NSEC record (RFC 4035 §2.3)")]
    MissingNsec {
        /// The name.
        owner: Name<'static>,
    },
    /// An NSEC3PARAM of another hash algorithm than SHA-1, the only one (RFC 5155 §11): no name can be hashed to
    /// prove it absent.
    #[error("NSEC3PARAM of hash algorithm {algorithm}, not SHA-1 (RFC 5155 §11)")]
    Nsec3Algorithm {
        /// The algorithm.
        algorithm: Nsec3HashAlgorithm,
    },
    /// More errors than [`Limits::errors`](crate::Limits::errors): the load stopped.
    #[error("more than {limit} errors: stopped")]
    Stopped {
        /// The value of the limit.
        limit: usize,
    },
}

/// What is wrong with a zone that it is still served for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WarningKind {
    /// The records of an `RRset` have different TTLs (RFC 2181 §5.2 deprecates it): all take the lowest, as that
    /// section tells a client to do (D204).
    #[error("{rtype} records with different TTLs; using the lowest, {kept} (RFC 2181 §5.2)")]
    DifferentTtls {
        /// The type of the `RRset`; for signatures, `RRSIG`.
        rtype: RecordType,
        /// The TTL used, in seconds.
        kept: u32,
    },
    /// A delegation whose name server is inside the delegated domain and has no A or AAAA record in the zone:
    /// nothing can find the server (RFC 1034 §4.2.1, RFC 9471 §2).
    #[error(
        "{target} is a name server of {delegation} inside it, with no address (RFC 1034 §4.2.1)"
    )]
    MissingGlue {
        /// The delegation point.
        delegation: Name<'static>,
        /// The name server.
        target: Name<'static>,
    },
    /// Names below a DNAME: they are kept, never answered from (RFC 6672 §2.4 says the owner has no children).
    #[error("{first} is below the DNAME at this name, and never answered from (RFC 6672 §2.4)")]
    BelowDname {
        /// The first name below, in canonical order.
        first: Name<'static>,
    },
    /// A record of a transfer at neither the apex nor below it, dropped (RFC 5936 says nothing of it; Knot drops it
    /// with a warning, `zonefile.c:zcreator_step`, D210). Only the first [`Limits::errors`](crate::Limits::errors)
    /// are reported one by one; [`WarningKind::OutsideZoneMore`] counts the rest.
    #[error("{owner} is outside the zone: its record is dropped (D210)")]
    OutsideZone {
        /// The owner of the record.
        owner: Name<'static>,
    },
    /// The records outside the zone dropped past the first [`Limits::errors`](crate::Limits::errors), which
    /// [`WarningKind::OutsideZone`] reports one by one: the place is the first of them.
    #[error("{count} more records outside the zone dropped (D210)")]
    OutsideZoneMore {
        /// How many.
        count: usize,
    },
    /// An NSEC3 record whose owner is not one label below the apex: the owner is the hash "prepended as a single
    /// label to the zone name" (RFC 5155 §3, §7.1). It is served, but answers may differ from other servers' for
    /// names around it (D206).
    #[error(
        "{owner} holds an NSEC3 record but is not one label below the apex (RFC 5155 §3, §7.1)"
    )]
    Nsec3Owner {
        /// The owner of the record.
        owner: Name<'static>,
    },
    /// The apex holds a DNSKEY or signatures, but no NSEC3PARAM of flags 0 and no NSEC names a chain: the answers
    /// carry their RRSIGs and no proof that a name or type is absent, which a validating resolver takes as bogus
    /// (RFC 4035 §3.1.3, RFC 5155 §4.1.2). A signer that left out the apex NSEC, or an NSEC3PARAM of flags 1 only
    /// (not a chain to serve, RFC 5155 §4.1.2), shows so.
    #[error(
        "signed zone with no NSEC chain or NSEC3PARAM of flags 0: no proof of absence (RFC 4035 §3.1.3)"
    )]
    SignedWithoutChain,
    /// NSEC3 parameters of more than 0 iterations, which RFC 9276 §3.1 advises against: an answer that proves a
    /// name absent hashes the next closer name that many times more, and validators may take the zone as insecure
    /// (§3.2).
    #[error("NSEC3PARAM of {iterations} iterations; RFC 9276 §3.1 advises 0")]
    Nsec3Iterations {
        /// The iterations.
        iterations: u16,
    },
}

/// An error and where it is; `at` is `None` for what the zone lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneError {
    /// The place of the record at fault.
    pub at: Option<Place>,
    /// What is wrong.
    pub kind: ErrorKind,
}

/// A warning and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// The place of the record at fault.
    pub at: Place,
    /// What is wrong.
    pub kind: WarningKind,
}

/// What a load found, in the order it found it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// The files read: the zone file, then each `$INCLUDE`, as written.
    pub files: Vec<String>,
    /// Why the zone is refused; empty for a zone that loaded.
    pub errors: Vec<ZoneError>,
    /// What the zone is served with.
    pub warnings: Vec<Warning>,
}

impl Report {
    fn place(&self, f: &mut fmt::Formatter<'_>, at: Option<Place>) -> fmt::Result {
        let Some(at) = at else {
            return f.write_str(self.files.first().map_or("", String::as_str));
        };
        let file = self.files.get(at.file).map_or("", String::as_str);
        if at.line == 0 {
            return f.write_str(file);
        }
        write!(f, "{file}:{}:{}", at.line, at.column)
    }
}

/// One line per error then per warning: `file:line:column: error: ...`.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut line = |f: &mut fmt::Formatter<'_>| {
            if !core::mem::take(&mut first) {
                f.write_str("\n")?;
            }
            Ok(())
        };
        for e in &self.errors {
            line(f)?;
            self.place(f, e.at)?;
            write!(f, ": error: {}", e.kind)?;
        }
        for w in &self.warnings {
            line(f)?;
            self.place(f, Some(w.at))?;
            write!(f, ": warning: {}", w.kind)?;
        }
        Ok(())
    }
}

impl std::error::Error for Report {}
