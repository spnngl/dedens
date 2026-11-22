//! The bounds of a load (D204).

/// What a load of a zone accepts: a zone is held in memory whole, and its text is outside data.
///
/// A record past a bound is an error, [`ErrorKind::Limit`](crate::ErrorKind::Limit), and the load goes on to report
/// the rest. Each field says what it bounds, why, and what Knot, NSD and BIND do; `tests/limits.rs`
/// reaches each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Records in the zone, once duplicates are merged: 16 777 216 (2²⁴). Memory is what the zone costs per record
    /// (`docs/benchmarks.md`), so a bound has to exist; none of the three has one by default (BIND's `max-records`
    /// is 0, unlimited, `bin/include/defaultconfig.h`; Knot's and NSD's loaders, `zonefile.c` and `zonec_accept` in
    /// `zonec.c`, read until the file ends).
    pub records: usize,
    /// Names in the zone, those with records and the empty non-terminals between them: 16 777 216, as `records`:
    /// every name holds a record or sits above one, and a name costs a node.
    pub names: usize,
    /// Records in one `RRset`: 100, BIND's `max-records-per-type` (`bin/include/defaultconfig.h`). Knot and NSD
    /// have no such bound; a larger one cannot be sent whole in most responses anyway (RFC 2181 §9).
    pub records_per_rrset: usize,
    /// `RRset`s at one name, signatures counted by the type they cover: 100, BIND's `max-types-per-name`
    /// (`bin/include/defaultconfig.h`). The types in use number about a hundred; a name holding more is an attack
    /// on the lookups that walk its `RRset`s.
    pub rrsets_per_name: usize,
    /// Bytes of RDATA in the zone: 1 GiB (2³⁰). Records bound the count; a record holds up to 65 535 bytes (RFC 1035
    /// §3.2.1), so a zone of the most records of the largest size would not fit any memory. No other loader bounds
    /// it.
    pub rdata_bytes: usize,
    /// Depth of `$INCLUDE`: 8. A file including itself would otherwise nest until the stack ends. Knot's scanner
    /// (`src/libzscanner/scanner_body.rl`, `ZS_STATE_INCLUDE`: one scanner per file, nested without a count) and
    /// BIND's `pushfile` (`lib/dns/master.c`) have no bound; the zones of RFC 1035 §5.1 use one level.
    pub include_depth: usize,
    /// Errors a load reports before it gives up: 100. A zone of wrong data would report each record; the first
    /// hundred are what a person reads. Knot's checker (`src/knot/zone/semantic-check.c`) reports them all.
    pub errors: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            records: 1 << 24,
            names: 1 << 24,
            records_per_rrset: 100,
            rrsets_per_name: 100,
            rdata_bytes: 1 << 30,
            include_depth: 8,
            errors: 100,
        }
    }
}
