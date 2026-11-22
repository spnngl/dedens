//! The bytes of a journal file: a header, then one framed changeset after another (D207).
//!
//! Pure functions over bytes, no I/O, so that a fuzz target reads any file and a test cuts or flips any byte of one.
//!
//! ```text
//! file    = MAGIC record*
//! record  = payload_len:u32 BE, crc:u32 BE, payload
//! crc     = CRC-32 of the four bytes of payload_len, then the payload
//! payload = the RFC 1995 §4 sequence of a changeset, each record in wire form (RFC 1035 §3.2.1, names not
//!           compressed): old SOA, the removed records, new SOA, the added records
//! ```

use dedens_proto::{EncodeError, Record, RecordType, Serial};

use super::JournalError;
use super::crc::crc32;
use crate::Changeset;

/// The first bytes of a journal file: the format and its version.
pub const MAGIC: [u8; 8] = *b"dedensj1";

/// The bytes before a record's payload: its length and its CRC.
pub const FRAME: usize = 8;

/// Why a file's records stop before its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    /// Every byte is in a record.
    Clean,
    /// The last record is cut short: a write that a crash interrupted, or a length that cannot be real.
    Torn,
    /// The CRC of a record is not that of its bytes.
    BadCrc,
    /// A record whose payload is no changeset.
    Undecodable,
    /// A record that starts from another serial than the previous one ends at.
    NotConsecutive,
}

/// What [`scan`] read from a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    /// The changesets, oldest first, each starting from the serial the one before it ends at.
    pub changesets: Vec<Changeset>,
    /// The size in the file of each changeset's record, frame included.
    pub sizes: Vec<usize>,
    /// How many bytes of the file are the header and whole, good records: a file cut there is a journal.
    /// Zero when the file is not yet a whole header.
    pub valid: usize,
    /// Why the file goes on past `valid`, if it does.
    pub tail: Tail,
}

/// The record of `changeset`, appended to `out`: its frame and its payload.
///
/// # Errors
///
/// [`EncodeError::BufferFull`] when a record's RDATA, or the whole payload, is over what its length takes; `out`
/// is then as it was.
pub fn encode(changeset: &Changeset, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let mut payload = Vec::new();
    changeset.from_soa().write_wire(&mut payload)?;
    for record in changeset.removed() {
        record.write_wire(&mut payload)?;
    }
    changeset.to_soa().write_wire(&mut payload)?;
    for record in changeset.added() {
        record.write_wire(&mut payload)?;
    }
    frame(&payload, out)
}

/// A record of `payload` appended to `out`: its length, its CRC, the payload.
///
/// # Errors
///
/// [`EncodeError::BufferFull`] when the payload is longer than a `u32` counts.
pub fn frame(payload: &[u8], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| EncodeError::BufferFull)?
        .to_be_bytes();
    out.extend_from_slice(&len);
    out.extend_from_slice(&crc32(&[&len, payload]).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// The records of a file, as far as they are good.
///
/// Stops at the first record that is cut short, whose CRC fails, that is no changeset, or that does not follow the
/// one before; everything after it is lost with it, as the records after a flipped bit cannot be told from noise.
///
/// A file shorter than the header that is the start of it (a crash while the file was made) has no record and no
/// valid bytes.
///
/// # Errors
///
/// [`JournalError::NotAJournal`] when the file starts with other bytes than the header.
pub fn scan(bytes: &[u8]) -> Result<Scan, JournalError> {
    let mut scan = Scan {
        changesets: Vec::new(),
        sizes: Vec::new(),
        valid: 0,
        tail: Tail::Clean,
    };
    let Some(mut rest) = bytes.strip_prefix(&MAGIC) else {
        if !MAGIC.starts_with(bytes) {
            return Err(JournalError::NotAJournal);
        }
        if !bytes.is_empty() {
            scan.tail = Tail::Torn;
        }
        return Ok(scan);
    };
    scan.valid = MAGIC.len();
    let mut tip: Option<Serial> = None;
    while !rest.is_empty() {
        let (changeset, size) = match record(rest) {
            Ok(found) => found,
            Err(tail) => {
                scan.tail = tail;
                break;
            }
        };
        if tip.is_some_and(|tip| tip != changeset.from_serial()) {
            scan.tail = Tail::NotConsecutive;
            break;
        }
        tip = Some(changeset.to_serial());
        scan.changesets.push(changeset);
        scan.sizes.push(size);
        scan.valid += size;
        rest = rest.get(size..).unwrap_or_default();
    }
    Ok(scan)
}

/// The record at the start of `rest`, and its size.
fn record(rest: &[u8]) -> Result<(Changeset, usize), Tail> {
    let (&[l0, l1, l2, l3, c0, c1, c2, c3], after) =
        rest.split_first_chunk::<FRAME>().ok_or(Tail::Torn)?;
    let len_bytes = [l0, l1, l2, l3];
    let len = usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| Tail::Torn)?;
    let payload = after.get(..len).ok_or(Tail::Torn)?;
    if crc32(&[&len_bytes, payload]) != u32::from_be_bytes([c0, c1, c2, c3]) {
        return Err(Tail::BadCrc);
    }
    let changeset = decode(payload).ok_or(Tail::Undecodable)?;
    Ok((changeset, FRAME + len))
}

/// The changeset a payload holds.
fn decode(payload: &[u8]) -> Option<Changeset> {
    let mut rest = payload;
    let from = take(&mut rest)?;
    let mut removed = Vec::new();
    let to = loop {
        let record = take(&mut rest)?;
        if record.rtype() == RecordType::SOA {
            break record;
        }
        removed.push(record);
    };
    let mut added = Vec::new();
    while !rest.is_empty() {
        added.push(take(&mut rest)?);
    }
    Changeset::new(from, to, removed, added).ok()
}

/// The record at the start of `rest`, which then starts after it. `None` for bytes that are no record, or RDATA
/// that is invalid for its type: the journal only holds what the zone's checks let through.
fn take(rest: &mut &[u8]) -> Option<Record<'static>> {
    let (decoded, used) = Record::from_wire(rest).ok()?;
    if decoded.invalid_rdata.is_some() {
        return None;
    }
    let record = decoded.record.into_owned();
    *rest = rest.get(used..)?;
    Some(record)
}
