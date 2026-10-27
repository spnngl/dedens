//! Unknown and unsupported types: RDATA kept byte for byte (RFC 3597 §4-5).

use crate::codes::RecordType;
use crate::error::EncodeError;
use crate::wire::Writer;

/// RDATA of a type this crate does not interpret, or whose content is invalid for its type (D9).
///
/// Written back unchanged: nothing in it is decompressed, so a type that may hold compressed names never ends up
/// here with pointers (RFC 3597 §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Opaque {
    /// The record type.
    pub rtype: RecordType,
    /// The RDATA bytes.
    pub data: Box<[u8]>,
}

impl Opaque {
    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&self.data)
    }
}
