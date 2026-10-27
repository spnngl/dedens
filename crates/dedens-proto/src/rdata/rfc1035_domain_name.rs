//! NS, CNAME and PTR: RDATA that is one domain name (RFC 1035 §3.3.1, §3.3.11, §3.3.12).
//!
//! The name may be compressed (RFC 3597 §4).

use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

pub(super) fn decode(r: &mut Reader<'_>) -> Result<Name, DecodeError> {
    Name::decode(r)
}

pub(super) fn encode(name: &Name, w: &mut Writer<'_>) -> Result<(), EncodeError> {
    w.put_name_compressed(name)
}
