//! edns-tcp-keepalive option (RFC 7828 §3.1).

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

/// Idle timeout in units of 100 milliseconds: absent in a query, present in a response.
pub(super) fn decode(r: &mut Reader<'_>) -> Result<Option<u16>, DecodeError> {
    match r.remaining() {
        0 => Ok(None),
        2 => r.u16().map(Some),
        _ => Err(r.error(DecodeErrorKind::Invalid(
            "keepalive is empty or a 2-byte timeout",
        ))),
    }
}

pub(super) fn encode(timeout: Option<u16>, w: &mut Writer<'_>) -> Result<(), EncodeError> {
    timeout.map_or(Ok(()), |t| w.put_u16(t))
}
