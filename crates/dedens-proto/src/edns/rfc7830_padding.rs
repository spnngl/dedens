//! Padding option (RFC 7830).
//!
//! Only the length is kept: the padding octets carry no information, are written as zeros, and a receiver must
//! ignore them (RFC 7830 §3).

use crate::error::EncodeError;
use crate::wire::{Reader, Writer};

pub(super) fn decode(r: &mut Reader<'_>) -> u16 {
    // The option length is a `u16`, so the padding fits.
    u16::try_from(r.rest().len()).unwrap_or(u16::MAX)
}

pub(super) fn encode(len: u16, w: &mut Writer<'_>) -> Result<(), EncodeError> {
    w.put_zeros(usize::from(len))
}
