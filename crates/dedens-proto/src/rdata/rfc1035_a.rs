//! A: an IPv4 address (RFC 1035 §3.4.1).

use core::net::Ipv4Addr;

use crate::error::{DecodeError, EncodeError};
use crate::wire::{Reader, Writer};

pub(super) fn decode(r: &mut Reader<'_>) -> Result<Ipv4Addr, DecodeError> {
    Ok(Ipv4Addr::from(r.array::<4>()?))
}

pub(super) fn encode(addr: Ipv4Addr, w: &mut Writer<'_>) -> Result<(), EncodeError> {
    w.put_bytes(&addr.octets())
}
