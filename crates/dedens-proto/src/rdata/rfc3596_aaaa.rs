//! AAAA: an IPv6 address (RFC 3596 §2.2).

use core::net::Ipv6Addr;

use crate::error::{DecodeError, EncodeError};
use crate::text::{Fields, TextError};
use crate::wire::{Reader, Writer};

pub(super) fn decode(r: &mut Reader<'_>) -> Result<Ipv6Addr, DecodeError> {
    Ok(Ipv6Addr::from(r.array::<16>()?))
}

pub(super) fn encode(addr: &Ipv6Addr, w: &mut Writer<'_>) -> Result<(), EncodeError> {
    w.put_bytes(&addr.octets())
}

pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Ipv6Addr, TextError> {
    f.parse("IPv6 address")
}

pub(super) const fn into_owned(addr: Ipv6Addr) -> Ipv6Addr {
    addr
}
