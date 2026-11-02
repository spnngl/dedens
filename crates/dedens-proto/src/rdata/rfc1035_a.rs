//! A: an IPv4 address (RFC 1035 §3.4.1).

use core::net::Ipv4Addr;

use crate::error::{DecodeError, EncodeError};
use crate::text::{Fields, TextError};
use crate::wire::{Reader, Writer};

pub(super) fn decode(r: &mut Reader<'_>) -> Result<Ipv4Addr, DecodeError> {
    Ok(Ipv4Addr::from(r.array::<4>()?))
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature of every codec in the table (D139)"
)]
pub(super) fn encode(addr: &Ipv4Addr, w: &mut Writer<'_>) -> Result<(), EncodeError> {
    w.put_bytes(&addr.octets())
}

pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Ipv4Addr, TextError> {
    f.parse("IPv4 address")
}

pub(super) const fn into_owned(addr: Ipv4Addr) -> Ipv4Addr {
    addr
}
