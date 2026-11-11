//! edns-client-subnet option (RFC 7871 §6).

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

const FAMILY_IPV4: u16 = 1;
const FAMILY_IPV6: u16 = 2;

/// A prefix longer than its address family allows, or an address with bits set beyond the source prefix (RFC 7871
/// §6: they must be zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "client subnet prefix too long for the family, or address bits set beyond the source prefix"
)]
pub struct SubnetError;

/// The network a query comes from (RFC 7871 §6): an address truncated to `source_prefix` bits, and in a response
/// the `scope_prefix` the answer is valid for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientSubnet {
    address: IpAddr,
    source_prefix: u8,
    scope_prefix: u8,
}

impl ClientSubnet {
    /// A client subnet.
    ///
    /// # Errors
    ///
    /// [`SubnetError`] when a prefix exceeds 32 (IPv4) or 128 (IPv6) bits, or `address` has a bit set after
    /// the first `source_prefix` bits.
    pub fn new(address: IpAddr, source_prefix: u8, scope_prefix: u8) -> Result<Self, SubnetError> {
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if source_prefix > max || scope_prefix > max {
            return Err(SubnetError);
        }
        let (bytes, len) = octets(address);
        let clean = bytes.iter().take(len).enumerate().all(|(i, &b)| {
            let first_bit = u8::try_from(i * 8).unwrap_or(u8::MAX);
            let kept = source_prefix.saturating_sub(first_bit).min(8);
            b & !high_bits(kept) == 0
        });
        if !clean {
            return Err(SubnetError);
        }
        Ok(Self {
            address,
            source_prefix,
            scope_prefix,
        })
    }

    /// The address, with zero bits after the source prefix.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// Bits of the address that are significant for the lookup.
    #[must_use]
    pub const fn source_prefix(&self) -> u8 {
        self.source_prefix
    }

    /// Bits of the address the answer applies to; 0 in a query.
    #[must_use]
    pub const fn scope_prefix(&self) -> u8 {
        self.scope_prefix
    }

    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let family = r.u16()?;
        let source_prefix = r.u8()?;
        let scope_prefix = r.u8()?;
        let bytes = r.rest();
        let invalid = |r: &Reader<'_>| r.error(DecodeErrorKind::Invalid("invalid client subnet"));
        if bytes.len() != usize::from(source_prefix).div_ceil(8) {
            return Err(invalid(r));
        }
        let address = match family {
            FAMILY_IPV4 => IpAddr::V4(Ipv4Addr::from(
                padded::<4>(bytes).ok_or_else(|| invalid(r))?,
            )),
            FAMILY_IPV6 => IpAddr::V6(Ipv6Addr::from(
                padded::<16>(bytes).ok_or_else(|| invalid(r))?,
            )),
            _ => return Err(invalid(r)),
        };
        Self::new(address, source_prefix, scope_prefix).map_err(|_| invalid(r))
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let family = match self.address {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };
        w.put_u16(family)?;
        w.put_u8(self.source_prefix)?;
        w.put_u8(self.scope_prefix)?;
        let (octets, _) = octets(self.address);
        let len = usize::from(self.source_prefix).div_ceil(8);
        w.put_bytes(octets.get(..len).unwrap_or_default())
    }
}

/// A byte with its `n` high bits set, `n` at most 8.
fn high_bits(n: u8) -> u8 {
    0xFF_u8.checked_shl(u32::from(8 - n)).unwrap_or(0)
}

/// The bytes of `address`: an IPv4 address in the first 4 of 16.
fn octets(address: IpAddr) -> ([u8; 16], usize) {
    match address {
        IpAddr::V4(a) => (padded(&a.octets()).unwrap_or_default(), 4),
        IpAddr::V6(a) => (a.octets(), 16),
    }
}

/// `bytes` followed by zeros up to `N`, or `None` when it is longer.
fn padded<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    let mut out = [0; N];
    out.get_mut(..bytes.len())?.copy_from_slice(bytes);
    Some(out)
}

/// Kani proof of the option's wire form (D145), for every input of up to 8 bytes: an IPv4 subnet whole, an IPv6 one
/// to its fourth byte.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Any option data of up to 8 bytes decodes without panicking, and a subnet it decodes encodes back to the same
    /// bytes: the address bits past the source prefix are zero (RFC 7871 §6), so none is lost or added.
    #[kani::proof]
    #[kani::unwind(17)]
    fn a_decoded_subnet_encodes_back() {
        let bytes: [u8; 8] = kani::any();
        let len = kani::any_where(|&len: &usize| len <= bytes.len());
        let input = &bytes[..len];
        let Ok(subnet) = ClientSubnet::decode(&mut Reader::new(input)) else {
            return;
        };
        let mut buf = [0; 8];
        let mut w = Writer::uncompressed(&mut buf);
        assert!(subnet.encode(&mut w).is_ok());
        assert_eq!(w.written(), input);
    }
}
