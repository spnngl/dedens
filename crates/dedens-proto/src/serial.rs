//! [`Serial`]: the serial number arithmetic of RFC 1982, for SOA serials, RRSIG times and cookie timestamps.

use core::cmp::Ordering;

/// Half the circle of 32-bit serials: two serials this far apart have no order (RFC 1982 §3.2).
const HALF: u32 = 1 << 31;

/// A 32-bit serial number, compared on a circle (RFC 1982 §3.2).
///
/// Of two serials, the one ahead by less than 2^31 steps is the greater, so the order holds across the wrap from
/// 2^32 - 1 to 0. Two serials exactly 2^31 apart have no order (§3.2: "undefined"), which [`PartialOrd`] says as
/// `None`, so neither `<` nor `>` holds between them. The order is no total order, hence no `Ord`: a serial cannot be
/// a key of a sorted map.
///
/// ```
/// use dedens_proto::Serial;
///
/// assert!(Serial::new(u32::MAX) < Serial::new(1));
/// assert_eq!(Serial::new(1).partial_cmp(&Serial::new((1 << 31) + 1)), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Serial(u32);

impl Serial {
    /// The serial of `value`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The 32 bits.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The serial `steps` ahead, wrapping at 2^32 (RFC 1982 §3.1).
    ///
    /// `None` for `steps` over 2^31 - 1, the largest increment the RFC allows: past it, the result would not be
    /// ahead of `self`.
    #[must_use]
    pub const fn checked_add(self, steps: u32) -> Option<Self> {
        if steps < HALF {
            Some(Self(self.0.wrapping_add(steps)))
        } else {
            None
        }
    }

    /// How far `self` is ahead of `earlier`: positive when ahead, negative when behind, 0 when equal.
    ///
    /// `None` when the two are exactly 2^31 apart: the order of RFC 1982 §3.2 is undefined there.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Option<i32> {
        let steps = self.0.wrapping_sub(earlier.0);
        if steps == HALF {
            None
        } else {
            Some(steps.cast_signed())
        }
    }
}

/// RFC 1982 §3.2: `None` when the serials are 2^31 apart.
impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.since(*other).map(|d| d.cmp(&0))
    }
}

impl From<u32> for Serial {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Serial> for u32 {
    fn from(serial: Serial) -> Self {
        serial.0
    }
}

/// The number, as zone files and `dig` write it.
impl core::fmt::Display for Serial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}
