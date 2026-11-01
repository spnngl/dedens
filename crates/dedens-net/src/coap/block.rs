//! Block-wise transfers: the Block1 and Block2 option values, the reassembly of a body from its blocks and the
//! slicing of a body into them (RFC 7959 §2).

use super::message::encode_uint;

/// A block size: 2^(SZX + 4) bytes, SZX 0 to 6, so 16 to 1024 bytes (RFC 7959 §2.2). SZX 7 is reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockSize(u8);

impl BlockSize {
    /// 16 bytes.
    pub const MIN: Self = Self(0);
    /// 1024 bytes.
    pub const MAX: Self = Self(6);

    /// The size of `szx`, none for 7 and over.
    #[must_use]
    pub const fn new(szx: u8) -> Option<Self> {
        if szx <= Self::MAX.0 {
            Some(Self(szx))
        } else {
            None
        }
    }

    /// The SZX: the base 2 logarithm of the size, less 4.
    #[must_use]
    pub const fn szx(self) -> u8 {
        self.0
    }

    /// The size in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        16 << self.0
    }
}

/// A Block1 or Block2 option value: block number, more bit and size (RFC 7959 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Block {
    num: u32,
    more: bool,
    size: BlockSize,
}

/// A block option value that is not a block (RFC 7959 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BlockError {
    /// More than 3 bytes.
    #[error("a block option is at most 3 bytes, not {0}")]
    TooLong(usize),
    /// SZX 7, which is reserved.
    #[error("a block size of SZX 7 is reserved")]
    ReservedSize,
}

/// The largest block number: 20 bits (RFC 7959 §2.2).
const MAX_NUM: u32 = (1 << 20) - 1;

impl Block {
    /// The block `num` of blocks of `size`, `more` blocks following; none if `num` does not fit in 20 bits.
    #[must_use]
    pub const fn new(num: u32, more: bool, size: BlockSize) -> Option<Self> {
        if num <= MAX_NUM {
            Some(Self { num, more, size })
        } else {
            None
        }
    }

    /// Reads an option value; an empty one is block 0 of 16 bytes, no more (RFC 7959 §2.2).
    ///
    /// # Errors
    ///
    /// [`BlockError`] if it is over 3 bytes or has the reserved SZX 7.
    pub fn from_value(value: &[u8]) -> Result<Self, BlockError> {
        if value.len() > 3 {
            return Err(BlockError::TooLong(value.len()));
        }
        let word = value.iter().fold(0u32, |sum, &b| (sum << 8) | u32::from(b));
        // Three bytes make at most 24 bits: 20 for the number.
        Ok(Self {
            num: word >> 4,
            more: word & 0b1000 != 0,
            size: u8::try_from(word & 0b111)
                .ok()
                .and_then(BlockSize::new)
                .ok_or(BlockError::ReservedSize)?,
        })
    }

    /// The option value, in the fewest bytes.
    #[must_use]
    pub fn to_value(self) -> Vec<u8> {
        encode_uint((self.num << 4) | (u32::from(self.more) << 3) | u32::from(self.size.0))
    }

    /// The block number.
    #[must_use]
    pub const fn num(self) -> u32 {
        self.num
    }

    /// Whether more blocks follow: always unset in a request for a block of a response (RFC 7959 §2.2).
    #[must_use]
    pub const fn more(self) -> bool {
        self.more
    }

    /// The block size.
    #[must_use]
    pub const fn size(self) -> BlockSize {
        self.size
    }

    /// The offset of the block in the body: NUM times the size (RFC 7959 §2.4).
    #[must_use]
    pub fn offset(self) -> usize {
        // At most 2^20 times 1024: 2^30.
        usize::try_from(self.num << (self.size.0 + 4)).unwrap_or(usize::MAX)
    }
}

/// Why a block does not add to a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReassemblyError {
    /// The block does not start where the body received so far ends.
    #[error("block at offset {got}, the body received so far is {expected} bytes")]
    OutOfOrder {
        /// The length of the body so far.
        expected: usize,
        /// The offset of the block.
        got: usize,
    },
    /// A block with more to come is not a whole block (RFC 7959 §2.2).
    #[error("a block with the more bit set holds {got} bytes, not {size}")]
    ShortBlock {
        /// The size of the block.
        size: usize,
        /// The payload length.
        got: usize,
    },
    /// The body is over the limit.
    #[error("the body is over {0} bytes")]
    TooLarge(usize),
}

/// A body received block by block, in order (RFC 7959 §2.4).
#[derive(Debug, Clone)]
pub struct Reassembly {
    body: Vec<u8>,
    limit: usize,
}

impl Reassembly {
    /// The most a body may hold by default: that of a DNS message (RFC 1035 §4.2.2).
    pub const DEFAULT_LIMIT: usize = 65535;

    /// A body of at most `limit` bytes.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            body: Vec::new(),
            limit,
        }
    }

    /// Adds the next block: the one at the end of the body. Returns the block to ask for next if more are due
    /// (in the size this block has, RFC 7959 §2.4), none if the body is complete.
    ///
    /// # Errors
    ///
    /// [`ReassemblyError`] for a block out of order, short with more to come, or past the limit.
    pub fn push(&mut self, block: Block, payload: &[u8]) -> Result<Option<Block>, ReassemblyError> {
        if block.offset() != self.body.len() {
            return Err(ReassemblyError::OutOfOrder {
                expected: self.body.len(),
                got: block.offset(),
            });
        }
        let size = block.size().bytes();
        if block.more() && payload.len() != size {
            return Err(ReassemblyError::ShortBlock {
                size,
                got: payload.len(),
            });
        }
        if self.body.len() + payload.len() > self.limit {
            return Err(ReassemblyError::TooLarge(self.limit));
        }
        self.body.extend_from_slice(payload);
        if !block.more() {
            return Ok(None);
        }
        let next = u32::try_from(self.body.len() >> (block.size().szx() + 4))
            .map_err(|_| ReassemblyError::TooLarge(self.limit))?;
        Block::new(next, false, block.size())
            .map(Some)
            .ok_or(ReassemblyError::TooLarge(self.limit))
    }

    /// The body received so far.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// A part of a body and the Block2 option that says which (RFC 7959 §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slice<'a> {
    /// The Block2 option of the response: none if the whole body fits one message and no block was asked for.
    pub block: Option<Block>,
    /// The bytes of the body.
    pub payload: &'a [u8],
}

/// A request for a block past the end of the body: a 4.00 Bad Request or 4.02 Bad Option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the block starts past the end of the body")]
pub struct OutOfRange;

/// The part of `body` for a response to a request with the Block2 option `requested`, or none; the blocks are
/// at most `max` (RFC 7959 §2.4, RFC 9953 §4.3).
///
/// The size is the smaller of the requested one and `max`; if that is not the requested one, the block number
/// is counted in it (RFC 7959 §2.3).
///
/// # Errors
///
/// [`OutOfRange`] if the block starts past the end of the body.
pub fn slice(
    body: &[u8],
    requested: Option<Block>,
    max: BlockSize,
) -> Result<Slice<'_>, OutOfRange> {
    let size = requested.map_or(max, |block| block.size().min(max));
    let start = requested.map_or(0, Block::offset);
    if requested.is_none() && body.len() <= size.bytes() {
        return Ok(Slice {
            block: None,
            payload: body,
        });
    }
    // A block at the end is empty, which only the first of an empty body may be.
    if start > body.len() || (start == body.len() && start != 0) {
        return Err(OutOfRange);
    }
    let end = body.len().min(start + size.bytes());
    let num = u32::try_from(start >> (size.szx() + 4)).map_err(|_| OutOfRange)?;
    Ok(Slice {
        block: Some(Block::new(num, end < body.len(), size).ok_or(OutOfRange)?),
        payload: &body[start..end],
    })
}
