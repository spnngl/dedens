//! The CoAP message: header, token, options and payload (RFC 7252 §3), read and written as bytes.

use std::fmt;

use super::block::{Block, BlockError};

/// The version of CoAP, the only one there is (RFC 7252 §3).
const VERSION: u8 = 1;
/// The byte before the payload (RFC 7252 §3).
const PAYLOAD_MARKER: u8 = 0xFF;
/// The longest token, in bytes (RFC 7252 §3).
const MAX_TOKEN: usize = 8;
/// The most options [`Message::parse`] reads in a message, 64 (D105): the RFC sets no limit, and a datagram of zeros
/// holds a thousand empty options, each an allocation. A `DoC` request has a dozen (Uri-Path segments, Content-Format,
/// Accept, Request-Tag, Block2, Uri-Query of a discovery).
pub const MAX_OPTIONS: usize = 64;

/// The type of a message: how it is delivered (RFC 7252 §3, §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    /// CON: sent again until acknowledged or reset (RFC 7252 §4.2).
    Confirmable,
    /// NON: sent once (RFC 7252 §4.3).
    NonConfirmable,
    /// ACK: acknowledges the CON of the same message ID, and may carry its response (RFC 7252 §4.2, §5.2.1).
    Acknowledgement,
    /// RST: tells that a message could not be processed (RFC 7252 §4.2, §4.3).
    Reset,
}

impl Type {
    const fn bits(self) -> u8 {
        match self {
            Self::Confirmable => 0,
            Self::NonConfirmable => 1,
            Self::Acknowledgement => 2,
            Self::Reset => 3,
        }
    }

    /// The type of two header bits; only those are looked at, so every value is a type.
    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::Confirmable,
            1 => Self::NonConfirmable,
            2 => Self::Acknowledgement,
            _ => Self::Reset,
        }
    }
}

/// The code of a message: a request method or a response code, as class and detail (RFC 7252 §3, §12.1).
///
/// Shown as `class.detail`, `2.05` for Content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Code(pub u8);

impl Code {
    /// 0.00: an empty message, a ping, an empty ACK or a RST (RFC 7252 §4.1).
    pub const EMPTY: Self = Self::new(0, 0);
    /// 0.01 GET (RFC 7252 §5.8.1).
    pub const GET: Self = Self::new(0, 1);
    /// 0.02 POST (RFC 7252 §5.8.2).
    pub const POST: Self = Self::new(0, 2);
    /// 0.03 PUT (RFC 7252 §5.8.3).
    pub const PUT: Self = Self::new(0, 3);
    /// 0.04 DELETE (RFC 7252 §5.8.4).
    pub const DELETE: Self = Self::new(0, 4);
    /// 0.05 FETCH (RFC 8132 §2).
    pub const FETCH: Self = Self::new(0, 5);
    /// 2.01 Created (RFC 7252 §5.9.1.1).
    pub const CREATED: Self = Self::new(2, 1);
    /// 2.02 Deleted (RFC 7252 §5.9.1.2).
    pub const DELETED: Self = Self::new(2, 2);
    /// 2.03 Valid (RFC 7252 §5.9.1.3).
    pub const VALID: Self = Self::new(2, 3);
    /// 2.04 Changed (RFC 7252 §5.9.1.4).
    pub const CHANGED: Self = Self::new(2, 4);
    /// 2.05 Content (RFC 7252 §5.9.1.5).
    pub const CONTENT: Self = Self::new(2, 5);
    /// 2.31 Continue: a block of a block-wise request was taken, more are due (RFC 7959 §2.9.1).
    pub const CONTINUE: Self = Self::new(2, 31);
    /// 4.00 Bad Request (RFC 7252 §5.9.2.1).
    pub const BAD_REQUEST: Self = Self::new(4, 0);
    /// 4.02 Bad Option (RFC 7252 §5.9.2.3).
    pub const BAD_OPTION: Self = Self::new(4, 2);
    /// 4.04 Not Found (RFC 7252 §5.9.2.5).
    pub const NOT_FOUND: Self = Self::new(4, 4);
    /// 4.05 Method Not Allowed (RFC 7252 §5.9.2.6).
    pub const METHOD_NOT_ALLOWED: Self = Self::new(4, 5);
    /// 4.06 Not Acceptable (RFC 7252 §5.9.2.7).
    pub const NOT_ACCEPTABLE: Self = Self::new(4, 6);
    /// 4.08 Request Entity Incomplete (RFC 7959 §2.9.2).
    pub const REQUEST_ENTITY_INCOMPLETE: Self = Self::new(4, 8);
    /// 4.12 Precondition Failed: an If-Match or If-None-Match condition is not fulfilled (RFC 7252 §5.9.2.8).
    pub const PRECONDITION_FAILED: Self = Self::new(4, 12);
    /// 4.13 Request Entity Too Large (RFC 7252 §5.9.2.9, RFC 7959 §2.9.3).
    pub const REQUEST_ENTITY_TOO_LARGE: Self = Self::new(4, 13);
    /// 4.15 Unsupported Content-Format (RFC 7252 §5.9.2.10).
    pub const UNSUPPORTED_CONTENT_FORMAT: Self = Self::new(4, 15);
    /// 5.00 Internal Server Error (RFC 7252 §5.9.3.1).
    pub const INTERNAL_SERVER_ERROR: Self = Self::new(5, 0);
    /// 5.03 Service Unavailable (RFC 7252 §5.9.3.4).
    pub const SERVICE_UNAVAILABLE: Self = Self::new(5, 3);
    /// 5.05 Proxying Not Supported: a request with a Proxy-Uri or Proxy-Scheme the server does not act on (RFC 7252
    /// §5.9.3.6).
    pub const PROXYING_NOT_SUPPORTED: Self = Self::new(5, 5);

    /// The code of `class` (0 to 7) and `detail` (0 to 31); the bits above those are dropped.
    #[must_use]
    pub const fn new(class: u8, detail: u8) -> Self {
        Self(((class & 0b111) << 5) | (detail & 0b1_1111))
    }

    /// The class: 0 for a request, 2 success, 4 client error, 5 server error.
    #[must_use]
    pub const fn class(self) -> u8 {
        self.0 >> 5
    }

    /// The detail within the class.
    #[must_use]
    pub const fn detail(self) -> u8 {
        self.0 & 0b1_1111
    }

    /// Whether this is a request method: class 0, but not 0.00.
    #[must_use]
    pub const fn is_request(self) -> bool {
        self.class() == 0 && self.detail() != 0
    }

    /// Whether this is a response code: class 2, 4 or 5 (classes 1, 3, 6 and 7 are reserved, RFC 7252 §12.1).
    #[must_use]
    pub const fn is_response(self) -> bool {
        matches!(self.class(), 2 | 4 | 5)
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.class(), self.detail())
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code({self})")
    }
}

/// A token: 0 to 8 opaque bytes tying a response to its request (RFC 7252 §5.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token {
    len: u8,
    /// Zero after `len`, so that equal tokens are equal bytes.
    bytes: [u8; MAX_TOKEN],
}

/// A token longer than 8 bytes (RFC 7252 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a token is at most 8 bytes, not {0}")]
pub struct TokenTooLong(pub usize);

impl Token {
    /// The empty token.
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; MAX_TOKEN],
    };

    /// The token of `bytes`.
    ///
    /// # Errors
    ///
    /// [`TokenTooLong`] if there are more than 8 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, TokenTooLong> {
        let len = u8::try_from(bytes.len())
            .ok()
            .filter(|&len| usize::from(len) <= MAX_TOKEN)
            .ok_or(TokenTooLong(bytes.len()))?;
        let mut token = Self::EMPTY;
        token.len = len;
        token.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(token)
    }

    /// The bytes of the token.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(")?;
        for byte in self.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// The number of an option (RFC 7252 §5.4.6, §5.10).
///
/// The registered options of RFC 7252, RFC 7959, RFC 8132 and Request-Tag of RFC 9175 have a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OptionNumber(pub u16);

impl OptionNumber {
    /// If-Match, opaque, repeatable (RFC 7252 §5.10.8.1).
    pub const IF_MATCH: Self = Self(1);
    /// Uri-Host, string (RFC 7252 §5.10.1).
    pub const URI_HOST: Self = Self(3);
    /// `ETag`, opaque of 1 to 8 bytes, repeatable in a request (RFC 7252 §5.10.6).
    pub const ETAG: Self = Self(4);
    /// If-None-Match, empty (RFC 7252 §5.10.8.2).
    pub const IF_NONE_MATCH: Self = Self(5);
    /// Uri-Port, uint of up to 2 bytes (RFC 7252 §5.10.1).
    pub const URI_PORT: Self = Self(7);
    /// Location-Path, string, repeatable (RFC 7252 §5.10.7).
    pub const LOCATION_PATH: Self = Self(8);
    /// Uri-Path, string, repeatable: one path segment each (RFC 7252 §5.10.1).
    pub const URI_PATH: Self = Self(11);
    /// Content-Format, uint of up to 2 bytes (RFC 7252 §5.10.3).
    pub const CONTENT_FORMAT: Self = Self(12);
    /// Max-Age, uint of up to 4 bytes, 60 seconds by default (RFC 7252 §5.10.5).
    pub const MAX_AGE: Self = Self(14);
    /// Uri-Query, string, repeatable (RFC 7252 §5.10.1).
    pub const URI_QUERY: Self = Self(15);
    /// Accept, uint of up to 2 bytes (RFC 7252 §5.10.4).
    pub const ACCEPT: Self = Self(17);
    /// Location-Query, string, repeatable (RFC 7252 §5.10.7).
    pub const LOCATION_QUERY: Self = Self(20);
    /// Block2, the block of a response body (RFC 7959 §2.1).
    pub const BLOCK2: Self = Self(23);
    /// Block1, the block of a request body (RFC 7959 §2.1).
    pub const BLOCK1: Self = Self(27);
    /// Size2, the size of a response body (RFC 7959 §4).
    pub const SIZE2: Self = Self(28);
    /// Proxy-Uri, string (RFC 7252 §5.10.2).
    pub const PROXY_URI: Self = Self(35);
    /// Proxy-Scheme, string (RFC 7252 §5.10.2).
    pub const PROXY_SCHEME: Self = Self(39);
    /// Size1, the size of a request body (RFC 7959 §4).
    pub const SIZE1: Self = Self(60);
    /// Request-Tag, opaque of up to 8 bytes, repeatable: what the blocks of one request share (RFC 9175 §3.2).
    pub const REQUEST_TAG: Self = Self(292);

    /// Whether a recipient that does not know the option must reject the message (RFC 7252 §5.4.1).
    #[must_use]
    pub const fn is_critical(self) -> bool {
        self.0 & 1 == 1
    }

    /// Whether a proxy that does not know the option must not forward the message (RFC 7252 §5.4.2).
    #[must_use]
    pub const fn is_unsafe(self) -> bool {
        self.0 & 2 == 2
    }

    /// Whether the option is left out of the cache key (RFC 7252 §5.4.2).
    #[must_use]
    pub const fn is_no_cache_key(self) -> bool {
        self.0 & 0x1e == 0x1c
    }

    /// Whether this is one of the options with a constant here.
    #[must_use]
    pub const fn is_known(self) -> bool {
        matches!(
            self.0,
            1 | 3 | 4 | 5 | 7 | 8 | 11 | 12 | 14 | 15 | 17 | 20 | 23 | 27 | 28 | 35 | 39 | 60 | 292
        )
    }
}

/// The options of a message, in the order they are written: by number, those of a number in the order added
/// (RFC 7252 §3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options(Vec<(OptionNumber, Vec<u8>)>);

impl Options {
    /// The content format of a DNS message, `application/dns-message` (RFC 9953 §4.1).
    pub const DNS_MESSAGE: u16 = 553;

    /// The content format of links, `application/link-format` (RFC 6690 §7.3; RFC 7252 §12.3).
    pub const LINK_FORMAT: u16 = 40;

    /// No options.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Adds an option after those of its number.
    pub fn insert(&mut self, number: OptionNumber, value: impl Into<Vec<u8>>) {
        let at = self.0.partition_point(|(n, _)| *n <= number);
        self.0.insert(at, (number, value.into()));
    }

    /// Makes `value` the only value of `number`.
    pub fn set(&mut self, number: OptionNumber, value: impl Into<Vec<u8>>) {
        self.remove(number);
        self.insert(number, value);
    }

    /// Drops the options of `number`.
    pub fn remove(&mut self, number: OptionNumber) {
        self.0.retain(|(n, _)| *n != number);
    }

    /// The options in order, as number and value.
    pub fn iter(&self) -> impl Iterator<Item = (OptionNumber, &[u8])> {
        self.0
            .iter()
            .map(|(number, value)| (*number, value.as_slice()))
    }

    /// The values of `number`, in order.
    pub fn get_all(&self, number: OptionNumber) -> impl Iterator<Item = &[u8]> {
        self.iter()
            .filter(move |(n, _)| *n == number)
            .map(|(_, value)| value)
    }

    /// The first value of `number`.
    #[must_use]
    pub fn get(&self, number: OptionNumber) -> Option<&[u8]> {
        self.get_all(number).next()
    }

    /// The value of `number` as an unsigned integer of at most `max_len` bytes; none if absent or longer
    /// (RFC 7252 §3.2).
    fn uint(&self, number: OptionNumber, max_len: usize) -> Option<u32> {
        let value = self.get(number)?;
        (value.len() <= max_len).then(|| value.iter().fold(0, |sum, &b| (sum << 8) | u32::from(b)))
    }

    fn set_uint(&mut self, number: OptionNumber, value: u32) {
        self.set(number, encode_uint(value));
    }

    /// The segments of the path, from the Uri-Path options (RFC 7252 §5.10.1).
    pub fn uri_path(&self) -> impl Iterator<Item = &[u8]> {
        self.get_all(OptionNumber::URI_PATH)
    }

    /// Adds a Uri-Path option for each of `segments`.
    pub fn push_uri_path<'a>(&mut self, segments: impl IntoIterator<Item = &'a [u8]>) {
        for segment in segments {
            self.insert(OptionNumber::URI_PATH, segment);
        }
    }

    /// The Content-Format, if there is one of up to 2 bytes.
    #[must_use]
    pub fn content_format(&self) -> Option<u16> {
        self.uint(OptionNumber::CONTENT_FORMAT, 2)
            .and_then(|v| u16::try_from(v).ok())
    }

    /// Sets the Content-Format.
    pub fn set_content_format(&mut self, format: u16) {
        self.set_uint(OptionNumber::CONTENT_FORMAT, u32::from(format));
    }

    /// The Accept, if there is one of up to 2 bytes.
    #[must_use]
    pub fn accept(&self) -> Option<u16> {
        self.uint(OptionNumber::ACCEPT, 2)
            .and_then(|v| u16::try_from(v).ok())
    }

    /// Sets the Accept.
    pub fn set_accept(&mut self, format: u16) {
        self.set_uint(OptionNumber::ACCEPT, u32::from(format));
    }

    /// The Max-Age in seconds: 60 without the option (RFC 7252 §5.10.5).
    #[must_use]
    pub fn max_age(&self) -> u32 {
        self.uint(OptionNumber::MAX_AGE, 4).unwrap_or(60)
    }

    /// Sets the Max-Age in seconds.
    pub fn set_max_age(&mut self, seconds: u32) {
        self.set_uint(OptionNumber::MAX_AGE, seconds);
    }

    /// The Size1: the size of the request body, or the one a server accepts (RFC 7252 §5.10.9, RFC 7959 §4).
    #[must_use]
    pub fn size1(&self) -> Option<u32> {
        self.uint(OptionNumber::SIZE1, 4)
    }

    /// Sets the Size1.
    pub fn set_size1(&mut self, size: u32) {
        self.set_uint(OptionNumber::SIZE1, size);
    }

    /// The Size2: the size of the response body (RFC 7959 §4).
    #[must_use]
    pub fn size2(&self) -> Option<u32> {
        self.uint(OptionNumber::SIZE2, 4)
    }

    /// Sets the Size2.
    pub fn set_size2(&mut self, size: u32) {
        self.set_uint(OptionNumber::SIZE2, size);
    }

    /// The first `ETag` (RFC 7252 §5.10.6).
    #[must_use]
    pub fn etag(&self) -> Option<&[u8]> {
        self.get(OptionNumber::ETAG)
    }

    /// The Block1 option (RFC 7959 §2.1).
    ///
    /// # Errors
    ///
    /// [`BlockError`] if it does not hold a block.
    pub fn block1(&self) -> Result<Option<Block>, BlockError> {
        self.get(OptionNumber::BLOCK1)
            .map(Block::from_value)
            .transpose()
    }

    /// The Block2 option (RFC 7959 §2.1).
    ///
    /// # Errors
    ///
    /// [`BlockError`] if it does not hold a block.
    pub fn block2(&self) -> Result<Option<Block>, BlockError> {
        self.get(OptionNumber::BLOCK2)
            .map(Block::from_value)
            .transpose()
    }

    /// The value of the first Request-Tag option, empty if there is none (RFC 9175 §3.2).
    #[must_use]
    pub fn request_tag(&self) -> &[u8] {
        self.get(OptionNumber::REQUEST_TAG).unwrap_or_default()
    }

    /// Sets the Block1 option.
    pub fn set_block1(&mut self, block: Block) {
        self.set(OptionNumber::BLOCK1, block.to_value());
    }

    /// Sets the Block2 option.
    pub fn set_block2(&mut self, block: Block) {
        self.set(OptionNumber::BLOCK2, block.to_value());
    }
}

/// An unsigned integer option value: no leading zero bytes, none for 0 (RFC 7252 §3.2).
pub(super) fn encode_uint(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    bytes[zeros..].to_vec()
}

/// A CoAP message (RFC 7252 §3).
///
/// Read with [`Message::parse`] and written with [`Message::to_vec`]. The options are kept as received, those
/// the codec has no use for too; [`Message::unknown_critical`] tells which a recipient must reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// How the message is delivered.
    pub kind: Type,
    /// The method or response code.
    pub code: Code,
    /// The message ID: matches an ACK or RST to a CON, and finds duplicates (RFC 7252 §4.4, §4.5).
    pub id: u16,
    /// Ties a response to its request.
    pub token: Token,
    /// The options.
    pub options: Options,
    /// The payload, empty if the message has none.
    pub payload: Vec<u8>,
}

/// Why bytes are not a CoAP message (RFC 7252 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Fewer bytes than the header, token, or an option announce.
    #[error("the message ends before its header, token or an option does")]
    Truncated,
    /// Another version than 1: such a message is ignored without a reply (RFC 7252 §3).
    #[error("CoAP version {0}, not 1")]
    Version(u8),
    /// A token length of 9 to 15 (RFC 7252 §3).
    #[error("a token length of {0}, over 8")]
    TokenLength(u8),
    /// A 0.00 message with a token, options or a payload (RFC 7252 §4.1).
    #[error("an empty message has no token, option or payload")]
    EmptyWithContent,
    /// An option delta or length nibble of 15 (RFC 7252 §3.1).
    #[error("an option delta or length of 15 is reserved")]
    ReservedNibble,
    /// A payload marker with no payload after it (RFC 7252 §3).
    #[error("a payload marker with an empty payload")]
    EmptyPayload,
    /// Option numbers adding up past 65535.
    #[error("an option number over 65535")]
    OptionNumber,
    /// More than [`MAX_OPTIONS`] options.
    #[error("more than {MAX_OPTIONS} options")]
    TooManyOptions,
}

/// Why a message cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WriteError {
    /// A 0.00 message with a token, options or a payload (RFC 7252 §4.1).
    #[error("an empty message has no token, option or payload")]
    EmptyWithContent,
    /// An option value of more than 65804 bytes, the most a length can say (RFC 7252 §3.1).
    #[error("an option value is too long")]
    OptionTooLong,
}

impl Message {
    /// An empty message: an empty ACK, a RST or a ping (RFC 7252 §4.1).
    #[must_use]
    pub const fn empty(kind: Type, id: u16) -> Self {
        Self {
            kind,
            code: Code::EMPTY,
            id,
            token: Token::EMPTY,
            options: Options::new(),
            payload: Vec::new(),
        }
    }

    /// The ACK of the CON `request` that carries a response, with the ID and token of the request
    /// (RFC 7252 §5.2.1).
    #[must_use]
    pub fn piggybacked(request: &Self, code: Code) -> Self {
        Self {
            kind: Type::Acknowledgement,
            code,
            id: request.id,
            token: request.token,
            options: Options::new(),
            payload: Vec::new(),
        }
    }

    /// The RST that rejects `bytes`, a datagram [`Message::parse`] refused: one for a CON message of version 1 with a
    /// message ID to echo (RFC 7252 §4.2). None for the rest, which is dropped: NON (§4.3, a RST would be allowed,
    /// not needed), ACK and RST (§4.2), another version (§3), and under 4 bytes.
    #[must_use]
    pub fn reject(bytes: &[u8]) -> Option<Self> {
        let [first, _, id_hi, id_lo, ..] = bytes else {
            return None;
        };
        (first >> 6 == VERSION && Type::from_bits(first >> 4) == Type::Confirmable)
            .then(|| Self::empty(Type::Reset, u16::from_be_bytes([*id_hi, *id_lo])))
    }

    /// The options a recipient must reject the message for: critical, and not among those with a constant
    /// in [`OptionNumber`] (RFC 7252 §5.4.1). The reply is 4.02 to a CON request, a RST to a CON response or
    /// a NON.
    pub fn unknown_critical(&self) -> impl Iterator<Item = OptionNumber> {
        self.options
            .iter()
            .map(|(number, _)| number)
            .filter(|number| number.is_critical() && !number.is_known())
    }

    /// Reads a message.
    ///
    /// # Errors
    ///
    /// [`ParseError`] for what RFC 7252 §3 calls a message format error. The reply to a CON with one is the RST of
    /// [`Message::reject`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let [first, code, id_hi, id_lo, rest @ ..] = bytes else {
            return Err(ParseError::Truncated);
        };
        let version = first >> 6;
        if version != VERSION {
            return Err(ParseError::Version(version));
        }
        let token_len = first & 0x0F;
        if usize::from(token_len) > MAX_TOKEN {
            return Err(ParseError::TokenLength(token_len));
        }
        let code = Code(*code);
        let kind = Type::from_bits(first >> 4);
        let id = u16::from_be_bytes([*id_hi, *id_lo]);
        if code == Code::EMPTY {
            if token_len != 0 || !rest.is_empty() {
                return Err(ParseError::EmptyWithContent);
            }
            return Ok(Self::empty(kind, id));
        }
        let (token, mut rest) = rest
            .split_at_checked(usize::from(token_len))
            .ok_or(ParseError::Truncated)?;
        let token = Token::new(token).map_err(|_| ParseError::TokenLength(token_len))?;

        let mut options = Options::new();
        let mut number = 0u32;
        let mut payload = Vec::new();
        while let Some((&head, tail)) = rest.split_first() {
            if head == PAYLOAD_MARKER {
                if tail.is_empty() {
                    return Err(ParseError::EmptyPayload);
                }
                payload = tail.to_vec();
                break;
            }
            let (delta, tail) = read_nibble(head >> 4, tail)?;
            let (len, tail) = read_nibble(head & 0x0F, tail)?;
            number = number.checked_add(delta).ok_or(ParseError::OptionNumber)?;
            let number = u16::try_from(number).map_err(|_| ParseError::OptionNumber)?;
            let len = usize::try_from(len).map_err(|_| ParseError::Truncated)?;
            let (value, tail) = tail.split_at_checked(len).ok_or(ParseError::Truncated)?;
            if options.0.len() == MAX_OPTIONS {
                return Err(ParseError::TooManyOptions);
            }
            // Numbers never go down, so this is the end of the order.
            options.0.push((OptionNumber(number), value.to_vec()));
            rest = tail;
        }
        Ok(Self {
            kind,
            code,
            id,
            token,
            options,
            payload,
        })
    }

    /// Writes the message.
    ///
    /// # Errors
    ///
    /// [`WriteError`] if an empty message holds something, or an option value is too long.
    pub fn to_vec(&self) -> Result<Vec<u8>, WriteError> {
        let has_content = !self.token.as_bytes().is_empty()
            || !self.options.0.is_empty()
            || !self.payload.is_empty();
        if self.code == Code::EMPTY && has_content {
            return Err(WriteError::EmptyWithContent);
        }
        let mut out = Vec::with_capacity(
            4 + self.token.as_bytes().len()
                + self.payload.len()
                + 1
                + self
                    .options
                    .0
                    .iter()
                    .map(|(_, v)| v.len() + 3)
                    .sum::<usize>(),
        );
        out.push((VERSION << 6) | (self.kind.bits() << 4) | self.token.len);
        out.push(self.code.0);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(self.token.as_bytes());
        let mut previous = 0u16;
        for (number, value) in &self.options.0 {
            let len = u32::try_from(value.len()).map_err(|_| WriteError::OptionTooLong)?;
            let (delta_nibble, delta_ext) = write_nibble(u32::from(number.0 - previous))?;
            let (len_nibble, len_ext) = write_nibble(len)?;
            out.push((delta_nibble << 4) | len_nibble);
            out.extend_from_slice(delta_ext.as_slice());
            out.extend_from_slice(len_ext.as_slice());
            out.extend_from_slice(value);
            previous = number.0;
        }
        if !self.payload.is_empty() {
            out.push(PAYLOAD_MARKER);
            out.extend_from_slice(&self.payload);
        }
        Ok(out)
    }
}

/// The delta or length a nibble and its extension bytes say (RFC 7252 §3.1), and what follows them.
fn read_nibble(nibble: u8, rest: &[u8]) -> Result<(u32, &[u8]), ParseError> {
    match (nibble, rest) {
        (0..=12, _) => Ok((u32::from(nibble), rest)),
        (13, [byte, rest @ ..]) => Ok((u32::from(*byte) + 13, rest)),
        (14, [hi, lo, rest @ ..]) => Ok((u32::from(u16::from_be_bytes([*hi, *lo])) + 269, rest)),
        (13 | 14, _) => Err(ParseError::Truncated),
        _ => Err(ParseError::ReservedNibble),
    }
}

/// The extension bytes: at most 2.
struct Extension {
    bytes: [u8; 2],
    len: usize,
}

impl Extension {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The nibble that says `value`, the shortest way, and its extension bytes (RFC 7252 §3.1).
fn write_nibble(value: u32) -> Result<(u8, Extension), WriteError> {
    if let Ok(nibble @ 0..=12) = u8::try_from(value) {
        return Ok((
            nibble,
            Extension {
                bytes: [0; 2],
                len: 0,
            },
        ));
    }
    if let Ok(byte) = u8::try_from(value - 13) {
        return Ok((
            13,
            Extension {
                bytes: [byte, 0],
                len: 1,
            },
        ));
    }
    let extended = u16::try_from(value - 269).map_err(|_| WriteError::OptionTooLong)?;
    Ok((
        14,
        Extension {
            bytes: extended.to_be_bytes(),
            len: 2,
        },
    ))
}
