//! `ObliviousDoHMessage` and `ObliviousDoHMessagePlaintext` (RFC 9230 §6.1), and the padding of §11.

use crate::error::WireError;
use crate::wire::{Field, Reader};

/// The `message_type` of a [`Message`] (RFC 9230 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// A query, `0x01`.
    Query,
    /// A response, `0x02`.
    Response,
}

impl MessageType {
    /// The `message_type` byte.
    pub(crate) const fn byte(self) -> u8 {
        match self {
            Self::Query => 1,
            Self::Response => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, WireError> {
        match byte {
            1 => Ok(Self::Query),
            2 => Ok(Self::Response),
            other => Err(WireError::UnknownMessageType(other)),
        }
    }
}

/// An encrypted query or response as it travels between client and target (RFC 9230 §6.1).
///
/// ```text
/// struct {
///    uint8  message_type;
///    opaque key_id<0..2^16-1>;
///    opaque encrypted_message<1..2^16-1>;
/// } ObliviousDoHMessage;
/// ```
///
/// In a response, `key_id` carries the response nonce (§8 step 9).
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "the field names of RFC 9230 §6.1"
)]
pub struct Message {
    message_type: MessageType,
    key_id: Field,
    encrypted_message: Field,
}

impl Message {
    /// A message of the given parts.
    ///
    /// # Errors
    ///
    /// [`WireError::FieldTooLong`] when `key_id` or `encrypted_message` exceeds 65535 bytes,
    /// [`WireError::EmptyField`] when `encrypted_message` is empty.
    pub fn new(
        message_type: MessageType,
        key_id: Vec<u8>,
        encrypted_message: Vec<u8>,
    ) -> Result<Self, WireError> {
        Ok(Self {
            message_type,
            key_id: Field::new("key_id", key_id, 0)?,
            encrypted_message: Field::new("encrypted_message", encrypted_message, 1)?,
        })
    }

    /// Reads a message, as the body of an HTTP request or response carries it (RFC 9230 §4.1, §4.3).
    ///
    /// # Errors
    ///
    /// A [`WireError`] when the input is truncated, has bytes after the message, an unknown type or an
    /// empty `encrypted_message`.
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let message_type = MessageType::from_byte(reader.u8()?)?;
        let key_id = reader.vec16()?.to_vec();
        let encrypted_message = reader.vec16()?.to_vec();
        reader.finish()?;
        Self::new(message_type, key_id, encrypted_message)
    }

    /// The bytes of the message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.message_type.byte());
        self.key_id.put(&mut out);
        self.encrypted_message.put(&mut out);
        out
    }

    /// Query or response.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// The identifier of the target's key (query), or the response nonce (response).
    #[must_use]
    pub fn key_id(&self) -> &[u8] {
        self.key_id.as_slice()
    }

    /// The HPKE encapsulated key and ciphertext (query), or the ciphertext (response).
    #[must_use]
    pub fn encrypted_message(&self) -> &[u8] {
        self.encrypted_message.as_slice()
    }
}

/// The plaintext of a query or response: a DNS message and zero padding (RFC 9230 §6.1).
///
/// ```text
/// struct {
///    opaque dns_message<1..2^16-1>;
///    opaque padding<0..2^16-1>;
/// } ObliviousDoHMessagePlaintext;
/// ```
///
/// The padding is its length alone, so a padding that is not all zeros cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePlaintext {
    dns_message: Field,
    padding: u16,
}

impl MessagePlaintext {
    /// A plaintext of `dns_message` followed by `padding` zero bytes.
    ///
    /// # Errors
    ///
    /// [`WireError::EmptyField`] for an empty message, [`WireError::FieldTooLong`] when the message or
    /// the padding exceeds 65535 bytes.
    pub fn new(dns_message: Vec<u8>, padding: usize) -> Result<Self, WireError> {
        Ok(Self {
            dns_message: Field::new("dns_message", dns_message, 1)?,
            padding: u16::try_from(padding).map_err(|_| WireError::FieldTooLong("padding"))?,
        })
    }

    /// Reads a plaintext.
    ///
    /// # Errors
    ///
    /// A [`WireError`] when the input is truncated, has bytes after the plaintext, an empty message, or
    /// padding that is not all zeros (RFC 9230 §7 and §8 step 4 refuse it).
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes);
        let dns_message = reader.vec16()?.to_vec();
        let padding = reader.vec16()?;
        reader.finish()?;
        if padding.iter().any(|&byte| byte != 0) {
            return Err(WireError::NonZeroPadding);
        }
        Self::new(dns_message, padding.len())
    }

    /// The bytes of the plaintext.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.dns_message.put(&mut out);
        out.extend_from_slice(&self.padding.to_be_bytes());
        out.resize(out.len() + usize::from(self.padding), 0);
        out
    }

    /// The DNS message.
    #[must_use]
    pub fn dns_message(&self) -> &[u8] {
        self.dns_message.as_slice()
    }

    /// The DNS message, taken out.
    #[must_use]
    pub fn into_dns_message(self) -> Vec<u8> {
        self.dns_message.into_vec()
    }

    /// The number of padding bytes.
    #[must_use]
    pub fn padding(&self) -> usize {
        usize::from(self.padding)
    }
}

/// The block a query is padded to (RFC 8467 §4.1).
pub const QUERY_BLOCK: usize = 128;

/// The block a response is padded to (RFC 8467 §4.1).
pub const RESPONSE_BLOCK: usize = 468;

/// The padding that brings a DNS query of `dns_len` bytes to a multiple of [`QUERY_BLOCK`].
///
/// RFC 9230 §11 prescribes no length and tells implementations to follow RFC 8467, which pads queries to
/// 128 bytes. The block counts the DNS message alone: the plaintext adds 4 bytes of lengths and the
/// ciphertext a constant 48, so every query of a block has one size on the wire.
#[must_use]
pub const fn query_padding(dns_len: usize) -> usize {
    block_padding(dns_len, QUERY_BLOCK)
}

/// The padding that brings a DNS response of `dns_len` bytes to a multiple of [`RESPONSE_BLOCK`], as
/// [`query_padding`] does for queries (RFC 8467 §4.1 pads responses to 468 bytes).
#[must_use]
pub const fn response_padding(dns_len: usize) -> usize {
    block_padding(dns_len, RESPONSE_BLOCK)
}

const fn block_padding(len: usize, block: usize) -> usize {
    (block - len % block) % block
}

/// Kani proofs of the framing (D145), for every input of up to 8 bytes.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Any bytes up to 8 parse as a message without panicking, and a message they hold encodes back to them
    /// (RFC 9230 §6.1).
    #[kani::proof]
    #[kani::unwind(9)]
    fn a_parsed_message_encodes_back() {
        let bytes: [u8; 8] = kani::any();
        let len = kani::any_where(|&len: &usize| len <= bytes.len());
        if let Ok(message) = Message::parse(&bytes[..len]) {
            assert_eq!(message.encode(), &bytes[..len]);
        }
    }

    /// Any bytes up to 8 parse as a plaintext without panicking, and a plaintext they hold encodes back to them:
    /// its padding is zeros (RFC 9230 §6.1).
    #[kani::proof]
    #[kani::unwind(9)]
    fn a_parsed_plaintext_encodes_back() {
        let bytes: [u8; 8] = kani::any();
        let len = kani::any_where(|&len: &usize| len <= bytes.len());
        if let Ok(plaintext) = MessagePlaintext::parse(&bytes[..len]) {
            assert_eq!(plaintext.encode(), &bytes[..len]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_rounds_up_to_the_block() {
        assert_eq!(query_padding(1), 127);
        assert_eq!(query_padding(127), 1);
        assert_eq!(query_padding(128), 0);
        assert_eq!(query_padding(129), 127);
        assert_eq!(response_padding(468), 0);
        assert_eq!(response_padding(469), 467);
        assert_eq!((response_padding(100) + 100) % RESPONSE_BLOCK, 0);
    }

    #[test]
    fn message_round_trips() {
        let message = Message::new(MessageType::Response, vec![1; 16], vec![2, 3]).expect("fits");
        assert_eq!(
            message.encode(),
            [&[2, 0, 16][..], &[1; 16], &[0, 2, 2, 3]].concat()
        );
        assert_eq!(Message::parse(&message.encode()), Ok(message));
    }

    #[test]
    fn plaintext_round_trips() {
        let plaintext = MessagePlaintext::new(vec![7, 8], 3).expect("fits");
        assert_eq!(plaintext.encode(), [0, 2, 7, 8, 0, 3, 0, 0, 0]);
        assert_eq!(MessagePlaintext::parse(&plaintext.encode()), Ok(plaintext));
    }
}
