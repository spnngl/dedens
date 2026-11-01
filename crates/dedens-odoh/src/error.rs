//! The errors of the wire formats and of the exchange.

use crate::message::MessageType;

/// A structure that does not follow the TLS-style encoding of RFC 9230 §5 and §6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The input ends inside a field.
    #[error("input ends inside a field")]
    Truncated,
    /// Bytes follow the end of the structure.
    #[error("bytes follow the end of the structure")]
    TrailingBytes,
    /// A field has fewer bytes than its `<1..2^16-1>` bound allows.
    #[error("{0} is empty")]
    EmptyField(&'static str),
    /// A field has more bytes than its two-byte length can carry.
    #[error("{0} is longer than 65535 bytes")]
    FieldTooLong(&'static str),
    /// A message type other than query (1) and response (2).
    #[error("unknown message type {0}")]
    UnknownMessageType(u8),
    /// The padding of a plaintext holds a byte other than zero (RFC 9230 §6.1).
    #[error("padding is not all zeros")]
    NonZeroPadding,
    /// No config of a list is of version 1 with the suite of RFC 9230 §9 and a well-formed key.
    #[error("no usable config in the list")]
    NoUsableConfig,
}

/// A query or a response that cannot be encrypted or decrypted.
///
/// A target answers [`UnknownKey`](Self::UnknownKey) with HTTP 401 and any other failure of
/// [`decrypt_query`](crate::decrypt_query) with 400 (RFC 9230 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeError {
    /// The message does not parse, or its plaintext does not.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A query where a response is expected, or the reverse.
    #[error("message of type {found:?}, expected {expected:?}")]
    WrongType {
        /// The type the operation takes.
        expected: MessageType,
        /// The type the message carries.
        found: MessageType,
    },
    /// The key ID of a query names no key of the target (RFC 9230 §8 step 1).
    #[error("key ID names no key of this target")]
    UnknownKey,
    /// The key ID of a response, which carries the response nonce, is not 16 bytes (RFC 9230 §8 steps 6 and 9).
    #[error("response nonce of {0} bytes, expected 16")]
    ResponseNonceLength(usize),
    /// The key exchange of the client failed: the public key is a point of small order.
    #[error("encapsulation failed")]
    Encapsulation,
    /// The key exchange of the target failed: the encapsulated key is malformed or of small order.
    #[error("decapsulation failed")]
    Decapsulation,
    /// The ciphertext does not authenticate under the keys and the AAD.
    #[error("decryption failed")]
    Decrypt,
    /// The AEAD refused to encrypt.
    #[error("encryption failed")]
    Encrypt,
}
