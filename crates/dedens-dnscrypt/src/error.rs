//! The errors of keys, certificates, padding and packets.

use dedens_proto::{DecodeError, EncodeError};

/// The peer's public key is of low order: the X25519 result is all zero, whatever the secret key is
/// (draft "Negative Cases", case 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("public key of low order: the shared secret is all zero")]
pub struct LowOrderKey;

/// The 32 bytes of an Ed25519 seed were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Ed25519 seed refused")]
pub struct SigningKeyRejected;

/// A `<client-magic>` the draft forbids (draft "Certificates").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("client-magic is all 0xff, starts with seven NUL bytes or is the resume magic")]
pub struct InvalidClientMagic;

/// A certificate that cannot be read, or a TXT record that does not hold one (draft "Certificates").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CertificateError {
    /// Fewer bytes than the fixed fields of the certificate.
    #[error("certificate shorter than its fixed fields")]
    TooShort,
    /// The certificate does not start with `DNSC`.
    #[error("certificate magic is not DNSC")]
    WrongMagic,
    /// An `<es-version>` this crate does not implement; the rest of the certificate is not read, as its
    /// `<resolver-pk>` has a length only the system knows.
    #[error("unsupported es-version {0:#06x}")]
    UnsupportedSystem(u16),
    /// See [`InvalidClientMagic`].
    #[error(transparent)]
    ClientMagic(#[from] InvalidClientMagic),
    /// `<ts-start>` is not strictly earlier than `<ts-end>`.
    #[error("validity starts at or after its end")]
    EmptyValidity,
    /// The signature is not the provider's over the certificate.
    #[error("certificate signature does not verify")]
    BadSignature,
    /// The secret key does not belong to the certificate's `<resolver-pk>`.
    #[error("secret key is not the certificate's")]
    KeyMismatch,
}

/// Padding that is no ISO/IEC 7816-4 padding (draft "Padding For Client Queries Over UDP", "Negative Cases" case 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no 0x80 marker after the message, or other bytes after it than NUL")]
pub struct PaddingError;

/// A packet a resolver does not answer: it drops it without a reply (draft "Resolver Responses Over UDP", "Negative Cases").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum QueryError {
    /// Shorter than magic, key, nonce and tag.
    #[error("query packet shorter than its fixed fields")]
    Truncated,
    /// Longer than 4096 bytes.
    #[error("query packet longer than 4096 bytes")]
    TooLong,
    /// The `<client-magic>` is no certificate's.
    #[error("client-magic of no known certificate")]
    UnknownClientMagic,
    /// See [`LowOrderKey`].
    #[error(transparent)]
    LowOrderKey(#[from] LowOrderKey),
    /// The tag does not match: wrong key, or a packet changed on the way.
    #[error("query does not authenticate")]
    Authentication,
    /// See [`PaddingError`].
    #[error(transparent)]
    Padding(#[from] PaddingError),
}

/// A packet a client does not accept as the answer to its query (draft "Client Queries Over UDP", "Negative Cases" case 4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResponseError {
    /// Shorter than magic, nonce and tag.
    #[error("response packet shorter than its fixed fields")]
    Truncated,
    /// 4096 bytes or more.
    #[error("response packet of 4096 bytes or more")]
    TooLong,
    /// The packet does not start with the resolver magic.
    #[error("resolver magic missing")]
    WrongMagic,
    /// The first half of the nonce is not the query's.
    #[error("nonce is not the query's")]
    NonceMismatch,
    /// A response nonce of 12 NUL bytes: the query's ciphertext sent back as a response would pass for one.
    #[error("resolver nonce is all NUL")]
    ZeroResolverNonce,
    /// The tag does not match.
    #[error("response does not authenticate")]
    Authentication,
    /// See [`PaddingError`].
    #[error(transparent)]
    Padding(#[from] PaddingError),
    /// The plaintext is no DNS message.
    #[error("response is no DNS message: {0}")]
    Dns(#[from] DecodeError),
    /// The ID is not the query's.
    #[error("DNS ID is not the query's")]
    IdMismatch,
    /// The question is not the query's.
    #[error("question is not the query's")]
    QuestionMismatch,
}

/// A query that cannot be sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncryptQueryError {
    /// The query is no DNS message.
    #[error("query is no DNS message: {0}")]
    Dns(#[from] DecodeError),
    /// The query has no question, so no response can be matched to it.
    #[error("query has no question")]
    NoQuestion,
    /// The packet would be over 4096 bytes.
    #[error("query packet longer than 4096 bytes")]
    TooLong,
}

/// A response that cannot be sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncryptResponseError {
    /// The response is too large for the packet and is no DNS message that could be cut.
    #[error("response is no DNS message: {0}")]
    Dns(#[from] DecodeError),
    /// Not even the header, the question and the OPT record fit.
    #[error("no room for even the header and the question: {0}")]
    NoRoom(#[from] EncodeError),
}
