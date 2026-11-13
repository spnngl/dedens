//! `DNSCrypt`, sans I/O: the certificates a resolver publishes, and the encryption of queries and responses with
//! them (draft-denis-dprive-dnscrypt, D97). Experimental, as the draft is.
//!
//! Both classical systems are here: XChaCha20-Poly1305 (`es-version` 2, the draft's) and XSalsa20-Poly1305 (1,
//! the one older resolvers also serve). The keys are X25519, the certificates are signed with Ed25519. Nothing
//! here sends a packet or reads a clock: callers hand in bytes, Unix seconds and a random source, so an exchange
//! is reproducible under test.
//!
//! - `certificate`: [`Certificate`], read from the TXT RDATA of `2.dnscrypt-cert.<zone>` and checked with the
//!   provider's key, and [`select`] for the one a client uses.
//! - `key`: [`SecretKey`], [`PublicKey`] and the [`SharedKey`] of the two.
//! - `client`: [`ClientSession::encrypt_query`] and [`QueryContext::decrypt_response`].
//! - `resolver`: [`ResolverKey::decrypt_query`] and [`ResponseContext::encrypt_response`].
//! - `system`: [`EncryptionSystem`] and the client's [`SystemPolicy`].
//! - `anonymized`: [`relay_query`], the prefix that sends a query through an Anonymized `DNSCrypt` relay (D100).
//! - `error`: the error of each step.
//! - `secretbox` and `padding`: the cipher, and the ISO/IEC 7816-4 padding with the lengths the draft suggests.
//!
//! Every item is at the crate's root: the modules are private.
//!
//! What a packet is carried in is not here: the two-byte length of TCP and the certificate's DNS query belong to
//! the transports.

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod anonymized;
mod certificate;
mod client;
mod error;
mod key;
mod padding;
mod resolver;
mod secretbox;
mod system;
#[cfg(test)]
mod tests;

pub use anonymized::{RELAY_MAGIC, RELAY_PREFIX_LEN, relay_query};
pub use certificate::{
    Certificate, CertificateBody, ClientMagic, ProviderKey, SigningKey, Validity, select,
};
pub use client::{ClientNonce, ClientSession, QueryContext, QueryPadding};
pub use error::{
    CertificateError, EncryptQueryError, EncryptResponseError, InvalidClientMagic, LowOrderKey,
    PaddingError, QueryError, ResponseError, SigningKeyRejected,
};
pub use key::{KEY_LEN, PublicKey, SecretKey, SharedKey};
pub use resolver::{Carrier, ResolverKey, ResponseContext};
pub use system::{EncryptionSystem, SystemPolicy};

/// Length of a `<client-magic>`.
pub const CLIENT_MAGIC_LEN: usize = 8;

/// Length of each half of a nonce: the client's `<client-nonce>` and the resolver's `<resolver-nonce>`.
pub const NONCE_HALF_LEN: usize = 12;

/// What a query packet adds to the padded DNS message: magic, client key, client nonce and tag.
pub const QUERY_OVERHEAD: usize = CLIENT_MAGIC_LEN + KEY_LEN + NONCE_HALF_LEN + secretbox::TAG_LEN;

/// What a response packet adds to the padded DNS message: magic, both nonces and tag.
pub const RESPONSE_OVERHEAD: usize = RESPONSE_MAGIC.len() + 2 * NONCE_HALF_LEN + secretbox::TAG_LEN;

/// The most bytes of a query packet; a response packet is shorter than that (draft "Protocol Components").
pub const MAX_PACKET_LEN: usize = 4096;

/// `<resolver-magic>`: `r6fnvWj8`, the first 8 bytes of every response.
pub const RESPONSE_MAGIC: [u8; 8] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
