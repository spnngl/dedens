//! `DNSCrypt`, sans I/O: the certificates a resolver publishes, and the encryption of queries and responses with
//! them (draft-denis-dprive-dnscrypt, D97). Experimental, as the draft is.
//!
//! Both classical systems are here: XChaCha20-Poly1305 (`es-version` 2, the draft's) and XSalsa20-Poly1305 (1,
//! the one older resolvers also serve), and `PQDNSCrypt`'s X-Wing (3, D101). The classical keys are X25519, the
//! certificates are signed with Ed25519. Nothing
//! here sends a packet or reads a clock: callers hand in bytes, Unix seconds and a random source, so an exchange
//! is reproducible under test.
//!
//! - `certificate`: [`Certificate`], read from the TXT RDATA of `2.dnscrypt-cert.<zone>` and checked with the
//!   provider's key, and [`select`] for the one a client uses.
//! - `key`: [`SecretKey`], [`PublicKey`] and the [`SharedKey`] of the two.
//! - `client`: [`ClientSession::encrypt_query`] and [`QueryContext::decrypt_response`].
//! - `resolver`: [`ResolverKey::decrypt_query`] and [`ResponseContext::encrypt_response`].
//! - `system`: [`EncryptionSystem`] and the client's [`SystemPolicy`].
//! - `xwing`, `pq` and `ticket`: the X-Wing keys, `PQDNSCrypt`'s key schedule and control field, and the resumption
//!   tickets a resolver issues and opens ([`TicketKeys`]); the client's side of them is [`Resumption`].
//! - `error`: the error of each step.
//! - `secretbox` and `padding`: the cipher, and the ISO/IEC 7816-4 padding with the lengths the draft suggests.
//!
//! Every item is at the crate's root: the modules are private.
//!
//! What a packet is carried in is not here: the two-byte length of TCP, the relay prefix of Anonymized `DNSCrypt`
//! and the certificate's DNS query belong to the transports.

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod certificate;
mod client;
mod error;
mod key;
mod padding;
mod pq;
mod resolver;
mod secretbox;
mod system;
#[cfg(test)]
mod tests;
mod ticket;
mod xwing;

pub use certificate::{
    Certificate, CertificateBody, ClientMagic, ProviderKey, ResolverPublicKey, SigningKey,
    Validity, select,
};
pub use client::{ClientNonce, ClientSession, Opened, QueryContext, QueryPadding, Resumption};
pub use error::{
    CertificateError, ControlError, EncryptQueryError, EncryptResponseError, InvalidClientMagic,
    InvalidXWingKey, LowOrderKey, PaddingError, QueryError, ResponseError, SessionError,
    SigningKeyRejected,
};
pub use key::{KEY_LEN, PublicKey, SecretKey, SharedKey};
pub use pq::{RESUME_MAGIC, TicketOffer};
pub use resolver::{Carrier, ResolverKey, ResolverSecret, ResponseContext};
pub use system::{EncryptionSystem, SystemPolicy};
pub use ticket::{ResumedQuery, Ticket, TicketKey, TicketKeys};
pub use xwing::{XWING_CIPHERTEXT_LEN, XWING_PUBLIC_KEY_LEN, XWingPublicKey, XWingSecretKey};

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
