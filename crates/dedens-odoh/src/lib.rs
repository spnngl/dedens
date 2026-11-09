//! Oblivious DNS over HTTPS (RFC 9230), sans-IO and experimental: target configurations and the encryption of
//! queries and responses (D78).
//!
//! - [`Configs`]: the public keys a target publishes (§5).
//! - [`Message`], [`MessagePlaintext`]: the wire formats (§6.1).
//! - [`encrypt_query`], [`decrypt_response`]: the client (§7).
//! - [`TargetKey`], [`decrypt_query`], [`encrypt_response`]: the target (§8).
//!
//! HTTP, proxies and key storage belong to the caller. Randomness comes in as an argument, a `rand_core`
//! `CryptoRng`, so the exchange is reproducible under test. The one cipher suite is the one RFC 9230 §9 requires
//! ([`suite`]).

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod client;
mod config;
mod error;
mod exchange;
mod kdf;
mod message;
mod target;
mod wire;

pub use client::{QueryContext, decrypt_response, encrypt_query};
pub use config::{ConfigContents, Configs, KEY_ID_LEN, PUBLIC_KEY_LEN, VERSION};
pub use error::{ExchangeError, WireError};
pub use message::{
    Message, MessagePlaintext, MessageType, QUERY_BLOCK, RESPONSE_BLOCK, query_padding,
    response_padding,
};
pub use target::{ResponseContext, TargetKey, decrypt_query, encrypt_response};

/// The `Content-Type` of the HTTP body of a query and of a response (RFC 9230 §4.1, §4.3).
pub const MEDIA_TYPE: &str = "application/oblivious-dns-message";

/// The cipher suite of RFC 9230 §9, RFC 9180 §7 identifiers included.
///
/// The types are those of the `hpke` crate; they are public so that tests can run RFC 9180's vectors
/// through the very suite the exchange uses.
pub mod suite {
    use hpke::Kem as _;
    use hpke::aead::Aead as _;
    use hpke::kdf::Kdf as _;

    /// DHKEM(X25519, HKDF-SHA256).
    pub type Kem = hpke::kem::X25519HkdfSha256;
    /// HKDF-SHA256.
    pub type Kdf = hpke::kdf::HkdfSha256;
    /// AES-128-GCM.
    pub type Aead = hpke::aead::AesGcm128;

    /// `kem_id` of [`Kem`], `0x0020`.
    pub const KEM_ID: u16 = Kem::KEM_ID;
    /// `kdf_id` of [`Kdf`], `0x0001`.
    pub const KDF_ID: u16 = Kdf::KDF_ID;
    /// `aead_id` of [`Aead`], `0x0001`.
    pub const AEAD_ID: u16 = Aead::AEAD_ID;
}
