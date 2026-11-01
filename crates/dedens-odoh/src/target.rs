//! The target side of RFC 9230 §8: hold a key, decrypt queries, encrypt responses.

use hpke::rand_core::CryptoRng;
use hpke::{Deserializable as _, Kem as _, OpModeR, Serializable as _};
use zeroize::Zeroizing;

use crate::config::{ObliviousDoHConfigContents, PUBLIC_KEY_LEN};
use crate::error::{ExchangeError, WireError};
use crate::exchange::{NK, QUERY_INFO, RESPONSE_EXPORT, Secrets, aad};
use crate::message::{MessageType, ObliviousDoHMessage, ObliviousDoHMessagePlaintext};
use crate::suite::{Aead, Kdf, Kem};

/// The HPKE key pair a target decrypts queries with, and the config that publishes its public half.
pub struct TargetKey {
    private_key: <Kem as hpke::Kem>::PrivateKey,
    config: ObliviousDoHConfigContents,
}

// Hand-written so that the private key never reaches a log.
impl std::fmt::Debug for TargetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetKey")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TargetKey {
    /// The key pair of `ikm`, by `DeriveKeyPair` of RFC 9180 §7.1.3.
    ///
    /// `ikm` is the secret the target stores: 32 bytes from a CSPRNG, `Nsk` of RFC 9180 §7.1.3. The same
    /// `ikm` gives the same key and the same key ID. The caller wipes its copy.
    #[must_use]
    pub fn derive(ikm: &[u8; 32]) -> Self {
        let (private_key, public_key) = Kem::derive_keypair(ikm);
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key.to_bytes().into();
        Self {
            private_key,
            config: ObliviousDoHConfigContents::new(public_key),
        }
    }

    /// The config to publish (RFC 9230 §5).
    #[must_use]
    pub const fn config(&self) -> &ObliviousDoHConfigContents {
        &self.config
    }
}

/// What the target keeps of a query to answer it; one response per query, and its secrets are wiped when it is
/// dropped.
#[derive(Debug)]
pub struct ResponseContext {
    pub(crate) secrets: Secrets,
}

/// Decrypts a query (RFC 9230 §8 steps 1 to 4).
///
/// # Errors
///
/// [`ExchangeError::UnknownKey`] when the key ID is not that of `key`: the target answers 401 (§4.3).
/// Any other error is a query the target answers with 400: [`ExchangeError::WrongType`] for a message that
/// is not a query, [`ExchangeError::Wire`] for a truncated encapsulated key or a malformed plaintext,
/// [`ExchangeError::Decapsulation`] and [`ExchangeError::Decrypt`] when HPKE fails.
pub fn decrypt_query(
    key: &TargetKey,
    message: &ObliviousDoHMessage,
) -> Result<(ObliviousDoHMessagePlaintext, ResponseContext), ExchangeError> {
    if message.message_type() != MessageType::Query {
        return Err(ExchangeError::WrongType {
            expected: MessageType::Query,
            found: message.message_type(),
        });
    }
    if message.key_id() != key.config.key_id() {
        return Err(ExchangeError::UnknownKey);
    }
    let (encapsulated, sealed) = message
        .encrypted_message()
        .split_at_checked(PUBLIC_KEY_LEN)
        .ok_or(WireError::Truncated)?;
    let encapsulated = <Kem as hpke::Kem>::EncappedKey::from_bytes(encapsulated)
        .map_err(|_| ExchangeError::Decapsulation)?;
    let mut context = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &key.private_key,
        &encapsulated,
        QUERY_INFO,
    )
    .map_err(|_| ExchangeError::Decapsulation)?;
    let query_plaintext = context
        .open(sealed, &aad(MessageType::Query, message.key_id())?)
        .map(Zeroizing::new)
        .map_err(|_| ExchangeError::Decrypt)?;
    let mut exporter = Zeroizing::new([0; NK]);
    context
        .export(RESPONSE_EXPORT, exporter.as_mut_slice())
        .map_err(|_| ExchangeError::Decrypt)?;

    let plaintext = ObliviousDoHMessagePlaintext::parse(&query_plaintext)?;
    let secrets = Secrets {
        exporter,
        query_plaintext,
    };
    Ok((plaintext, ResponseContext { secrets }))
}

/// Encrypts `dns_response` for the query of `context` (RFC 9230 §8 steps 6 to 9).
///
/// `padding` zero bytes follow the DNS message inside the encryption; [`response_padding`](crate::response_padding)
/// gives the length RFC 8467 recommends. `rng` yields the 16-byte response nonce.
///
/// # Warning
///
/// Give each call its own randomness: a generator whose state is replayed or cloned repeats the nonce, the
/// one input that keeps the keys of responses apart when two queries share a secret. Only tests, which replay a
/// vector, do so.
///
/// # Errors
///
/// [`ExchangeError::Wire`] for an empty or over-long `dns_response` or `padding`,
/// [`ExchangeError::Encrypt`] when the AEAD refuses.
pub fn encrypt_response(
    context: ResponseContext,
    dns_response: &[u8],
    padding: usize,
    rng: &mut impl CryptoRng,
) -> Result<ObliviousDoHMessage, ExchangeError> {
    let plaintext = ObliviousDoHMessagePlaintext::new(dns_response.to_vec(), padding)?.encode();
    let mut nonce = [0; NK];
    rng.fill_bytes(&mut nonce);
    let encrypted = context.secrets.seal(&nonce, &plaintext)?;
    Ok(ObliviousDoHMessage::new(
        MessageType::Response,
        nonce.to_vec(),
        encrypted,
    )?)
}
