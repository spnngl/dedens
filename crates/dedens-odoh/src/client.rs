//! The client side of RFC 9230 §7: encrypt a query, decrypt its response.

use hpke::rand_core::CryptoRng;
use hpke::{Deserializable as _, OpModeS, Serializable as _};

use crate::config::ObliviousDoHConfigContents;
use crate::error::ExchangeError;
use crate::exchange::{NK, QUERY_INFO, RESPONSE_EXPORT, Secrets, aad};
use crate::message::{MessageType, ObliviousDoHMessage, ObliviousDoHMessagePlaintext};
use crate::suite::{Aead, Kdf, Kem};

/// What the client keeps of a query to read its response; one response per query.
#[derive(Debug)]
pub struct QueryContext {
    secrets: Secrets,
}

/// Encrypts `dns_query` for the target of `config` (RFC 9230 §6.2 `encrypt_query_body`, §7).
///
/// `padding` zero bytes follow the DNS message inside the encryption; [`query_padding`](crate::query_padding)
/// gives the length RFC 8467 recommends. `rng` yields the ephemeral key of HPKE; it must be a CSPRNG.
///
/// # Errors
///
/// [`ExchangeError::Wire`] for an empty or over-long `dns_query` or `padding`,
/// [`ExchangeError::Encapsulation`] when the key exchange fails, [`ExchangeError::Encrypt`] when the AEAD
/// refuses.
pub fn encrypt_query(
    config: &ObliviousDoHConfigContents,
    dns_query: &[u8],
    padding: usize,
    rng: &mut impl CryptoRng,
) -> Result<(ObliviousDoHMessage, QueryContext), ExchangeError> {
    let query_plaintext = ObliviousDoHMessagePlaintext::new(dns_query.to_vec(), padding)?.encode();
    let public_key = <Kem as hpke::Kem>::PublicKey::from_bytes(config.public_key())
        .map_err(|_| ExchangeError::Encapsulation)?;
    let (encapsulated, mut context) =
        hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(&OpModeS::Base, &public_key, QUERY_INFO, rng)
            .map_err(|_| ExchangeError::Encapsulation)?;
    let sealed = context
        .seal(&query_plaintext, &aad(MessageType::Query, config.key_id()))
        .map_err(|_| ExchangeError::Encrypt)?;
    let mut exporter = [0; NK];
    context
        .export(RESPONSE_EXPORT, &mut exporter)
        .map_err(|_| ExchangeError::Encrypt)?;

    let encrypted = [encapsulated.to_bytes().as_slice(), &sealed].concat();
    let message =
        ObliviousDoHMessage::new(MessageType::Query, config.key_id().to_vec(), encrypted)?;
    let secrets = Secrets {
        exporter,
        query_plaintext,
    };
    Ok((message, QueryContext { secrets }))
}

/// Decrypts the response to the query of `context` (RFC 9230 §7).
///
/// # Errors
///
/// [`ExchangeError::WrongType`] for a message that is not a response,
/// [`ExchangeError::ResponseNonceLength`] when its key ID is not 16 bytes, [`ExchangeError::Decrypt`] when
/// the ciphertext does not authenticate, [`ExchangeError::Wire`] when the plaintext is malformed or its
/// padding is not zeros.
pub fn decrypt_response(
    context: QueryContext,
    message: &ObliviousDoHMessage,
) -> Result<ObliviousDoHMessagePlaintext, ExchangeError> {
    if message.message_type() != MessageType::Response {
        return Err(ExchangeError::WrongType {
            expected: MessageType::Response,
            found: message.message_type(),
        });
    }
    let nonce = <[u8; NK]>::try_from(message.key_id())
        .map_err(|_| ExchangeError::ResponseNonceLength(message.key_id().len()))?;
    let plaintext = context.secrets.open(&nonce, message.encrypted_message())?;
    Ok(ObliviousDoHMessagePlaintext::parse(&plaintext)?)
}
