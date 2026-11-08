//! The client side of RFC 9230 §7: encrypt a query, decrypt its response.

use hpke::rand_core::CryptoRng;
use hpke::{Deserializable as _, OpModeS, Serializable as _};
use zeroize::Zeroizing;

use crate::config::ConfigContents;
use crate::error::ExchangeError;
use crate::exchange::{NK, QUERY_INFO, RESPONSE_EXPORT, Secrets, aad};
use crate::message::{Message, MessagePlaintext, MessageType};
use crate::suite::{Aead, Kdf, Kem};

/// What the client keeps of a query to read its response; its secrets are wiped when it is dropped.
#[derive(Debug)]
pub struct QueryContext {
    secrets: Secrets,
}

/// Encrypts `dns_query` for the target of `config` (RFC 9230 §6.2 `encrypt_query_body`, §7).
///
/// `padding` zero bytes follow the DNS message inside the encryption; [`query_padding`](crate::query_padding)
/// gives the length RFC 8467 recommends. `rng` yields the ephemeral key of HPKE; it must be a CSPRNG.
///
/// # Warning
///
/// Give each call its own randomness: a generator whose state is replayed or cloned repeats the ephemeral
/// key, and with it the encryption of two queries under one secret. Only tests, which replay a vector, do so.
///
/// # Errors
///
/// [`ExchangeError::Wire`] for an empty or over-long `dns_query` or `padding`,
/// [`ExchangeError::Encapsulation`] when the key exchange fails, [`ExchangeError::Encrypt`] when the AEAD
/// refuses.
pub fn encrypt_query(
    config: &ConfigContents,
    dns_query: &[u8],
    padding: usize,
    rng: &mut impl CryptoRng,
) -> Result<(Message, QueryContext), ExchangeError> {
    let query_plaintext =
        Zeroizing::new(MessagePlaintext::new(dns_query.to_vec(), padding)?.encode());
    let public_key = <Kem as hpke::Kem>::PublicKey::from_bytes(config.public_key())
        .map_err(|_| ExchangeError::Encapsulation)?;
    let (encapsulated, mut context) =
        hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(&OpModeS::Base, &public_key, QUERY_INFO, rng)
            .map_err(|_| ExchangeError::Encapsulation)?;
    let sealed = context
        .seal(&query_plaintext, &aad(MessageType::Query, config.key_id())?)
        .map_err(|_| ExchangeError::Encrypt)?;
    let mut exporter = Zeroizing::new([0; NK]);
    context
        .export(RESPONSE_EXPORT, exporter.as_mut_slice())
        .map_err(|_| ExchangeError::Encrypt)?;

    let encrypted = [encapsulated.to_bytes().as_slice(), &sealed].concat();
    let message = Message::new(MessageType::Query, config.key_id().to_vec(), encrypted)?;
    let secrets = Secrets {
        exporter,
        query_plaintext,
    };
    Ok((message, QueryContext { secrets }))
}

/// Decrypts the response to the query of `context` (RFC 9230 §7).
///
/// `context` is borrowed, not consumed: a proxy can answer with garbage, and that must not lose the context
/// of a query still waiting for the target's answer. Opening twice under one context is safe, since it
/// encrypts nothing.
///
/// # Errors
///
/// [`ExchangeError::WrongType`] for a message that is not a response,
/// [`ExchangeError::ResponseNonceLength`] when its key ID is not 16 bytes, [`ExchangeError::Decrypt`] when
/// the ciphertext does not authenticate, [`ExchangeError::Wire`] when the plaintext is malformed or its
/// padding is not zeros.
pub fn decrypt_response(
    context: &QueryContext,
    message: &Message,
) -> Result<MessagePlaintext, ExchangeError> {
    if message.message_type() != MessageType::Response {
        return Err(ExchangeError::WrongType {
            expected: MessageType::Response,
            found: message.message_type(),
        });
    }
    let nonce = <[u8; NK]>::try_from(message.key_id())
        .map_err(|_| ExchangeError::ResponseNonceLength(message.key_id().len()))?;
    let plaintext = context.secrets.open(&nonce, message.encrypted_message())?;
    Ok(MessagePlaintext::parse(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use serde_json::Value;

    use super::*;
    use crate::target::{TargetKey, decrypt_query};

    fn hex(value: &Value) -> Vec<u8> {
        HEXLOWER
            .decode(value.as_str().expect("a string").as_bytes())
            .expect("valid hex")
    }

    /// The responses of `cloudflare/odoh-go`, read by the client. The vectors hold no ephemeral key, so the
    /// client's context is made from the target's: both hold the same exporter secret and query plaintext.
    #[test]
    fn decrypts_the_responses_of_odoh_go() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/testdata/odoh-go-test-vectors.json"))
                .expect("the vectors");
        for vector in vectors.as_array().expect("an array") {
            let seed: [u8; 32] = hex(&vector["public_key_seed"])
                .try_into()
                .expect("32 bytes");
            let key = TargetKey::derive(&seed);
            for transaction in vector["transactions"].as_array().expect("an array") {
                let query = Message::parse(&hex(&transaction["obliviousQuery"])).expect("parses");
                let (_, target) = decrypt_query(&key, &query).expect("decrypts");
                let client = QueryContext {
                    secrets: target.secrets,
                };
                let response =
                    Message::parse(&hex(&transaction["obliviousResponse"])).expect("parses");
                let plaintext = decrypt_response(&client, &response).expect("decrypts");
                assert_eq!(plaintext.dns_message(), hex(&transaction["response"]));
                assert_eq!(
                    plaintext.padding(),
                    usize::try_from(
                        transaction["responsePaddingLength"]
                            .as_u64()
                            .expect("a number")
                    )
                    .expect("small")
                );
            }
        }
    }
}
