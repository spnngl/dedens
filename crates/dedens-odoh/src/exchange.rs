//! What a query leaves behind for its response: the keys of RFC 9230 §6.2 `derive_secrets`.

use ring::aead::{AES_128_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

use crate::error::ExchangeError;
use crate::kdf;
use crate::message::MessageType;

/// The length of the response nonce and of the HPKE exporter secret, `Nk` of AES-128-GCM
/// (RFC 9230 §6.2: `max(Nn, Nk)`).
pub(crate) const NK: usize = 16;

/// The HPKE `info` of a query (RFC 9230 §6.2).
pub(crate) const QUERY_INFO: &[u8] = b"odoh query";

/// The HPKE exporter context of the response secret (RFC 9230 §6.2).
pub(crate) const RESPONSE_EXPORT: &[u8] = b"odoh response";

/// The AAD of a message: `message_type || len(id) || id`, with the key ID of a query or the nonce of a
/// response as `id` (RFC 9230 §6.2).
pub(crate) fn aad(message_type: MessageType, id: &[u8]) -> Vec<u8> {
    let len = u16::try_from(id.len()).expect("a key ID or a nonce is checked to fit two bytes");
    let mut out = Vec::with_capacity(3 + id.len());
    out.push(message_type as u8);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(id);
    out
}

/// What the client and the target both know once the target has decrypted the query: the HPKE exporter
/// secret and the serialized plaintext of the query, padding included.
pub(crate) struct Secrets {
    pub(crate) exporter: [u8; NK],
    pub(crate) query_plaintext: Vec<u8>,
}

// Hand-written so that the secret never reaches a log.
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets").finish_non_exhaustive()
    }
}

impl Secrets {
    /// The AEAD key and nonce for the response nonce `response_nonce` (RFC 9230 §6.2 `derive_secrets`).
    fn derive(&self, response_nonce: &[u8; NK]) -> (LessSafeKey, Nonce) {
        let mut salt = self.query_plaintext.clone();
        salt.extend_from_slice(&u16::try_from(NK).expect("16 fits").to_be_bytes());
        salt.extend_from_slice(response_nonce);
        let prk = kdf::extract(&salt, &self.exporter);
        let key: [u8; NK] = kdf::expand(&prk, b"odoh key");
        let nonce: [u8; NONCE_LEN] = kdf::expand(&prk, b"odoh nonce");
        let key = UnboundKey::new(&AES_128_GCM, &key).expect("AES-128 takes a key of 16 bytes");
        (LessSafeKey::new(key), Nonce::assume_unique_for_key(nonce))
    }

    /// The ciphertext of `plaintext` under the keys of `response_nonce` (RFC 9230 §8 steps 7 to 9).
    ///
    /// The nonce is unique for the key: each response nonce yields a fresh key.
    pub(crate) fn seal(
        self,
        response_nonce: &[u8; NK],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ExchangeError> {
        let (key, nonce) = self.derive(response_nonce);
        let aad = aad(MessageType::Response, response_nonce);
        let mut buffer = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buffer)
            .map_err(|_| ExchangeError::Encrypt)?;
        Ok(buffer)
    }

    /// The plaintext of `ciphertext` under the keys of `response_nonce` (RFC 9230 §7).
    pub(crate) fn open(
        self,
        response_nonce: &[u8; NK],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ExchangeError> {
        let (key, nonce) = self.derive(response_nonce);
        let aad = aad(MessageType::Response, response_nonce);
        let mut buffer = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), &mut buffer)
            .map_err(|_| ExchangeError::Decrypt)?;
        let len = plaintext.len();
        buffer.truncate(len);
        Ok(buffer)
    }
}
