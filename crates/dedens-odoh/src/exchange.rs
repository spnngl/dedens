//! What a query leaves behind for its response: the keys of RFC 9230 §6.2 `derive_secrets`.

use ring::aead::{AES_128_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::error::Unspecified;
use zeroize::Zeroizing;

use crate::error::ExchangeError;
use crate::kdf;
use crate::message::MessageType;

/// The length of the response nonce and of the HPKE exporter secret, `Nk` of AES-128-GCM
/// (RFC 9230 §8 step 6: `max(Nn, Nk)`).
pub(crate) const NK: usize = 16;

/// `len(response_nonce)` as the salt of `derive_secrets` writes it.
const NONCE_PREFIX: [u8; 2] = [0, 16];

const _: () = assert!(NK == 16);

/// The length of an AES-128-GCM tag (RFC 5116 §5.1).
pub(crate) const TAG_LEN: usize = 16;

/// The HPKE `info` of a query (RFC 9230 §6.2).
pub(crate) const QUERY_INFO: &[u8] = b"odoh query";

/// The HPKE exporter context of the response secret (RFC 9230 §6.2).
pub(crate) const RESPONSE_EXPORT: &[u8] = b"odoh response";

/// The AAD of a message: `message_type || len(id) || id`, with the key ID of a query or the nonce of a
/// response as `id` (RFC 9230 §6.2), `M` bytes, `N` + 3.
pub(crate) fn aad<const N: usize, const M: usize>(
    message_type: MessageType,
    id: &[u8; N],
) -> [u8; M] {
    const { assert!(M == N + 3 && N <= 0xffff) };
    let [.., high, low] = N.to_be_bytes();
    let mut out = [0; M];
    let (head, rest) = out.split_at_mut(3);
    head.copy_from_slice(&[message_type.byte(), high, low]);
    rest.copy_from_slice(id);
    out
}

/// What the client and the target both know once the target has decrypted the query: the HPKE exporter
/// secret and the serialized plaintext of the query, padding included. Both are wiped when dropped.
pub(crate) struct Secrets {
    pub(crate) exporter: Zeroizing<[u8; NK]>,
    pub(crate) query_plaintext: Zeroizing<Vec<u8>>,
}

// Hand-written so that the secret never reaches a log.
impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets").finish_non_exhaustive()
    }
}

impl Secrets {
    /// The AEAD key and nonce for the response nonce `response_nonce` (RFC 9230 §6.2 `derive_secrets`).
    ///
    /// `ring` keeps the key schedule it builds from the key, which it does not wipe.
    fn derive(&self, response_nonce: &[u8; NK]) -> Result<(LessSafeKey, Nonce), Unspecified> {
        // Sized once: a reallocation would leave a copy of the query plaintext behind, unwiped.
        let mut salt = Zeroizing::new(Vec::with_capacity(
            self.query_plaintext.len() + NONCE_PREFIX.len() + NK,
        ));
        salt.extend_from_slice(&self.query_plaintext);
        salt.extend_from_slice(&NONCE_PREFIX);
        salt.extend_from_slice(response_nonce);
        let prk = kdf::extract(&salt, self.exporter.as_slice());
        let key = kdf::expand::<NK>(&prk, b"odoh key");
        let nonce = kdf::expand::<NONCE_LEN>(&prk, b"odoh nonce");
        let key = UnboundKey::new(&AES_128_GCM, key.as_slice())?;
        Ok((LessSafeKey::new(key), Nonce::assume_unique_for_key(*nonce)))
    }

    /// `plaintext` sealed in place under the keys of `response_nonce`, the tag appended (RFC 9230 §8 steps 7 to
    /// 9): give it [`TAG_LEN`] bytes of spare capacity and it does not reallocate.
    ///
    /// The nonce is unique for the key: each response nonce yields a fresh key.
    pub(crate) fn seal(
        self,
        response_nonce: &[u8; NK],
        mut plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, ExchangeError> {
        let (key, nonce) = self
            .derive(response_nonce)
            .map_err(|_| ExchangeError::Encrypt)?;
        let aad: [u8; 3 + NK] = aad(MessageType::Response, response_nonce);
        key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut plaintext)
            .map_err(|_| ExchangeError::Encrypt)?;
        Ok(plaintext)
    }

    /// The plaintext of `ciphertext` under the keys of `response_nonce` (RFC 9230 §7).
    pub(crate) fn open(
        &self,
        response_nonce: &[u8; NK],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ExchangeError> {
        let (key, nonce) = self
            .derive(response_nonce)
            .map_err(|_| ExchangeError::Decrypt)?;
        let aad: [u8; 3 + NK] = aad(MessageType::Response, response_nonce);
        let mut buffer = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad), &mut buffer)
            .map_err(|_| ExchangeError::Decrypt)?;
        let len = plaintext.len();
        buffer.truncate(len);
        Ok(buffer)
    }
}
