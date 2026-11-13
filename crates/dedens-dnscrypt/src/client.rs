//! The client's side: queries encrypted for a certificate, and the responses to them.

use dedens_proto::{Message, Question};
use rand_core::CryptoRng;

use crate::certificate::{Certificate, ClientMagic};
use crate::error::{EncryptQueryError, LowOrderKey, ResponseError};
use crate::key::{PublicKey, SecretKey, SharedKey};
use crate::padding::{self, BLOCK};
use crate::secretbox::{self, NONCE_LEN, TAG_LEN};
use crate::{MAX_PACKET_LEN, NONCE_HALF_LEN, QUERY_OVERHEAD, RESPONSE_MAGIC};

/// The 12 bytes the client picks for a query; the resolver repeats them in its response, which is how the client
/// knows what the response answers (draft "Protocol Components": `<client-nonce>`).
///
/// Never to be used twice with the same shared key: the encryption would repeat its keystream. Random bytes will
/// not repeat in the life of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientNonce([u8; NONCE_HALF_LEN]);

impl ClientNonce {
    /// The nonce of the 12 bytes `bytes`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_HALF_LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh random nonce.
    #[must_use]
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        let mut bytes = [0; NONCE_HALF_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The 12 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_HALF_LEN] {
        &self.0
    }
}

/// The most a query's padded plaintext can be: what is left of the 4096 bytes of a packet.
const MAX_PLAINTEXT_LEN: usize = MAX_PACKET_LEN - QUERY_OVERHEAD;

/// The length the plaintext of a query is padded to, with its 0x80 marker (draft "Padding For Client Queries
/// Over UDP", "Padding For Client Queries Over TCP").
///
/// A target below what the query needs, itself and one byte, is raised to that. [`QueryPadding::udp`] and
/// [`QueryPadding::tcp`] stop at the 4028 bytes a packet can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPadding(usize);

impl QueryPadding {
    /// A plaintext of exactly `len` bytes.
    #[must_use]
    pub const fn to(len: usize) -> Self {
        Self(len)
    }

    /// For a UDP query of `query_len` bytes: the packet at least `min_packet_len` bytes (`<min-query-len>`, 256
    /// at first), and the plaintext a multiple of 64 bytes, except at the largest packet.
    ///
    /// `min_packet_len` is a floor, not the packet's length: rounding to a block makes the packet up to 63 bytes
    /// longer. A `min_packet_len` over 4096 gives the largest packet.
    #[must_use]
    pub fn udp(query_len: usize, min_packet_len: usize) -> Self {
        let wanted = (query_len + 1).max(min_packet_len.saturating_sub(QUERY_OVERHEAD));
        Self(wanted.next_multiple_of(BLOCK).min(MAX_PLAINTEXT_LEN))
    }

    /// For a TCP query of `query_len` bytes: 1 to 256 bytes of padding, the plaintext a multiple of 64 bytes, with
    /// a random number of blocks so that the same query is not padded the same twice, except at the largest
    /// packet.
    #[must_use]
    pub fn tcp(query_len: usize, rng: &mut impl CryptoRng) -> Self {
        let mut byte = [0];
        rng.fill_bytes(&mut byte);
        let extra_blocks = usize::from(u8::from_ne_bytes(byte) & 0b11);
        let padded = query_len + padding::to_block(query_len, extra_blocks);
        Self(padded.min(MAX_PLAINTEXT_LEN))
    }
}

/// What a client keeps for one resolver certificate: the magic, the client's key and the shared key, so that a
/// query costs no scalar multiplication.
#[derive(Debug, Clone)]
pub struct ClientSession {
    magic: ClientMagic,
    client_key: PublicKey,
    shared: SharedKey,
}

impl ClientSession {
    /// The session of the client key `secret` with the resolver of `certificate`.
    ///
    /// The client key can be one for all queries to a resolver, or one per query: the resolver sees it either way
    /// (draft "Protocol Components": `<client-pk>`).
    ///
    /// # Errors
    ///
    /// [`LowOrderKey`] when the certificate's resolver key is of low order.
    pub fn new(certificate: &Certificate, secret: &SecretKey) -> Result<Self, LowOrderKey> {
        let body = certificate.body();
        Ok(Self {
            magic: body.client_magic,
            client_key: secret.public_key(),
            shared: secret.shared_key(body.system, &body.resolver_key)?,
        })
    }

    /// The packet for `query`, a DNS message, and what is needed to read its response.
    ///
    /// # Errors
    ///
    /// [`EncryptQueryError`] when `query` is no DNS message or has no question, or the packet would be over 4096
    /// bytes.
    pub fn encrypt_query(
        &self,
        query: &[u8],
        padding: QueryPadding,
        nonce: ClientNonce,
    ) -> Result<(Vec<u8>, QueryContext), EncryptQueryError> {
        let decoded = Message::decode(query)?;
        let message = decoded.message;
        if message.questions.is_empty() {
            return Err(EncryptQueryError::NoQuestion);
        }
        let padded_len = padding.0.max(query.len() + 1);
        if QUERY_OVERHEAD + padded_len > MAX_PACKET_LEN {
            return Err(EncryptQueryError::TooLong);
        }

        let mut ciphertext = Vec::with_capacity(padded_len);
        ciphertext.extend_from_slice(query);
        padding::pad(&mut ciphertext, padded_len);
        let tag = secretbox::seal(
            &self.shared,
            &secretbox::query_nonce(nonce.as_bytes()),
            &mut ciphertext,
        );

        let mut packet = Vec::with_capacity(QUERY_OVERHEAD + padded_len);
        packet.extend_from_slice(self.magic.as_bytes());
        packet.extend_from_slice(self.client_key.as_bytes());
        packet.extend_from_slice(nonce.as_bytes());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&ciphertext);

        let context = QueryContext {
            nonce,
            id: message.header.id,
            questions: message
                .questions
                .into_iter()
                .map(Question::into_owned)
                .collect(),
            shared: self.shared.clone(),
        };
        Ok((packet, context))
    }
}

/// What a client needs of a query to accept its response: the nonce, the ID and the questions.
#[derive(Debug, Clone)]
pub struct QueryContext {
    nonce: ClientNonce,
    id: u16,
    questions: Vec<Question<'static>>,
    shared: SharedKey,
}

impl QueryContext {
    /// The DNS response in `packet`, if it answers the query: authenticated, decrypted, unpadded, a DNS message
    /// with the query's ID and questions (draft "Client Queries Over UDP", "Resolver Responses Over UDP").
    ///
    /// A client disregards a packet that fails, and goes on waiting for the one it asked for.
    ///
    /// # Errors
    ///
    /// [`ResponseError`] saying what is wrong with the packet.
    pub fn decrypt_response(&self, packet: &[u8]) -> Result<Vec<u8>, ResponseError> {
        if packet.len() >= MAX_PACKET_LEN {
            return Err(ResponseError::TooLong);
        }
        let (magic, rest) = packet.split_first_chunk().ok_or(ResponseError::Truncated)?;
        let (nonce, rest) = rest
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(ResponseError::Truncated)?;
        let (tag, ciphertext) = rest
            .split_first_chunk::<TAG_LEN>()
            .ok_or(ResponseError::Truncated)?;
        if *magic != RESPONSE_MAGIC {
            return Err(ResponseError::WrongMagic);
        }
        let (client_half, resolver_half) = nonce.split_at(NONCE_HALF_LEN);
        if client_half != self.nonce.as_bytes() {
            return Err(ResponseError::NonceMismatch);
        }
        if resolver_half.iter().all(|&byte| byte == 0) {
            return Err(ResponseError::ZeroResolverNonce);
        }

        let mut plaintext = ciphertext.to_vec();
        secretbox::open(&self.shared, nonce, tag, &mut plaintext)
            .map_err(|_| ResponseError::Authentication)?;
        plaintext.truncate(padding::unpadded_len(&plaintext)?);

        let decoded = Message::decode(&plaintext)?;
        if decoded.message.header.id != self.id {
            return Err(ResponseError::IdMismatch);
        }
        if decoded.message.questions != self.questions {
            return Err(ResponseError::QuestionMismatch);
        }
        Ok(plaintext)
    }
}
