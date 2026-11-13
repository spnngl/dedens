//! The resolver's side: queries decrypted with a certificate's secret key, and responses encrypted for the client
//! that sent them.

use dedens_proto::Message;
use rand_core::CryptoRng;

use crate::certificate::{Certificate, ClientMagic};
use crate::error::{CertificateError, EncryptResponseError, LowOrderKey, QueryError};
use crate::key::{KEY_LEN, PublicKey, SecretKey, SharedKey};
use crate::secretbox::{self, NONCE_LEN, TAG_LEN};
use crate::system::EncryptionSystem;
use crate::{
    CLIENT_MAGIC_LEN, MAX_PACKET_LEN, NONCE_HALF_LEN, QUERY_OVERHEAD, RESPONSE_MAGIC,
    RESPONSE_OVERHEAD, padding,
};

/// The secret key of one certificate, with the magic and the system that go with it: what a resolver needs to
/// read the queries sent for that certificate.
#[derive(Debug)]
pub struct ResolverKey {
    magic: ClientMagic,
    system: EncryptionSystem,
    secret: SecretKey,
}

impl ResolverKey {
    /// The key `secret` of `certificate`.
    ///
    /// # Errors
    ///
    /// [`CertificateError::KeyMismatch`] when `secret` is not the key of the certificate's `<resolver-pk>`: every
    /// query would fail to authenticate.
    pub fn new(certificate: &Certificate, secret: SecretKey) -> Result<Self, CertificateError> {
        let body = certificate.body();
        if secret.public_key() != body.resolver_key {
            return Err(CertificateError::KeyMismatch);
        }
        Ok(Self {
            magic: body.client_magic,
            system: body.system,
            secret,
        })
    }

    /// The magic of the queries for this key, to find the key of a packet by.
    #[must_use]
    pub const fn client_magic(&self) -> ClientMagic {
        self.magic
    }

    /// The client's public key in `packet`, a query for this key.
    ///
    /// A resolver that sees the same client keys again keeps the [`SharedKey`] of each, made with
    /// [`ResolverKey::shared_key`], and decrypts with [`ResolverKey::decrypt_query_with`].
    ///
    /// # Errors
    ///
    /// [`QueryError`] when the packet is too short or too long, or is for another magic.
    pub fn client_key(&self, packet: &[u8]) -> Result<PublicKey, QueryError> {
        let fields = self.split(packet)?;
        Ok(PublicKey::from_bytes(*fields.client_key))
    }

    /// The key shared with the client of `client_key`.
    ///
    /// # Errors
    ///
    /// [`LowOrderKey`] when `client_key` is of low order.
    pub fn shared_key(&self, client_key: &PublicKey) -> Result<SharedKey, LowOrderKey> {
        self.secret.shared_key(self.system, client_key)
    }

    /// The DNS query in `packet`, authenticated, decrypted and unpadded, and what is needed to answer it.
    ///
    /// The plaintext is no more than that: parsing it as a DNS message, and ignoring it when it is not one, is the
    /// caller's (draft "Resolver Responses Over UDP").
    ///
    /// # Errors
    ///
    /// [`QueryError`] saying why the resolver drops the packet without a response.
    pub fn decrypt_query(&self, packet: &[u8]) -> Result<(Vec<u8>, ResponseContext), QueryError> {
        let shared = self.shared_key(&self.client_key(packet)?)?;
        self.decrypt_query_with(packet, &shared)
    }

    /// As [`ResolverKey::decrypt_query`], with the shared key of the client in `packet` already made.
    ///
    /// # Errors
    ///
    /// As [`ResolverKey::decrypt_query`]; a `shared` made for another client key does not authenticate.
    pub fn decrypt_query_with(
        &self,
        packet: &[u8],
        shared: &SharedKey,
    ) -> Result<(Vec<u8>, ResponseContext), QueryError> {
        let fields = self.split(packet)?;
        let mut plaintext = fields.ciphertext.to_vec();
        secretbox::open(
            shared,
            &secretbox::query_nonce(fields.client_nonce),
            fields.tag,
            &mut plaintext,
        )
        .map_err(|_| QueryError::Authentication)?;
        plaintext.truncate(padding::unpadded_len(&plaintext)?);
        let context = ResponseContext {
            client_nonce: *fields.client_nonce,
            query_packet_len: packet.len(),
            shared: shared.clone(),
        };
        Ok((plaintext, context))
    }

    /// The fields of a query packet for this key.
    fn split<'p>(&self, packet: &'p [u8]) -> Result<QueryFields<'p>, QueryError> {
        if packet.len() > MAX_PACKET_LEN {
            return Err(QueryError::TooLong);
        }
        let (magic, rest) = packet
            .split_first_chunk::<CLIENT_MAGIC_LEN>()
            .ok_or(QueryError::Truncated)?;
        let (client_key, rest) = rest
            .split_first_chunk::<KEY_LEN>()
            .ok_or(QueryError::Truncated)?;
        let (client_nonce, rest) = rest
            .split_first_chunk::<NONCE_HALF_LEN>()
            .ok_or(QueryError::Truncated)?;
        let (tag, ciphertext) = rest
            .split_first_chunk::<TAG_LEN>()
            .ok_or(QueryError::Truncated)?;
        if magic != self.magic.as_bytes() {
            return Err(QueryError::UnknownClientMagic);
        }
        Ok(QueryFields {
            client_key,
            client_nonce,
            tag,
            ciphertext,
        })
    }
}

/// The parts of a query packet.
struct QueryFields<'p> {
    client_key: &'p [u8; KEY_LEN],
    client_nonce: &'p [u8; NONCE_HALF_LEN],
    tag: &'p [u8; TAG_LEN],
    ciphertext: &'p [u8],
}

/// The transport a response goes out on, which decides how large it may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// UDP: the encrypted response may not be larger than the query packet (draft "Resolver Responses Over UDP").
    Udp,
    /// TCP: the encrypted response is whatever it is, under 4096 bytes (draft "Resolver Responses Over TCP"). The
    /// two-byte length prefix is the transport's.
    Tcp,
}

/// What a resolver keeps of a query to answer it: the client's nonce, the size of its packet and the shared key.
#[derive(Debug, Clone)]
pub struct ResponseContext {
    client_nonce: [u8; NONCE_HALF_LEN],
    query_packet_len: usize,
    shared: SharedKey,
}

impl ResponseContext {
    /// The packet answering the query with `response`, a DNS message that echoes the query's ID and question.
    ///
    /// The response is padded to a multiple of 64 bytes, by a length that depends on the key and the client nonce
    /// alone, so that a retransmitted query gets the same padding, when the carrier's budget allows it, and to less
    /// when it does not. A response that does not fit even unpadded is truncated: answer and authority records
    /// left out and TC set, never silence (draft "Padding For Resolver Responses", "Resolver Responses Over
    /// UDP", "Resolver Responses Over TCP").
    ///
    /// `rng` makes the resolver nonce.
    ///
    /// # Errors
    ///
    /// [`EncryptResponseError`] when `response` has to be truncated and is no DNS message, or when the packet has
    /// no room for even the header and the question.
    pub fn encrypt_response(
        &self,
        response: &[u8],
        carrier: Carrier,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<u8>, EncryptResponseError> {
        // A response is under 4096 bytes on both carriers, even when the query packet is 4096.
        let packet_budget = match carrier {
            Carrier::Udp => self.query_packet_len,
            Carrier::Tcp => MAX_PACKET_LEN,
        }
        .min(MAX_PACKET_LEN - 1);
        // One byte of the budget is for the 0x80 marker at least.
        let plaintext_budget = packet_budget.saturating_sub(RESPONSE_OVERHEAD);
        let mut plaintext = if response.len() < plaintext_budget {
            response.to_vec()
        } else {
            let decoded = Message::decode(response)?;
            let mut buf = vec![0; plaintext_budget.saturating_sub(1)];
            let encoded = decoded.message.encode_truncated(&mut buf)?;
            buf.truncate(encoded.len);
            buf
        };
        let extra_blocks = padding::response_extra_blocks(&self.shared, &self.client_nonce);
        let preferred = plaintext.len() + padding::to_block(plaintext.len(), extra_blocks);
        padding::pad(&mut plaintext, preferred.min(plaintext_budget));

        let mut resolver_nonce = [0; NONCE_HALF_LEN];
        while resolver_nonce.iter().all(|&byte| byte == 0) {
            rng.fill_bytes(&mut resolver_nonce);
        }
        let mut nonce = [0; NONCE_LEN];
        nonce
            .iter_mut()
            .zip(self.client_nonce.iter().chain(&resolver_nonce))
            .for_each(|(to, from)| *to = *from);
        let tag = secretbox::seal(&self.shared, &nonce, &mut plaintext);

        let mut packet = Vec::with_capacity(RESPONSE_OVERHEAD + plaintext.len());
        packet.extend_from_slice(&RESPONSE_MAGIC);
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&plaintext);
        Ok(packet)
    }
}

const _: () = assert!(QUERY_OVERHEAD == CLIENT_MAGIC_LEN + KEY_LEN + NONCE_HALF_LEN + TAG_LEN);
