//! The resolver's side: queries decrypted with a certificate's secret key, and responses encrypted for the client
//! that sent them.

use dedens_proto::{Flags, Message};
use rand_core::CryptoRng;

use crate::certificate::{Certificate, ClientMagic, ResolverPublicKey, Validity};
use crate::error::{CertificateError, EncryptResponseError, QueryError, SessionError};
use crate::key::{KEY_LEN, PublicKey, SecretKey, SharedKey};
use crate::pq::{self, Binding};
use crate::secretbox::{self, NONCE_LEN, TAG_LEN};
use crate::system::EncryptionSystem;
use crate::ticket::{ResumedQuery, Ticket};
use crate::xwing::{XWING_CIPHERTEXT_LEN, XWingSecretKey};
use crate::{
    CLIENT_MAGIC_LEN, MAX_PACKET_LEN, NONCE_HALF_LEN, QUERY_OVERHEAD, RESPONSE_MAGIC,
    RESPONSE_OVERHEAD, padding,
};

/// The secret key of a certificate: X25519 or X-Wing, as the certificate's system is.
#[derive(Debug)]
pub enum ResolverSecret {
    /// The key of a certificate of `<es-version>` 0x0001 or 0x0002.
    X25519(SecretKey),
    /// The key of a certificate of `<es-version>` 0x0003.
    XWing(XWingSecretKey),
}

impl From<SecretKey> for ResolverSecret {
    fn from(key: SecretKey) -> Self {
        Self::X25519(key)
    }
}

impl From<XWingSecretKey> for ResolverSecret {
    fn from(key: XWingSecretKey) -> Self {
        Self::XWing(key)
    }
}

/// What a resolver derives from a PQ certificate once: what its queries' keys and its tickets are bound to.
#[derive(Debug)]
struct PqCertificate {
    key: XWingSecretKey,
    context: Vec<u8>,
    binding: Binding,
    validity: Validity,
}

#[derive(Debug)]
enum Kind {
    X25519 {
        system: EncryptionSystem,
        key: SecretKey,
    },
    XWing(Box<PqCertificate>),
}

/// The secret key of one certificate, with the magic and the system that go with it: what a resolver needs to
/// read the queries sent for that certificate.
#[derive(Debug)]
pub struct ResolverKey {
    magic: ClientMagic,
    kind: Kind,
}

impl ResolverKey {
    /// The key `secret` of `certificate`.
    ///
    /// # Errors
    ///
    /// [`CertificateError::KeyMismatch`] when `secret` is not the key of the certificate's `<resolver-pk>`, or
    /// is of the other kind of system: every query would fail to authenticate.
    pub fn new(
        certificate: &Certificate,
        secret: impl Into<ResolverSecret>,
    ) -> Result<Self, CertificateError> {
        let body = certificate.body();
        let kind = match (secret.into(), &body.resolver_key) {
            (
                ResolverSecret::X25519(key),
                ResolverPublicKey::XSalsa20(public) | ResolverPublicKey::XChaCha20(public),
            ) if key.public_key() == *public => Kind::X25519 {
                system: body.system(),
                key,
            },
            (ResolverSecret::XWing(key), ResolverPublicKey::XWing(public))
                if key.matches(public) =>
            {
                Kind::XWing(Box::new(PqCertificate {
                    key,
                    context: pq::cert_context(&body.signed_bytes()),
                    binding: Binding::of(body),
                    validity: body.validity,
                }))
            }
            _ => return Err(CertificateError::KeyMismatch),
        };
        Ok(Self {
            magic: body.client_magic,
            kind,
        })
    }

    /// The magic of the queries for this key, to find the key of a packet by.
    #[must_use]
    pub const fn client_magic(&self) -> ClientMagic {
        self.magic
    }

    /// The system of the certificate this is the key of.
    #[must_use]
    pub const fn system(&self) -> EncryptionSystem {
        match &self.kind {
            Kind::X25519 { system, .. } => *system,
            Kind::XWing(_) => EncryptionSystem::XWing,
        }
    }

    /// The client's public key in `packet`, a query for this key.
    ///
    /// A resolver that sees the same client keys again keeps the [`SharedKey`] of each, made with
    /// [`ResolverKey::shared_key`], and decrypts with [`ResolverKey::decrypt_query_with`].
    ///
    /// # Errors
    ///
    /// [`QueryError`] when the packet is too short or too long, or is for another magic, or when this is the key of
    /// an X-Wing certificate, whose queries carry a ciphertext in the place of a key.
    pub fn client_key(&self, packet: &[u8]) -> Result<PublicKey, QueryError> {
        let fields = self.split(packet)?;
        let key =
            <[u8; KEY_LEN]>::try_from(fields.client_key).map_err(|_| QueryError::WrongSystem)?;
        Ok(PublicKey::from_bytes(key))
    }

    /// The key shared with the client of `client_key`.
    ///
    /// # Errors
    ///
    /// [`SessionError::LowOrderKey`] when `client_key` is of low order, [`SessionError::WrongSystem`] when this is
    /// the key of an X-Wing certificate.
    pub fn shared_key(&self, client_key: &PublicKey) -> Result<SharedKey, SessionError> {
        match &self.kind {
            Kind::X25519 { system, key } => key.shared_key(*system, client_key),
            Kind::XWing(_) => Err(SessionError::WrongSystem),
        }
    }

    /// The DNS query in `packet`, authenticated, decrypted and unpadded, and what is needed to answer it.
    ///
    /// The plaintext is no more than that: parsing it as a DNS message, and ignoring it when it is not one, is the
    /// caller's (draft "Resolver Responses Over UDP").
    ///
    /// For an X-Wing key this decapsulates the ciphertext in the packet, which costs more than an X25519 key
    /// agreement: a resolver rate-limits it (draft "Implicit Rejection"). A ciphertext that was altered gives
    /// another key and fails to authenticate, like any other forged packet.
    ///
    /// # Errors
    ///
    /// [`QueryError`] saying why the resolver drops the packet without a response.
    pub fn decrypt_query(&self, packet: &[u8]) -> Result<(Vec<u8>, ResponseContext), QueryError> {
        let shared = match &self.kind {
            Kind::X25519 { .. } => self.shared_key(&self.client_key(packet)?)?,
            Kind::XWing(pq) => {
                let fields = self.split(packet)?;
                let ciphertext = <&[u8; XWING_CIPHERTEXT_LEN]>::try_from(fields.client_key)
                    .map_err(|_| QueryError::Truncated)?;
                let secret = pq.key.decapsulate(ciphertext);
                pq::session_key(&pq.context, self.magic, &secret, ciphertext)
            }
        };
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
        let binding = match &self.kind {
            Kind::X25519 { .. } => None,
            Kind::XWing(pq) => Some(pq.binding.clone()),
        };
        open_query(
            fields.client_nonce,
            fields.tag,
            fields.ciphertext,
            packet.len(),
            shared.clone(),
            binding,
        )
    }

    /// The DNS query in a resumed query whose ticket `query` is, if the ticket is bound to this key's
    /// certificate, which has to be valid at `now`, in Unix seconds (draft "Resuming").
    ///
    /// A resolver that has several PQ keys tries each: [`QueryError::TicketContext`] says the ticket is for
    /// another.
    ///
    /// # Errors
    ///
    /// [`QueryError`] saying why the resolver drops the packet without a response.
    pub fn decrypt_resumed(
        &self,
        query: &ResumedQuery<'_>,
        now: u64,
    ) -> Result<(Vec<u8>, ResponseContext), QueryError> {
        let Kind::XWing(pq) = &self.kind else {
            return Err(QueryError::WrongSystem);
        };
        if query.binding != pq.binding || !pq.validity.contains(now) {
            return Err(QueryError::TicketContext);
        }
        let shared = pq::resumed_key(
            &query.secret,
            query.binding.magic,
            query.client_nonce,
            query.ticket,
        );
        open_query(
            query.client_nonce,
            query.tag,
            query.ciphertext,
            query.packet_len,
            shared,
            Some(pq.binding.clone()),
        )
    }

    /// The fields of a query packet for this key.
    fn split<'p>(&self, packet: &'p [u8]) -> Result<QueryFields<'p>, QueryError> {
        if packet.len() > MAX_PACKET_LEN {
            return Err(QueryError::TooLong);
        }
        let key_len = match self.kind {
            Kind::X25519 { .. } => KEY_LEN,
            Kind::XWing(_) => XWING_CIPHERTEXT_LEN,
        };
        let (magic, rest) = packet
            .split_first_chunk::<CLIENT_MAGIC_LEN>()
            .ok_or(QueryError::Truncated)?;
        let (client_key, rest) = rest
            .split_at_checked(key_len)
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
    client_key: &'p [u8],
    client_nonce: &'p [u8; NONCE_HALF_LEN],
    tag: &'p [u8; TAG_LEN],
    ciphertext: &'p [u8],
}

/// Authenticates and unpads a query ciphertext.
fn open_query(
    client_nonce: &[u8; NONCE_HALF_LEN],
    tag: &[u8; TAG_LEN],
    ciphertext: &[u8],
    packet_len: usize,
    shared: SharedKey,
    binding: Option<Binding>,
) -> Result<(Vec<u8>, ResponseContext), QueryError> {
    let mut plaintext = ciphertext.to_vec();
    secretbox::open(
        &shared,
        &secretbox::query_nonce(client_nonce),
        tag,
        &mut plaintext,
    )
    .map_err(|_| QueryError::Authentication)?;
    plaintext.truncate(padding::unpadded_len(&plaintext)?);
    let context = ResponseContext {
        client_nonce: *client_nonce,
        query_packet_len: packet_len,
        shared,
        binding,
    };
    Ok((plaintext, context))
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

/// What a resolver keeps of a query to answer it: the client's nonce, the size of its packet and the shared key,
/// and for a PQ query what the certificate binds a ticket to.
#[derive(Debug, Clone)]
pub struct ResponseContext {
    client_nonce: [u8; NONCE_HALF_LEN],
    query_packet_len: usize,
    shared: SharedKey,
    binding: Option<Binding>,
}

impl ResponseContext {
    pub(crate) const fn binding(&self) -> Option<&Binding> {
        self.binding.as_ref()
    }

    pub(crate) const fn shared(&self) -> &SharedKey {
        &self.shared
    }

    pub(crate) const fn client_nonce(&self) -> &[u8; NONCE_HALF_LEN] {
        &self.client_nonce
    }

    /// Whether the query was a PQ one, which a ticket may be issued for.
    #[must_use]
    pub const fn is_pq(&self) -> bool {
        self.binding.is_some()
    }

    /// The packet answering the query with `response`, a DNS message that echoes the query's ID and question.
    ///
    /// The response is padded to a multiple of 64 bytes, by a length that depends on the key and the client nonce
    /// alone, so that a retransmitted query gets the same padding, when the carrier's budget allows it, and to less
    /// when it does not. A response that does not fit even unpadded is truncated: the records that do not fit
    /// are left out and TC is set, whichever section lost them, never silence (draft "Padding For Resolver
    /// Responses", "Resolver Responses Over UDP", "Resolver Responses Over TCP").
    ///
    /// `rng` makes the resolver nonce. A response to a PQ query carries no ticket: see
    /// [`ResponseContext::encrypt_response_with`].
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
        self.encrypt_response_with(response, None, carrier, rng)
    }

    /// As [`ResponseContext::encrypt_response`], with `ticket` in the control field of a PQ response, which
    /// has one, empty or not, in all of them (draft "PQ Query and Response Format"). A `ticket` for a classical
    /// response is dropped.
    ///
    /// Over UDP, when the ticket leaves no room for the response, the ticket is withheld, the control field is
    /// empty, before the response is truncated for it.
    ///
    /// # Errors
    ///
    /// As [`ResponseContext::encrypt_response`].
    pub fn encrypt_response_with(
        &self,
        response: &[u8],
        ticket: Option<&Ticket>,
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

        let mut control = Vec::new();
        if self.is_pq()
            && let Some(ticket) = ticket
        {
            let wanted = ticket.control();
            if 2 + wanted.len() + response.len() < plaintext_budget {
                control = wanted;
            }
        }
        // `<control-len> <control>` goes before the response, in a PQ response only.
        let mut plaintext = Vec::new();
        if self.is_pq() {
            let len = u16::try_from(control.len()).unwrap_or(0);
            plaintext.extend_from_slice(&len.to_be_bytes());
            plaintext.extend_from_slice(&control);
        }
        let response_budget = plaintext_budget.saturating_sub(plaintext.len());
        if response.len() < response_budget {
            plaintext.extend_from_slice(response);
        } else {
            let decoded = Message::decode(response)?;
            let mut buf = vec![0; response_budget.saturating_sub(1)];
            let encoded = decoded.message.encode_truncated(&mut buf)?;
            buf.truncate(encoded.len);
            // `encode_truncated` leaves TC clear when only additional records were left out; the draft
            // wants it set whenever anything is.
            let [tc_byte, _] = Flags::TC.bits().to_be_bytes();
            if encoded.dropped > 0
                && let Some(flags) = buf.get_mut(2)
            {
                *flags |= tc_byte;
            }
            plaintext.extend_from_slice(&buf);
        }
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
