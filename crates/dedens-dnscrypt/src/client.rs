//! The client's side: queries encrypted for a certificate, and the responses to them.

use std::fmt;

use dedens_proto::{Message, Question};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::certificate::{Certificate, ClientMagic, ResolverPublicKey};
use crate::error::{ControlError, EncryptQueryError, ResponseError, SessionError};
use crate::key::{KEY_LEN, SecretKey, SharedKey};
use crate::padding::{self, BLOCK};
use crate::pq::{self, RESUME_MAGIC, TicketOffer};
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
/// [`QueryPadding::tcp`] stop at the 4028 bytes a classical packet can carry; a PQ packet, whose key field is
/// longer, is refused when it comes out over 4096 bytes.
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

/// The padded plaintext a resumed query over UDP starts at, with its overhead (draft "PQ Query and Response Format").
const RESUMED_UDP_FLOOR: usize = 256;

/// The `<client-magic>`, the `<ticket-len>` and the ticket that open a resumed query: the head `Resumption` seals after.
const fn resumed_head_len(ticket_len: usize) -> usize {
    RESUME_MAGIC.len() + 2 + ticket_len
}

/// What a ticket of a PQ session is bound to, and the end of the certificate that caps its life.
#[derive(Debug, Clone, Copy)]
struct TicketOrigin {
    magic: ClientMagic,
    ts_end: u32,
}

/// What a client keeps for one resolver certificate: the magic, what the resolver reads the client's key from
/// (the X25519 key, or the X-Wing ciphertext) and the shared key, so that a query costs no key agreement.
#[derive(Debug, Clone)]
pub struct ClientSession {
    magic: ClientMagic,
    /// `<client-pk>`: 32 bytes of X25519 public key, or the 1120 of an X-Wing ciphertext.
    client_kex: Vec<u8>,
    shared: SharedKey,
    origin: Option<TicketOrigin>,
}

impl ClientSession {
    /// The session of the client key `secret` with the resolver of `certificate`, an X25519 one.
    ///
    /// The client key can be one for all queries to a resolver, or one per query: the resolver sees it either way
    /// (draft "Protocol Components": `<client-pk>`).
    ///
    /// # Errors
    ///
    /// [`SessionError::LowOrderKey`] when the certificate's resolver key is of low order,
    /// [`SessionError::WrongSystem`] when the certificate is an X-Wing one: see [`ClientSession::xwing`].
    pub fn new(certificate: &Certificate, secret: &SecretKey) -> Result<Self, SessionError> {
        let body = certificate.body();
        let resolver_key = body
            .resolver_key
            .x25519()
            .ok_or(SessionError::WrongSystem)?;
        Ok(Self {
            magic: body.client_magic,
            client_kex: secret.public_key().as_bytes().to_vec(),
            shared: secret.shared_key(body.system(), resolver_key)?,
            origin: None,
        })
    }

    /// The session with the resolver of `certificate`, an X-Wing one: a fresh encapsulation, whose ciphertext is
    /// the `<client-pk>` of the queries of the session (draft "PQ Key Derivation").
    ///
    /// The draft has the ciphertext "freshly generated for every query" ("PQ Certificates"), and its forward secrecy
    /// rests on it ("PQ Security Considerations"): make one session per query, as `dedens-net` does. Reused, the
    /// session links its queries and shares one key among them.
    ///
    /// # Errors
    ///
    /// [`SessionError::WrongSystem`] when the certificate is an X25519 one: see [`ClientSession::new`].
    pub fn xwing(
        certificate: &Certificate,
        rng: &mut impl CryptoRng,
    ) -> Result<Self, SessionError> {
        let body = certificate.body();
        let ResolverPublicKey::XWing(resolver_key) = &body.resolver_key else {
            return Err(SessionError::WrongSystem);
        };
        let (ciphertext, secret) = resolver_key.encapsulate(rng);
        let context = pq::cert_context(certificate.minor_version(), &body.signed_bytes());
        Ok(Self {
            magic: body.client_magic,
            shared: pq::session_key(&context, body.client_magic, &secret, &ciphertext),
            client_kex: ciphertext,
            origin: Some(TicketOrigin {
                magic: body.client_magic,
                ts_end: body.validity.end(),
            }),
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
        let head: [&[u8]; 2] = [self.magic.as_bytes(), &self.client_kex];
        seal_query(&head, &self.shared, self.origin, query, padding, nonce)
    }
}

/// The packet of `query` sealed with `shared`, after the parts of `head`: everything that comes before the client
/// nonce. The query is padded and sealed in the packet, which is allocated once.
fn seal_query(
    head: &[&[u8]],
    shared: &SharedKey,
    origin: Option<TicketOrigin>,
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
    let head_len = head.iter().map(|part| part.len()).sum::<usize>();
    let overhead = head_len + NONCE_HALF_LEN + TAG_LEN;
    if overhead + padded_len > MAX_PACKET_LEN {
        return Err(EncryptQueryError::TooLong);
    }

    let mut packet = Vec::with_capacity(overhead + padded_len);
    for part in head {
        packet.extend_from_slice(part);
    }
    packet.extend_from_slice(nonce.as_bytes());
    packet.resize(overhead, 0);
    packet.extend_from_slice(query);
    padding::pad(&mut packet, overhead + padded_len);
    let (sealed_head, ciphertext) = packet.split_at_mut(overhead);
    let tag = secretbox::seal(
        shared,
        &secretbox::query_nonce(nonce.as_bytes()),
        ciphertext,
    );
    if let Some((_, tag_slot)) = sealed_head.split_last_chunk_mut::<TAG_LEN>() {
        *tag_slot = tag;
    }

    let context = QueryContext {
        nonce,
        id: message.header.id,
        questions: message
            .questions
            .into_iter()
            .map(Question::into_owned)
            .collect(),
        shared: shared.clone(),
        origin,
    };
    Ok((packet, context))
}

/// A ticket the resolver gave, to resume a PQ session with (draft "Stateless Resumption"). A client that wants
/// its queries unlinkable does not keep it, or keeps it only on the network it came from.
///
/// Holds a secret, wiped when dropped. A resumed query may be answered with a new ticket: take it from
/// [`Opened::resumption`] and use that one next, as the old one expires.
#[derive(Clone)]
pub struct Resumption {
    ticket: Vec<u8>,
    lifetime: u32,
    secret: Zeroizing<[u8; KEY_LEN]>,
    origin: TicketOrigin,
}

impl Resumption {
    /// The opaque ticket, as it goes in a resumed query.
    #[must_use]
    pub fn ticket(&self) -> &[u8] {
        &self.ticket
    }

    /// The seconds from receipt the resolver says the ticket is good for.
    #[must_use]
    pub const fn lifetime(&self) -> u32 {
        self.lifetime
    }

    /// When the ticket expires, in Unix seconds, if it was received at `received_at`: the resolver's lifetime,
    /// cut short at the end of the certificate (draft "Issuing a Ticket").
    #[must_use]
    pub fn expires_at(&self, received_at: u64) -> u64 {
        received_at
            .saturating_add(u64::from(self.lifetime))
            .min(u64::from(self.origin.ts_end))
    }

    /// The packet for `query`, resumed with this ticket, and what is needed to read its response.
    ///
    /// `padding` is that of a classical UDP query, 256 bytes of packet at first (draft "PQ Query and Response
    /// Format"): an Anonymized relay applies its size check to resumed queries too. `nonce` is never to be used
    /// twice with this ticket.
    ///
    /// # Errors
    ///
    /// As [`ClientSession::encrypt_query`].
    pub fn encrypt_query(
        &self,
        query: &[u8],
        padding: QueryPadding,
        nonce: ClientNonce,
    ) -> Result<(Vec<u8>, QueryContext), EncryptQueryError> {
        let shared = pq::resumed_key(
            &self.secret,
            *self.origin.magic.as_bytes(),
            nonce.as_bytes(),
            &self.ticket,
        );
        let ticket_len =
            u16::try_from(self.ticket.len()).map_err(|_| EncryptQueryError::TooLong)?;
        let head: [&[u8]; 3] = [&RESUME_MAGIC, &ticket_len.to_be_bytes(), &self.ticket];
        seal_query(&head, &shared, Some(self.origin), query, padding, nonce)
    }
}

impl fmt::Debug for Resumption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resumption")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

/// What a client needs of a query to accept its response: the nonce, the ID and the questions.
#[derive(Debug, Clone)]
pub struct QueryContext {
    nonce: ClientNonce,
    id: u16,
    questions: Vec<Question<'static>>,
    shared: SharedKey,
    origin: Option<TicketOrigin>,
}

/// A response that was accepted: the DNS message, and the ticket it carried, if it did.
#[derive(Debug, Clone)]
pub struct Opened {
    /// The DNS response.
    pub message: Vec<u8>,
    /// The ticket of a PQ response, to resume with.
    pub resumption: Option<Resumption>,
}

impl QueryContext {
    /// The DNS response in `packet`, if it answers the query: authenticated, decrypted, unpadded, a DNS message
    /// with the query's ID and questions (draft "Client Queries Over UDP", "Resolver Responses Over UDP"). The
    /// ticket a PQ response carries is dropped: see [`QueryContext::open_response`].
    ///
    /// A client disregards a packet that fails, and goes on waiting for the one it asked for.
    ///
    /// # Errors
    ///
    /// [`ResponseError`] saying what is wrong with the packet.
    pub fn decrypt_response(&self, packet: &[u8]) -> Result<Vec<u8>, ResponseError> {
        self.open_response(packet).map(|opened| opened.message)
    }

    /// As [`QueryContext::decrypt_response`], with the ticket of a PQ response too.
    ///
    /// # Errors
    ///
    /// As [`QueryContext::decrypt_response`]; a PQ response whose control field is malformed is refused. A
    /// control field of another type or version is skipped, whatever it holds (draft "PQ Query and Response
    /// Format").
    pub fn open_response(&self, packet: &[u8]) -> Result<Opened, ResponseError> {
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

        let (message, resumption) = match self.origin {
            Some(origin) => self.split_control(&plaintext, origin)?,
            None => (plaintext.as_slice(), None),
        };
        let decoded = Message::decode(message)?;
        if decoded.message.header.id != self.id {
            return Err(ResponseError::IdMismatch);
        }
        if decoded.message.questions != self.questions {
            return Err(ResponseError::QuestionMismatch);
        }
        // The message ends the plaintext: the control field, if any, is all that goes before it.
        let control_len = plaintext.len() - message.len();
        plaintext.drain(..control_len);
        Ok(Opened {
            message: plaintext,
            resumption,
        })
    }

    /// The DNS message and the ticket of a PQ response plaintext: `<control-len> <control> <response>`.
    fn split_control<'p>(
        &self,
        plaintext: &'p [u8],
        origin: TicketOrigin,
    ) -> Result<(&'p [u8], Option<Resumption>), ResponseError> {
        let (len, rest) = plaintext
            .split_first_chunk::<2>()
            .ok_or(ResponseError::Control)?;
        let (control, message) = rest
            .split_at_checked(usize::from(u16::from_be_bytes(*len)))
            .ok_or(ResponseError::Control)?;
        let offer = TicketOffer::parse(control).map_err(|ControlError| ResponseError::Control)?;
        // A ticket whose resumed query, at the 256 bytes a classical UDP query starts at, would not fit the largest
        // packet is ignored, as `dnscrypt-proxy` does; the draft sets no limit ("Issuing a Ticket").
        let fits = |ticket: &[u8]| {
            resumed_head_len(ticket.len()) + NONCE_HALF_LEN + TAG_LEN + RESUMED_UDP_FLOOR
                <= MAX_PACKET_LEN
        };
        let resumption = offer
            .filter(|offer| fits(offer.ticket))
            .map(|offer| Resumption {
                ticket: offer.ticket.to_vec(),
                lifetime: offer.lifetime,
                secret: pq::resume_secret(
                    &self.shared,
                    *origin.magic.as_bytes(),
                    self.nonce.as_bytes(),
                ),
                origin,
            });
        Ok((message, resumption))
    }
}

#[cfg(test)]
mod tests {
    use dedens_proto::RecordType;

    use super::*;
    use crate::EncryptionSystem;

    /// The response to a query of this context, sealed as a resolver does, whose control field offers a ticket of
    /// `ticket_len` bytes. The one thing no resolver of this workspace makes: it issues tickets of 130 bytes.
    fn offering(ticket_len: usize) -> Result<Opened, ResponseError> {
        let question = Question::new("www.example".parse().expect("a name"), RecordType::A);
        let nonce = ClientNonce::from_bytes([3; NONCE_HALF_LEN]);
        let shared = SharedKey::new(EncryptionSystem::XWing, Zeroizing::new([5; KEY_LEN]));
        let context = QueryContext {
            nonce,
            id: 9,
            questions: vec![question.clone().into_owned()],
            shared: shared.clone(),
            origin: Some(TicketOrigin {
                magic: ClientMagic::try_from([1; 8]).expect("a magic"),
                ts_end: 1_800_000_000,
            }),
        };
        let mut control = b"PQDR\x01".to_vec();
        control.extend_from_slice(&600_u32.to_be_bytes());
        control.extend_from_slice(&u16::try_from(ticket_len).expect("a length").to_be_bytes());
        control.resize(control.len() + ticket_len, 7);
        let mut plaintext = u16::try_from(control.len())
            .expect("a length")
            .to_be_bytes()
            .to_vec();
        plaintext.extend_from_slice(&control);
        plaintext.extend_from_slice(&Message::query(9, question).to_vec().expect("encodes"));
        let padded = (plaintext.len() + 1).next_multiple_of(BLOCK);
        padding::pad(&mut plaintext, padded);
        let mut full_nonce = [0; NONCE_LEN];
        full_nonce[..NONCE_HALF_LEN].copy_from_slice(nonce.as_bytes());
        full_nonce[NONCE_HALF_LEN..].fill(4);
        let tag = secretbox::seal(&shared, &full_nonce, &mut plaintext);
        let packet = [&RESPONSE_MAGIC[..], &full_nonce, &tag, &plaintext].concat();
        context.open_response(&packet)
    }

    /// A ticket too large for a resumed query is ignored, as `dnscrypt-proxy` does (`pq.go`) when the resumed query,
    /// 256 bytes at least, would not fit the largest packet: the response is kept, the ticket is not. The largest
    /// ticket that fits is kept.
    #[test]
    fn a_ticket_too_large_for_a_resumed_query_is_ignored() {
        // "PQResume" (8), the two-byte length and the draft's 130-byte ticket: the 140 bytes before the nonce of the
        // 424-byte resumed query of the vectors (140 + 12 + 16 + 256).
        assert_eq!(resumed_head_len(130), 140);
        let largest =
            MAX_PACKET_LEN - RESUMED_UDP_FLOOR - resumed_head_len(0) - NONCE_HALF_LEN - TAG_LEN;
        let kept = offering(largest).expect("a response");
        assert_eq!(kept.resumption.expect("kept").ticket().len(), largest);
        let ignored = offering(largest + 1).expect("a response");
        assert!(ignored.resumption.is_none());
        assert!(
            ignored.message.len() >= 12,
            "the response is kept: a DNS header at least"
        );
    }
}
