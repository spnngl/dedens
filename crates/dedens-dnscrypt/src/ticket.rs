//! Resumption tickets, the resolver's side: sealing them under a ticket key and opening them in a resumed query
//! (draft "Stateless Resumption").

use std::fmt;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::error::QueryError;
use crate::key::{KEY_LEN, SharedKey};
use crate::pq::{self, Binding, RESUME_MAGIC, TICKET_LEN, TICKET_PLAIN_LEN};
use crate::resolver::ResponseContext;
use crate::secretbox::{self, NONCE_LEN, TAG_LEN};
use crate::system::EncryptionSystem;
use crate::{CLIENT_MAGIC_LEN, MAX_PACKET_LEN, NONCE_HALF_LEN};

/// Length of a `<ticket-key-id>`.
const KEY_ID_LEN: usize = 4;

/// One ticket key, TK: what the resolver seals tickets with, wiped when dropped (draft "Resumption Tickets").
#[derive(Clone)]
pub struct TicketKey {
    id: [u8; KEY_ID_LEN],
    key: SharedKey,
}

impl TicketKey {
    /// The key of the 32 bytes `key`, named `id` in the tickets it seals (`<ticket-key-id>`).
    #[must_use]
    pub fn new(id: [u8; KEY_ID_LEN], key: [u8; KEY_LEN]) -> Self {
        Self {
            id,
            key: SharedKey::new(EncryptionSystem::XChaCha20Poly1305, Zeroizing::new(key)),
        }
    }

    /// A fresh key and id from `rng`.
    #[must_use]
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut id = [0; KEY_ID_LEN];
        let mut key = Zeroizing::new([0; KEY_LEN]);
        rng.fill_bytes(&mut id);
        rng.fill_bytes(key.as_mut());
        Self::new(id, *key)
    }
}

impl fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The ticket keys a resolver has: the one it seals with, and the ones it only opens with (draft "Resumption
/// Tickets": the key before the last rotation, kept for the tickets sealed under it).
#[derive(Debug, Clone)]
pub struct TicketKeys {
    current: TicketKey,
    previous: Option<TicketKey>,
}

impl TicketKeys {
    /// The keys `current`, which seals, and `previous`, which only opens.
    ///
    /// A key a resolver rotates out is dropped, so that it is wiped, as soon as the tickets sealed under it have
    /// expired: a recorded resumed query is open to whoever gets a key until then.
    #[must_use]
    pub const fn new(current: TicketKey, previous: Option<TicketKey>) -> Self {
        Self { current, previous }
    }

    /// The keys after a rotation to `next`, which seals from now on: the key that sealed until now only opens.
    #[must_use]
    pub fn rotated(&self, next: TicketKey) -> Self {
        Self::new(next, Some(self.current.clone()))
    }

    /// The same keys with no previous one: the tickets it sealed have expired.
    #[must_use]
    pub fn without_previous(&self) -> Self {
        Self::new(self.current.clone(), None)
    }

    /// A ticket for the session of `context`, good for `lifetime` seconds from `now` (Unix seconds), cut short
    /// at the end of the certificate; `None` for a context that is no PQ session, or when nothing is left of the
    /// certificate.
    ///
    /// `lifetime` is the resolver's, and it must not run past the life of the ticket key: the caller keeps the
    /// key at least that long. `rng` makes the ticket nonce.
    #[must_use]
    pub fn issue(
        &self,
        context: &ResponseContext,
        now: u64,
        lifetime: u32,
        rng: &mut impl CryptoRng,
    ) -> Option<Ticket> {
        let binding = context.binding()?;
        let expiry = now
            .saturating_add(u64::from(lifetime))
            .min(u64::from(binding.ts_end));
        let granted = u32::try_from(expiry.checked_sub(now)?).ok()?;
        let expiry = u32::try_from(expiry).ok()?;
        if granted == 0 {
            return None;
        }
        let secret = pq::resume_secret(context.shared(), binding.magic, context.client_nonce());

        let mut sealed = Vec::with_capacity(TICKET_PLAIN_LEN);
        sealed.extend_from_slice(&*secret);
        sealed.extend_from_slice(&binding.es_version);
        sealed.extend_from_slice(&binding.magic);
        sealed.extend_from_slice(&binding.serial.to_be_bytes());
        sealed.extend_from_slice(&binding.ts_end.to_be_bytes());
        sealed.extend_from_slice(&expiry.to_be_bytes());
        sealed.extend_from_slice(&binding.extensions_hash);
        let mut nonce = [0; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let tag = secretbox::seal(&self.current.key, &nonce, &mut sealed);

        let mut bytes = [0; TICKET_LEN];
        let parts = [&self.current.id[..], &nonce, &tag, &sealed];
        let mut filled = 0;
        for part in parts {
            bytes
                .get_mut(filled..filled + part.len())?
                .copy_from_slice(part);
            filled += part.len();
        }
        Some(Ticket {
            bytes: Box::new(bytes),
            lifetime: granted,
        })
    }

    /// The resumed query in `packet`, with its ticket opened: the first step of answering it, before the
    /// certificate it is bound to is looked for (draft "Resuming").
    ///
    /// # Errors
    ///
    /// [`QueryError`] saying why the resolver drops the packet without a response: it is cut short, its ticket was
    /// sealed under no key this has or was changed, or the ticket expired at `now`.
    pub fn open<'p>(&self, packet: &'p [u8], now: u64) -> Result<ResumedQuery<'p>, QueryError> {
        if packet.len() > MAX_PACKET_LEN {
            return Err(QueryError::TooLong);
        }
        let (magic, rest) = packet
            .split_first_chunk::<CLIENT_MAGIC_LEN>()
            .ok_or(QueryError::Truncated)?;
        if *magic != RESUME_MAGIC {
            return Err(QueryError::UnknownClientMagic);
        }
        let (len, rest) = rest.split_first_chunk::<2>().ok_or(QueryError::Truncated)?;
        let len = usize::from(u16::from_be_bytes(*len));
        let (ticket, rest) = rest.split_at_checked(len).ok_or(QueryError::Truncated)?;
        let (client_nonce, rest) = rest
            .split_first_chunk::<NONCE_HALF_LEN>()
            .ok_or(QueryError::Truncated)?;
        let (tag, ciphertext) = rest
            .split_first_chunk::<TAG_LEN>()
            .ok_or(QueryError::Truncated)?;

        let ticket: &[u8; TICKET_LEN] = ticket.try_into().map_err(|_| QueryError::Ticket)?;
        let (id, ticket_rest) = ticket
            .split_first_chunk::<KEY_ID_LEN>()
            .ok_or(QueryError::Ticket)?;
        let (nonce, ticket_rest) = ticket_rest
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(QueryError::Ticket)?;
        let (ticket_tag, sealed) = ticket_rest
            .split_first_chunk::<TAG_LEN>()
            .ok_or(QueryError::Ticket)?;
        let key = [Some(&self.current), self.previous.as_ref()]
            .into_iter()
            .flatten()
            .find(|key| key.id == *id)
            .ok_or(QueryError::Ticket)?;
        let mut plain = Zeroizing::new(sealed.to_vec());
        secretbox::open(&key.key, nonce, ticket_tag, &mut plain).map_err(|_| QueryError::Ticket)?;

        let (secret, rest) = plain
            .split_first_chunk::<KEY_LEN>()
            .ok_or(QueryError::Ticket)?;
        let (es_version, rest) = rest.split_first_chunk().ok_or(QueryError::Ticket)?;
        let (ticket_magic, rest) = rest.split_first_chunk().ok_or(QueryError::Ticket)?;
        let (serial, rest) = rest.split_first_chunk().ok_or(QueryError::Ticket)?;
        let (ts_end, rest) = rest.split_first_chunk().ok_or(QueryError::Ticket)?;
        let (expiry, extensions_hash) = rest.split_first_chunk().ok_or(QueryError::Ticket)?;
        let expiry = u32::from_be_bytes(*expiry);
        if now > u64::from(expiry) {
            return Err(QueryError::TicketExpired);
        }
        Ok(ResumedQuery {
            packet_len: packet.len(),
            ticket,
            client_nonce,
            tag,
            ciphertext,
            secret: Zeroizing::new(*secret),
            binding: Binding {
                es_version: *es_version,
                magic: *ticket_magic,
                serial: u32::from_be_bytes(*serial),
                ts_end: u32::from_be_bytes(*ts_end),
                extensions_hash: *extensions_hash.first_chunk().ok_or(QueryError::Ticket)?,
            },
            expiry,
        })
    }
}

/// A ticket to give a client, with the lifetime to tell it (draft "Resumption Tickets").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    bytes: Box<[u8; TICKET_LEN]>,
    lifetime: u32,
}

impl Ticket {
    /// The seconds from now the ticket is good for.
    #[must_use]
    pub const fn lifetime(&self) -> u32 {
        self.lifetime
    }

    /// The 130 bytes of the ticket, as a client sends them back in a resumed query.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &*self.bytes
    }

    /// The `<control>` block that carries the ticket in a response.
    pub(crate) fn control(&self) -> Vec<u8> {
        pq::control(self.lifetime, &self.bytes)
    }
}

/// A resumed query whose ticket opened: what the resolver reads of it until it knows which certificate it is for
/// (draft "Resuming").
pub struct ResumedQuery<'p> {
    pub(crate) packet_len: usize,
    pub(crate) ticket: &'p [u8],
    pub(crate) client_nonce: &'p [u8; NONCE_HALF_LEN],
    pub(crate) tag: &'p [u8; TAG_LEN],
    pub(crate) ciphertext: &'p [u8],
    pub(crate) secret: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) binding: Binding,
    expiry: u32,
}

impl ResumedQuery<'_> {
    /// The `<client-magic>` of the certificate the ticket was issued under, which names the key to resume with.
    #[must_use]
    pub const fn client_magic(&self) -> &[u8; CLIENT_MAGIC_LEN] {
        &self.binding.magic
    }

    /// When the ticket expires, in Unix seconds: a resolver that renews tickets does it for one close to this.
    #[must_use]
    pub const fn expiry(&self) -> u32 {
        self.expiry
    }
}

impl fmt::Debug for ResumedQuery<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumedQuery")
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}
