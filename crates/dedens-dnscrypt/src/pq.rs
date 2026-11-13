//! `PQDNSCrypt`'s key schedule and its wire constants (draft "PQ Certificates", "PQ Key Derivation", "Stateless
//! Resumption"): HKDF-SHA256 from `ring`, over what the X-Wing KEM gives.

use ring::digest::{SHA256, digest};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use zeroize::Zeroizing;

use crate::certificate::{CertificateBody, ClientMagic};
use crate::error::ControlError;
use crate::key::{KEY_LEN, SharedKey};
use crate::system::EncryptionSystem;

/// `<resume-magic>`: `PQResume`, in place of a `<client-magic>` on a resumed query.
pub const RESUME_MAGIC: [u8; 8] = *b"PQResume";

/// The `<extensions>` of every PQ certificate, the `<pq-profile-ext>`: `PQD`, version 1, `<es-version>` 0x0003,
/// HKDF-SHA256, XChaCha20_DJB-Poly1305, the lengths of the encapsulation key (1216) and of the ciphertext (1120).
pub(crate) const PROFILE: [u8; 12] = [
    0x50, 0x51, 0x44, 0x01, 0x00, 0x03, 0x01, 0x01, 0x04, 0xc0, 0x04, 0x60,
];

/// The `<es-version>` of the X-Wing system.
pub(crate) const ES_VERSION: [u8; 2] = [0, 3];

/// Length of what a ticket seals (draft "Resumption Tickets"): the resume secret, the binding and the expiry.
pub(crate) const TICKET_PLAIN_LEN: usize = KEY_LEN + 2 + 8 + 4 + 4 + 4 + 32;

/// Length of a ticket: key id, nonce, tag and the sealed plaintext.
pub(crate) const TICKET_LEN: usize = 4 + 24 + 16 + TICKET_PLAIN_LEN;

/// [`TICKET_LEN`] as the `<ticket-len>` field holds it.
const TICKET_LEN_WIRE: u16 = 130;

const _: () = assert!(TICKET_LEN == 130 && TICKET_PLAIN_LEN == 86);

/// What a ticket binds a resumed session to: the certificate it was issued under (draft "Resumption Tickets":
/// the sealed certificate-context fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) es_version: [u8; 2],
    pub(crate) magic: [u8; 8],
    pub(crate) serial: u32,
    pub(crate) ts_end: u32,
    pub(crate) extensions_hash: [u8; 32],
}

impl Binding {
    pub(crate) fn of(body: &CertificateBody) -> Self {
        Self {
            es_version: body.resolver_key.system().es_version(),
            magic: *body.client_magic.as_bytes(),
            serial: body.serial,
            ts_end: body.validity.end(),
            extensions_hash: sha256(&[&body.extensions]),
        }
    }
}

/// SHA-256 of the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut input = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        input.extend_from_slice(part);
    }
    let mut out = [0; 32];
    out.copy_from_slice(digest(&SHA256, &input).as_ref());
    out
}

/// HKDF-SHA256 with a 32-byte output (RFC 5869).
fn hkdf(ikm: &[u8], salt: &[&[u8]], info: &[&[u8]]) -> Zeroizing<[u8; KEY_LEN]> {
    struct Len32;
    impl KeyType for Len32 {
        fn len(&self) -> usize {
            KEY_LEN
        }
    }
    let salt = salt.concat();
    let mut out = Zeroizing::new([0; KEY_LEN]);
    // `expand` and `fill` fail for an output of more than 255 hashes, and this is one.
    Salt::new(HKDF_SHA256, &salt)
        .extract(ikm)
        .expand(info, Len32)
        .expect("32 bytes of output")
        .fill(out.as_mut())
        .expect("32 bytes of output");
    out
}

/// `<cert-context>` up to the resolver key and the rest of the signed fields (draft "PQ Key Derivation"): a label,
/// `<es-version>`, `<protocol-minor-version>`, then what the provider signed.
pub(crate) fn cert_context(signed: &[u8]) -> Vec<u8> {
    let mut context = Vec::with_capacity(18 + signed.len());
    context.extend_from_slice(b"DNSCrypt-PQ-v1");
    context.extend_from_slice(&ES_VERSION);
    context.extend_from_slice(&[0, 0]);
    context.extend_from_slice(signed);
    context
}

/// The `<shared-key>` of a query that carries a ciphertext (draft "PQ Key Derivation").
pub(crate) fn session_key(
    context: &[u8],
    magic: ClientMagic,
    kem_secret: &[u8; KEY_LEN],
    ciphertext: &[u8],
) -> SharedKey {
    let key = hkdf(
        kem_secret,
        &[&ES_VERSION, magic.as_bytes()],
        &[context, ciphertext],
    );
    SharedKey::new(EncryptionSystem::XWing, key)
}

/// The secret a ticket carries, from the key and the client nonce of the query it answers (draft "Resumption
/// Tickets").
pub(crate) fn resume_secret(
    shared: &SharedKey,
    magic: [u8; 8],
    client_nonce: &[u8; 12],
) -> Zeroizing<[u8; KEY_LEN]> {
    hkdf(
        shared.bytes(),
        &[&magic, client_nonce],
        &[b"DNSCrypt-PQ-resume-secret-v1"],
    )
}

/// The `<shared-key>` of a resumed query (draft "Resuming").
pub(crate) fn resumed_key(
    resume_secret: &[u8; KEY_LEN],
    magic: [u8; 8],
    client_nonce: &[u8; 12],
    ticket: &[u8],
) -> SharedKey {
    let key = hkdf(
        resume_secret,
        &[&magic, client_nonce],
        &[b"DNSCrypt-PQ-resumed-query-v1", &sha256(&[ticket])],
    );
    SharedKey::new(EncryptionSystem::XWing, key)
}

/// A ticket a response carries, with its lifetime: the `<control>` of the draft ("PQ Query and Response Format").
///
/// Only version 1, `PQDR`, is defined; a block of another magic or another version is no ticket and is skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketOffer<'c> {
    /// How long the resolver says the ticket is good for, in seconds from receipt.
    pub lifetime: u32,
    /// The ticket, opaque to the client.
    pub ticket: &'c [u8],
}

/// `<control>` magic of a ticket: `PQDR`.
const CONTROL_MAGIC: [u8; 4] = *b"PQDR";

/// `<control-version>` this crate reads and writes.
const CONTROL_VERSION: u8 = 1;

impl<'c> TicketOffer<'c> {
    /// The ticket in `control`, the bytes after `<control-len>`.
    ///
    /// An empty block, another magic and another version give `Ok(None)`: the client keeps the response and has
    /// no ticket (draft "PQ Query and Response Format").
    ///
    /// # Errors
    ///
    /// [`ControlError`] when a version 1 block is cut short, longer than its ticket, or holds no ticket or no
    /// lifetime.
    pub fn parse(control: &'c [u8]) -> Result<Option<Self>, ControlError> {
        let Some((magic, rest)) = control.split_first_chunk::<4>() else {
            return Ok(None);
        };
        if *magic != CONTROL_MAGIC {
            return Ok(None);
        }
        let (&version, rest) = rest.split_first().ok_or(ControlError)?;
        if version != CONTROL_VERSION {
            return Ok(None);
        }
        let (lifetime, rest) = rest.split_first_chunk::<4>().ok_or(ControlError)?;
        let (len, ticket) = rest.split_first_chunk::<2>().ok_or(ControlError)?;
        let lifetime = u32::from_be_bytes(*lifetime);
        if lifetime == 0
            || ticket.is_empty()
            || ticket.len() != usize::from(u16::from_be_bytes(*len))
        {
            return Err(ControlError);
        }
        Ok(Some(Self { lifetime, ticket }))
    }
}

/// The `<control>` block of a ticket of `lifetime` seconds.
pub(crate) fn control(lifetime: u32, ticket: &[u8; TICKET_LEN]) -> Vec<u8> {
    let mut control = Vec::with_capacity(11 + TICKET_LEN);
    control.extend_from_slice(&CONTROL_MAGIC);
    control.push(CONTROL_VERSION);
    control.extend_from_slice(&lifetime.to_be_bytes());
    control.extend_from_slice(&TICKET_LEN_WIRE.to_be_bytes());
    control.extend_from_slice(ticket);
    control
}
