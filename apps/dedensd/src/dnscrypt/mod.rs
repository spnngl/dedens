//! `dedensd` as a `DNSCrypt` resolver (D99): the provider key read from its file, the short-term key pairs and the
//! certificates made from them, rotated and erased as time passes, and the answer to the certificate query, which is
//! sent in the clear (draft-denis-dprive-dnscrypt-11, "Certificates", "Key Management"). Sans I/O but for the
//! randomness: the loops that carry queries are `serve/dnscrypt.rs`'s.

use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use dedens_dnscrypt::{
    Certificate, CertificateBody, ClientMagic, EncryptionSystem, ResolverKey, SecretKey,
    SigningKey, Validity,
};
use dedens_net::entropy::Entropy;
use dedens_net::io::Io;
use dedens_net::stamp::{DEFAULT_PORT, DnsCrypt, Endpoint, ProviderName, Stamp};
use dedens_proto::edns::Edns;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Name, Opcode, Record, RecordType, Ttl};

use crate::config::{SECRET_LEN, address, provider, read_secret};

/// How often a new key pair is made, in seconds: the draft requires a rotation every 24 hours at most ("Key
/// Management"), and twelve keep two certificates valid at any moment, so a client that fetched the older one an
/// instant before the rotation has half a validity left to refresh in.
const ROTATION: u64 = 12 * 3600;

/// How long a certificate is valid from its making, in seconds: twice [`ROTATION`], so that the last two key pairs
/// are always valid, and no key pair is kept longer than a day.
const VALIDITY: u64 = 24 * 3600;

/// How much earlier than its making a certificate starts to be valid, in seconds: a client whose clock is slow by
/// less does not find the new certificate "not yet valid".
const BACKDATE: u64 = 3600;

/// How long to wait after a rotation that failed (no randomness), in seconds, before trying again; the keys of the
/// last one serve meanwhile.
const RETRY: u64 = 60;

/// The TTL of the certificates in the answer to their query, in seconds: shorter than [`ROTATION`] by far, and
/// longer than a client's burst of retries.
const CERTIFICATE_TTL: u32 = 600;

/// The settings of the `dnscrypt` section (D99): kept to tell a reload that changed them, which takes a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    /// The name the certificates are asked under: `2.dnscrypt-cert.` and a domain.
    pub(crate) provider: ProviderName,
    /// The file with the provider's `Ed25519` seed, 64 hexadecimal digits.
    pub(crate) key: PathBuf,
    /// The encryption systems offered, each once.
    pub(crate) systems: Vec<EncryptionSystem>,
}

impl Section {
    /// The resolver this section describes: its provider key read, its first key pairs made.
    ///
    /// # Errors
    ///
    /// A key file that does not read, is not 64 hexadecimal digits, or is readable by others (D115); a seed the
    /// crypto library refuses; no randomness; no clock.
    pub(crate) fn service(&self) -> anyhow::Result<Service> {
        let seed = read_secret(&self.key, "`dnscrypt`")?;
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("`dnscrypt`: the system clock is before 1970")?
            .as_secs();
        Service::new(
            &seed,
            self.provider.clone(),
            self.systems.clone(),
            unix,
            &dedens_net::io::Compio,
        )
    }
}

/// The resolver: the provider's signing key, and the key pairs it serves, one state for all serving threads, swapped
/// as a whole (D99).
pub(crate) struct Service {
    signing: SigningKey,
    provider: ProviderName,
    systems: Vec<EncryptionSystem>,
    /// Unix time when the service was made, which a thread's seconds since its start count from.
    epoch: u64,
    state: Mutex<Arc<KeySet>>,
}

impl Service {
    /// The resolver of the seed `seed`, which signs certificates for `provider`, offering `systems`, at the Unix time
    /// `unix`, with its first key pairs made.
    ///
    /// # Errors
    ///
    /// A seed the crypto library refuses, `systems` empty, or the first key pairs not made: see [`Service::keys`].
    pub(crate) fn new(
        seed: &[u8; SECRET_LEN],
        provider: ProviderName,
        systems: Vec<EncryptionSystem>,
        unix: u64,
        io: &impl Io,
    ) -> anyhow::Result<Self> {
        let Ok(signing) = SigningKey::from_seed(seed) else {
            bail!("`dnscrypt`: the key is not an Ed25519 seed");
        };
        if systems.is_empty() {
            bail!("`dnscrypt`: no encryption system");
        }
        let first = KeySet::default().advance(&signing, &systems, unix, io);
        if first.keys.is_empty() {
            bail!("`dnscrypt`: cannot make a key pair: no randomness");
        }
        Ok(Self {
            signing,
            provider,
            systems,
            epoch: unix,
            state: Mutex::new(Arc::new(first)),
        })
    }

    /// The name certificates are asked under.
    pub(crate) fn provider(&self) -> &Name<'static> {
        self.provider.name()
    }

    /// The Unix time `elapsed` seconds after the service was made.
    pub(crate) fn unix(&self, elapsed: u32) -> u64 {
        self.epoch.saturating_add(u64::from(elapsed))
    }

    /// The stamp of the resolver listening at `addr`: the properties it claims are none (it says nothing of logs or
    /// filtering; a stamp's reader trusts them).
    pub(crate) fn stamp(&self, addr: SocketAddr) -> Stamp {
        Stamp::DnsCrypt(DnsCrypt {
            properties: dedens_net::stamp::Properties::default(),
            address: Endpoint {
                ip: addr.ip(),
                port: NonZeroU16::new(addr.port()).filter(|port| port.get() != DEFAULT_PORT),
            },
            public_key: *self.signing.provider_key().as_bytes(),
            provider_name: self.provider.clone(),
        })
    }

    /// The key pairs served at the Unix time `unix`, made again if it is time (see [`ROTATION`]): the state every
    /// thread shares, swapped as a whole once a thread finds it due. A rotation that cannot draw randomness keeps the
    /// keys of the last, which serve until their certificates expire, and is tried again after [`RETRY`].
    pub(crate) fn keys(&self, unix: u64, io: &impl Io) -> Arc<KeySet> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.refresh_at <= unix {
            *state = Arc::new(state.advance(&self.signing, &self.systems, unix, io));
        }
        Arc::clone(&state)
    }
}

/// A new provider key for `provider_name` and the stamp of the resolver at `address`, as `dedensd dnscrypt-keygen`
/// prints them: the `secret_key` line of the `dnscrypt` section, and the stamp clients take.
///
/// # Errors
///
/// A provider name or an address that does not read, or no randomness.
pub(crate) fn keygen(provider_name: &str, address_text: &str) -> anyhow::Result<String> {
    use std::fmt::Write as _;

    let provider = provider(provider_name)?;
    let addr = address(address_text, DEFAULT_PORT)
        .with_context(|| format!("`--address` {address_text:?} is neither IP:PORT nor IP"))?;
    let mut seed = zeroize::Zeroizing::new([0; SECRET_LEN]);
    getrandom::fill(seed.as_mut_slice()).context("no randomness")?;
    let service = Service::new(
        &seed,
        provider,
        vec![EncryptionSystem::XChaCha20Poly1305],
        0,
        &dedens_net::io::Compio,
    )?;
    let mut text = String::from("secret_key: ");
    for byte in seed.iter() {
        write!(text, "{byte:02x}")?;
    }
    writeln!(text, "\nstamp: {}", service.stamp(addr))?;
    Ok(text)
}

/// A key pair and its certificate.
pub(crate) struct Issued {
    pub(crate) resolver: ResolverKey,
    certificate: Certificate,
    /// When it was made, Unix seconds.
    at: u64,
}

impl Issued {
    pub(crate) fn system(&self) -> EncryptionSystem {
        self.certificate.body().system
    }
}

/// The key pairs of the certificates still valid, newest first, and when to look at them again. Immutable: a thread
/// holds the one it last took from [`Service::keys`]; a key pair is erased when the last set holding it is dropped.
#[derive(Default)]
pub(crate) struct KeySet {
    keys: Vec<Arc<Issued>>,
    /// The Unix time from which the set must be made again: a rotation is due, or a certificate expires.
    pub(crate) refresh_at: u64,
}

impl KeySet {
    /// The set after the key pairs whose certificates are not valid at `now` are dropped, and, if the newest is
    /// [`ROTATION`] old or there is none, a new pair for each of `systems`. Kept ones stay valid and accepted
    /// (draft, "Key Management": a resolver keeps accepting queries for a certificate a client may still hold).
    fn advance(
        &self,
        signing: &SigningKey,
        systems: &[EncryptionSystem],
        now: u64,
        io: &impl Io,
    ) -> Self {
        let mut keys: Vec<Arc<Issued>> = self
            .keys
            .iter()
            .filter(|issued| issued.certificate.is_valid_at(now))
            .cloned()
            .collect();
        let newest = keys.iter().map(|issued| issued.at).max();
        let mut due = newest.map_or(now, |newest| newest.saturating_add(ROTATION));
        if due <= now {
            match issue(signing, systems, now, io) {
                Ok(mut fresh) => {
                    fresh.append(&mut keys);
                    keys = fresh;
                    due = now.saturating_add(ROTATION);
                }
                Err(error) => {
                    tracing::warn!(error = format!("{error:#}"), "dnscrypt: no new key pair");
                    due = now.saturating_add(RETRY);
                }
            }
        }
        let expiry = keys
            .iter()
            .map(|issued| u64::from(issued.certificate.body().validity.end()).saturating_add(1))
            .min();
        Self {
            keys,
            refresh_at: expiry.map_or(due, |expiry| expiry.min(due)),
        }
    }

    /// The key pair a query packet is for, by its client magic.
    pub(crate) fn find(&self, packet: &[u8]) -> Option<&Arc<Issued>> {
        let magic = packet.get(..8)?;
        self.keys
            .iter()
            .find(|issued| issued.resolver.client_magic().as_bytes() == magic)
    }

    /// The number of key pairs.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.keys.len()
    }

    /// The newest key pair.
    #[cfg(test)]
    pub(crate) fn newest(&self) -> Option<&Arc<Issued>> {
        self.keys.first()
    }

    /// The validity end of the last certificate made, as Unix seconds.
    #[cfg(test)]
    pub(crate) fn last_end(&self) -> Option<u32> {
        self.keys
            .iter()
            .map(|issued| issued.certificate.body().validity.end())
            .max()
    }

    /// The answer to `query` if it is the clear certificate query for `provider` (draft, "Certificates"): a TXT
    /// question in class IN for the provider name, answered with the newest certificate of each system. `None` for
    /// any other message, and when there is no certificate to give.
    pub(crate) fn certificates(&self, query: &[u8], provider: &Name<'_>) -> Option<Vec<u8>> {
        let message = Message::decode(query).ok()?.message;
        let [question] = message.questions.as_slice() else {
            return None;
        };
        let asks = question.qtype == RecordType::TXT
            && question.qclass == Class::IN
            && question.name == *provider
            && message.header.opcode == Opcode::QUERY
            && !message.header.flags.contains(Flags::QR);
        if !asks {
            return None;
        }
        let mut seen = Vec::new();
        let mut answer = Vec::new();
        for issued in &self.keys {
            let system = issued.system();
            if seen.contains(&system) {
                continue;
            }
            seen.push(system);
            let txt = issued.certificate.to_txt().ok()?;
            let ttl = Ttl::new(CERTIFICATE_TTL)?;
            answer.push(Record::new(
                question.name.clone().into_owned(),
                Class::IN,
                ttl,
                &RData::Txt(txt),
            ));
        }
        if answer.is_empty() {
            return None;
        }
        let mut response = message.clone().into_owned();
        response.header.flags = response.header.flags.with(Flags::QR).with(Flags::AA);
        response.answer = answer;
        response.authority.clear();
        response.additional.clear();
        response.edns = message.edns.as_ref().map(|_| Edns::default());
        response.to_vec().ok()
    }
}

/// A new key pair for each of `systems`, made at `now`: its certificate valid from [`BACKDATE`] before to
/// [`VALIDITY`] after, signed by `signing`. The client magic is the start of the public key, which a client cannot
/// tell from a random one.
///
/// # Errors
///
/// No randomness, a time past 2106 (certificates count in 32 bits), or the improbable key whose start the draft
/// forbids as a magic.
fn issue(
    signing: &SigningKey,
    systems: &[EncryptionSystem],
    now: u64,
    io: &impl Io,
) -> anyhow::Result<Vec<Arc<Issued>>> {
    let start = u32::try_from(now.saturating_sub(BACKDATE)).context("time past 2106")?;
    let end = u32::try_from(now.saturating_add(VALIDITY)).context("time past 2106")?;
    let serial = u32::try_from(now).context("time past 2106")?;
    let validity = Validity::new(start, end).context("an empty validity")?;
    systems
        .iter()
        .map(|&system| {
            let mut entropy = Entropy::from_io(io).context("no randomness")?;
            let secret = SecretKey::generate(&mut entropy);
            entropy.finish().context("no randomness")?;
            let public = secret.public_key();
            let magic = <[u8; 8]>::try_from(public.as_bytes().get(..8).unwrap_or_default())
                .ok()
                .and_then(|bytes| ClientMagic::try_from(bytes).ok())
                .context("a key that cannot be a client magic")?;
            let certificate = Certificate::sign(
                signing,
                CertificateBody {
                    system,
                    resolver_key: public,
                    client_magic: magic,
                    serial,
                    validity,
                    extensions: Vec::new(),
                },
            );
            let resolver = ResolverKey::new(&certificate, secret)
                .context("a certificate that is not its key's")?;
            Ok(Arc::new(Issued {
                resolver,
                certificate,
                at: now,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests;
