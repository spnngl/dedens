//! `dedensd` as a `DNSCrypt` resolver (D99): the provider key read from its file, the short-term key pairs and the
//! certificates made from them, rotated and erased as time passes, and the answer to the certificate query, which is
//! sent in the clear (draft-denis-dprive-dnscrypt-11, "Certificates", "Key Management"). Sans I/O but for the
//! randomness: the loops that carry queries are `serve/dnscrypt.rs`'s.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use dedens_dnscrypt::{
    Carrier, Certificate, CertificateBody, ClientMagic, EncryptionSystem, ResolverKey,
    ResolverPublicKey, ResolverSecret, SecretKey, SigningKey, TicketKey, TicketKeys, Validity,
    XWingSecretKey,
};
use dedens_net::entropy::Entropy;
use dedens_net::io::Io;
use dedens_net::stamp::{DEFAULT_PORT, DnsCrypt, Endpoint, ProviderName, Stamp};
use dedens_proto::edns::Edns;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Name, Opcode, Record, RecordType, Ttl};
use dedens_server::{Budget, Budgets, Slot};

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

/// How long a resumption ticket is good for, in seconds (D101): short, so that a recorded resumed query is of little
/// use and the key before a rotation is kept briefly, and no longer than a client's burst of queries needs.
pub(crate) const TICKET_LIFETIME: u32 = 600;

/// What a client network, a /24 of IPv4 or a /48 of IPv6, may have decapsulated by default, a tenth of
/// [`GLOBAL_DECAPSULATIONS`] (D101, D117): a unit is one `X-Wing` decapsulation, 101 µs of a core
/// (`docs/benchmarks.md`), so 250 a second are 2.5% of one, and a client that resumes asks for one a session.
const CLIENT_DECAPSULATIONS: Budget = Budget {
    per_second: 250,
    burst: 500,
    table: 1 << 16,
};

/// What all clients together may have decapsulated by default, shared by all threads: 2500 a second, a quarter of a
/// core, with 5000 at once (D101).
const GLOBAL_DECAPSULATIONS: Budget = Budget {
    per_second: 2_500,
    burst: 5_000,
    table: 1,
};

/// What bounds the decapsulations a resolver does for packets nobody has authenticated (D101; the draft's "Resolvers
/// SHOULD limit unauthenticated KEM work under load"), shared by all threads (D117: one table per thread would give a
/// client the budget of each thread its packets are spread over).
pub(crate) struct Decapsulations {
    clients: Budgets,
    global: Budgets,
}

impl Decapsulations {
    /// The budgets `client` for each network and `global` for all.
    ///
    /// # Errors
    ///
    /// A budget the table refuses: a burst above 2^30, or a table of no bucket or too many.
    pub(crate) fn new(client: Budget, global: Budget) -> anyhow::Result<Self> {
        Ok(Self {
            clients: Budgets::new(client).context("`dnscrypt`: a client decapsulation budget")?,
            global: Budgets::new(global).context("`dnscrypt`: the decapsulation budget")?,
        })
    }

    /// Whether the client at `from` may have a packet decapsulated at second `now`, by the budget that refuses it
    /// (`"client"` or `"global"`) if not. The network of `from` pays a unit first, then all clients: a refusal by
    /// the second gives the first back, so a client over the global budget does not spend its network's. `proven` is
    /// an address the client cannot have spoofed (a connection): an unproven one has a bucket of its own, so a flood
    /// in a victim's name from UDP drains only the victim's unproven bucket (D113). `exempt` is a source on the rate
    /// limit's exempt list: it pays no network unit.
    ///
    /// # Errors
    ///
    /// The name of the budget that is spent.
    pub(crate) fn admit(
        &self,
        from: IpAddr,
        proven: bool,
        exempt: bool,
        now: u32,
    ) -> Result<(), &'static str> {
        let network = (!exempt).then(|| Slot::new(from, proven));
        if let Some(network) = network
            && !self.clients.admit(network, now)
        {
            return Err("client");
        }
        if !self.global.admit(Slot::ONLY, now) {
            if let Some(network) = network {
                self.clients.refund(network);
            }
            return Err("global");
        }
        Ok(())
    }
}

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
    /// What the `X-Wing` packets of unauthenticated clients may cost (D101).
    decapsulations: Decapsulations,
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
            decapsulations: Decapsulations::new(CLIENT_DECAPSULATIONS, GLOBAL_DECAPSULATIONS)?,
        })
    }

    /// The service with `decapsulations` instead of the default budgets.
    #[cfg(test)]
    pub(crate) fn with_decapsulations(self, decapsulations: Decapsulations) -> Self {
        Self {
            decapsulations,
            ..self
        }
    }

    /// What bounds the decapsulations.
    pub(crate) const fn decapsulations(&self) -> &Decapsulations {
        &self.decapsulations
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
        self.certificate.body().system()
    }
}

/// The key pairs of the certificates still valid, newest first, and when to look at them again. Immutable: a thread
/// holds the one it last took from [`Service::keys`]; a key pair is erased when the last set holding it is dropped.
#[derive(Default)]
pub(crate) struct KeySet {
    keys: Vec<Arc<Issued>>,
    /// The keys tickets are sealed with, when `X-Wing` is offered and a key could be made (D101).
    tickets: Option<Ticketing>,
    /// The Unix time from which the set must be made again: a rotation is due, or a certificate expires.
    pub(crate) refresh_at: u64,
}

/// The ticket keys, when the current one was made (Unix seconds), and whether the one before it is still kept.
#[derive(Clone)]
struct Ticketing {
    keys: TicketKeys,
    rotated: u64,
    has_previous: bool,
}

/// The ticket keys after a rotation: a new key seals, the one before only opens (D101). `old` stays when no key can
/// be made: tickets go on with it.
fn rotate_tickets(old: Option<Ticketing>, now: u64, io: &impl Io) -> Option<Ticketing> {
    let Ok(mut entropy) = Entropy::from_io(io) else {
        return old;
    };
    let next = TicketKey::generate(&mut entropy);
    if entropy.finish().is_err() {
        return old;
    }
    Some(match old {
        Some(old) => Ticketing {
            keys: old.keys.rotated(next),
            rotated: now,
            has_previous: true,
        },
        None => Ticketing {
            keys: TicketKeys::new(next, None),
            rotated: now,
            has_previous: false,
        },
    })
}

impl KeySet {
    /// The keys to seal and open tickets with (D101): `None` unless `X-Wing` is offered.
    pub(crate) fn tickets(&self) -> Option<&TicketKeys> {
        self.tickets.as_ref().map(|ticketing| &ticketing.keys)
    }

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
        let mut tickets = self.tickets.clone();
        if due <= now {
            match issue(signing, systems, now, io) {
                Ok(mut fresh) => {
                    fresh.append(&mut keys);
                    keys = fresh;
                    due = now.saturating_add(ROTATION);
                    if systems.contains(&EncryptionSystem::XWing) {
                        tickets = rotate_tickets(tickets, now, io);
                    }
                }
                Err(error) => {
                    tracing::warn!(error = format!("{error:#}"), "dnscrypt: no new key pair");
                    due = now.saturating_add(RETRY);
                }
            }
        }
        // The key before the last rotation opens the tickets sealed under it, until they have expired (D101).
        let mut ticket_due = u64::MAX;
        if let Some(ticketing) = tickets.as_mut().filter(|ticketing| ticketing.has_previous) {
            let stale = ticketing.rotated.saturating_add(u64::from(TICKET_LIFETIME));
            if stale <= now {
                ticketing.keys = ticketing.keys.without_previous();
                ticketing.has_previous = false;
            } else {
                ticket_due = stale;
            }
        }
        let expiry = keys
            .iter()
            .map(|issued| u64::from(issued.certificate.body().validity.end()).saturating_add(1))
            .min();
        Self {
            keys,
            tickets,
            refresh_at: expiry.map_or(due, |expiry| expiry.min(due)).min(ticket_due),
        }
    }

    /// The key pair a query packet is for, by its client magic.
    pub(crate) fn find(&self, packet: &[u8]) -> Option<&Arc<Issued>> {
        self.find_magic(packet.get(..8)?)
    }

    /// The key pair of the client magic `magic`.
    pub(crate) fn find_magic(&self, magic: &[u8]) -> Option<&Arc<Issued>> {
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
    ///
    /// Over UDP the `X-Wing` certificate goes in only when the answer is no longer than the query (draft
    /// "Certificate Retrieval"; D101): else the answer has the others, with TC set, and the client asks again over TCP.
    pub(crate) fn certificates(
        &self,
        query: &[u8],
        provider: &Name<'_>,
        carrier: Carrier,
    ) -> Option<Vec<u8>> {
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
        let mut post_quantum = Vec::new();
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
            post_quantum.push(system == EncryptionSystem::XWing);
        }
        if answer.is_empty() {
            return None;
        }
        let respond = |with_pq: bool| {
            let mut response = message.clone().into_owned();
            response.header.flags = response.header.flags.with(Flags::QR).with(Flags::AA);
            let kept = answer
                .iter()
                .zip(&post_quantum)
                .filter(|(_, pq)| with_pq || !**pq)
                .map(|(record, _)| record.clone())
                .collect::<Vec<_>>();
            if kept.len() < answer.len() {
                response.header.flags = response.header.flags.with(Flags::TC);
            }
            response.answer = kept;
            response.authority.clear();
            response.additional.clear();
            response.edns = message.edns.as_ref().map(|_| Edns::default());
            response.to_vec().ok()
        };
        let full = respond(true)?;
        if carrier == Carrier::Udp && post_quantum.contains(&true) && full.len() > query.len() {
            return respond(false);
        }
        Some(full)
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
            let (public, secret, magic) = if system == EncryptionSystem::XWing {
                let secret = XWingSecretKey::generate(&mut entropy);
                let magic = ClientMagic::random(&mut entropy);
                (
                    ResolverPublicKey::XWing(secret.public_key()),
                    ResolverSecret::from(secret),
                    magic.ok(),
                )
            } else {
                let secret = SecretKey::generate(&mut entropy);
                let public = secret.public_key();
                // The start of the public key, which a client cannot tell from a random one.
                let magic = <[u8; 8]>::try_from(public.as_bytes().get(..8).unwrap_or_default())
                    .ok()
                    .and_then(|bytes| ClientMagic::try_from(bytes).ok());
                (
                    ResolverPublicKey::classical(system, public).context("a classical system")?,
                    ResolverSecret::from(secret),
                    magic,
                )
            };
            entropy.finish().context("no randomness")?;
            let magic = magic.context("a key that cannot be a client magic")?;
            let certificate = Certificate::sign(
                signing,
                CertificateBody {
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
