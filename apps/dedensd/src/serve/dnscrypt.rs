//! `DNSCrypt` (D99): the UDP loop and the TCP codec of a `dnscrypt://` listener, and the task that keeps each thread's
//! keys current. A query is opened with the key pair its client magic names, answered by the pipeline as any other
//! (the client's address is the peer's), and its reply sealed within the budget of the carrier. What does not open is
//! dropped, with no answer to aim at an address. The sockets and the clock are the thread's [`Io`]'s (D182).

#![deny(clippy::disallowed_methods)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use dedens_dnscrypt::{
    Carrier, ClientMagic, EncryptionSystem, PublicKey, RESUME_MAGIC, ResponseContext, SharedKey,
};
use dedens_net::entropy::Entropy;
use dedens_net::io::{Datagram, Io, Udp as _};
use dedens_net::tcp::frame;
use dedens_proto::Transport;
use dedens_server::{Pipeline, Upstream};
use futures_util::future::{join, join_all};
use futures_util::lock::Mutex;
use futures_util::{Stream, StreamExt};

use super::isolate::{Listener, Origin};
use super::tcp::{Codec, Opened};
use super::udp::{Outbox, Receiving, UDP_RECEIVES, Warned, receive_failed, send_replies};
use super::upstream::answer;
use super::{Slot, Started, Thread, pause, start};
use crate::dnscrypt::{KeySet, Service, TICKET_LIFETIME};

/// Client key pairs a thread keeps the shared key of, so that a client asking again skips the key exchange: 19 µs
/// of the 19.5 µs a query costs to open, against 0.5 (`docs/benchmarks.md`). A bound on memory, 100 bytes a
/// pair; the cache is emptied when it is full, and at each rotation.
const SHARED_MAX: usize = 1024;

/// Queries by system and result.
const QUERIES: &str = "dedensd_dnscrypt_queries_total";

/// Describes the metrics of this module.
pub(crate) fn describe() {
    metrics::describe_counter!(
        QUERIES,
        "DNSCrypt queries by encryption system and result: answered once a reply is sealed, dropped when the query does not open, is denied or was not answered. System none: no key pair opened it."
    );
}

/// The keys one thread serves with: the service's, as the thread last took them, and the shared keys of the clients
/// that proved they hold theirs.
pub(super) struct Keys {
    service: Arc<Service>,
    held: RefCell<Held>,
}

struct Held {
    set: Arc<KeySet>,
    /// By the resolver key pair a client asked (its client magic) and the client's public key. Only a query whose
    /// tag verified puts a pair here: a forged one costs the exchange, not a place.
    shared: HashMap<(ClientMagic, PublicKey), SharedKey>,
}

/// What a message read from a client is.
enum Open {
    /// A query for the pipeline, and what seals its reply.
    Query(Vec<u8>, Reply),
    /// The answer to a certificate query, to send in the clear.
    Clear(Vec<u8>),
    Drop,
}

impl Keys {
    /// The keys of `service` for the thread `thread`.
    pub(super) fn new<N: Io>(service: Arc<Service>, thread: &Thread<N>) -> Self {
        let set = service.keys(service.unix(thread.now()), &thread.io);
        Self {
            service,
            held: RefCell::new(Held {
                set,
                shared: HashMap::new(),
            }),
        }
    }

    /// Takes the service's keys if they are due at the Unix time `unix`, and returns the Unix time from which to look
    /// again. Keys whose certificate expired are not used from the second they do, and are erased once no thread holds
    /// them.
    fn refresh(&self, unix: u64, io: &impl Io) -> u64 {
        let mut held = self.held.borrow_mut();
        if held.set.refresh_at <= unix {
            let set = self.service.keys(unix, io);
            if !Arc::ptr_eq(&set, &held.set) {
                held.shared.clear();
            }
            held.set = set;
        }
        held.set.refresh_at
    }

    /// What `packet`, from the client at `from`, is: a client denied by `pipeline` gets nothing, and no work is
    /// done for it (D91), a certificate query is answered in the clear, any other must open.
    fn open<N: Io>(
        &self,
        thread: &Thread<N>,
        pipeline: &Pipeline,
        from: IpAddr,
        packet: &[u8],
        carrier: Carrier,
    ) -> Open {
        if pipeline.denies(from) {
            dropped("none");
            return Open::Drop;
        }
        let unix = self.service.unix(thread.now());
        self.refresh(unix, &thread.io);
        let mut held = self.held.borrow_mut();
        let Held { set, shared } = &mut *held;
        if packet.starts_with(&RESUME_MAGIC) {
            return resume(set, packet, unix, from);
        }
        let Some(issued) = set.find(packet) else {
            let answer = set.certificates(packet, self.service.provider(), carrier);
            return answer.map_or_else(
                || {
                    dropped("none");
                    Open::Drop
                },
                Open::Clear,
            );
        };
        let tally = Tally::new(issued.system());
        let resolver = &issued.resolver;
        if issued.system() == EncryptionSystem::XWing {
            // A new ciphertext each query: there is no shared key to keep.
            return match resolver.decrypt_query(packet) {
                Ok((query, context)) => Open::Query(
                    query,
                    Reply {
                        context,
                        tally,
                        ticket: Issuing::of(set, unix),
                    },
                ),
                Err(error) => {
                    tracing::debug!(%from, %error, "DNSCrypt query does not open");
                    Open::Drop
                }
            };
        }
        let Ok(client) = resolver.client_key(packet) else {
            return Open::Drop;
        };
        let key = (resolver.client_magic(), client);
        let opened = if let Some(shared) = shared.get(&key) {
            resolver.decrypt_query_with(packet, shared)
        } else {
            let Ok(shared_key) = resolver.shared_key(&client) else {
                return Open::Drop;
            };
            let opened = resolver.decrypt_query_with(packet, &shared_key);
            if opened.is_ok() {
                if shared.len() >= SHARED_MAX {
                    shared.clear();
                }
                shared.insert(key, shared_key);
            }
            opened
        };
        match opened {
            Ok((query, context)) => Open::Query(
                query,
                Reply {
                    context,
                    tally,
                    ticket: None,
                },
            ),
            Err(error) => {
                tracing::debug!(%from, %error, "DNSCrypt query does not open");
                Open::Drop
            }
        }
    }
}

/// A resumed query (draft "Resuming", D101): its ticket opened with the keys of `set`, then the query with the key
/// pair of its certificate. A ticket close to its end is renewed in the reply. Dropped, with no word, when any of
/// it fails.
fn resume(set: &Arc<KeySet>, packet: &[u8], unix: u64, from: IpAddr) -> Open {
    let opened = set
        .tickets()
        .ok_or(dedens_dnscrypt::QueryError::Ticket)
        .and_then(|tickets| tickets.open(packet, unix));
    let Ok(query) = opened else {
        dropped("none");
        return Open::Drop;
    };
    let Some(issued) = set.find_magic(query.client_magic()) else {
        dropped("none");
        return Open::Drop;
    };
    let tally = Tally::new(issued.system());
    match issued.resolver.decrypt_resumed(&query, unix) {
        Ok((plaintext, context)) => {
            let near_end = u64::from(query.expiry()) <= unix + u64::from(TICKET_LIFETIME / 2);
            Open::Query(
                plaintext,
                Reply {
                    context,
                    tally,
                    ticket: if near_end {
                        Issuing::of(set, unix)
                    } else {
                        None
                    },
                },
            )
        }
        Err(error) => {
            tracing::debug!(%from, %error, "DNSCrypt resumed query does not open");
            Open::Drop
        }
    }
}

/// What issues a ticket with a reply: the keys that seal it and the time it is issued at.
struct Issuing {
    set: Arc<KeySet>,
    unix: u64,
}

impl Issuing {
    /// The issuing of `set` at `unix`, if it has keys to seal tickets with.
    fn of(set: &Arc<KeySet>, unix: u64) -> Option<Self> {
        set.tickets().is_some().then(|| Self {
            set: Arc::clone(set),
            unix,
        })
    }
}

/// Counts a dropped query of `system`.
fn dropped(system: &'static str) {
    metrics::counter!(QUERIES, "system" => system, "result" => "dropped").increment(1);
}

/// What a query opened leaves for its reply: the keys it was sealed with, and its count. A query dropped counts
/// when this is, whichever way it was: the count follows the value, not the code paths.
pub(super) struct Reply {
    context: ResponseContext,
    tally: Tally,
    /// A ticket goes with the reply: the first reply of a PQ session, and the one of a resumed query near the end of
    /// its ticket (D101).
    ticket: Option<Issuing>,
}

impl Reply {
    /// `wire`, the pipeline's reply, sealed for the client within what `carrier` allows (the draft's "Padding" and
    /// "Response" rules are the library's); `None` if no randomness can be drawn: the client is not answered.
    fn seal<N: Io>(&self, thread: &Thread<N>, wire: &[u8], carrier: Carrier) -> Option<Vec<u8>> {
        let mut entropy = Entropy::from_io(&thread.io).ok()?;
        let ticket = self.ticket.as_ref().and_then(|issuing| {
            issuing
                .set
                .tickets()?
                .issue(&self.context, issuing.unix, TICKET_LIFETIME, &mut entropy)
        });
        let sealed =
            self.context
                .encrypt_response_with(wire, ticket.as_ref(), carrier, &mut entropy);
        entropy.finish().ok()?;
        match sealed {
            Ok(sealed) => {
                self.tally.answered.set(true);
                Some(sealed)
            }
            Err(error) => {
                tracing::debug!(%error, "DNSCrypt reply not sealed");
                None
            }
        }
    }
}

/// A query's count: `dropped` when it ends without a reply sealed, else `answered`.
struct Tally {
    system: &'static str,
    answered: Cell<bool>,
}

impl Tally {
    fn new(system: dedens_dnscrypt::EncryptionSystem) -> Self {
        let system = match system {
            dedens_dnscrypt::EncryptionSystem::XSalsa20Poly1305 => "xsalsa20",
            dedens_dnscrypt::EncryptionSystem::XChaCha20Poly1305 => "xchacha20",
            dedens_dnscrypt::EncryptionSystem::XWing => "xwing",
        };
        Self {
            system,
            answered: Cell::new(false),
        }
    }
}

impl Drop for Tally {
    fn drop(&mut self) {
        let result = if self.answered.get() {
            "answered"
        } else {
            "dropped"
        };
        metrics::counter!(QUERIES, "system" => self.system, "result" => result).increment(1);
    }
}

/// Keeps `keys` current until the end of the thread: a thread that gets no query would otherwise hold a key pair
/// past its certificate, which erasing it is the point of (draft, "Key Management"). Never ends.
pub(super) async fn rotate<N: Io>(keys: Rc<Keys>, thread: Rc<Thread<N>>) {
    loop {
        let now = keys.service.unix(thread.now());
        let due = keys.refresh(now, &thread.io);
        pause(
            &thread.io,
            Duration::from_secs(due.saturating_sub(now).max(1)),
        )
        .await;
    }
}

/// Opens the messages of a TCP connection with `keys`.
pub(super) struct Encrypted(pub(super) Rc<Keys>);

impl Codec for Encrypted {
    type Context = Reply;

    fn silenced(&self, pipeline: &Pipeline, ip: IpAddr) -> bool {
        // Both actions: a client denied gets no answer, sealed or not (D99).
        pipeline.denies(ip)
    }

    fn open<N: Io>(&self, thread: &Thread<N>, from: IpAddr, message: Vec<u8>) -> Opened<Reply> {
        match self
            .0
            .open(thread, &thread.pipeline(), from, &message, Carrier::Tcp)
        {
            Open::Query(query, reply) => Opened::Query(query, reply),
            Open::Clear(answer) => frame(&answer).map_or(Opened::Drop, Opened::Reply),
            Open::Drop => Opened::Drop,
        }
    }

    fn seal<N: Io>(&self, thread: &Thread<N>, reply: &Reply, wire: &[u8]) -> Option<Vec<u8>> {
        frame(&reply.seal(thread, wire, Carrier::Tcp)?)
    }

    fn reseal<N: Io>(&self, thread: &Thread<N>, reply: &Reply, framed: Vec<u8>) -> Option<Vec<u8>> {
        self.seal(thread, reply, framed.get(2..)?)
    }
}

/// Answers the queries of one UDP socket as [`super::udp::udp`] does, from sealed packets.
pub(super) async fn udp<N: Io>(
    socket: Rc<N::Udp>,
    outbox: Rc<Outbox>,
    keys: Rc<Keys>,
    listener: Listener,
    thread: Rc<Thread<N>>,
) {
    let datagrams = pin!(socket.recv_multi());
    let datagrams = Mutex::new(datagrams);
    let tasks = (0..UDP_RECEIVES).map(|_| queries(&datagrams, &outbox, &keys, &listener, &thread));
    join(join_all(tasks), send_replies(&*socket, &outbox)).await;
}

/// Answers queries from `datagrams`, one after the other.
async fn queries<N: Io, D: Datagram>(
    datagrams: &Mutex<impl Stream<Item = io::Result<D>> + Unpin>,
    outbox: &Rc<Outbox>,
    keys: &Rc<Keys>,
    listener: &Listener,
    thread: &Rc<Thread<N>>,
) {
    let mut receiving = Receiving::Fine;
    let mut warned = Warned::default();
    loop {
        let next = datagrams.lock().await.next().await;
        let datagram = match next {
            Some(Ok(datagram)) => datagram,
            Some(Err(error)) => {
                receive_failed(&error, &mut receiving, &mut warned, listener, thread).await;
                continue;
            }
            None => continue,
        };
        receiving = Receiving::Fine;
        let Some(peer) = datagram.peer() else {
            continue;
        };
        let pipeline = thread.pipeline();
        // A panic anywhere in the datagram's turn costs this query, not the socket (D121).
        let stepped = listener
            .guard_async(peer, step(outbox, keys, thread, &pipeline, datagram, peer))
            .await;
        let Some(Some((upstream, slot, reply))) = stepped else {
            continue;
        };
        let (outbox, thread) = (Rc::clone(outbox), Rc::clone(thread));
        Origin::new(listener, peer).spawn(&thread.io.clone(), async move {
            let deliver = async |wire: Vec<u8>| {
                if let Some(sealed) = reply.seal(&thread, &wire, Carrier::Udp) {
                    let len = sealed.len();
                    outbox.push(sealed, len, peer).await;
                }
            };
            answer(&thread, &pipeline, upstream, Transport::Udp, deliver).await;
            drop(slot);
        });
    }
}

/// The turn of one datagram: opened, the pipeline's first step, the reply sealed and queued, and the upstream query
/// it leaves, if any, with the place it holds and what seals its reply.
async fn step<N: Io>(
    outbox: &Outbox,
    keys: &Keys,
    thread: &Thread<N>,
    pipeline: &Pipeline,
    datagram: impl Datagram,
    peer: SocketAddr,
) -> Option<(Box<Upstream>, Slot, Reply)> {
    let opened = keys.open(thread, pipeline, peer.ip(), datagram.data(), Carrier::Udp);
    drop(datagram);
    let (query, reply) = match opened {
        Open::Query(query, reply) => (query, reply),
        Open::Clear(answer) => {
            let len = answer.len();
            outbox.push(answer, len, peer).await;
            return None;
        }
        Open::Drop => return None,
    };
    let mut sealed = None;
    let started = start(
        thread,
        pipeline,
        &query,
        Transport::Udp,
        peer.ip(),
        |wire| {
            sealed = reply.seal(thread, wire, Carrier::Udp);
            true
        },
    );
    if let Some(sealed) = sealed {
        let len = sealed.len();
        outbox.push(sealed, len, peer).await;
    }
    match started {
        Some(Started::Upstream(upstream, slot)) => Some((upstream, slot, reply)),
        Some(Started::Done) | None => None,
    }
}

#[cfg(test)]
mod tests {
    use dedens_dnscrypt::{EncryptionSystem, SecretKey};
    use dedens_net::io::Compio;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;
    use crate::serve::tests::answering;

    /// A Unix time of 2026, so that certificates fit their 32 bits.
    const T0: u64 = 1_800_000_000;
    const HALF_DAY: u64 = 43_200;

    fn service() -> Arc<Service> {
        let provider = "2.dnscrypt-cert.test.example"
            .parse()
            .expect("a provider name");
        let systems = vec![EncryptionSystem::XChaCha20Poly1305];
        Arc::new(Service::new(&[7; 32], provider, systems, T0, &Compio).expect("a service"))
    }

    /// A key shared with the first key pair of `keys`, as a verified query leaves.
    fn learn(keys: &Keys) {
        let mut entropy = Entropy::new().expect("entropy");
        let client = SecretKey::generate(&mut entropy).public_key();
        let mut held = keys.held.borrow_mut();
        let issued = Arc::clone(held.set.newest().expect("a key pair"));
        let shared = issued.resolver.shared_key(&client).expect("a shared key");
        held.shared
            .insert((issued.resolver.client_magic(), client), shared);
    }

    /// D99: a thread takes the service's keys when they are due and no sooner, forgets the shared keys of the pairs
    /// it replaces, and says when to look again.
    #[test]
    fn a_thread_takes_the_keys_when_they_are_due() {
        let thread = answering();
        let keys = Keys::new(service(), &thread);
        learn(&keys);
        let first = Arc::clone(&keys.held.borrow().set);
        assert_eq!(keys.refresh(T0 + 1, &thread.io), T0 + HALF_DAY);
        assert!(Arc::ptr_eq(&first, &keys.held.borrow().set));
        assert_eq!(keys.held.borrow().shared.len(), 1);

        assert_eq!(keys.refresh(T0 + HALF_DAY, &thread.io), T0 + 2 * HALF_DAY);
        let held = keys.held.borrow();
        assert!(!Arc::ptr_eq(&first, &held.set));
        assert_eq!(held.set.len(), 2, "the older pair is still valid");
        assert!(held.shared.is_empty(), "no shared key outlives a rotation");
    }

    /// D99, D48: the count of each query by system and result, described.
    #[test]
    fn queries_are_counted_by_system_and_result() {
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            describe();
            drop(Tally::new(EncryptionSystem::XSalsa20Poly1305));
            let answered = Tally::new(EncryptionSystem::XChaCha20Poly1305);
            answered.answered.set(true);
            drop(answered);
            dropped("none");
        });
        let mut counted: Vec<_> = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, description, value)| match value {
                DebugValue::Counter(count) if key.key().name() == QUERIES => {
                    let labels: Vec<_> = key
                        .key()
                        .labels()
                        .map(|label| label.value().to_owned())
                        .collect();
                    Some((labels, count, description.is_some()))
                }
                _ => None,
            })
            .collect();
        counted.sort();
        let row = |system: &str, result: &str| vec![system.to_owned(), result.to_owned()];
        assert_eq!(
            counted,
            [
                (row("none", "dropped"), 1, true),
                (row("xchacha20", "answered"), 1, true),
                (row("xsalsa20", "dropped"), 1, true),
            ]
        );
    }

    /// D99, D91: a client the access check denies is silenced at accept, whichever action it sets; an allowed one is
    /// not.
    #[test]
    fn a_denied_client_is_silenced() {
        let thread = answering();
        let codec = Encrypted(Rc::new(Keys::new(service(), &thread)));
        let pipeline = thread.pipeline();
        assert!(codec.silenced(&pipeline, "8.8.8.8".parse().expect("an address")));
        assert!(!codec.silenced(&pipeline, "127.0.0.1".parse().expect("an address")));
    }
}
