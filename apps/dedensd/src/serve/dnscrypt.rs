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
use dedens_proto::{Query, Transport};
use dedens_server::Pipeline;
use futures_util::future::{join, join_all};
use futures_util::lock::Mutex;
use futures_util::{Stream, StreamExt};

use super::isolate::{Listener, Origin};
use super::tcp::{Codec, Opened};
use super::udp::{Outbox, Receiving, UDP_RECEIVES, Warned, receive_failed, send_replies};
use super::upstream::{Ask, answer};
use super::{Slot, Started, Thread, pause, start};
use crate::dnscrypt::{KeySet, Service, TICKET_LIFETIME};

/// Client key pairs a thread keeps the shared key of, so that a client asking again skips the key exchange: 19 µs
/// of the 19.5 µs a query costs to open, against 0.5 (`docs/benchmarks.md`). A bound on memory, 100 bytes a
/// pair; the cache is emptied when it is full, and at each rotation.
const SHARED_MAX: usize = 1024;

/// Queries by system and result.
const QUERIES: &str = "dedensd_dnscrypt_queries_total";

/// X-Wing queries dropped unopened, by the budget that was spent.
const LIMITED: &str = "dedensd_dnscrypt_limited_total";

/// Describes the metrics of this module.
pub(crate) fn describe() {
    metrics::describe_counter!(
        QUERIES,
        "DNSCrypt queries by encryption system and result: answered once a reply is sealed, dropped when the query does not open, is over a decapsulation budget, is denied or was not answered. System none: no key pair opened it."
    );
    metrics::describe_counter!(
        LIMITED,
        "DNSCrypt X-Wing queries dropped before their decapsulation: the client network or all clients were over their budget."
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

impl Open {
    /// The opened `plaintext`, a query for the pipeline, unless it is no DNS message: the draft ignores it (§5.4.6,
    /// §5.4.7), where the pipeline would answer FORMERR to a header that reads. Dropping `reply` counts it dropped.
    fn query(plaintext: Vec<u8>, reply: Reply) -> Self {
        if Query::read(&plaintext).is_err() {
            return Self::Drop;
        }
        Self::Query(plaintext, reply)
    }
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

    /// What `packet`, from the client at `from`, is: a client [silenced](Pipeline::silences) by `pipeline` gets
    /// nothing, and no work is done for it (D91), nor a denied one a certificate over UDP (D208), a certificate
    /// query is answered in the clear, any other must open.
    fn open<N: Io>(
        &self,
        thread: &Thread<N>,
        pipeline: &Pipeline,
        from: IpAddr,
        packet: &[u8],
        carrier: Carrier,
    ) -> Open {
        if pipeline.silences(from) {
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
            // The certificates are answered outside the pipeline, with no rate limit (D99): the access check is
            // their bound over UDP, even where the zones answer every client (D208), or any source could have
            // them reflected at a victim. A denied client has them over TCP, where it proves its address.
            if carrier == Carrier::Udp && pipeline.denies(from) {
                dropped("none");
                return Open::Drop;
            }
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
            // A new ciphertext each query: there is no shared key to keep, and each costs a decapsulation, 101 µs of a
            // core, which any packet with the client magic asks for: it is paid out of a budget first (D101). A
            // source on the rate limit's exempt list pays no network unit (D113).
            let exempt = pipeline
                .rate_limit()
                .is_some_and(|limit| limit.exempts(from));
            let proven = carrier == Carrier::Tcp;
            if let Err(spent) =
                self.service
                    .decapsulations()
                    .admit(from, proven, exempt, thread.now())
            {
                let budget = spent.name();
                metrics::counter!(LIMITED, "budget" => budget).increment(1);
                tracing::debug!(%from, budget, "DNSCrypt decapsulation budget spent: dropped");
                return Open::Drop;
            }
            return match resolver.decrypt_query(packet) {
                Ok((query, context)) => Open::query(
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
            Ok((query, context)) => Open::query(
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
            Open::query(
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
        pipeline.silences(ip)
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
) -> Option<(Ask, Slot, Reply)> {
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
    use dedens_dnscrypt::{ClientNonce, EncryptionSystem, QueryPadding, SecretKey};
    use dedens_net::io::Compio;
    use dedens_server::Budget;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;
    use crate::dnscrypt::Decapsulations;
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

    /// A service that offers `X-Wing` alone, on the provider key `[7; 32]`.
    fn pq_service() -> Arc<Service> {
        let provider = "2.dnscrypt-cert.test.example"
            .parse()
            .expect("a provider name");
        let systems = vec![EncryptionSystem::XWing];
        Arc::new(Service::new(&[7; 32], provider, systems, T0, &Compio).expect("a service"))
    }

    /// A full PQ query for `www.example A` as a client that fetched the certificate of `set` sends it: the packet,
    /// the DNS query it carries and what opens its response.
    fn pq_query(
        service: &Service,
        set: &KeySet,
        entropy: &mut Entropy,
    ) -> (Vec<u8>, Vec<u8>, dedens_dnscrypt::QueryContext) {
        use dedens_dnscrypt::{Certificate, ClientSession, SigningKey};
        use dedens_proto::rdata::RData;
        use dedens_proto::{Message, Question, RecordType};

        let certificates = Message::query(
            7,
            Question::new(service.provider().clone(), RecordType::TXT),
        )
        .to_vec()
        .expect("encodes");
        let answer = set
            .certificates(&certificates, service.provider(), Carrier::Tcp)
            .expect("an answer");
        let provider_key = SigningKey::from_seed(&[7; 32])
            .expect("a seed")
            .provider_key();
        let decoded = Message::decode(&answer).expect("a message").message;
        let [record] = &decoded.answer[..] else {
            panic!("one certificate")
        };
        let RData::Txt(txt) = record.data() else {
            panic!("a TXT")
        };
        let certificate = Certificate::from_txt(&txt, &provider_key).expect("signed");
        let wire = Message::query(
            9,
            Question::new("www.example".parse().expect("a name"), RecordType::A),
        )
        .to_vec()
        .expect("encodes");
        let session = ClientSession::xwing(&certificate, entropy).expect("a session");
        let (packet, context) = session
            .encrypt_query(&wire, QueryPadding::to(64), ClientNonce::random(entropy))
            .expect("a query");
        (packet, wire, context)
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

    /// D101, "Key Management" (S4 of the review of step 14): a thread that gets no query still lets go of the key
    /// sets it held, so the ticket keys and X-Wing seeds they own are erased when their time is out: `rotate` takes
    /// the keys at each time `refresh` returns, and the last holder of a retired set is the thread.
    #[test]
    fn an_idle_thread_lets_go_of_retired_key_sets_on_time() {
        let thread = answering();
        let keys = Keys::new(pq_service(), &thread);
        let first = Arc::downgrade(&keys.held.borrow().set);
        let ticket_life = u64::from(TICKET_LIFETIME);

        let due = keys.refresh(T0 + HALF_DAY, &thread.io);
        assert!(first.upgrade().is_none(), "the rotated set is gone");
        assert_eq!(
            due,
            T0 + HALF_DAY + ticket_life,
            "the thread looks again when the previous ticket key is out"
        );
        let second = Arc::downgrade(&keys.held.borrow().set);

        keys.refresh(T0 + HALF_DAY + ticket_life, &thread.io);
        assert!(
            second.upgrade().is_none(),
            "the set with the previous ticket key is gone"
        );
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

    /// D101: the first reply of a PQ session brings a ticket; a resumed query is answered, and its reply renews the
    /// ticket from half of the ticket's life on, not before.
    #[test]
    fn a_pq_reply_carries_a_ticket_and_a_resumed_query_renews_it_from_half_of_its_life() {
        let thread = answering();
        let service = pq_service();
        let keys = Keys::new(Arc::clone(&service), &thread);
        let set = Arc::clone(&keys.held.borrow().set);
        let mut entropy = Entropy::new().expect("entropy");
        let (packet, wire, context) = pq_query(&service, &set, &mut entropy);
        let from: IpAddr = "127.0.0.1".parse().expect("an address");
        let Open::Query(_, reply) =
            keys.open(&thread, &thread.pipeline(), from, &packet, Carrier::Tcp)
        else {
            panic!("the query opens")
        };
        let issuing = reply.ticket.as_ref().expect("a ticket for the first reply");
        let issued_at = issuing.unix;
        // The reply to the query: the same message with QR set, which `open_response` requires (RFC 1035 §4.1.1).
        let mut response = wire.clone();
        response[2] |= 0x80;
        let sealed = reply
            .seal(&thread, &response, Carrier::Tcp)
            .expect("a sealed reply");
        let resumption = context
            .open_response(&sealed)
            .expect("a response")
            .resumption
            .expect("the ticket");
        assert_eq!(resumption.lifetime(), TICKET_LIFETIME);

        let (resumed, _) = resumption
            .encrypt_query(
                &wire,
                QueryPadding::to(256),
                ClientNonce::random(&mut entropy),
            )
            .expect("a resumed query");
        let renews = |unix: u64| {
            let Open::Query(_, reply) = resume(&set, &resumed, unix, from) else {
                panic!("the resumed query opens at {unix}")
            };
            reply.ticket.is_some()
        };
        let half = u64::from(TICKET_LIFETIME / 2);
        assert!(!renews(issued_at));
        assert!(!renews(issued_at + half - 1));
        assert!(renews(issued_at + half));
        assert!(renews(issued_at + 2 * half - 1));
    }

    /// The counters `recorder` saw: name, label values and count. A snapshot reads them once: the next sees none.
    fn counted(recorder: &DebuggingRecorder) -> Vec<(String, Vec<String>, u64)> {
        let mut counted: Vec<_> = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .filter_map(|(key, _, _, value)| match value {
                DebugValue::Counter(count) => Some((
                    key.key().name().to_owned(),
                    key.key()
                        .labels()
                        .map(|label| label.value().to_owned())
                        .collect(),
                    count,
                )),
                _ => None,
            })
            .collect();
        counted.sort();
        counted
    }

    /// D101: a flood of packets that carry the X-Wing client magic and a ciphertext that is junk is cut at the
    /// budget of its network, and a flood from many networks at the global one, before any decapsulation; each packet
    /// is counted dropped, opened or not; a network's flood leaves other networks and the proven connections of its
    /// own their budgets; a source the rate limit exempts pays no network unit.
    #[test]
    fn a_flood_of_junk_ciphertexts_is_cut_before_the_decapsulation() {
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            describe();
            let thread = answering();
            let budget = |per_second, burst, table| Budget {
                per_second,
                burst,
                table,
            };
            // Two at once for a network, twelve for all, and nothing refilled: the test reads the thread's clock,
            // whose second may turn while it runs.
            let service = Arc::try_unwrap(pq_service())
                .ok()
                .expect("one owner")
                .with_decapsulations(Decapsulations::keyed(
                    budget(0, 2, 1 << 8),
                    budget(0, 12, 1),
                ));
            let keys = Keys::new(Arc::new(service), &thread);
            let set = Arc::clone(&keys.held.borrow().set);
            let mut entropy = Entropy::new().expect("entropy");
            let (genuine, _, _) = pq_query(&keys.service, &set, &mut entropy);
            let mut junk = genuine.clone();
            // A ciphertext that decapsulates to a key nobody has, as ML-KEM's implicit rejection returns for any bytes.
            for byte in junk.iter_mut().skip(8).take(1120) {
                *byte = !*byte;
            }
            let pipeline = thread.pipeline();
            let opens = |from: &str, packet: &[u8], carrier| {
                let from: IpAddr = from.parse().expect("an address");
                matches!(
                    keys.open(&thread, &pipeline, from, packet, carrier),
                    Open::Query(..)
                )
            };
            // One network's flood: two decapsulated and refused (the tag), the other four cut by its budget.
            for _ in 0..6 {
                assert!(!opens("10.0.1.1", &junk, Carrier::Tcp));
            }
            // The genuine query of the same network is cut too: the flood spent what it had.
            assert!(!opens("10.0.1.99", &genuine, Carrier::Tcp));
            // Another network has its own budget, and so has the unproven UDP source of the flooded network.
            assert!(opens("10.0.2.1", &genuine, Carrier::Tcp));
            assert!(opens("10.0.1.1", &genuine, Carrier::Udp));
            // Loopback is exempt from the rate limit (D113): no network unit, however many.
            for _ in 0..4 {
                assert!(opens("127.0.0.1", &genuine, Carrier::Tcp));
            }
            // Four more networks take the last four units of all; the global budget cuts the next two.
            for network in 3..=6 {
                assert!(opens(&format!("10.0.{network}.1"), &genuine, Carrier::Tcp));
            }
            assert!(!opens("10.0.7.1", &genuine, Carrier::Tcp));
            assert!(!opens("10.0.8.1", &genuine, Carrier::Tcp));
        });
        let counted = counted(&recorder);
        let named = |name: &str| {
            counted
                .iter()
                .filter(|(counter, ..)| counter == name)
                .map(|(_, labels, count)| (labels.clone(), *count))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            named(LIMITED),
            [
                (vec!["client".to_owned()], 5),
                (vec!["global".to_owned()], 2)
            ]
        );
        // None of the 19 packets is answered here: each is counted dropped, however far it got.
        assert_eq!(
            named(QUERIES),
            [(vec!["xwing".to_owned(), "dropped".to_owned()], 19)]
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

    /// Draft §5.4.6, §5.4.7: a query that opens to no DNS message, its header whole and its question cut, is ignored
    /// and counted dropped, where the pipeline would answer FORMERR; the whole query goes to the pipeline.
    #[test]
    fn a_query_that_opens_to_no_dns_message_is_dropped() {
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            let thread = answering();
            let service = pq_service();
            let keys = Keys::new(Arc::clone(&service), &thread);
            let set = Arc::clone(&keys.held.borrow().set);
            let mut entropy = Entropy::new().expect("entropy");
            let from: IpAddr = "127.0.0.1".parse().expect("an address");
            let mut opened = || {
                let (packet, ..) = pq_query(&service, &set, &mut entropy);
                match keys.open(&thread, &thread.pipeline(), from, &packet, Carrier::Tcp) {
                    Open::Query(wire, reply) => (wire, reply),
                    _ => panic!("the query opens"),
                }
            };
            let (wire, reply) = opened();
            assert!(matches!(
                Open::query(wire[..20].to_vec(), reply),
                Open::Drop
            ));
            let (wire, reply) = opened();
            assert!(matches!(Open::query(wire, reply), Open::Query(..)));
        });
        let dropped: Vec<_> = counted(&recorder)
            .into_iter()
            .filter(|(counter, ..)| counter == QUERIES)
            .collect();
        assert_eq!(
            dropped,
            [(
                QUERIES.to_owned(),
                vec!["xwing".to_owned(), "dropped".to_owned()],
                2
            )],
            "the cut query, and the whole one that the test does not answer"
        );
    }
}
