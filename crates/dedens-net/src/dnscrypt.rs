//! The `DNSCrypt` client over UDP and TCP, experimental (draft-denis-dprive-dnscrypt, "Transport", "Client Queries
//! Over UDP", "Client Queries Over TCP", "Certificates", "Key Management"; D98): a [`Resolver`] per stamp
//! ([`stamp::DnsCrypt`]) fetching the resolver's certificates, choosing one, and sealing each query under it. The
//! cryptography is [`dedens_dnscrypt`]'s (D97); this module is the network and the clock around it.
//!
//! The certificates come from a plain TXT query for the stamp's provider name, to the stamp's address, over UDP and
//! TCP when the answer is truncated, or over TCP from the start with `+tcp`; the ones whose signature is not the
//! provider's key's are dropped by `dedens_dnscrypt::Certificate::from_txt`. The one kept is the valid one of the
//! highest serial of the preferred system. It is fetched again when it is not valid any more, when an hour has
//! passed (the draft asks for a periodic refresh) and after a response that does not open.
//!
//! Every query has a client key and nonce of its own and a socket or connection of its own: no public key links two
//! queries, nor does the address a client has when its network changes (draft "Key Management"), and a TCP
//! connection carries one query (draft "Client Queries Over TCP"). Nothing of a query outlives it but the padding
//! target of UDP.
//!
//! With relays (draft "Anonymized `DNSCrypt`", D100) every packet, the certificate query included, goes to a relay
//! with the resolver's address before it ([`dedens_dnscrypt::relay_query`]), and the resolver never sees the
//! client's. A relay forwards over UDP whatever the client used, and drops a response larger than the query it
//! forwarded: so the certificate query is padded to hold the response, and over TCP the inner query is
//! as large as [`RELAY_PACKET_LEN`] says, 4096 bytes. One relay is picked at random for each query, but the one that
//! failed the last: that is skipped until another fails, so that a relay that is down costs one try, not one in every
//! few.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::io::util::Splittable;
use dedens_dnscrypt::{
    Certificate, ClientMagic, ClientNonce, ClientSession, EncryptQueryError, EncryptionSystem,
    MAX_PACKET_LEN, Opened, ProviderKey, QueryContext, QueryPadding, ResponseError, Resumption,
    SecretKey, SessionError, SystemPolicy, relay_query, select,
};
use dedens_proto::edns::EdnsOption;
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Question, RecordType, Transport};

use crate::client::{Client, ClientError, Server};
use crate::entropy::Entropy;
use crate::exchange::{CertificateInfo, Failure, Options, Response, after};
use crate::io::{Io, Stream, Udp};
use crate::stamp::{DnsCrypt, Relay};
use crate::tcp::{TcpError, frame, read_message};
use crate::udp::unspecified;

/// How long a chosen certificate is kept before the resolver is asked again: the draft asks for a refresh "early
/// enough to avoid" an expired certificate, and hourly suits (draft "Certificates").
const REFRESH: std::time::Duration = std::time::Duration::from_hours(1);

/// The size of the query for the certificates: it covers the rollover set, two classical certificates and two PQ ones,
/// about 3 KB (draft "Certificate Retrieval"), so that a resolver may answer them all over UDP.
const CERTIFICATE_QUERY_LEN: usize = 3072;

/// The smallest packet of a UDP query at first (draft "Padding For Client Queries Over UDP": `<min-query-len>`, 256).
const FIRST_FLOOR: usize = 256;

/// The inner query a relay gets over TCP, certificate query or sealed packet: the relay asks the resolver over UDP and
/// drops a response longer than it, so it is the largest a packet can be, 4096 bytes (D100): a sealed one holds 4028
/// bytes of plaintext and 68 of overhead.
const RELAY_PACKET_LEN: usize = MAX_PACKET_LEN;

/// The length of a certificate query to a relay over UDP: the relay drops a response longer than the query, and the
/// classical certificates a resolver serves make a response of about 400 bytes (draft "Anonymized `DNSCrypt`",
/// "Certificate Retrieval Amplification"). 1200 bytes and the relay's prefix still fit the 1280 of the smallest IPv6
/// link, with the headers.
const CERTIFICATE_UDP_LEN: usize = 1200;

/// What an EDNS option adds to its data: the code and the length (RFC 6891 §6.1.2).
const OPTION_HEAD: usize = 4;
/// Why a `DNSCrypt` exchange failed, besides the sockets.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DnsCryptError {
    /// The resolver's certificates could not be fetched.
    #[error("cannot fetch the certificates")]
    Certificates(#[source] Box<ClientError>),
    /// None of the certificates the resolver serves is signed by the provider key, valid now and of a system this
    /// client knows.
    #[error("the resolver serves no usable certificate")]
    NoCertificate,
    /// The resolver's key is of low order, or of a system the certificate is not for.
    #[error(transparent)]
    Session(#[from] SessionError),
    /// The query cannot be sealed.
    #[error("cannot encrypt the query")]
    Encrypt(#[from] EncryptQueryError),
}

impl DnsCryptError {
    /// Whether the failure is ours, not the resolver's or the network's.
    #[must_use]
    pub fn is_local(&self) -> bool {
        match self {
            Self::Certificates(error) => error.is_local(),
            Self::NoCertificate => false,
            Self::Session(_) | Self::Encrypt(_) => true,
        }
    }
}

/// The resolvers a client has asked, by stamp and relays.
#[derive(Debug, Default)]
pub(crate) struct Resolvers(RefCell<Vec<Rc<Resolver>>>);

impl Resolvers {
    /// The resolver of `stamp` reached through `relays`, made at the first call: the same resolver through other
    /// relays is another, with its own certificates.
    pub(crate) fn of(&self, stamp: &DnsCrypt, relays: &[Relay]) -> Rc<Resolver> {
        let mut known = self.0.borrow_mut();
        if let Some(resolver) = known
            .iter()
            .find(|resolver| resolver.stamp == *stamp && resolver.relays == relays)
        {
            return Rc::clone(resolver);
        }
        let resolver = Rc::new(Resolver::new(stamp.clone(), relays.to_vec()));
        known.push(Rc::clone(&resolver));
        resolver
    }
}

/// The certificates a resolver serves, and the response that held them.
#[derive(Debug, Clone)]
pub struct Listing {
    /// The response to the TXT query for the provider name.
    pub response: Response,
    /// The certificates signed by the provider key, in the order of the answers, expired or not.
    pub certificates: Vec<CertificateInfo>,
}

/// What a sealed exchange came to.
#[derive(Debug)]
pub(crate) enum Reply {
    /// The response, opened, and the certificate it came under.
    Answer(Vec<u8>, CertificateInfo),
    /// Nothing opened before the deadline.
    TimedOut,
}

/// A `DNSCrypt` resolver: its stamp, the relays its packets go through, if any, the provider key its certificates
/// are signed with, and what the client has learned of it.
#[derive(Debug)]
pub struct Resolver {
    stamp: DnsCrypt,
    relays: Vec<Relay>,
    provider: ProviderKey,
    state: RefCell<State>,
}

#[derive(Debug)]
struct State {
    /// The certificate in use and when it was fetched.
    chosen: Option<(Certificate, Instant)>,
    /// A response did not open: the certificate may be one the resolver dropped.
    stale: bool,
    /// The smallest packet of the next UDP queries: raised when a response came truncated, so that the next one fits.
    floor: usize,
    /// The relay that failed the last: not picked while another is, until another fails.
    avoid: Option<Relay>,
    /// The ticket of the last PQ response, kept only for `DnsCryptOptions::resume`.
    ticket: Option<Ticket>,
}

/// A resumption ticket and what the client checks before using it: the certificate it was issued under, by the client
/// magic and the end of validity the resolver binds the ticket to (draft "Resumption Tickets"; a serial may stay the
/// same when a provider rotates its keys), and when it expires on the clock of the exchanges.
#[derive(Debug)]
struct Ticket {
    resumption: Resumption,
    magic: ClientMagic,
    valid_until: u32,
    expires: Instant,
}

impl Ticket {
    /// Whether the ticket was issued under `certificate`.
    fn is_for(&self, certificate: &Certificate) -> bool {
        let body = certificate.body();
        body.client_magic == self.magic && body.validity.end() == self.valid_until
    }
}

impl Resolver {
    fn new(stamp: DnsCrypt, relays: Vec<Relay>) -> Self {
        Self {
            provider: ProviderKey::from_bytes(stamp.public_key),
            stamp,
            relays,
            state: RefCell::new(State {
                chosen: None,
                stale: false,
                floor: FIRST_FLOOR,
                avoid: None,
                ticket: None,
            }),
        }
    }

    /// The relay for the next packets: one of the relays at random, but the one that failed the last when there is
    /// another; none when the resolver is reached direct. A certificate fetch that follows a failed query must not
    /// pick the one that failed: it is kept until another fails.
    fn pick<N: Io>(&self, io: &N) -> Result<Option<Relay>, ClientError> {
        let avoid = self.state.borrow().avoid;
        let mut draw = [0; 2];
        io.random(&mut draw).map_err(ClientError::Random)?;
        Ok(choose(&self.relays, avoid, u16::from_be_bytes(draw)))
    }

    /// Notes that `relay` did not carry a query, so that the next is not sent through it.
    fn failed(&self, relay: Option<Relay>) {
        self.state.borrow_mut().avoid = relay;
    }

    /// A query got no response: the relay is skipped by the next picks, the certificate made stale when `stale`, and the
    /// ticket it was sealed under, if any, dropped.
    fn lost(&self, relay: Option<Relay>, stale: bool, resumed: bool) -> Reply {
        if resumed {
            self.state.borrow_mut().ticket = None;
        }
        if stale {
            self.state.borrow_mut().stale = true;
        }
        self.failed(relay);
        Reply::TimedOut
    }

    /// The certificate to seal queries under: the one kept while it is valid and recent, else the best of those the
    /// resolver serves now.
    pub(crate) async fn certificate<N: Io>(
        &self,
        client: &Client<N>,
        io: &N,
        options: &Options,
    ) -> Result<Certificate, ClientError> {
        let policy = policy(options);
        if let Some(kept) = self.kept(io, policy) {
            return Ok(kept);
        }
        let (_, certificates) = self.fetch(client, io, options).await?;
        let chosen = select(&certificates, unix_now(), policy)
            .ok_or(DnsCryptError::NoCertificate)?
            .clone();
        let mut state = self.state.borrow_mut();
        state.chosen = Some((chosen.clone(), io.now()));
        state.stale = false;
        Ok(chosen)
    }

    /// The certificate in use, while it is valid, recent, no response failed under it and `policy` allows its
    /// system.
    fn kept<N: Io>(&self, io: &N, policy: SystemPolicy) -> Option<Certificate> {
        let state = self.state.borrow();
        let (certificate, fetched) = state.chosen.as_ref()?;
        (!state.stale
            && policy.allows(certificate.body().system())
            && certificate.is_valid_at(unix_now())
            && io.now().saturating_duration_since(*fetched) < REFRESH)
            .then(|| certificate.clone())
    }

    /// The certificates the resolver serves, and the response that held them.
    pub(crate) async fn listing<N: Io>(
        &self,
        client: &Client<N>,
        io: &N,
        options: &Options,
    ) -> Result<Listing, ClientError> {
        let (response, certificates) = self.fetch(client, io, options).await?;
        Ok(Listing {
            response,
            certificates: certificates.iter().map(info).collect(),
        })
    }

    /// Asks the resolver for its certificates: a TXT query for the provider name, in the clear, padded to cover the
    /// rollover set (draft "Certificate Retrieval"), over UDP, then over TCP when UDP gets no answer or the answer is
    /// truncated (a resolver cuts a response that would be longer than the query, PQ certificates left out), whatever
    /// the transport of the queries: a public resolver may serve the certificates over UDP alone (Quad9 and
    /// `CleanBrowsing` answer none over TCP, November 2026), and nothing private is in them (draft "Certificates").
    /// Through relays the query goes to one of them, UDP then TCP.
    async fn fetch<N: Io>(
        &self,
        client: &Client<N>,
        io: &N,
        options: &Options,
    ) -> Result<(Response, Vec<Certificate>), ClientError> {
        let response = if self.relays.is_empty() {
            self.fetch_direct(client, options).await?
        } else {
            self.fetch_relayed(io, options).await?
        };
        let certificates = Message::decode(&response.wire)
            .map(|decoded| {
                decoded
                    .message
                    .answer
                    .iter()
                    .filter_map(|record| match record.data() {
                        RData::Txt(txt) => Certificate::from_txt(&txt, &self.provider).ok(),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok((response, certificates))
    }

    /// The TXT query for the provider name to the resolver's address, over UDP, then over TCP.
    async fn fetch_direct<N: Io>(
        &self,
        client: &Client<N>,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let question = Question::new(self.stamp.provider_name.name().clone(), RecordType::TXT);
        let server = Server::from(self.stamp.address.socket_addr());
        let attempt = |transport| {
            // No cookie: the query is nothing to link, and the exchange keeps none.
            let asked = Options {
                transport,
                cookies: false,
                tcp_fallback: true,
                ..*options
            };
            let query = certificate_query(question.clone(), 0, CERTIFICATE_QUERY_LEN);
            let server = server.clone();
            // Boxed: this is a query of the client, which may be the one that is waiting for the certificate.
            async move { Box::pin(client.exchange(query, server, &asked)).await }
        };
        match attempt(Transport::Udp).await {
            Ok(response) => Ok(response),
            Err(_) => attempt(Transport::Tcp)
                .await
                .map_err(|error| DnsCryptError::Certificates(Box::new(error)).into()),
        }
    }

    /// The same query through a relay: for each of the tries, a relay, UDP with the query padded to hold the
    /// response, and TCP with the query as large as can be when UDP got no answer or a truncated one. A relay that
    /// answers neither is skipped by the next picks.
    async fn fetch_relayed<N: Io>(
        &self,
        io: &N,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let target = self.stamp.address.socket_addr();
        let mut sends: u16 = 0;
        for _ in 0..options.tries.get() {
            let relay = self.pick(io)?;
            let Some(hop) = relay.map(|relay| relay.address.socket_addr()) else {
                break;
            };
            for transport in [Transport::Udp, Transport::Tcp] {
                let len = if transport == Transport::Udp {
                    CERTIFICATE_UDP_LEN
                } else {
                    RELAY_PACKET_LEN
                };
                let query = self.certificate_wire(io, len)?;
                let packet = relay_query(target, &query);
                let sent = io.now();
                let deadline = after(sent, options.timeout);
                let open = |datagram: &[u8]| certificate_response(&query, datagram);
                sends = sends.saturating_add(1);
                let heard = if transport == Transport::Udp {
                    udp_round(io, hop, &packet, deadline, open).await?
                } else {
                    tcp_round(io, hop, &packet, deadline, open).await?
                };
                if let Heard::Answer(wire) = heard {
                    // Truncated over UDP: the TCP query is as large as a relay lets it be.
                    if transport == Transport::Tcp || !is_truncated(&wire) {
                        return Ok(Response {
                            wire,
                            query,
                            transport,
                            rtt: io.now().saturating_duration_since(sent),
                            sends,
                            cookie: None,
                            http: None,
                            dnscrypt: None,
                        });
                    }
                }
            }
            self.failed(relay);
        }
        Err(DnsCryptError::Certificates(Box::new(Failure::TimedOut { sends }.into())).into())
    }

    /// The TXT query for the provider name as wire, `len` bytes long, with an ID of its own: a relay checks the
    /// response against it.
    fn certificate_wire<N: Io>(&self, io: &N, len: usize) -> Result<Vec<u8>, ClientError> {
        let mut id = [0; 2];
        io.random(&mut id).map_err(ClientError::Random)?;
        let question = Question::new(self.stamp.provider_name.name().clone(), RecordType::TXT);
        Ok(certificate_query(question, u16::from_be_bytes(id), len).to_vec()?)
    }

    /// Seals `wire`, a DNS query, under the certificate and sends it over `transport`, UDP or TCP: the response
    /// opened, or nothing before `deadline`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] for the certificates, the sockets or the encryption.
    pub(crate) async fn exchange<N: Io>(
        &self,
        client: &Client<N>,
        io: &N,
        wire: &[u8],
        transport: Transport,
        deadline: Instant,
        options: &Options,
    ) -> Result<Reply, ClientError> {
        let certificate = self.certificate(client, io, options).await?;
        let relay = self.pick(io)?;
        let pq = certificate.body().system() == EncryptionSystem::XWing;
        let mut entropy = Entropy::from_io(io).map_err(ClientError::Random)?;
        let nonce = ClientNonce::random(&mut entropy);
        let padding = if transport != Transport::Tcp {
            if pq && !options.dnscrypt.resume {
                // The ciphertext alone makes the packet longer than any response needs to be.
                QueryPadding::udp(wire.len(), 0)
            } else {
                QueryPadding::udp(wire.len(), self.state.borrow().floor)
            }
        } else if relay.is_some() {
            // A relay asks the resolver over UDP, and drops a response longer than the query: as large as is safe.
            QueryPadding::udp(wire.len(), RELAY_PACKET_LEN)
        } else {
            QueryPadding::tcp(wire.len(), &mut entropy)
        };
        // A ticket in hand and asked for: the query is a resumed one, with no encapsulation.
        let resumed = self.resumed(io, &certificate, options, wire, padding, nonce);
        let (packet, context, resumed) = if let Some((packet, context)) = resumed {
            (packet, context, true)
        } else {
            let session = if pq {
                ClientSession::xwing(&certificate, &mut entropy)
            } else {
                ClientSession::new(&certificate, &SecretKey::generate(&mut entropy))
            }
            .map_err(DnsCryptError::from)?;
            let (packet, context) = session
                .encrypt_query(wire, padding, nonce)
                .map_err(DnsCryptError::from)?;
            (packet, context, false)
        };
        entropy
            .finish()
            .map_err(|error| ClientError::Random(io::Error::other(error)))?;
        let (hop, packet) = match relay {
            Some(relay) => (
                relay.address.socket_addr(),
                relay_query(self.stamp.address.socket_addr(), &packet),
            ),
            None => (self.stamp.address.socket_addr(), packet),
        };
        let open = |datagram: &[u8]| self.opened(&context, datagram);
        let heard = if transport == Transport::Tcp {
            tcp_round(io, hop, &packet, deadline, open).await?
        } else {
            udp_round(io, hop, &packet, deadline, open).await?
        };
        Ok(match heard {
            Heard::Answer(Opened {
                message,
                resumption,
            }) => {
                if transport != Transport::Tcp && is_truncated(&message) {
                    self.raise_floor();
                }
                if options.dnscrypt.resume {
                    self.keep(io, &certificate, resumed, resumption);
                }
                Reply::Answer(
                    message,
                    CertificateInfo {
                        resumed,
                        ..info(&certificate)
                    },
                )
            }
            // A resolver drops the queries of a certificate it rotated, without a word (draft "Negative Cases"
            // case 1): silence over UDP, or a connection closed with no response, is all the sign there is, and
            // the next try fetches the certificates. A TCP query may only have been slow. A resolver drops a ticket
            // it does not accept in silence too: the next try is a full query.
            Heard::Closed => self.lost(relay, true, resumed),
            Heard::Silent => self.lost(relay, transport != Transport::Tcp, resumed),
        })
    }

    /// The query sealed under the ticket kept, if resuming is asked for and the ticket is of this certificate and
    /// has not expired at the exchange's clock. A ticket that is no good, or that no query can be sealed under, is
    /// dropped and the query is a full one.
    fn resumed<N: Io>(
        &self,
        io: &N,
        certificate: &Certificate,
        options: &Options,
        wire: &[u8],
        padding: QueryPadding,
        nonce: ClientNonce,
    ) -> Option<(Vec<u8>, QueryContext)> {
        if !options.dnscrypt.resume {
            return None;
        }
        let mut state = self.state.borrow_mut();
        let sealed = state
            .ticket
            .as_ref()
            .filter(|ticket| ticket.is_for(certificate) && io.now() < ticket.expires)
            .and_then(|ticket| ticket.resumption.encrypt_query(wire, padding, nonce).ok());
        if sealed.is_none() {
            state.ticket = None;
        }
        sealed
    }

    /// Keeps the ticket of a response, which replaces the one in use; a resumed query answered with none leaves
    /// the one in use, which the resolver still accepts until it expires.
    fn keep<N: Io>(
        &self,
        io: &N,
        certificate: &Certificate,
        resumed: bool,
        resumption: Option<Resumption>,
    ) {
        let mut state = self.state.borrow_mut();
        if let Some(resumption) = resumption {
            // The lifetime counts from receipt, cut at the end of the certificate, which is a date.
            let now = unix_now();
            let life = Duration::from_secs(resumption.expires_at(now).saturating_sub(now));
            state.ticket = io.now().checked_add(life).map(|expires| Ticket {
                expires,
                magic: certificate.body().client_magic,
                valid_until: certificate.body().validity.end(),
                resumption,
            });
        } else if !resumed {
            state.ticket = None;
        }
    }

    /// The response in `packet`, if it opens; one that does not authenticate makes the certificate stale.
    fn opened(&self, context: &QueryContext, packet: &[u8]) -> Option<Opened> {
        match context.open_response(packet) {
            Ok(response) => Some(response),
            Err(ResponseError::Authentication) => {
                self.state.borrow_mut().stale = true;
                None
            }
            Err(_) => None,
        }
    }

    /// Doubles the smallest packet of the next UDP queries, up to the largest: a resolver answers in no more bytes
    /// than the query had (draft "Client Queries Over UDP").
    fn raise_floor(&self) {
        let mut state = self.state.borrow_mut();
        state.floor = state.floor.saturating_mul(2).min(MAX_PACKET_LEN);
    }
}

/// What a packet sent to `hop`, the resolver or its relay, was answered with.
#[derive(Debug, PartialEq, Eq)]
enum Heard<T> {
    /// A response that `open` took.
    Answer(T),
    /// A connection closed with no response.
    Closed,
    /// Nothing, or nothing `open` took, before the deadline.
    Silent,
}

/// One datagram to `hop` from a socket of its own, and the first response `open` takes (draft "Client Queries Over
/// UDP": a packet that fails is disregarded).
async fn udp_round<N: Io, T>(
    io: &N,
    hop: SocketAddr,
    packet: &[u8],
    deadline: Instant,
    mut open: impl FnMut(&[u8]) -> Option<T>,
) -> Result<Heard<T>, ClientError> {
    let socket = io
        .udp_bind(unspecified(hop))
        .await
        .map_err(ClientError::Udp)?;
    socket.connect(hop).await.map_err(ClientError::Udp)?;
    let BufResult(sent, _) = socket.send(packet.to_vec()).await;
    sent.map_err(ClientError::Udp)?;
    // A response may be a spoof: the next datagram is waited for until the deadline.
    loop {
        let received = io
            .timeout_at(
                deadline,
                socket.recv(Vec::with_capacity(MAX_PACKET_LEN + 1)),
            )
            .await;
        let Ok(BufResult(read, datagram)) = received else {
            return Ok(Heard::Silent);
        };
        read.map_err(ClientError::Udp)?;
        if let Some(response) = open(&datagram) {
            return Ok(Heard::Answer(response));
        }
    }
}

/// The packet on a connection to `hop` of its own, framed, and the response on it, if `open` takes it (draft "Client
/// Queries Over TCP").
async fn tcp_round<N: Io, T>(
    io: &N,
    hop: SocketAddr,
    packet: &[u8],
    deadline: Instant,
    open: impl FnOnce(&[u8]) -> Option<T>,
) -> Result<Heard<T>, ClientError> {
    let framed = frame(packet).ok_or(TcpError::BadLength(packet.len()))?;
    let asked = async {
        let stream = io.tcp_connect(hop).await.map_err(TcpError::Connect)?;
        stream.set_nodelay(true).map_err(TcpError::Connect)?;
        let (mut reader, mut writer) = stream.split();
        let BufResult(written, _) = crate::tcp::Outbound::write_all(&mut writer, framed).await;
        written.map_err(|_| TcpError::Closed)?;
        Ok::<_, TcpError>(read_message(&mut reader).await.ok())
    };
    let Ok(asked) = io.timeout_at(deadline, asked).await else {
        return Ok(Heard::Silent);
    };
    Ok(match asked? {
        None => Heard::Closed,
        Some(datagram) => open(&datagram).map_or(Heard::Silent, Heard::Answer),
    })
}

/// The relay for a packet: one of `relays` by `draw`, but not `avoid`, the one that failed the last time, unless it is
/// the only one; none when there are no relays.
fn choose(relays: &[Relay], avoid: Option<Relay>, draw: u16) -> Option<Relay> {
    let others: Vec<Relay> = relays
        .iter()
        .copied()
        .filter(|relay| Some(*relay) != avoid)
        .collect();
    let pool = if others.is_empty() { relays } else { &others };
    pool.get(usize::from(draw).checked_rem(pool.len())?)
        .copied()
}

/// `datagram` if it answers the certificate query `query`: a response with its ID and question, the one a relay
/// checks too (draft "Anonymized `DNSCrypt`", "Relay Behavior").
fn certificate_response(query: &[u8], datagram: &[u8]) -> Option<Vec<u8>> {
    let asked = Message::decode(query).ok()?.message;
    let answer = Message::decode(datagram).ok()?.message;
    (answer.header.id == asked.header.id
        && answer.header.flags.contains(Flags::QR)
        && answer.questions == asked.questions)
        .then(|| datagram.to_vec())
}

/// The query for the certificates: a TXT query with `id`, its EDNS padding (RFC 7830) bringing it to `len` bytes, which
/// is also the response size it advertises.
fn certificate_query(question: Question<'_>, id: u16, len: usize) -> Message<'_> {
    let mut query = Message::query(id, question);
    let mut buf = [0; 512];
    let unpadded = query.encode(&mut buf).unwrap_or(buf.len());
    let padding = len.saturating_sub(unpadded + OPTION_HEAD);
    if let (Some(edns), Ok(padding)) = (query.edns.as_mut(), u16::try_from(padding)) {
        edns.udp_payload = u16::try_from(len).unwrap_or(u16::MAX);
        edns.options.push(EdnsOption::Padding(padding));
    }
    query
}

/// Which certificates the client takes: any, the PQ one first, or with `+dnscrypt-pq` the PQ ones only (D101).
fn policy(options: &Options) -> SystemPolicy {
    if options.dnscrypt.pq {
        SystemPolicy::Only(EncryptionSystem::XWing)
    } else {
        SystemPolicy::Preferred
    }
}

/// What a certificate tells, as the exchange reports it.
pub(crate) fn info(certificate: &Certificate) -> CertificateInfo {
    let body = certificate.body();
    CertificateInfo {
        es_version: u16::from_be_bytes(body.system().es_version()),
        serial: body.serial,
        valid_from: body.validity.start(),
        valid_until: body.validity.end(),
        resumed: false,
    }
}

/// Whether the TC flag of a DNS message is set (RFC 1035 §4.1.1).
fn is_truncated(message: &[u8]) -> bool {
    message.get(2).is_some_and(|flags| flags & 0b10 != 0)
}

/// The seconds since 1970 the certificates' validity is read against.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
