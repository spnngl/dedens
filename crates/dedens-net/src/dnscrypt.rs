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

use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use compio::BufResult;
use compio::io::util::Splittable;
use dedens_dnscrypt::{
    Certificate, ClientNonce, ClientSession, EncryptQueryError, EncryptionSystem, MAX_PACKET_LEN,
    Opened, ProviderKey, QueryContext, QueryPadding, ResponseError, Resumption, SecretKey,
    SessionError, SystemPolicy, select,
};
use dedens_proto::edns::EdnsOption;
use dedens_proto::rdata::RData;
use dedens_proto::{Message, Question, RecordType, Transport};

use crate::client::{Client, ClientError, Server};
use crate::entropy::Entropy;
use crate::exchange::{CertificateInfo, Options, Response};
use crate::io::{Io, Stream, Udp};
use crate::stamp::DnsCrypt;
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

/// The resolvers a client has asked, by stamp.
#[derive(Debug, Default)]
pub(crate) struct Resolvers(RefCell<Vec<Rc<Resolver>>>);

impl Resolvers {
    /// The resolver of `stamp`, made at the first call.
    pub(crate) fn of(&self, stamp: &DnsCrypt) -> Rc<Resolver> {
        let mut known = self.0.borrow_mut();
        if let Some(resolver) = known.iter().find(|resolver| resolver.stamp == *stamp) {
            return Rc::clone(resolver);
        }
        let resolver = Rc::new(Resolver::new(stamp.clone()));
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

/// A `DNSCrypt` resolver: its stamp, the provider key its certificates are signed with, and what the client has
/// learned of it.
#[derive(Debug)]
pub struct Resolver {
    stamp: DnsCrypt,
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
    /// The ticket of the last PQ response, kept only for `DnsCryptOptions::resume`.
    ticket: Option<Ticket>,
}

/// A resumption ticket and what the client checks before using it: the certificate it was issued under and when it
/// expires, in Unix seconds.
#[derive(Debug)]
struct Ticket {
    resumption: Resumption,
    serial: u32,
    expires: u64,
}

impl Resolver {
    fn new(stamp: DnsCrypt) -> Self {
        Self {
            provider: ProviderKey::from_bytes(stamp.public_key),
            stamp,
            state: RefCell::new(State {
                chosen: None,
                stale: false,
                floor: FIRST_FLOOR,
                ticket: None,
            }),
        }
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
        let (_, certificates) = self.fetch(client, options).await?;
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
        options: &Options,
    ) -> Result<Listing, ClientError> {
        let (response, certificates) = self.fetch(client, options).await?;
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
    async fn fetch<N: Io>(
        &self,
        client: &Client<N>,
        options: &Options,
    ) -> Result<(Response, Vec<Certificate>), ClientError> {
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
            let query = certificate_query(question.clone());
            let server = server.clone();
            // Boxed: this is a query of the client, which may be the one that is waiting for the certificate.
            async move { Box::pin(client.exchange(query, server, &asked)).await }
        };
        let response = match attempt(Transport::Udp).await {
            Ok(response) => response,
            Err(_) => attempt(Transport::Tcp)
                .await
                .map_err(|error| DnsCryptError::Certificates(Box::new(error)))?,
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
        let pq = certificate.body().system() == EncryptionSystem::XWing;
        let mut entropy = Entropy::from_io(io).map_err(ClientError::Random)?;
        let nonce = ClientNonce::random(&mut entropy);
        let padding = if transport == Transport::Tcp {
            QueryPadding::tcp(wire.len(), &mut entropy)
        } else if pq && !options.dnscrypt.resume {
            // The ciphertext alone makes the packet longer than any response needs to be.
            QueryPadding::udp(wire.len(), 0)
        } else {
            QueryPadding::udp(wire.len(), self.state.borrow().floor)
        };
        // A ticket in hand and asked for: the query is a resumed one, with no encapsulation.
        let resumed = self.resumed(&certificate, options, wire, padding, nonce);
        let (packet, context, resumed) = if let Some(sealed) = resumed {
            let (packet, context) = sealed.map_err(DnsCryptError::from)?;
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
        let opened = if transport == Transport::Tcp {
            self.over_tcp(io, &packet, &context, deadline).await?
        } else {
            self.over_udp(io, &packet, &context, deadline).await?
        };
        let Some(Opened {
            message,
            resumption,
        }) = opened
        else {
            // A resolver drops a ticket it does not accept in silence: the next try is a full query.
            if resumed {
                self.state.borrow_mut().ticket = None;
            }
            return Ok(Reply::TimedOut);
        };
        if options.dnscrypt.resume {
            self.keep(&certificate, resumed, resumption);
        }
        Ok(Reply::Answer(message, info(&certificate)))
    }

    /// The query sealed under the ticket kept, if resuming is asked for and the ticket is of this certificate and
    /// has not expired; a ticket that is no good is dropped.
    fn resumed(
        &self,
        certificate: &Certificate,
        options: &Options,
        wire: &[u8],
        padding: QueryPadding,
        nonce: ClientNonce,
    ) -> Option<Result<(Vec<u8>, QueryContext), EncryptQueryError>> {
        if !options.dnscrypt.resume {
            return None;
        }
        let mut state = self.state.borrow_mut();
        let usable = state.ticket.as_ref().is_some_and(|ticket| {
            ticket.serial == certificate.body().serial && ticket.expires > unix_now()
        });
        if !usable {
            state.ticket = None;
            return None;
        }
        state
            .ticket
            .as_ref()
            .map(|ticket| ticket.resumption.encrypt_query(wire, padding, nonce))
    }

    /// Keeps the ticket of a response, which replaces the one in use; a resumed query answered with none leaves
    /// the one in use, which the resolver still accepts until it expires.
    fn keep(&self, certificate: &Certificate, resumed: bool, resumption: Option<Resumption>) {
        let mut state = self.state.borrow_mut();
        if let Some(resumption) = resumption {
            state.ticket = Some(Ticket {
                expires: resumption.expires_at(unix_now()),
                serial: certificate.body().serial,
                resumption,
            });
        } else if !resumed {
            state.ticket = None;
        }
    }

    /// One datagram from a socket of its own, and the first that opens (draft "Client Queries Over UDP": a packet
    /// that fails is disregarded).
    async fn over_udp<N: Io>(
        &self,
        io: &N,
        packet: &[u8],
        context: &QueryContext,
        deadline: Instant,
    ) -> Result<Option<Opened>, ClientError> {
        let server = self.stamp.address.socket_addr();
        let socket = io
            .udp_bind(unspecified(server))
            .await
            .map_err(ClientError::Udp)?;
        socket.connect(server).await.map_err(ClientError::Udp)?;
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
                // A resolver drops the queries of a certificate it rotated, without a word (draft "Negative
                // Cases" case 1): silence is all the sign there is, and the next try fetches the certificates.
                self.state.borrow_mut().stale = true;
                return Ok(None);
            };
            read.map_err(ClientError::Udp)?;
            if let Some(opened) = self.opened(context, &datagram) {
                if is_truncated(&opened.message) {
                    self.raise_floor();
                }
                return Ok(Some(opened));
            }
        }
    }

    /// The query on a connection of its own, framed, and the response on it (draft "Client Queries Over TCP"). A
    /// connection closed with no response, as a resolver does with a query of a certificate it dropped, makes the
    /// certificate stale.
    async fn over_tcp<N: Io>(
        &self,
        io: &N,
        packet: &[u8],
        context: &QueryContext,
        deadline: Instant,
    ) -> Result<Option<Opened>, ClientError> {
        let server = self.stamp.address.socket_addr();
        let framed = frame(packet).ok_or(TcpError::BadLength(packet.len()))?;
        let asked = async {
            let stream = io.tcp_connect(server).await.map_err(TcpError::Connect)?;
            stream.set_nodelay(true).map_err(TcpError::Connect)?;
            let (mut reader, mut writer) = stream.split();
            let BufResult(written, _) = crate::tcp::Outbound::write_all(&mut writer, framed).await;
            written.map_err(|_| TcpError::Closed)?;
            Ok::<_, TcpError>(read_message(&mut reader).await.ok())
        };
        let Ok(asked) = io.timeout_at(deadline, asked).await else {
            return Ok(None);
        };
        let Some(datagram) = asked? else {
            self.state.borrow_mut().stale = true;
            return Ok(None);
        };
        Ok(self.opened(context, &datagram))
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

/// The query for the certificates: a TXT query, its EDNS padding bringing it to [`CERTIFICATE_QUERY_LEN`] bytes, which
/// is also the response size it advertises.
fn certificate_query(question: Question<'_>) -> Message<'_> {
    let mut query = Message::query(0, question);
    let mut buf = [0; 512];
    let unpadded = query.encode(&mut buf).unwrap_or(buf.len());
    // The option's own header is 4 bytes.
    let padding = CERTIFICATE_QUERY_LEN.saturating_sub(unpadded + 4);
    if let (Some(edns), Ok(padding)) = (query.edns.as_mut(), u16::try_from(padding)) {
        edns.udp_payload = u16::try_from(CERTIFICATE_QUERY_LEN).unwrap_or(u16::MAX);
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
