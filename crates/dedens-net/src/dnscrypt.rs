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
    Certificate, ClientNonce, ClientSession, EncryptQueryError, LowOrderKey, MAX_PACKET_LEN,
    ProviderKey, QueryContext, QueryPadding, ResponseError, SecretKey, SystemPolicy, select,
};
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
    /// The resolver's key is of low order.
    #[error(transparent)]
    LowOrderKey(#[from] LowOrderKey),
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
            Self::LowOrderKey(_) | Self::Encrypt(_) => true,
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
        if let Some(kept) = self.kept(io) {
            return Ok(kept);
        }
        let (_, certificates) = self.fetch(client, options).await?;
        let chosen = select(&certificates, unix_now(), SystemPolicy::Preferred)
            .ok_or(DnsCryptError::NoCertificate)?
            .clone();
        let mut state = self.state.borrow_mut();
        state.chosen = Some((chosen.clone(), io.now()));
        state.stale = false;
        Ok(chosen)
    }

    /// The certificate in use, while it is valid, recent and no response failed under it.
    fn kept<N: Io>(&self, io: &N) -> Option<Certificate> {
        let state = self.state.borrow();
        let (certificate, fetched) = state.chosen.as_ref()?;
        (!state.stale
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

    /// Asks the resolver for its certificates: a TXT query for the provider name, in the clear, over TCP when
    /// `options` say so and over UDP, then TCP, else (draft "Certificates").
    async fn fetch<N: Io>(
        &self,
        client: &Client<N>,
        options: &Options,
    ) -> Result<(Response, Vec<Certificate>), ClientError> {
        let question = Question::new(self.stamp.provider_name.name().clone(), RecordType::TXT);
        // No cookie: the query is nothing to link, and the exchange keeps none.
        let asked = Options {
            transport: if options.transport == Transport::Tcp {
                Transport::Tcp
            } else {
                Transport::Udp
            },
            cookies: false,
            ..*options
        };
        // Boxed: this is a query of the client, which may be the one that is waiting for the certificate.
        let response = Box::pin(client.exchange(
            Message::query(0, question),
            Server::from(self.stamp.address.socket_addr()),
            &asked,
        ))
        .await
        .map_err(|error| DnsCryptError::Certificates(Box::new(error)))?;
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
        let mut entropy = Entropy::from_io(io).map_err(ClientError::Random)?;
        let secret = SecretKey::generate(&mut entropy);
        let nonce = ClientNonce::random(&mut entropy);
        let padding = if transport == Transport::Tcp {
            QueryPadding::tcp(wire.len(), &mut entropy)
        } else {
            QueryPadding::udp(wire.len(), self.state.borrow().floor)
        };
        entropy
            .finish()
            .map_err(|error| ClientError::Random(io::Error::other(error)))?;
        let session = ClientSession::new(&certificate, &secret).map_err(DnsCryptError::from)?;
        let (packet, context) = session
            .encrypt_query(wire, padding, nonce)
            .map_err(DnsCryptError::from)?;
        let opened = if transport == Transport::Tcp {
            self.over_tcp(io, &packet, &context, deadline).await?
        } else {
            self.over_udp(io, &packet, &context, deadline).await?
        };
        Ok(match opened {
            Some(response) => Reply::Answer(response, info(&certificate)),
            None => Reply::TimedOut,
        })
    }

    /// One datagram from a socket of its own, and the first that opens (draft "Client Queries Over UDP": a packet
    /// that fails is disregarded).
    async fn over_udp<N: Io>(
        &self,
        io: &N,
        packet: &[u8],
        context: &QueryContext,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, ClientError> {
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
            if let Some(response) = self.opened(context, &datagram) {
                if is_truncated(&response) {
                    self.raise_floor();
                }
                return Ok(Some(response));
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
    ) -> Result<Option<Vec<u8>>, ClientError> {
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
    fn opened(&self, context: &QueryContext, packet: &[u8]) -> Option<Vec<u8>> {
        match context.decrypt_response(packet) {
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

/// What a certificate tells, as the exchange reports it.
pub(crate) fn info(certificate: &Certificate) -> CertificateInfo {
    let body = certificate.body();
    CertificateInfo {
        es_version: u16::from_be_bytes(body.system.es_version()),
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
