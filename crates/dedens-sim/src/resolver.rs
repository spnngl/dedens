//! The resolver host: a [`Pipeline`] served over UDP and TCP, as `dedensd` serves it (D42, D43, D45, D46;
//! `apps/dedensd/src/serve.rs`: `start` and `answer`).
//!
//! The pipeline is the scenario's: [`Resolver::build`] makes a new one at each start of the host, as a restarted
//! `dedensd` has an empty cache. [`pipeline`] is the default, a cache and a forwarder. A cache the scenario builds
//! must keep `shards: 1` ([`pipeline_with`] forces it): the shard of a key follows from a hash that is random for each
//! process, so with more the entry a full cache evicts could change from one process to another (D133).
//!
//! Mirrored: the forward stage's timeout and tries for each upstream query, the client response timer and the
//! stale reply it sends (D45), a failure of the query itself that abandons the question (D46), and the
//! connections `action: drop` refuses (D91).
//!
//! Left out (D133): socket pools, the inboxes of D108, connection reuse and idle timeouts (a connection's queries
//! are answered one after the other, in order), the shared flights of D86, the cap on connections and on
//! upstream queries, the few reading tasks of `dedensd` (here one task answers each datagram, so none is ever
//! waiting for a reader), compio's timers (tokio's, which turmoil advances, stand in) and threads.

use std::cell::RefCell;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_net::exchange::Options;
use dedens_proto::Transport;
use dedens_server::{Clock, Forward, Pipeline, Stage, Step, Upstream, Validating, Via};
use tokio::time::{Instant, timeout_at};
use turmoil::net::TcpStream;

use crate::client::{Carrier, Client};
use crate::framing;
use crate::port::{Arrival, Port};
use crate::seed::Rng;
use crate::trace::{Trace, What};

/// The size of the buffer a reply is made in: the largest message.
const OUT: usize = 65535;

/// Makes the pipeline of a start of the resolver from its upstream servers.
pub type Build = Rc<dyn Fn(&[SocketAddr]) -> Pipeline>;

/// The default pipeline: a cache of the default configuration and a forwarder to `upstreams`.
///
/// # Panics
///
/// With no upstream server.
#[must_use]
pub fn pipeline(upstreams: &[SocketAddr]) -> Pipeline {
    pipeline_with(Config::default(), upstreams)
}

/// A cache of `config`, in one shard whatever `config` says, and a forwarder to `upstreams`.
///
/// # Panics
///
/// With no upstream server, or a configuration the cache refuses.
#[must_use]
pub fn pipeline_with(config: Config, upstreams: &[SocketAddr]) -> Pipeline {
    let forward =
        Forward::new(upstreams.iter().copied()).expect("an upstream server to forward to");
    pipeline_forwarding(config, forward)
}

/// A cache of `config`, in one shard whatever `config` says, then `forward`: for a scenario that sets the forward
/// stage's timeout and tries ([`Forward::with_timeout`], [`Forward::with_tries`]).
///
/// # Panics
///
/// With a configuration the cache refuses.
#[must_use]
pub fn pipeline_forwarding(mut config: Config, forward: Forward) -> Pipeline {
    config.shards = 1;
    let cache = Cache::new(config).expect("the cache's configuration is valid");
    Pipeline::new(vec![Stage::Cache(Arc::new(cache)), Stage::Forward(forward)])
}

/// [`pipeline`] whose forward stage validates (D77) as `validating` says: its clock is [`wall_clock`] when it is
/// made with it.
///
/// # Panics
///
/// With no upstream server.
#[must_use]
pub fn pipeline_validating(upstreams: &[SocketAddr], validating: Validating) -> Pipeline {
    let forward = Forward::new(upstreams.iter().copied())
        .expect("an upstream server to forward to")
        .validating(validating);
    pipeline_forwarding(Config::default(), forward)
}

/// The wall clock of a host, in seconds since the epoch of the run ([`Topology::epoch`](crate::topology::Topology::epoch)):
/// what a validating stage reads in place of the system time, as `dedensd` does (D77).
#[must_use]
pub fn wall_clock() -> Clock {
    Arc::new(|| turmoil::since_epoch().map_or(0, |since| since.as_secs()))
}

/// The resolver's settings, and what its software starts from.
#[derive(Clone)]
pub struct Resolver {
    /// The upstream servers, asked in turn.
    pub upstreams: Vec<SocketAddr>,
    /// Its IDs, shared between its starts.
    pub rng: Rc<RefCell<Rng>>,
    /// The events of the run.
    pub trace: Trace,
    /// Makes the pipeline of each start.
    pub build: Build,
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("upstreams", &self.upstreams)
            .finish_non_exhaustive()
    }
}

/// What the tasks of one start share.
#[derive(Debug)]
struct Shared {
    pipeline: Pipeline,
    client: Client,
    /// Seconds since the start of the host are the clock of the cache, as `dedensd`'s `now`.
    started: Instant,
    host: IpAddr,
    trace: Trace,
}

impl Resolver {
    /// The software of the resolver host: serves port 53 until the host crashes.
    ///
    /// # Errors
    ///
    /// A socket that fails, or a task that panics.
    pub async fn serve(&self, host: IpAddr) -> turmoil::Result {
        let shared = Rc::new(Shared {
            pipeline: (self.build)(&self.upstreams),
            client: Client::new(Rc::clone(&self.rng), host, self.trace.clone()),
            started: Instant::now(),
            host,
            trace: self.trace.clone(),
        });
        let mut port = Port::bind().await?;
        loop {
            match port.next().await? {
                Arrival::Datagram { wire, from } => {
                    let shared = Rc::clone(&shared);
                    let socket = port.udp();
                    port.spawn(async move {
                        let mut out = vec![0; OUT];
                        let step = shared.pipeline.query(
                            &wire,
                            Transport::Udp,
                            from.ip(),
                            shared.now(),
                            &mut out,
                        );
                        shared
                            .start(step, Transport::Udp, &mut out, async |reply: &[u8]| {
                                socket.send_to(reply, from).await.ok();
                            })
                            .await;
                    });
                }
                Arrival::Connection { stream, peer } => {
                    // `action: drop` (D91): no reply, and no connection kept.
                    if shared.pipeline.drops(peer.ip()) {
                        drop(stream);
                        continue;
                    }
                    port.spawn(connection(Rc::clone(&shared), stream, peer));
                }
            }
        }
    }
}

/// Answers the queries of a connection, one after the other, until it closes or a reply cannot be written.
async fn connection(shared: Rc<Shared>, mut stream: TcpStream, peer: SocketAddr) {
    let mut out = vec![0; OUT];
    while let Ok(query) = framing::read(&mut stream).await {
        let step = shared
            .pipeline
            .query(&query, Transport::Tcp, peer.ip(), shared.now(), &mut out);
        let mut broken = false;
        shared
            .start(step, Transport::Tcp, &mut out, async |reply: &[u8]| {
                broken |= framing::write(&mut stream, reply).await.is_err();
            })
            .await;
        if broken {
            return;
        }
    }
}

impl Shared {
    /// Seconds since the host started, as `dedensd`'s `now()`.
    fn now(&self) -> u32 {
        u32::try_from(self.started.elapsed().as_secs()).unwrap_or(u32::MAX)
    }

    /// The entries and bytes of the cache, if the pipeline has one.
    fn held(&self) -> Option<(usize, usize)> {
        self.pipeline.stages().iter().find_map(|stage| match stage {
            Stage::Cache(cache) => Some((cache.len(), cache.used())),
            _ => None,
        })
    }

    /// Hands `reply` to `deliver`, and notes it.
    async fn send(
        &self,
        transport: Transport,
        reply: &[u8],
        stale: bool,
        deliver: &mut impl AsyncFnMut(&[u8]),
    ) {
        self.trace.record(
            self.host,
            What::Replied {
                transport,
                len: reply.len(),
                stale,
            },
        );
        deliver(reply).await;
    }

    /// Carries out the first `step` of a query that came over `transport`: replies are handed to `deliver`, made
    /// in `out`.
    async fn start(
        &self,
        step: Step,
        transport: Transport,
        out: &mut [u8],
        mut deliver: impl AsyncFnMut(&[u8]),
    ) {
        let upstream = match step {
            Step::Reply(len) => {
                self.send(transport, &out[..len], false, &mut deliver).await;
                return;
            }
            Step::Drop => return,
            // The cached answer goes out, then the cache is refreshed.
            Step::Refresh(len, upstream) => {
                self.send(transport, &out[..len], false, &mut deliver).await;
                upstream
            }
            Step::Upstream(upstream) => upstream,
        };
        self.answer(upstream, transport, out, deliver).await;
    }

    /// Asks the upstream servers for `upstream` in turn, as `dedensd`'s `answer`: each with the forward stage's
    /// timeout and tries, EDNS kept (a response without it would be stored for clients asking for DNSSEC
    /// records, RFC 3225), until the pipeline has a reply or none. When the client response timer runs out first,
    /// expired data goes out and resolution goes on (D45, RFC 8767 §5).
    async fn answer(
        &self,
        mut upstream: Box<Upstream>,
        transport: Transport,
        out: &mut [u8],
        mut deliver: impl AsyncFnMut(&[u8]),
    ) {
        let mut options = Options::default();
        (options.timeout, options.tries) = upstream.patience();
        options.edns_fallback = false;
        // The servers are plain: asked over the transport of the client (D65). `dedensd`'s `target` also maps the
        // others (TLS, QUIC, HTTPS) to their transports; the driver has none of them (D133), and a pipeline that
        // forwards to one stops the run rather than ask it in clear.
        let carrier = if transport == Transport::Udp {
            Carrier::Udp
        } else {
            Carrier::Tcp
        };
        let mut stale_at = upstream.stale_after().map(|after| Instant::now() + after);
        loop {
            let target = upstream.server();
            assert!(
                matches!(target.via, Via::Plain),
                "the driver forwards over plain DNS only, not {:?} (D133)",
                target.via
            );
            let server = target.addr;
            self.trace.record(
                self.host,
                What::Forwarded {
                    server,
                    transport: carrier.into(),
                },
            );
            let result = 'ask: {
                let mut exchange =
                    pin!(
                        self.client
                            .exchange(upstream.request(), server, carrier, &options)
                    );
                if let Some(at) = stale_at {
                    // A reborrow: the exchange goes on after the timer.
                    if let Ok(done) = timeout_at(at, exchange.as_mut()).await {
                        break 'ask done;
                    }
                    stale_at = None;
                    if let Some(len) = self.pipeline.stale(&mut upstream, self.now(), out) {
                        self.send(transport, &out[..len], true, &mut deliver).await;
                    }
                }
                exchange.await
            };
            let before = self.held();
            let step = match result {
                Ok(response) => {
                    self.pipeline
                        .receive(upstream, Some(&response.wire), self.now(), out)
                }
                // Not sent: the failure is local (`ClientError::is_local`, D46).
                Err(error) if error.is_local() => self.pipeline.abandon(&upstream, out),
                Err(_) => self.pipeline.receive(upstream, None, self.now(), out),
            };
            let after = self.held();
            if after != before
                && let Some((entries, bytes)) = after
            {
                self.trace
                    .record(self.host, What::Stored { entries, bytes });
            }
            match step {
                Step::Reply(len) | Step::Refresh(len, _) => {
                    self.send(transport, &out[..len], false, &mut deliver).await;
                    return;
                }
                Step::Drop => return,
                Step::Upstream(next) => upstream = next,
            }
        }
    }
}
