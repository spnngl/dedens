//! The resolver host: a [`Pipeline`] of a cache and a forwarder served over UDP and TCP, as `dedensd` serves it
//! (D42, D43, D45, D46; `apps/dedensd/src/serve.rs`: `start` and `answer`).
//!
//! Left out, for step 10 (D133): socket pools, the inboxes of D108, connection reuse and idle timeouts (a
//! connection's queries are answered one after the other), the shared flights of D86, the stale-answer timer of
//! D45 and compio's timers (tokio's, which turmoil advances, stand in).

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_net::exchange::{Failure, Options};
use dedens_proto::Transport;
use dedens_server::{Forward, Pipeline, Stage, Step, Upstream};
use tokio::time::Instant;
use turmoil::net::TcpStream;

use crate::client::{Carrier, Client};
use crate::framing;
use crate::port::{Arrival, Port};
use crate::seed::Rng;
use crate::trace::{Trace, What};

/// The size of the buffer a reply is made in: the largest message.
const OUT: usize = 65535;

/// The resolver's settings, and what its software starts from: a new [`Pipeline`] with an empty cache at each
/// start, as a restarted `dedensd` has.
#[derive(Debug, Clone)]
pub struct Resolver {
    /// The upstream servers, asked in turn.
    pub upstreams: Vec<SocketAddr>,
    /// Its IDs, shared between its starts.
    pub rng: Rc<RefCell<Rng>>,
    /// The events of the run.
    pub trace: Trace,
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
    /// A socket that fails, a task that panics, or no upstream server.
    pub async fn serve(&self, host: IpAddr) -> turmoil::Result {
        let forward = Forward::new(self.upstreams.iter().copied()).ok_or("no upstream server")?;
        let shared = Rc::new(Shared {
            pipeline: Pipeline::new(vec![
                // One shard: the shard of a key follows from a hash that is random for each process (D133).
                Stage::Cache(Arc::new(Cache::new(Config {
                    shards: 1,
                    ..Config::default()
                })?)),
                Stage::Forward(forward),
            ]),
            client: Client::new(Rc::clone(&self.rng)),
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
                deliver(&out[..len]).await;
                return;
            }
            Step::Drop => return,
            // The cached answer goes out, then the cache is refreshed.
            Step::Refresh(len, upstream) => {
                deliver(&out[..len]).await;
                upstream
            }
            Step::Upstream(upstream) => upstream,
        };
        self.answer(upstream, transport, out, deliver).await;
    }

    /// Asks the upstream servers for `upstream` in turn, as `dedensd`'s `answer`: each with the forward stage's
    /// timeout and tries, EDNS kept (a response without it would be stored for clients asking for DNSSEC
    /// records, RFC 3225), until the pipeline has a reply or none.
    async fn answer(
        &self,
        mut upstream: Box<Upstream>,
        transport: Transport,
        out: &mut [u8],
        mut deliver: impl AsyncFnMut(&[u8]),
    ) {
        loop {
            let server = upstream.server().addr;
            let mut options = Options::default();
            (options.timeout, options.tries) = upstream.patience();
            options.edns_fallback = false;
            // The servers are plain: asked over the transport of the client (D65).
            let carrier = if transport == Transport::Udp {
                Carrier::Udp
            } else {
                Carrier::Tcp
            };
            self.trace.record(
                self.host,
                What::Forwarded {
                    server,
                    transport: carrier.into(),
                },
            );
            let result = self
                .client
                .exchange(upstream.request(), server, carrier, &options)
                .await;
            let step = match result {
                Ok(response) => {
                    self.pipeline
                        .receive(upstream, Some(&response.wire), self.now(), out)
                }
                // Not sent: the failure is local (`ClientError::is_local`, D46).
                Err(Failure::Encode(_)) => self.pipeline.abandon(&upstream, out),
                Err(_) => self.pipeline.receive(upstream, None, self.now(), out),
            };
            match step {
                Step::Reply(len) | Step::Refresh(len, _) => {
                    deliver(&out[..len]).await;
                    return;
                }
                Step::Drop => return,
                Step::Upstream(next) => upstream = next,
            }
        }
    }
}
