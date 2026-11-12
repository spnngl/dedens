//! A DNS-over-TLS server host (RFC 7858): port 853, rustls over turmoil's TCP through the seam's stream, answering
//! from [`Answers`] as the upstream host answers over TCP, its faults too (`faulty`, `silent`, `tcp`), and the
//! queries of a connection pipelined (RFC 7858 §3.3).

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::sync::Arc;

use compio::tls::TlsAcceptor;
use dedens_net::tcp::Polled;
use dedens_net::tls::{self, Presented};
use dedens_proto::Transport;
use tokio::task::JoinSet;
use turmoil::net::{TcpListener, TcpStream};

use crate::io::SimStream;
use crate::seed::Rng;
use crate::trace::Trace;
use crate::upstream::{self, Answers};

/// The DNS-over-TLS port.
pub const PORT: u16 = 853;

/// The software of a DNS-over-TLS server host: answers on port 853 with the certificate `presented`, drawing its
/// faults from `rng`, until the host crashes.
///
/// # Errors
///
/// A configuration rustls refuses, a listener that fails, or a task that panics.
pub async fn serve(
    answers: Rc<Answers>,
    host: IpAddr,
    presented: Arc<Presented>,
    rng: Rc<RefCell<Rng>>,
    trace: Trace,
) -> turmoil::Result {
    let acceptor = tls::acceptor(presented)?;
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, PORT)).await?;
    let mut tasks = JoinSet::new();
    loop {
        // Biased: the random order of the branches is not drawn from the seed, and a run must replay.
        tokio::select! {
            biased;
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                answers.accepted();
                tasks.spawn_local(connection(
                    Rc::clone(&answers),
                    acceptor.clone(),
                    stream,
                    host,
                    Rc::clone(&rng),
                    trace.clone(),
                ));
            }
            Some(ended) = tasks.join_next() => ended?,
        }
    }
}

/// Serves the queries of a connection after its handshake (see [`upstream::queries`]), then counts it ended.
async fn connection(
    answers: Rc<Answers>,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    host: IpAddr,
    rng: Rc<RefCell<Rng>>,
    trace: Trace,
) {
    // A stream closed as it was accepted, or a client that fails the handshake, has nothing to serve.
    if let Ok(stream) = SimStream::new(stream)
        && let Ok(stream) = acceptor.accept(stream).await
    {
        let (reader, writer) = Polled::halves(stream);
        upstream::queries(&answers, Transport::Tls, reader, writer, host, &rng, &trace).await;
    }
    answers.closed();
}
