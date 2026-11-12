//! A DNS-over-TLS server host (RFC 7858): port 853, rustls over turmoil's TCP through the seam's stream, answering
//! from [`Answers`] one query at a time per connection. The faults of [`Answers`] (`faulty`, `silent`, `tcp`) are
//! plain DNS's: this host answers every query it holds data for.

use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::sync::Arc;

use compio::BufResult;
use compio::io::{AsyncReadExt, AsyncWrite as _, AsyncWriteExt};
use compio::tls::TlsAcceptor;
use dedens_net::tls::{self, Presented};
use dedens_proto::Transport;
use tokio::task::JoinSet;
use turmoil::net::{TcpListener, TcpStream};

use crate::io::SimStream;
use crate::trace::{Trace, What};
use crate::upstream::Answers;

/// The DNS-over-TLS port.
pub const PORT: u16 = 853;

/// The software of a DNS-over-TLS server host: answers on port 853 with the certificate `presented`, until the host
/// crashes.
///
/// # Errors
///
/// A configuration rustls refuses, a listener that fails, or a task that panics.
pub async fn serve(
    answers: Rc<Answers>,
    host: IpAddr,
    presented: Arc<Presented>,
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
                    trace.clone(),
                ));
            }
            Some(ended) = tasks.join_next() => ended?,
        }
    }
}

/// Serves the queries of a connection, one at a time, until it closes.
async fn connection(
    answers: Rc<Answers>,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    host: IpAddr,
    trace: Trace,
) {
    serve_queries(&answers, acceptor, stream, host, &trace).await;
    answers.closed();
}

/// The queries of [`connection`], until one side closes it or it fails.
async fn serve_queries(
    answers: &Answers,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    host: IpAddr,
    trace: &Trace,
) {
    let Ok(stream) = SimStream::new(stream) else {
        return;
    };
    let Ok(mut stream) = acceptor.accept(stream).await else {
        return;
    };
    loop {
        let Ok(len) = stream.read_u16().await else {
            return;
        };
        let BufResult(read, query) = stream
            .read_exact(Vec::with_capacity(usize::from(len)))
            .await;
        if read.is_err() {
            return;
        }
        trace.record(
            host,
            What::Received {
                transport: Transport::Tls,
            },
        );
        let Some((reply, question)) = answers.reply(&query, Transport::Tls) else {
            continue;
        };
        trace.record(
            host,
            What::Served {
                question,
                transport: Transport::Tls,
            },
        );
        let Ok(len) = u16::try_from(reply.len()) else {
            return;
        };
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        // A TLS stream holds what it wrote until flushed.
        if stream.write_all(framed).await.0.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}
