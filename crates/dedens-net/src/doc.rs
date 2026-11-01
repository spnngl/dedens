//! DNS over CoAP, the client's socket (RFC 9953 §4, D81; the `doc` feature).
//!
//! One UDP socket per query, connected to the server, source port picked by the OS, and a random token of 8 bytes:
//! the token is what an off-path attacker must guess, as the DNS ID is 0 (RFC 9953 §4.2.2, §6). The retransmission is
//! CoAP's, [`coap::exchange::Exchange`](crate::coap::exchange::Exchange) with the defaults of RFC 7252 §4.8, not the
//! DNS tries and timeout: the DNS exchange is told to try once.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use compio::BufResult;
use compio::net::UdpSocket;
use compio::time::timeout_at;

use crate::client::ClientError;
use crate::coap::doc::{add_max_age, request};
use crate::coap::exchange::{Exchange, Failure, Next, Params, Response, Step};
use crate::coap::{Code, Options, Token};
use crate::udp::unspecified;

/// The largest UDP payload, which a datagram may fill.
const MAX_DATAGRAM: usize = 65535;

/// Why a CoAP exchange gave no DNS response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DocError {
    /// The UDP socket failed, for instance on an ICMP port unreachable.
    #[error("UDP")]
    Udp(#[source] io::Error),
    /// The CoAP exchange ended without a response.
    #[error(transparent)]
    Exchange(#[from] Failure),
    /// A response code other than 2.05: a CoAP error never holds a DNS response (RFC 9953 §4.3.1).
    #[error("the server answered {0}")]
    Code(Code),
    /// A content format other than `application/dns-message`, 553 (RFC 9953 §4.3).
    #[error("the response has the content format {0}, not 553 (application/dns-message)")]
    Format(u16),
    /// A 2.05 response whose body is not a DNS message.
    #[error("the response is not a DNS message")]
    NotDns,
}

/// Asks `server` for the DNS response to `query` at the path `docpath`, with the `random` bytes for the token (8),
/// the first message ID (2) and the seed of the retransmission jitter (4). The response is the body of the 2.05
/// answer, the TTLs raised by its Max-Age (RFC 9953 §4.3.2).
///
/// # Errors
///
/// [`ClientError::Doc`]: a socket failure, no response, a CoAP error code, a content format or body that is not DNS.
pub(crate) async fn coap(
    query: &[u8],
    server: SocketAddr,
    docpath: &[Box<[u8]>],
    random: [u8; 14],
) -> Result<Vec<u8>, ClientError> {
    let [token @ .., id_high, id_low, s0, s1, s2, s3] = random;
    let token = Token::new(&token).expect("8 bytes fit a token");
    let request = request(docpath, query.to_vec(), token);
    let first_id = u16::from_be_bytes([id_high, id_low]);
    let seed = u32::from_be_bytes([s0, s1, s2, s3]).max(1);
    let response = run(request, server, first_id, seed).await?;
    debug!(
        %server,
        code = %response.code,
        max_age = response.options.max_age(),
        bytes = response.payload.len(),
        "CoAP response"
    );
    if response.code != Code::CONTENT {
        return Err(DocError::Code(response.code).into());
    }
    // No Content-Format is `application/dns-message`, the one asked for (RFC 9953 §4.3).
    if let Some(format) = response.options.content_format()
        && format != Options::DNS_MESSAGE
    {
        return Err(DocError::Format(format).into());
    }
    let mut body = response.payload;
    add_max_age(&mut body, response.options.max_age()).map_err(|_| DocError::NotDns)?;
    Ok(body)
}

/// The CoAP exchange of `request` over a socket of its own.
async fn run(
    request: crate::coap::exchange::Request,
    server: SocketAddr,
    first_id: u16,
    seed: u32,
) -> Result<Response, DocError> {
    let socket = UdpSocket::bind(unspecified(server))
        .await
        .map_err(DocError::Udp)?;
    socket.connect(server).await.map_err(DocError::Udp)?;
    let step = Exchange::start(
        request,
        server,
        Params::default(),
        first_id,
        seed,
        Instant::now(),
    );
    let mut buf = Vec::with_capacity(MAX_DATAGRAM);
    let Step { mut send, mut next } = step;
    loop {
        for datagram in send {
            let BufResult(sent, _) = socket.send(datagram).await;
            sent.map_err(DocError::Udp)?;
        }
        let exchange = match next {
            Next::Done(result) => return result.map_err(DocError::Exchange),
            Next::Wait(exchange) => exchange,
        };
        let deadline = exchange.deadline();
        buf.clear();
        let step =
            if let Ok(BufResult(received, back)) = timeout_at(deadline, socket.recv(buf)).await {
                buf = back;
                let len = received.map_err(DocError::Udp)?;
                exchange.receive(server, &buf[..len], Instant::now())
            } else {
                buf = Vec::with_capacity(MAX_DATAGRAM);
                exchange.time_out(Instant::now().max(deadline))
            };
        (send, next) = (step.send, step.next);
    }
}
