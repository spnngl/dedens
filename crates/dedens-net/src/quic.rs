//! DNS over QUIC (RFC 9250): one QUIC connection per server and certificate name, opened on first use and reused
//! while open; each query alone on a bidirectional stream, behind its two-byte length, the stream finished after it
//! (RFC 9250 §4.2). No 0-RTT: queries wait for the handshake (RFC 9250 §4.5). The server may open no stream
//! (RFC 9250 §4.3.3).

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::AsyncWriteExt as _;
use compio::quic::{ConnectError, Connection, ConnectionError, RecvStream, SendStream, VarInt};
use compio::rustls::pki_types::ServerName;

use crate::dial::{Dialer, Peer, Slots};
use crate::tcp::frame;
use crate::tls::{self, Trust};

/// `DOQ_PROTOCOL_ERROR`: the peer broke the protocol, and the connection is closed (RFC 9250 §4.3, §4.3.3).
pub const DOQ_PROTOCOL_ERROR: u32 = 0x2;

/// `DOQ_REQUEST_CANCELLED`: the client gave up waiting for a response (RFC 9250 §4.3, §4.3.1).
const DOQ_REQUEST_CANCELLED: u32 = 0x3;

/// The most a response stream holds: the two-byte length, then the message (RFC 9250 §4.2).
const MAX_STREAM: usize = 2 + 65535;

/// The bytes a QUIC peer may send on one stream before the reader returns credit (RFC 9000 §4.1; D119): a
/// whole message and its length (`MAX_STREAM`) with room for the HTTP/3 frames around a message (RFC 9114 §7.1).
pub const STREAM_RECEIVE_WINDOW: u32 = 80 << 10;

/// The bytes a client may send on all streams of a connection to `dedensd` before the server returns credit (RFC 9000
/// §4.1; D119): three full messages in flight, and the control and QPACK streams (RFC 9114 §6.2). Queries are small.
pub const RECEIVE_WINDOW: u32 = 256 << 10;

/// The bytes a server may send on all streams of a connection to a client's before it returns credit (RFC 9000
/// §4.1; D119): the replies of a forwarder's clients share one connection to an upstream (D61, D83), a reply being up
/// to [`STREAM_RECEIVE_WINDOW`], so the window is a throughput cap, 8 times the server's, not a memory bound.
pub const CLIENT_RECEIVE_WINDOW: u32 = 2 << 20;

/// Why a QUIC exchange failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum QuicError {
    /// TLS cannot be set up with the trust asked for, such as no certificate authority usable.
    #[error("cannot set up TLS")]
    Trust(#[source] compio::rustls::Error),
    /// No UDP socket to send from.
    #[error("cannot open a UDP socket")]
    Bind(#[source] io::Error),
    /// The connection cannot start, for instance with a name rustls refuses.
    #[error("cannot connect")]
    Connect(#[source] ConnectError),
    /// The connection failed or closed: a refused certificate (RFC 8310 §6.6), the server's closing or no packet
    /// for the idle timeout.
    #[error("connection")]
    Connection(#[source] ConnectionError),
    /// The stream of the query failed, reset or stopped by the server.
    #[error("stream")]
    Stream(#[source] io::Error),
    /// The query is longer than 65535 bytes.
    #[error("a query of {0} bytes cannot be framed")]
    BadLength(usize),
    /// What the stream held is not one message behind its length (RFC 9250 §4.3.3).
    #[error("the stream is not one message behind its length")]
    Framing,
    /// No response before the deadline.
    #[error("no response before the deadline")]
    TimedOut,
}

/// QUIC connections, one per server and name, closed by the QUIC idle timeout (RFC 9250 §4.4).
#[derive(Debug)]
pub struct QuicPool {
    dialer: Dialer,
    connections: Slots<Connection>,
}

impl QuicPool {
    /// No connection yet; those opened close after `idle` without a packet, unless the server asks for less.
    #[must_use]
    pub fn new(idle: Duration) -> Self {
        Self {
            // The server may open no stream (RFC 9250 §4.3.3).
            dialer: Dialer::new(tls::ALPN_DOQ, 0, idle),
            connections: Slots::default(),
        }
    }

    /// The pool, its connections trusting `trust`.
    #[must_use]
    pub fn trusting(self, trust: Trust) -> Self {
        Self {
            dialer: self.dialer.trusting(trust),
            ..self
        }
    }

    /// Sends `wire` to `addr`, whose certificate must hold `name`, and returns the response.
    ///
    /// A reused connection found closed once the query fails, as one the server dropped while idle (RFC 9250
    /// §4.4), is replaced once and the query sent again (D27). A response not framed closes the connection with
    /// `DOQ_PROTOCOL_ERROR` (RFC 9250 §4.3.3, D109): the query is not sent again, and the next one opens a new
    /// connection.
    ///
    /// # Errors
    ///
    /// [`QuicError`]: no TLS, socket or connection, a failed stream, a response not framed, or none before
    /// `deadline`.
    pub async fn exchange(
        &self,
        addr: SocketAddr,
        name: ServerName<'static>,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, QuicError> {
        let framed = frame(wire).ok_or(QuicError::BadLength(wire.len()))?;
        let server = (addr, name);
        let asked = async {
            let (connection, reused) = self.connection(&server).await?;
            match ask(&connection, &framed).await {
                // A framing error is the server's, and closes the connection here: not one found closed.
                Err(error)
                    if reused
                        && !matches!(error, QuicError::Framing)
                        && connection.close_reason().is_some() =>
                {
                    let (fresh, _) = self.connection(&server).await?;
                    ask(&fresh, &framed).await
                }
                asked => asked,
            }
        };
        compio::time::timeout_at(deadline, asked)
            .await
            .unwrap_or(Err(QuicError::TimedOut))
    }

    /// The open connection to `server`, reused, or a new one.
    async fn connection(&self, server: &Peer) -> Result<(Connection, bool), QuicError> {
        let slot = self.connections.slot(server);
        let mut slot = slot.lock().await;
        if let Some(open) = slot.as_ref()
            && open.close_reason().is_none()
        {
            return Ok((open.clone(), true));
        }
        let connection = self.dialer.connect(server.0, &server.1).await?;
        Ok((slot.insert(connection).clone(), false))
    }
}

/// Sends `framed` alone on a new stream of `connection` and reads the response to the end of the stream.
async fn ask(connection: &Connection, framed: &[u8]) -> Result<Vec<u8>, QuicError> {
    let (send, recv) = connection
        .open_bi_wait()
        .await
        .map_err(QuicError::Connection)?;
    let mut stream = Stream {
        send,
        recv,
        read: false,
    };
    let BufResult(written, _) = stream.send.write_all(framed.to_vec()).await;
    written.map_err(QuicError::Stream)?;
    stream
        .send
        .finish()
        .map_err(|closed| QuicError::Stream(io::Error::other(closed)))?;
    let response = match read_message(&mut stream.recv).await {
        Ok(response) => response,
        Err(QuicError::Framing) => {
            // The server broke the protocol: the connection goes, and the next query opens another (RFC 9250
            // §4.3.3, D109).
            connection.close(VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"response not framed");
            return Err(QuicError::Framing);
        }
        Err(error) => return Err(error),
    };
    stream.read = true;
    Ok(response)
}

/// The message on `recv`, read to the end of the stream: one message behind its two-byte length, a stream holding
/// anything else being a protocol error (RFC 9250 §4.2, §4.3.3).
///
/// # Errors
///
/// [`QuicError::Stream`] for a stream reset or a connection lost, [`QuicError::Framing`] for a stream that is not
/// one message behind its length.
pub async fn read_message(recv: &mut RecvStream) -> Result<Vec<u8>, QuicError> {
    let mut bytes = Vec::new();
    // One byte past the most a stream holds is enough to refuse it.
    while let Some(chunk) = recv
        .read_chunk(MAX_STREAM + 1 - bytes.len(), true)
        .await
        .map_err(|error| QuicError::Stream(error.into()))?
    {
        bytes.extend_from_slice(&chunk.bytes);
        if bytes.len() > MAX_STREAM {
            return Err(QuicError::Framing);
        }
    }
    match bytes.get(..2) {
        Some(&[high, low]) if usize::from(u16::from_be_bytes([high, low])) == bytes.len() - 2 => {
            bytes.drain(..2);
            Ok(bytes)
        }
        _ => Err(QuicError::Framing),
    }
}

/// The stream of a query, cancelled when dropped before its response is read whole: `RESET_STREAM` and
/// `STOP_SENDING` with `DOQ_REQUEST_CANCELLED` (RFC 9250 §4.3.1), so that a query cut by a timeout does not go out
/// finished.
struct Stream {
    send: SendStream,
    recv: RecvStream,
    /// The response was read to the end of the stream: nothing to cancel.
    read: bool,
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.read {
            let code = VarInt::from_u32(DOQ_REQUEST_CANCELLED);
            // Each fails once its side is closed: nothing left to cancel there.
            let _ = self.send.reset(code);
            let _ = self.recv.stop(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CLIENT_RECEIVE_WINDOW, MAX_STREAM, RECEIVE_WINDOW, STREAM_RECEIVE_WINDOW};

    /// The windows are sized as D119 sets: a stream takes a whole message, a server connection three streams and
    /// the control and QPACK streams, a client connection 8 times the server's.
    #[test]
    fn the_receive_windows_hold_what_d119_sizes() {
        let stream = u32::try_from(MAX_STREAM).expect("a stream size");
        assert!(STREAM_RECEIVE_WINDOW >= stream);
        const { assert!(RECEIVE_WINDOW > 3 * STREAM_RECEIVE_WINDOW) };
        assert_eq!(CLIENT_RECEIVE_WINDOW, 8 * RECEIVE_WINDOW);
    }
}
