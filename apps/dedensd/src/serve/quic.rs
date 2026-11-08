//! QUIC listeners: the endpoint and its connections (D66), DNS over QUIC one query per stream (RFC 9250 §4.2), and
//! HTTP/3 connections handed to `http3.rs` (D84).

use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::Arc;

use compio::BufResult;
use compio::io::AsyncWriteExt;
use compio::net::UdpSocket;
use compio::quic::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use compio::runtime::JoinHandle;
use dedens_net::quic::{
    DOQ_PROTOCOL_ERROR, QuicError, RECEIVE_WINDOW, STREAM_RECEIVE_WINDOW,
    read_message as read_stream,
};
use dedens_net::tcp::frame;
use dedens_proto::edns::OptionCode;
use dedens_proto::{Query, Transport};
use socket2::Socket;

use super::http3::requests;
use super::isolate::{Listener, Origin};
use super::tcp::{TCP_PENDING, TCP_WRITE};
use super::upstream::answer;
use super::{Started, TCP_IDLE, Thread, local, start, supervised};

/// Serves the QUIC endpoint on `udp_socket` as `service`, as the listener `scheme`. A restarted loop takes the same
/// endpoint: `wait_incoming` ends only once the endpoint is closed, which nothing here does, so the loop does not
/// end by itself, and a panic leaves the endpoint as it was.
pub(super) fn quic_task(
    thread: &Rc<Thread>,
    scheme: &str,
    udp_socket: Socket,
    config: ServerConfig,
    uni_streams: u32,
    service: Service,
) -> io::Result<JoinHandle<()>> {
    let name = Listener::new(scheme, local(&udp_socket));
    let serving = endpoint(udp_socket, config, uni_streams)?;
    let service = Rc::new(service);
    Ok(supervised(name, thread, move |name, thread| {
        quic(
            serving.clone(),
            Rc::clone(&service),
            name.clone(),
            Rc::clone(thread),
        )
    }))
}

/// The QUIC endpoint on `socket` with `config`: connections closed after [`TCP_IDLE`] without a packet (RFC 9250
/// §5.5.1), with [`TCP_PENDING`] queries in flight at most, and `uni_streams` the client may open: none for DNS over
/// QUIC (§4.2), [`H3_UNI_STREAMS`](super::http3::H3_UNI_STREAMS) for HTTP/3 (RFC 9114 §6.2). No DATAGRAM frame is read (D107): the receive buffer
/// is off, so quinn advertises no `max_datagram_frame_size` (RFC 9221 §3) and closes the connection on a DATAGRAM
/// frame from the peer. A peer may send [`RECEIVE_WINDOW`] bytes on the connection and [`STREAM_RECEIVE_WINDOW`] on a
/// stream before the reader returns credit (D119).
fn endpoint(socket: Socket, mut config: ServerConfig, uni_streams: u32) -> io::Result<Endpoint> {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(IdleTimeout::try_from(TCP_IDLE).ok())
        .max_concurrent_bidi_streams(
            u32::try_from(TCP_PENDING).map_or(VarInt::MAX, VarInt::from_u32),
        )
        .max_concurrent_uni_streams(VarInt::from_u32(uni_streams))
        .receive_window(VarInt::from_u32(RECEIVE_WINDOW))
        .stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .datagram_receive_buffer_size(None);
    config.transport_config(Arc::new(transport));
    let socket = UdpSocket::from_std(socket.into())?;
    Endpoint::new(socket, EndpointConfig::default(), Some(config), None)
}

/// What a QUIC endpoint serves.
pub(super) enum Service {
    /// DNS over QUIC (RFC 9250).
    Quic,
    /// `DoH` over HTTP/3 at the path (RFC 8484, RFC 9114; D84).
    Https(Arc<str>),
}

/// `DOQ_EXCESSIVE_LOAD`: a stream given up because its client does not read the reply (RFC 9250 §4.3.2).
const DOQ_EXCESSIVE_LOAD: u32 = 0x4;

/// Accepts the connections of one QUIC endpoint, up to [`TCP_CONNECTIONS`](super::tcp::TCP_CONNECTIONS) at once with those over TCP, and serves
/// each as `service` says. A client whose address is not validated gets a Retry (RFC 9000 §8.1.2) and no state or
/// slot: a spoofed source never sees it, so forged Initials cannot fill the slots.
async fn quic(endpoint: Endpoint, service: Rc<Service>, listener: Listener, thread: Rc<Thread>) {
    while let Some(incoming) = endpoint.wait_incoming().await {
        let peer = incoming.remote_address();
        // `action: drop` (D91): not even a Retry, no slot, no handshake; `refuse` answers each query.
        if thread.pipeline().drops(peer.ip()) {
            incoming.ignore();
            continue;
        }
        if !incoming.remote_address_validated() {
            if let Err(error) = incoming.retry() {
                tracing::debug!(%peer, %error, "QUIC retry failed");
            }
            continue;
        }
        let Some(slot) = thread.connections.take() else {
            tracing::debug!(%peer, "too many connections: refused");
            incoming.refuse();
            continue;
        };
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(error) => {
                tracing::debug!(%peer, %error, "QUIC connection refused");
                continue;
            }
        };
        let (service, thread) = (Rc::clone(&service), Rc::clone(&thread));
        let origin = Origin::new(&listener, peer);
        origin.clone().spawn(async move {
            match connecting.await {
                Ok(connection) => match &*service {
                    Service::Quic => streams(&connection, &origin, &thread).await,
                    Service::Https(path) => {
                        let budget = thread.h3.register(connection.clone(), &origin);
                        requests(connection, path, &origin, &thread, &budget).await;
                    }
                },
                Err(error) => tracing::debug!(%peer, %error, "QUIC handshake failed"),
            }
            drop(slot);
        });
    }
}

/// Answers the queries of one QUIC connection (RFC 9250 §4.2), each alone on a stream the client opened, as soon
/// as it can be; a stream not one query behind its length within [`TCP_IDLE`] is abandoned, and a query breaking
/// the protocol closes the connection with `DOQ_PROTOCOL_ERROR` (§4.3.3).
async fn streams(connection: &Connection, origin: &Origin, thread: &Rc<Thread>) {
    while let Ok(Ok((send, mut recv))) =
        compio::time::timeout(TCP_IDLE, connection.accept_bi()).await
    {
        let (connection, thread) = (connection.clone(), Rc::clone(thread));
        let from = origin.peer.ip();
        origin.clone().spawn(async move {
            let read = compio::time::timeout(TCP_IDLE, read_stream(&mut recv)).await;
            match read {
                Ok(Ok(query)) if !breaks_doq(&query) => stream(&query, send, from, &thread).await,
                Ok(Ok(_) | Err(QuicError::Framing)) => {
                    connection.close(VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"");
                }
                Ok(Err(_)) | Err(_) => {}
            }
        });
    }
}

/// Whether `query` breaks DNS over QUIC: a Message ID other than 0 (RFC 9250 §4.2.1) or an edns-tcp-keepalive option
/// (§5.5.2). A query that does not read goes on, to be answered FORMERR.
fn breaks_doq(query: &[u8]) -> bool {
    Query::read(query).is_ok_and(|query| {
        query.header().id != 0
            || query.edns().is_some_and(|edns| {
                edns.options()
                    .any(|option| option.code() == OptionCode::KEEPALIVE)
            })
    })
}

/// Answers `query` on its stream `send`, then finishes it: one reply, the first made.
async fn stream(query: &[u8], send: SendStream, from: IpAddr, thread: &Thread) {
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = start(thread, &pipeline, query, Transport::Quic, from, |wire| {
        first = frame(wire);
        true
    });
    let mut send = Some(send);
    if let Some(framed) = first {
        respond(&mut send, framed).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |framed| respond(&mut send, framed).await;
        answer(thread, &pipeline, upstream, Transport::Quic, deliver).await;
        drop(slot);
    }
}

/// Writes `framed` on `send` and finishes it, unless it was answered already; a write lasting [`TCP_WRITE`] is given
/// up and the stream reset with `DOQ_EXCESSIVE_LOAD` (RFC 9250 §4.3.2), as a TCP client reading too slowly loses
/// its connection (D47).
async fn respond(send: &mut Option<SendStream>, framed: Vec<u8>) {
    let Some(mut stream) = send.take() else {
        return;
    };
    match compio::time::timeout(TCP_WRITE, stream.write_all(framed)).await {
        Ok(BufResult(Ok(()), _)) => {
            let _ = stream.finish();
        }
        Ok(_) => {}
        Err(_) => {
            let _ = stream.reset(VarInt::from_u32(DOQ_EXCESSIVE_LOAD));
        }
    }
}

// The tests run sockets and a runtime, which loom's threads and locks cannot drive (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
mod tests {

    use dedens_proto::edns::EdnsOption;
    use dedens_proto::{Message, Question, RecordType};

    use super::breaks_doq;

    /// RFC 9250 §4.3.3: a Message ID other than 0 and an edns-tcp-keepalive option break DNS over QUIC.
    #[test]
    fn doq_queries_have_id_0_and_no_keepalive() {
        let name: dedens_proto::Name<'static> = "example.com.".parse().expect("a name");
        let query = |id, keepalive| {
            let mut query = Message::query(id, Question::new(name.clone(), RecordType::A));
            if keepalive && let Some(edns) = &mut query.edns {
                edns.options.push(EdnsOption::Keepalive(None));
            }
            query.to_vec().expect("a query fits")
        };
        assert!(!breaks_doq(&query(0, false)));
        assert!(breaks_doq(&query(1, false)));
        assert!(breaks_doq(&query(0, true)));
        assert!(!breaks_doq(b"not a query"));
    }
}
