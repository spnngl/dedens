//! Messages over a TCP stream: a two-byte length in front of each (RFC 1035 §4.2.2).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Writes `wire` behind its length.
///
/// # Errors
///
/// The stream's, or [`io::ErrorKind::InvalidInput`] for a message longer than 65535 bytes.
pub(crate) async fn write(stream: &mut (impl AsyncWrite + Unpin), wire: &[u8]) -> io::Result<()> {
    let len = u16::try_from(wire.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message over 65535 bytes"))?;
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(wire);
    stream.write_all(&framed).await
}

/// Reads one message.
///
/// # Errors
///
/// The stream's: [`io::ErrorKind::UnexpectedEof`] when it closed.
pub(crate) async fn read(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut len = [0; 2];
    stream.read_exact(&mut len).await?;
    let mut wire = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut wire).await?;
    Ok(wire)
}
