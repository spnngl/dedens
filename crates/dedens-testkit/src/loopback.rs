//! The socket loops the loopback servers ([`crate::responder`], [`crate::relay`]) share: a datagram received, a
//! connection accepted, past the errors that do not end them.

use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

/// The pause after a first failed accept.
const FIRST: Duration = Duration::from_millis(10);

/// The longest pause between two failed accepts.
const MOST: Duration = Duration::from_secs(1);

/// The next datagram on `socket`, in `buf`: its length and sender. An interrupted receive, or the error of an earlier
/// datagram some systems report (the ICMP error a reply to a client gone brings back), is skipped.
///
/// # Panics
///
/// On another error: the server would stop answering, and the test waiting on it would time out with no cause.
pub(crate) fn receive(socket: &UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    loop {
        match socket.recv_from(buf) {
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::Interrupted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionRefused
                ) => {}
            received => return received.expect("a loopback server's UDP socket receives"),
        }
    }
}

/// The next connection on `listener`. A failed accept (the process out of descriptors, `EMFILE`, or a connection
/// reset before it was taken) is logged and tried again after a pause doubling from [`FIRST`] to [`MOST`]: tried
/// again at once, it spun a core while the tests holding the descriptors starved.
pub(crate) fn accept(listener: &TcpListener) -> TcpStream {
    retry(
        "accept",
        || listener.accept().map(|(stream, _)| stream),
        thread::sleep,
    )
}

/// What `attempt` gives, tried again after each error, logged, with a `pause` of its own doubling up to [`MOST`].
fn retry<T>(
    what: &str,
    mut attempt: impl FnMut() -> io::Result<T>,
    mut pause: impl FnMut(Duration),
) -> T {
    let mut wait = FIRST;
    loop {
        match attempt() {
            Ok(value) => return value,
            Err(error) => {
                eprintln!("dedens-testkit: {what}: {error}; again in {wait:?}");
                pause(wait);
                wait = wait.saturating_mul(2).min(MOST);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `incoming().flatten()` tried again at once: out of descriptors (`EMFILE`), a core spun until one closed.
    #[test]
    fn a_failed_accept_is_tried_again_after_a_pause_growing_to_its_bound() {
        let mut failures = 12;
        let mut pauses = Vec::new();
        let accepted = retry(
            "accept",
            || {
                if failures == 0 {
                    return Ok("a connection");
                }
                failures -= 1;
                Err(io::Error::from_raw_os_error(24))
            },
            |pause| pauses.push(pause),
        );
        assert_eq!(accepted, "a connection");
        assert_eq!(pauses.len(), 12);
        assert_eq!(pauses[0], FIRST);
        assert!(pauses.is_sorted(), "{pauses:?}");
        assert_eq!(pauses.last(), Some(&MOST));
    }
}
