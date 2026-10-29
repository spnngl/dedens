//! The transports a message goes over, which bound its size.

/// UDP, TCP or TLS: the client's and the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP: a message fits the EDNS payload size, at most 1232 bytes asked (D10), or 512 without EDNS; TC says
    /// records were left out (RFC 1035 §4.2.1, RFC 6891 §6.2.5).
    Udp,
    /// TCP: each message whole, up to 65535 bytes, behind its two-byte length (RFC 1035 §4.2.2, RFC 7766 §8).
    Tcp,
    /// TLS: as TCP, the TCP connection carrying a TLS session (RFC 7858 §3.3).
    Tls,
}
