//! The transports a message goes over, which bound its size.

/// UDP, TCP, TLS, QUIC, HTTPS or `CoAP`: the client's and the server's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP: a message fits the EDNS payload size, at most 1232 bytes asked (D10), or 512 without EDNS; TC says
    /// records were left out (RFC 1035 §4.2.1, RFC 6891 §6.2.5).
    Udp,
    /// TCP: each message whole, up to 65535 bytes, behind its two-byte length (RFC 1035 §4.2.2, RFC 7766 §8).
    Tcp,
    /// TLS: as TCP, the TCP connection carrying a TLS session (RFC 7858 §3.3).
    Tls,
    /// QUIC: as TCP, each query and its response alone on a QUIC stream (RFC 9250 §4.2).
    Quic,
    /// HTTPS: each message whole, up to 65535 bytes, as the body or the `dns` parameter of one HTTP exchange, with
    /// no length prefix (RFC 8484 §6). TC says the server could not get a full answer, not to retry over TCP
    /// (RFC 8484 §9).
    Https,
    /// `CoAP` (`DoC`, RFC 9953): each message whole as the body of one CoAP exchange, in blocks when it is over the
    /// block size (RFC 7959), over UDP and without protection, the DNS ID 0 (RFC 9953 §4.2.2). A message may be as
    /// long as over HTTPS: the blocks are what keep a datagram small. TC does not ask for TCP.
    Coap,
}
