//! The addresses `dedensd` answers on (D66, D84): UDP and TCP, TLS (RFC 7858 §3.1), QUIC (RFC 9250 §4.1.1), HTTP/3
//! (RFC 8484 §3) and CoAP (RFC 9953, D81), and the certificate they present.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::{fmt, fs, io};

use anyhow::{Context, bail, ensure};
use compio::rustls::pki_types::pem::PemObject as _;
use compio::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use dedens_net::doh::DEFAULT_PATH;
use dedens_net::tls::Presented;
use http::uri::PathAndQuery;
use serde::Deserialize;

use super::keys::guard_key;
use super::upstream::{ENCRYPTED_PORT, HTTPS_PORT};

/// The certificate `dedensd` presents, as written: PEM files, read again on each reload.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TlsFile {
    /// The certificate chain, the server's first.
    certificate: PathBuf,
    /// Its private key.
    key: PathBuf,
}

/// An address `dedensd` answers on (D66, D84): `IP:PORT` over UDP and TCP; behind `tls://` over TLS, behind `quic://`
/// over QUIC, on port 853 unless `:PORT` follows (RFC 7858 §3.1, RFC 9250 §4.1.1); behind `https://` over HTTP/3, on
/// port 443 unless `:PORT` follows, at `/PATH` (`/dns-query` unless set; RFC 8484 §3, RFC 9114 §3.1); behind `coap://`
/// over CoAP, unprotected, on UDP port 5683 unless `:PORT` follows, at `/PATH` (`/` unless set; RFC 9953, D81; the `doc`
/// feature); behind `dnscrypt://` as a `DNSCrypt` resolver (D99), over UDP and TCP, on port 443
/// unless `:PORT` follows (the `dnscrypt` feature).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) enum Listen {
    Plain(SocketAddr),
    Tls(SocketAddr),
    Quic(SocketAddr),
    Https(SocketAddr, Arc<str>),
    #[cfg(feature = "doc")]
    Coap(SocketAddr, Arc<str>),
    #[cfg(feature = "dnscrypt")]
    Dnscrypt(SocketAddr),
}

impl Listen {
    /// The address listened on.
    pub(crate) const fn addr(&self) -> SocketAddr {
        match self {
            Self::Plain(addr) | Self::Tls(addr) | Self::Quic(addr) | Self::Https(addr, _) => *addr,
            #[cfg(feature = "doc")]
            Self::Coap(addr, _) => *addr,
            #[cfg(feature = "dnscrypt")]
            Self::Dnscrypt(addr) => *addr,
        }
    }

    /// Whether queries come encrypted, with the certificate of `tls`.
    const fn encrypted(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            #[cfg(feature = "doc")]
            Self::Coap(..) => false,
            #[cfg(feature = "dnscrypt")]
            Self::Dnscrypt(_) => false,
            Self::Tls(_) | Self::Quic(_) | Self::Https(..) => true,
        }
    }
}

/// As written, for the logs: `[tls://127.0.0.1:853]` rather than `[Tls(127.0.0.1:853)]`.
impl fmt::Debug for Listen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(addr) => write!(f, "{addr}"),
            Self::Tls(addr) => write!(f, "tls://{addr}"),
            Self::Quic(addr) => write!(f, "quic://{addr}"),
            Self::Https(addr, path) => write!(f, "https://{addr}{path}"),
            #[cfg(feature = "doc")]
            Self::Coap(addr, path) => write!(f, "coap://{addr}{path}"),
            #[cfg(feature = "dnscrypt")]
            Self::Dnscrypt(addr) => write!(f, "dnscrypt://{addr}"),
        }
    }
}

/// The port of CoAP (RFC 7252 §6.1; RFC 9953 §3).
#[cfg(feature = "doc")]
const COAP_PORT: u16 = 5683;

impl TryFrom<String> for Listen {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let encrypted = |rest: &str| address(rest, ENCRYPTED_PORT);
        let listen = match text.split_once("://") {
            None => text.parse().ok().map(Self::Plain),
            Some(("tls", rest)) => encrypted(rest).map(Self::Tls),
            Some(("quic", rest)) => encrypted(rest).map(Self::Quic),
            Some(("https", rest)) => {
                let (rest, path) =
                    split_path(rest).map_err(|error| format!("`{text}`: {error}"))?;
                address(rest, HTTPS_PORT).map(|addr| Self::Https(addr, path))
            }
            #[cfg(feature = "doc")]
            Some(("coap", rest)) => {
                let (rest, path) =
                    split_coap_path(rest).map_err(|error| format!("`{text}`: {error}"))?;
                address(rest, COAP_PORT).map(|addr| Self::Coap(addr, path))
            }
            #[cfg(feature = "dnscrypt")]
            Some(("dnscrypt", rest)) => address(rest, HTTPS_PORT).map(Self::Dnscrypt),
            Some(_) => None,
        };
        listen.ok_or_else(|| {
            format!(
                "`{text}` is neither IP:PORT nor tls://, quic://, https://, coap:// (built with the `doc` feature) or dnscrypt:// (built with the `dnscrypt` feature) before IP[:PORT]"
            )
        })
    }
}

/// Refuses a `dnscrypt://` address on the IP and the port of another listener's UDP socket or TCP listener: one
/// socket for both goes to `docs/TODECIDE.md` (D99). Other pairs are not checked: the OS refuses a bound port, but
/// where it allows `SO_REUSEPORT`, the two would share it and each would see the other's datagrams.
///
/// # Errors
///
/// A `dnscrypt://` address and another that share a port.
#[cfg(feature = "dnscrypt")]
pub(super) fn distinct_ports(listen: &[Listen]) -> anyhow::Result<()> {
    // The transports an address takes a port of: (UDP, TCP).
    let ports = |listen: &Listen| match listen {
        Listen::Plain(_) | Listen::Dnscrypt(_) => (true, true),
        Listen::Tls(_) => (false, true),
        Listen::Quic(_) | Listen::Https(..) => (true, false),
        #[cfg(feature = "doc")]
        Listen::Coap(..) => (true, false),
    };
    for (index, one) in listen.iter().enumerate() {
        let others = listen.iter().skip(index + 1);
        for other in others.filter(|other| other.addr() == one.addr()) {
            let both = matches!(one, Listen::Dnscrypt(_)) || matches!(other, Listen::Dnscrypt(_));
            let ((udp, tcp), (other_udp, other_tcp)) = (ports(one), ports(other));
            ensure!(
                !both || !(udp && other_udp || tcp && other_tcp),
                "`listen`: {one:?} and {other:?} take the same port"
            );
        }
    }
    Ok(())
}

/// `ADDR[/PATH]` split in `ADDR` and the path, `/dns-query` unless set (RFC 8484 §3): a path of a request target
/// without query, which a template's `{?dns}` fills (RFC 6570 §3.2.8).
pub(super) fn split_path(text: &str) -> Result<(&str, Arc<str>), String> {
    let Some(start) = text.find('/') else {
        return Ok((text, Arc::from(DEFAULT_PATH)));
    };
    let (rest, path) = text.split_at(start);
    let valid = path
        .parse::<PathAndQuery>()
        .is_ok_and(|parsed| parsed.query().is_none())
        && !path.contains(['{', '}']);
    if valid {
        Ok((rest, Arc::from(path)))
    } else {
        Err(format!("`{path}` is not a path without query"))
    }
}

/// `ADDR[/PATH]` split in `ADDR` and the path of a CoAP URI, `/` unless set (RFC 9953 §3.2): without query, fragment
/// or percent-encoding, which segments are read as written;
/// no `.` or `..` segment, and not `/.well-known/core`, which lists the resource (D95).
#[cfg(feature = "doc")]
fn split_coap_path(text: &str) -> Result<(&str, Arc<str>), String> {
    let Some(start) = text.find('/') else {
        return Ok((text, Arc::from("/")));
    };
    let (rest, path) = text.split_at(start);
    if path.contains(['?', '#', '%']) {
        Err(format!(
            "`{path}` is not a path without query, fragment or %"
        ))
    } else if path == "/.well-known/core" {
        Err(format!("`{path}` is where the resources are listed"))
    } else if path.split('/').any(|segment| matches!(segment, "." | "..")) {
        // A Uri-Path is never one (RFC 7252 §5.10.1): no request could reach it.
        Err(format!("`{path}` has a segment `.` or `..`"))
    } else {
        Ok((rest, Arc::from(path)))
    }
}

/// `IP:PORT`, or an IP address, on `port`; an IPv6 address in brackets or not.
pub(crate) fn address(text: &str, port: u16) -> Option<SocketAddr> {
    let bare = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    text.parse()
        .or_else(|_| bare.parse().map(|ip: IpAddr| SocketAddr::new(ip, port)))
        .ok()
}

/// The certificate of `tls`, read from its files, when `listen` has an address over TLS, QUIC or HTTP/3.
///
/// # Errors
///
/// A certificate without such an address or the reverse, a file that does not read, a chain without a certificate,
/// a file without a key, a key file others can access ([`guard_key`]), or a key that is not the certificate's.
pub(super) fn presented(
    listen: &[Listen],
    tls: Option<&TlsFile>,
) -> anyhow::Result<Option<Presented>> {
    let encrypted = listen.iter().any(Listen::encrypted);
    let tls = match (tls, encrypted) {
        (Some(tls), true) => tls,
        (None, false) => return Ok(None),
        (None, true) => {
            bail!("`listen` has a tls://, quic:// or https:// address, and `tls` no certificate")
        }
        (Some(_), false) => {
            bail!("`tls` has a certificate, and `listen` no tls://, quic:// or https:// address")
        }
    };
    let path = tls.certificate.display();
    let chain = CertificateDer::pem_file_iter(&tls.certificate)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("`tls`: cannot read certificates from {path}"))?;
    ensure!(!chain.is_empty(), "`tls`: no certificate in {path}");
    let unreadable = || {
        format!(
            "`tls`: cannot read a private key from {}",
            tls.key.display()
        )
    };
    let file = fs::File::open(&tls.key).with_context(unreadable)?;
    guard_key(&file, "`tls`", &tls.key)?;
    let key = PrivateKeyDer::from_pem_reader(io::BufReader::new(file)).with_context(unreadable)?;
    let presented = Presented::new(chain, key)
        .with_context(|| format!("`tls`: the key does not fit {path}"))?;
    Ok(Some(presented))
}

#[cfg(test)]
mod tests {
    use dedens_server::Pipeline;

    use super::*;
    use crate::config::tests::*;

    #[test]
    fn listen_addresses_take_port_853_encrypted_and_443_over_https() {
        for (text, listen) in [
            (
                "127.0.0.1:53",
                Listen::Plain("127.0.0.1:53".parse().unwrap()),
            ),
            (
                "tls://127.0.0.1",
                Listen::Tls("127.0.0.1:853".parse().unwrap()),
            ),
            (
                "tls://[::1]:8853",
                Listen::Tls("[::1]:8853".parse().unwrap()),
            ),
            ("quic://[::1]", Listen::Quic("[::1]:853".parse().unwrap())),
            (
                "https://127.0.0.1",
                Listen::Https("127.0.0.1:443".parse().unwrap(), "/dns-query".into()),
            ),
            (
                "https://[::1]:8443/doh",
                Listen::Https("[::1]:8443".parse().unwrap(), "/doh".into()),
            ),
        ] {
            assert_eq!(Listen::try_from(text.to_owned()), Ok(listen), "{text}");
        }
        for text in [
            "127.0.0.1",
            "https://dns.example",
            "https://127.0.0.1/dns-query?dns=",
            "https://127.0.0.1/{?dns}",
            "https://127.0.0.1#dns.example",
            "https://127.0.0.1:0x1",
            "tls://dns.example",
            "tls://127.0.0.1#dns.example",
        ] {
            assert!(Listen::try_from(text.to_owned()).is_err(), "{text}");
        }
    }

    /// A `dnscrypt://` address takes UDP and TCP of its port, the other listeners one of them: none shares an address
    /// with it.
    #[cfg(feature = "dnscrypt")]
    #[test]
    fn dnscrypt_does_not_share_a_port_by_transport() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let dnscrypt = Listen::Dnscrypt(addr);
        for other in [
            Listen::Plain(addr),
            Listen::Tls(addr),
            Listen::Quic(addr),
            Listen::Https(addr, "/dns-query".into()),
            Listen::Dnscrypt(addr),
        ] {
            assert!(distinct_ports(&[dnscrypt.clone(), other.clone()]).is_err());
            assert!(distinct_ports(&[other, dnscrypt.clone()]).is_err());
        }
        // Listeners of other kinds share a port by transport, which this check leaves to the bind.
        let tls = Listen::Tls(addr);
        let quic = Listen::Quic(addr);
        assert!(distinct_ports(&[tls, quic]).is_ok());
        assert!(
            distinct_ports(&[dnscrypt, Listen::Plain("127.0.0.1:444".parse().unwrap())]).is_ok()
        );
    }

    /// `coap://` takes port 5683 and the path `/` unless set, a path without query, fragment or `%`, with no `.` or
    /// `..` segment, and not the one where the resources are listed (D95).
    #[cfg(feature = "doc")]
    #[test]
    fn coap_listen_addresses_take_port_5683_and_the_root_path() {
        for (text, listen) in [
            (
                "coap://127.0.0.1",
                Listen::Coap("127.0.0.1:5683".parse().unwrap(), "/".into()),
            ),
            (
                "coap://[::1]:5684/dns/query",
                Listen::Coap("[::1]:5684".parse().unwrap(), "/dns/query".into()),
            ),
        ] {
            assert_eq!(Listen::try_from(text.to_owned()), Ok(listen), "{text}");
        }
        for text in [
            "coap://dns.example",
            "coap://127.0.0.1/dns?dns=",
            "coap://127.0.0.1/a#b",
            "coap://127.0.0.1/a%20b",
            "coap://127.0.0.1/.well-known/core",
            "coap://127.0.0.1/a/./b",
            "coap://127.0.0.1/a/..",
        ] {
            assert!(Listen::try_from(text.to_owned()).is_err(), "{text}");
        }
    }

    /// A certificate goes with an address over TLS or QUIC, and the reverse.
    #[test]
    fn tls_listeners_and_a_certificate_go_together() {
        let encrypted = MINIMAL.replace("'127.0.0.1:53'", "'tls://127.0.0.1'");
        let tls = "tls:\n  certificate: /nonexistent.pem\n  key: /nonexistent.pem\n";
        for (text, message) in [
            (encrypted.clone(), "`tls` no certificate"),
            (format!("{tls}{MINIMAL}"), "`listen` no tls://"),
            (format!("{tls}{encrypted}"), "cannot read certificates"),
        ] {
            let error = read(&text, env, &Pipeline::default()).unwrap_err();
            assert!(format!("{error:#}").contains(message), "{error:#}");
        }
        assert!(
            read(MINIMAL, env, &Pipeline::default())
                .unwrap()
                .presented
                .is_none()
        );
    }
}
