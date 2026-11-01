//! TLS for DNS over TLS (RFC 7858) and over QUIC (RFC 9250): which certificates a client trusts and the client
//! configurations built from that; the certificate a server presents and the server configurations.
//!
//! The strict privacy profile of RFC 8310 §6.6: a server whose certificate does not verify for the name expected,
//! or the address when there is none, is not queried, short of [`Trust::Anyone`]. rustls with ring, TLS 1.2 and
//! 1.3 (RFC 8310 §9: no older version) over TCP, TLS 1.3 alone over QUIC (RFC 9001 §4.2), session resumption on
//! (RFC 7858 §3.4), ALPN `dot`, `doq` or `h3` (RFC 9461 §4.1, RFC 9250 §4.1.1, RFC 9114 §3.1).

use std::sync::{Arc, PoisonError, RwLock};

use compio::quic::ServerConfig;
use compio::quic::crypto::rustls::QuicServerConfig;
use compio::rustls;
use compio::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use compio::rustls::crypto::{
    CryptoProvider, ring, verify_tls12_signature, verify_tls13_signature,
};
use compio::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use compio::rustls::server::{ClientHello, ResolvesServerCert};
use compio::rustls::sign::CertifiedKey;
use compio::rustls::version::TLS13;
use compio::rustls::{
    ClientConfig, DEFAULT_VERSIONS, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    SupportedProtocolVersion,
};
use compio::tls::{TlsAcceptor, TlsConnector};

/// Which server certificates a client accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Trust {
    /// Those the operating system's trust store verifies.
    #[default]
    System,
    /// Those signed by one of these certificate authorities, instead of the system's.
    Roots(Vec<CertificateDer<'static>>),
    /// Any, unverified: for tests only, the connection is encrypted but the server unknown.
    Anyone,
}

/// The ALPN protocol of DNS over TLS (RFC 9461 §4.1, RFC 7301).
const ALPN_DOT: &[u8] = b"dot";

/// The ALPN protocol of DNS over QUIC (RFC 9250 §4.1.1).
pub(crate) const ALPN_DOQ: &[u8] = b"doq";

/// The ALPN protocol of HTTP/3, which DNS over HTTPS goes over (RFC 9114 §3.1, RFC 8484 §5.2).
pub(crate) const ALPN_H3: &[u8] = b"h3";

/// The certificate a server presents, which may be replaced while it serves: each handshake takes the one
/// current then.
#[derive(Debug)]
pub struct Presented(RwLock<Arc<CertifiedKey>>);

impl Presented {
    /// Presents `chain`, the server's certificate first, signed with `key`.
    ///
    /// # Errors
    ///
    /// rustls' [`Error`] for a key ring cannot sign with, or which is not that of the first certificate.
    pub fn new(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, Error> {
        let certified = CertifiedKey::from_der(chain, key, &ring::default_provider())?;
        Ok(Self(RwLock::new(Arc::new(certified))))
    }

    /// Presents what `with` presents, from the next handshake on.
    pub fn replace(&self, with: Self) {
        let certified = with.0.into_inner().unwrap_or_else(PoisonError::into_inner);
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = certified;
    }
}

impl ResolvesServerCert for Presented {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(
            &self.0.read().unwrap_or_else(PoisonError::into_inner),
        ))
    }
}

/// The acceptor of TLS sessions presenting `presented`, for DNS over TLS.
///
/// # Errors
///
/// rustls' [`Error`], never with ring's defaults.
pub fn acceptor(presented: Arc<Presented>) -> Result<TlsAcceptor, Error> {
    let config = server_config(presented, DEFAULT_VERSIONS, ALPN_DOT)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The configuration of QUIC connections presenting `presented`, for DNS over QUIC: without 0-RTT, which a
/// replayed query could use (RFC 9250 §4.5).
///
/// # Errors
///
/// As [`acceptor`].
pub fn quic_server_config(presented: Arc<Presented>) -> Result<ServerConfig, Error> {
    let config = server_config(presented, &[&TLS13], ALPN_DOQ)?;
    let crypto =
        QuicServerConfig::try_from(config).map_err(|error| Error::General(error.to_string()))?;
    Ok(ServerConfig::with_crypto(Arc::new(crypto)))
}

/// The configuration of servers presenting `presented`, over `versions`, offering `alpn` alone: a client asking
/// for another protocol is refused.
fn server_config(
    presented: Arc<Presented>,
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[u8],
) -> Result<rustls::ServerConfig, Error> {
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(versions)?
            .with_no_client_auth()
            .with_cert_resolver(presented);
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// The connector of TLS sessions trusting `trust`.
///
/// # Errors
///
/// rustls' [`Error`] when the trust store cannot be read, or holds no certificate rustls takes.
pub(crate) fn connector(trust: &Trust) -> Result<TlsConnector, Error> {
    let config = client_config(trust, DEFAULT_VERSIONS, ALPN_DOT)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// The TLS configuration of QUIC connections trusting `trust`, asking for `alpn`.
///
/// # Errors
///
/// As [`connector`].
pub(crate) fn quic_config(trust: &Trust, alpn: &[u8]) -> Result<ClientConfig, Error> {
    client_config(trust, &[&TLS13], alpn)
}

/// The configuration of clients trusting `trust`, over `versions`, asking for `alpn`.
fn client_config(
    trust: &Trust,
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[u8],
) -> Result<ClientConfig, Error> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)?;
    let mut config = match trust {
        Trust::System => {
            let verifier = rustls_platform_verifier::Verifier::new(provider)?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
        Trust::Roots(certificates) => {
            let mut roots = RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(certificates.iter().cloned());
            if added == 0 {
                return Err(Error::General(
                    "no certificate authority to trust".to_owned(),
                ));
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        Trust::Anyone => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Anyone(provider)))
            .with_no_client_auth(),
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// Takes any certificate, still checking the handshake's signatures with it: [`Trust::Anyone`].
#[derive(Debug)]
struct Anyone(Arc<CryptoProvider>);

impl ServerCertVerifier for Anyone {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
