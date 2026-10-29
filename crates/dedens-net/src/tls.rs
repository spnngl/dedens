//! TLS for DNS over TLS (RFC 7858) and over QUIC (RFC 9250): which certificates a client trusts, and the client
//! configurations built from that.
//!
//! The strict privacy profile of RFC 8310 §6.6: a server whose certificate does not verify for the name expected,
//! or the address when there is none, is not queried, short of [`Trust::Anyone`]. rustls with ring, TLS 1.2 and
//! 1.3 (RFC 8310 §9: no older version) over TCP, TLS 1.3 alone over QUIC (RFC 9001 §4.2), session resumption on
//! (RFC 7858 §3.4), ALPN `dot` or `doq` (RFC 9461 §4.1, RFC 9250 §4.1.1).

use std::sync::Arc;

use compio::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use compio::rustls::crypto::{
    CryptoProvider, ring, verify_tls12_signature, verify_tls13_signature,
};
use compio::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use compio::rustls::version::TLS13;
use compio::rustls::{
    ClientConfig, DEFAULT_VERSIONS, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    SupportedProtocolVersion,
};
use compio::tls::TlsConnector;

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
const ALPN_DOQ: &[u8] = b"doq";

/// The connector of TLS sessions trusting `trust`.
///
/// # Errors
///
/// rustls' [`Error`] when the trust store cannot be read, or holds no certificate rustls takes.
pub(crate) fn connector(trust: &Trust) -> Result<TlsConnector, Error> {
    let config = client_config(trust, DEFAULT_VERSIONS, ALPN_DOT)?;
    Ok(TlsConnector::from(Arc::new(config)))
}

/// The TLS configuration of QUIC connections trusting `trust`.
///
/// # Errors
///
/// As [`connector`].
pub(crate) fn quic_config(trust: &Trust) -> Result<ClientConfig, Error> {
    client_config(trust, &[&TLS13], ALPN_DOQ)
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
