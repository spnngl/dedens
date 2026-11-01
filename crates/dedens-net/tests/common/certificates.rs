//! Certificates made for the TLS and QUIC tests.

use std::net::SocketAddr;
use std::sync::Arc;

use compio::rustls::ServerConfig;
use compio::rustls::crypto::ring;
use compio::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use dedens_net::client::Server;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

/// The name the server's certificate holds, with 127.0.0.1.
pub(crate) const NAME: &str = "dns.example";

/// A certificate authority, and the server's certificate it signed, with its key.
pub(crate) struct Certificates {
    pub(crate) ca: CertificateDer<'static>,
    /// The authority in PEM, for a client reading it from a file.
    pub(crate) ca_pem: String,
    pub(crate) server: CertificateDer<'static>,
    pub(crate) key: PrivateKeyDer<'static>,
    /// The server's certificate and key in PEM, for a server reading them from files.
    pub(crate) server_pem: String,
    pub(crate) key_pem: String,
}

impl Certificates {
    /// A server configuration with the server's certificate, for TLS versions `versions` and protocols `alpn`.
    pub(crate) fn config(
        &self,
        versions: &[&'static compio::rustls::SupportedProtocolVersion],
        alpn: &[u8],
    ) -> ServerConfig {
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(versions)
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![self.server.clone()], self.key.clone_key())
            .expect("a server configuration");
        config.alpn_protocols = vec![alpn.to_vec()];
        config
    }
}

pub(crate) fn certificates() -> Certificates {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca =
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("a key")).expect("a CA");
    let key = KeyPair::generate().expect("a key");
    let server = CertificateParams::new(vec![NAME.to_owned(), "127.0.0.1".to_owned()])
        .expect("server parameters")
        .signed_by(&key, &ca)
        .expect("a server certificate");
    Certificates {
        ca: ca.der().clone(),
        ca_pem: ca.pem(),
        server: server.der().clone(),
        key: PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        server_pem: server.pem(),
        key_pem: key.serialize_pem(),
    }
}

/// The server at `addr`, its certificate to hold `name`.
pub(crate) fn named(addr: SocketAddr, name: &'static str) -> Server {
    Server {
        addr,
        name: Some(ServerName::try_from(name).expect("a server name")),
        doh: None,
        docpath: Vec::new(),
    }
}
