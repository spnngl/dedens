//! A DNS-over-TLS server host (RFC 7858): port 853, rustls over turmoil's TCP through the seam's stream, answering
//! from [`Answers`] as the upstream host answers over TCP, its faults too (`faulty`, `silent`, `tcp`), and the
//! queries of a connection pipelined (RFC 7858 §3.3). Its [`certificates`] are fixed, so that a run over TLS
//! replays from its seed.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::sync::Arc;

use compio::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use compio::tls::TlsAcceptor;
use dedens_net::tcp::Polled;
use dedens_net::tls::{self, Presented};
use dedens_proto::Transport;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use tokio::task::JoinSet;
use turmoil::net::{TcpListener, TcpStream};

use crate::io::SimStream;
use crate::seed::Rng;
use crate::trace::Trace;
use crate::upstream::{self, Answers};

/// The DNS-over-TLS port.
pub const PORT: u16 = 853;

/// The name the server certificates of [`certificates`] hold.
pub const NAME: &str = "dns.example";

/// The certificate authority `authority`, and the server certificate for [`NAME`] it signed: the authority to trust
/// and what the server presents. The same bytes on every run (fixed keys, Ed25519's signatures, rcgen's fixed
/// validity and its serial numbers from the keys), so that a run over TLS replays from its seed.
///
/// # Panics
///
/// When rcgen or rustls refuse the fixed keys, which they accept.
#[must_use]
pub fn certificates(authority: u8) -> (CertificateDer<'static>, Arc<Presented>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, key(authority)).expect("a CA");
    let key = key(authority.wrapping_add(128));
    let server = CertificateParams::new(vec![NAME.to_owned()])
        .expect("server parameters")
        .signed_by(&key, &ca)
        .expect("a server certificate");
    let presented = Presented::new(
        vec![server.der().clone()],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .expect("a certificate rustls signs with");
    (ca.der().clone(), Arc::new(presented))
}

/// The Ed25519 key of the 32 bytes `seed`, in PKCS #8 (RFC 8410 §7): the same on every run.
fn key(seed: u8) -> KeyPair {
    /// The PKCS #8 encoding of an Ed25519 private key up to its 32 bytes.
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(&[seed; 32]);
    KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(der), &rcgen::PKCS_ED25519)
        .expect("an Ed25519 key")
}

/// The software of a DNS-over-TLS server host: answers on port 853 with the certificate `presented`, drawing its
/// faults from `rng`, until the host crashes.
///
/// # Errors
///
/// A configuration rustls refuses, a listener that fails, or a task that panics.
pub async fn serve(
    answers: Rc<Answers>,
    host: IpAddr,
    presented: Arc<Presented>,
    rng: Rc<RefCell<Rng>>,
    trace: Trace,
) -> turmoil::Result {
    let acceptor = tls::acceptor(presented)?;
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, PORT)).await?;
    let mut tasks = JoinSet::new();
    loop {
        // Biased: the random order of the branches is not drawn from the seed, and a run must replay.
        tokio::select! {
            biased;
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                answers.accepted();
                tasks.spawn_local(connection(
                    Rc::clone(&answers),
                    acceptor.clone(),
                    stream,
                    host,
                    Rc::clone(&rng),
                    trace.clone(),
                ));
            }
            Some(ended) = tasks.join_next() => ended?,
        }
    }
}

/// Serves the queries of a connection after its handshake (see [`upstream::queries`]), then counts it ended.
async fn connection(
    answers: Rc<Answers>,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    host: IpAddr,
    rng: Rc<RefCell<Rng>>,
    trace: Trace,
) {
    // A stream closed as it was accepted, or a client that fails the handshake, has nothing to serve.
    if let Ok(stream) = SimStream::new(stream)
        && let Ok(stream) = acceptor.accept(stream).await
    {
        let (reader, writer) = Polled::halves(stream);
        upstream::queries(&answers, Transport::Tls, reader, writer, host, &rng, &trace).await;
    }
    answers.closed();
}
