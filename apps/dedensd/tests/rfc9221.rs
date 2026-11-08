//! The QUIC DATAGRAM extension (RFC 9221) is not used: `dedensd` answers over QUIC streams (RFC 9250), reads no
//! DATAGRAM frame, and so advertises no datagram support (D107).

mod common;

use common::{Responder, Server, write_config};
use compio::quic::{ClientBuilder, VarInt};
use compio::runtime::Runtime;
use dedens_testkit::certificates::{NAME, certificates};

/// RFC 9221 §3: a server that does not support DATAGRAM frames leaves `max_datagram_frame_size` out, so a client
/// sees no size it may send. quinn derives the parameter from its receive buffer, 1.25 MB unless unset. That a
/// DATAGRAM frame to a server without the parameter closes the connection with `PROTOCOL_VIOLATION` is quinn's
/// behaviour, not tested here.
#[test]
fn s3_a_quic_server_advertises_no_datagram_support() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let config = write_config("");
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &ca.server_pem).expect("the certificate written");
    common::write_key(&key, &ca.key_pem);
    let server = Server::configured(|listen| {
        format!(
            "listen: ['quic://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{}']\n    timeout_ms: 2000\n    tries: 1\n",
            certificate.display(),
            key.display(),
            upstream.addr
        )
    });
    Runtime::new().expect("a runtime").block_on(async {
        let endpoint = ClientBuilder::new_with_empty_roots()
            .with_custom_certificate(ca.ca.clone())
            .expect("a root")
            .with_no_crls()
            .with_alpn_protocols(&["doq"])
            .bind("127.0.0.1:0")
            .await
            .expect("an endpoint");
        let connection = endpoint
            .connect(server.addr, NAME, None)
            .expect("connecting")
            .await
            .expect("connected");
        assert_eq!(connection.max_datagram_size(), None);
        connection.close(VarInt::from_u32(0), b"");
    });
}
