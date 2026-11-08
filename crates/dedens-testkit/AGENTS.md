# dedens-testkit

What the tests, benches, fuzz targets and simulations of more than one package share (D161): a dev-dependency,
but a regular one of `dedens-sim`, whose library code reads the data. The unit tests of `dedens-proto` link
another build of `dedens-proto` than the kit's: there, take paths and bytes from it, never a `Name` or a
`Message`.

Its public modules are one per concern, each item at one path (D160): nothing is re-exported.

- `src/lib.rs`: `path` (a file of the root `testdata/`), `captured` (a response of `testdata/proto/`), `message`
  (a capture decoded without a violation), `zone`, `hex`, `dns`.
- `src/dnssec.rs`: the captures of `testdata/dnssec/` by question (`Captures`), `capture`, `response` (decoded),
  `names`, `captured_at`; the RFC examples' keys and signatures and the data an RRSIG signs (`Rrsig`, `signed_data`).
- `src/certificates.rs`, feature `certificates`: a certificate authority and a server certificate for
  `dns.example` and 127.0.0.1 made per test (D60), as a rustls configuration and PEM files.
- `src/responder.rs`, feature `responder`: `Responder`, the loopback server the tests of `apps/dedens` and
  `apps/dedensd` query, answering with captures over UDP and TCP, TLS, QUIC and HTTP/3; Oblivious DoH and CoAP
  with the features `odoh` and `doc`, which `apps/dedens` turns on with its own.
