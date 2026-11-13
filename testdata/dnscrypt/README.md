# DNSCrypt test data

Read by `crates/dedens-dnscrypt/tests/` (and, as seeds, by the fuzz smoke test).

| File | Source | Holds |
|---|---|---|
| `draft-vectors.json` | "Appendix 2: DNSCrypt Test Vectors" of `docs/rfc/archive/draft-denis-dprive-dnscrypt-11.txt`, the hex strings copied by script, lengths checked | The pinned inputs' keys, the 124-byte certificate, its retrieval (question and TXT answer), one query and one response, in hex. System `0x0002`, XChaCha20-Poly1305 |
| `draft-certificate.bin` | The `certificate` of `draft-vectors.json`, decoded from hex | The 124 bytes of the draft's certificate, a seed of the fuzz targets |
| `quad9-cert-response.bin` | `2.dnscrypt-cert.quad9.net` TXT sent to `9.9.9.9:8443` over UDP (stamp `quad9-dnscrypt-ip4-filter-pri` of the `public-resolvers.md` of [DNSCrypt/dnscrypt-resolvers](https://github.com/DNSCrypt/dnscrypt-resolvers)), at `captured_at` of `quad9.json` | The DNS response, two TXT records: a certificate for `0x0001` (serial 2026010501) and one for `0x0002` (serial 2026010502), both signed by the provider key of `quad9.json` |
| `quad9-xsalsa20-query.bin`, `quad9-xchacha20-query.bin` | Built by `ClientSession::encrypt_query` from the certificate of each system, the client key, the nonce and the query of `quad9.json`, padded with `QueryPadding::udp(33, 256)`; sent to `9.9.9.9:8443` | 260-byte query packets |
| `quad9-xsalsa20-response.bin`, `quad9-xchacha20-response.bin` | What Quad9 sent back for the query beside it | 256-byte response packets: the answer to `www.example.com` A, padded by Quad9. The only data here of `0x0001` from a resolver that is not ours |
| `quad9.json` | This capture | `provider_pk` (the 32-byte Ed25519 key of the stamp), `captured_at` (Unix seconds: inside both certificates' validity), the client key and nonce the queries were made with, the DNS query, the minimum packet size |

The draft's keys derive from counting bytes (`00 01 ..`, `20 21 ..`, `40 41 ..`); the client key of `quad9.json` is
`40 41 .. 5f` too. Quad9's responses are read with that key and the certificates' keys alone, so no secret of
Quad9's is involved. A resolver's response to the same query is not byte-identical from one capture to the next
(its nonce and padding are its own), which is why the queries and the responses are stored together.
