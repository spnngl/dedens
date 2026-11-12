# Transports

Decisions; the rules and the index are in [`README.md`](README.md).

- D26 (amended by D133, D134) `dedens-net` splits like `dedens-proto`: a sans-IO client core (retries, response
  matching, TC fallback, EDNS fallback, cookies) fed bytes and time, so tests drive drops, delays and forged replies
  exactly without a server; a thin compio layer moves the bytes, tested over loopback (D133: the cores also run over
  a simulated network; D134: the client's pools are generic over a seam, `Io`). Public at both levels: `Client` for
  the whole exchange, and the UDP and TCP exchanges for callers that pick the transport (`+tcp`, the
  forwarder). Rejected: an in-process test server (slower, less exact), real servers in CI (cannot forge a
  wrong ID or a drop). compio 0.19.2 until 0.20 is released.
- D27 (amended by D50, D53, D108, D114) Client behaviour:
  - UDP: a pool of sockets per server (D50); a random ID from `getrandom`, drawn 256 bytes at a time: a call costs
    846 ns on macOS, 14 ns on Linux (vDSO).
  - Matching: source address, ID and question (case-insensitive) or the datagram is dropped and the wait goes
    on, as hickory and Unbound do; miekg/dns fails on a wrong ID and CoreDNS checks the ID only. `0x20` case
    randomization of the question is an option, off by default as in Unbound.
  - dig's defaults: 3 tries, 5 s each. TC over UDP is retried over TCP. EDNS is dropped once on FORMERR or
    NOTIMP to an EDNS query (RFC 6891 §7), never on a timeout (RFC 8906); `+noednsneg` turns it off. A query
    changed by a fallback goes with another ID, so a late response to the query before cannot end the exchange
    (D114 says how the ID is drawn and when EDNS is dropped).
  - Cookies (RFC 7873 §5): the client cookie drawn from `getrandom` once per pair of source and server
    addresses, a memoized random function of both as §4.1 asks, without a hash to pick; server cookies kept
    per server for the life of the client, including the fresh one of a BADCOOKIE; BADCOOKIE retried with it
    over UDP, then over TCP (§5.3).
  - TCP (RFC 7766): one connection per server, queries pipelined and matched by ID in any order, each under an
    ID free on the connection (§6.2.1), the caller's put back in the response; the ID of a query that stopped
    waiting stays taken until its response comes. Idle close; edns-tcp-keepalive sent empty in TCP queries only
    and its timeout honoured when shorter, 0 taking no new query (RFC 7828); a closed
    connection retried once on a new one, as is one whose IDs are all taken. Queries are written whole by a task of
    the connection, so a query that stops waiting never cuts a message short; those queued meanwhile go in one
    write (D53), at most 1024 (D108). A write lasts the idle time at most, and a query that times out with no
    response read on its connection since it was sent closes it: a server that stopped reading or answering is replaced. A connection
    that cannot open fails each query waiting for it with its error. A connection slower than a try, waited for
    the source address of a cookie, costs that try, not the exchange.
- D31 (amended by D68, D114) The sans-IO exchange (`dedens-net::exchange`) takes the query whole from the caller, ID and
  cookie in it, and owns no randomness or secret (D114: the IDs of changed queries come from the caller too); `0x20`
  takes its random bits as an option, which also turns on the exact-case match, so a randomized question is never matched loosely. Each step consumes the `Exchange`
  and returns `Send`, `Wait` or `Done`: a finished exchange cannot be fed. Only timeouts spend tries, and tries lost to a socket error or a slow connection; the TC,
  EDNS and cookie fallbacks each happen a bounded number of times. Stricter than dig: FORMERR and NOTIMP
  alone may leave the question out (D114); once a server has sent a cookie, a response without one is dropped, even
  without OPT (RFC 7873 §5.3 MUST), at the price of timeouts if that server loses cookie support mid-process.
- D68 (amends D31) An exchange that runs out of tries after dropping a response for its cookie fails as
  `Forged`, not `TimedOut`: "no response after N queries, responses with a wrong cookie dropped (RFC 7873
  §5.3)", so a packet cache answering with an earlier client's cookie is told from silence (UncensoredDNS,
  D67). Exit code 9, as a timeout (D33).
- D60 (amends D2) Encrypted transports come before DNSSEC: DoT, then DoQ and DoH, each in the client and CLI
  first, then in `dedensd`. DoT (RFC 7858) is D27's TCP connection with a TLS session on it: one pipelined
  connection per server, the same idle, keepalive and retry rules. The TLS stream splits into halves locked only
  while polled (futures-util); compio's split holds its lock across a read and would stall the writer. rustls
  with ring, already in the lock through ureq; TLS 1.2 and 1.3 (RFC 8310 §9); ALPN `dot` (RFC 9461 §4.1).
  - Strict privacy profile by default (RFC 8310 §6.6): the OS trust store (`rustls-platform-verifier`, as D57),
    and the certificate must hold the name after `#`, else the host name given, else the address (§8.1).
    `--tls-ca=FILE` trusts the authorities of a PEM file instead; `--tls-insecure` any certificate, for tests.
    Rejected: dig's default, which verifies nothing without `+tls-ca`.
  - Queries over TLS are padded to a multiple of 128 bytes (RFC 8467 §4.1); padding the caller set is replaced.
    Replies to a padded query over TLS or QUIC are padded to a multiple of 468 bytes, with zeros, though the
    reply buffer is reused (RFC 7830 §3-4).
    The CLI refuses `+noedns` over TLS or QUIC, which would leave a query unpadded.
  - The CLI writes a TLS server `tls://HOST[:PORT][#NAME]`, or any server with `+tls`; port 853 unless given. An
    address, `[ADDRESS]:PORT` or with its zone, is taken as such before any name; a name for TLS is made only
    over TLS or QUIC.
  - Tests make their certificates with rcgen at run time, so no private key is checked in.
- D61 (amended by D109, D119, D175) DoQ (RFC 9250) goes through compio's QUIC (`compio-quic`, quinn-proto underneath), no QUIC of our own.
  One connection per server and certificate name, opened on first use: queries meanwhile wait for it instead of
  opening another. Each query goes alone on its own bidirectional stream, behind its length, with ID 0
  (§4.2.1) and no cookie, since QUIC checks the client's address itself. The connection closes after D27's idle
  time (§4.4) and is opened again on the next query; a query on a reused connection found closed goes again once
  on a new one, as D27's TCP. A query given up is cancelled with STOP_SENDING and RESET_STREAM (§4.3.1). A
  response is read up to its 2 + 65535 bytes, a longer stream being a protocol error; the server may open no
  stream (§4.3.3), the client allowing none.
  - TLS 1.3 only (RFC 9001 §4.2), ALPN `doq`, the same trust as D60 (strict profile). No 0-RTT, early data off: a query waits for
    the handshake, since one in early data could be replayed (§4.5).
  - Queries are padded as over TLS (§5.4), and carry no edns-tcp-keepalive (§5.5.2).
  - The CLI writes a QUIC server `quic://HOST[:PORT][#NAME]`, or any server with `+quic`; UDP port 853 unless
    given.
- D62 (amended by D82, D83) DoH (RFC 8484) waits for compio to release tokio's I/O traits on its streams (the `h2`
  crate needs them; draft on branch `feat/io-tokio-compat` of compio); no adapter of our own meanwhile.
  ~~HTTP/3 waits for compio too.~~ Queries go by GET by default, ID 0 so HTTP caches can keep them (§4.1), and
  by POST with `+https-post`, as dig.
- D82 (amends D62) DoH goes over HTTP/3 first, on compio's released `h3` feature (compio 0.19.2,
  `compio-quic/h3`, the `h3` crate 0.0.8) over the QUIC connection of D61; HTTP/2 follows when a compio release
  carries the `tokio::io` traits, as D62 says. `h3` calls itself "very experimental" and is pre-1.0 (API may
  change, bugs possible); accepted because compio's QUIC is the only QUIC we have (D61), HTTP/3 over it costs no
  adapter, and it sits behind `Transport::Https`, so replacing it touches one module. Rejected: our own HTTP/3
  (a protocol of its own to fuzz and keep), waiting for HTTP/2 (blocks DoH and ODoH on a compio release).
  The core is sans-IO like D26 and knows no HTTP version: `dedens-net::doh` makes and reads `http` types
  (`http` is a workspace dependency), so HTTP/3 and HTTP/2 carry the same code, for the client, `dedensd` and ODoH.
  - `Transport::Https`: the whole message, up to 65535 bytes, no length prefix (RFC 8484 §6). ID 0 as over QUIC,
    no edns-tcp-keepalive (RFC 7828 does not apply, §9), queries padded to 128 bytes and replies to padded
    queries to 468 bytes (D60). TC means the server could not get a full answer (§9), not a retry over TCP. A POST
    states its `content-length`: `cloudflare-dns.com` answers an HTTP/3 POST without it 405 (found by the live check
    of D84, 2026-11-01; HTTP/2 clients always send it, and `h3` does not add it).
  - Checked live (2026-11-01): `dns.google`, `cloudflare-dns.com`, `dns.adguard-dns.com`, `dns.quad9.net` and
    `dns.nextdns.io` answer GET and POST over HTTP/3 (the first, second and fourth advertise `h3` in Alt-Svc;
    AdGuard and NextDNS answer without one); `doh.opendns.com` and `doh.mullvad.net` do not answer HTTP/3.
  - `Template`: `https://host[:port]/path{?dns}`, or the same without the expression, `{?dns}` implied as dig and
    kdig take it (a provider's `https://doh.cleanbrowsing.org/doh/security-filter/` has none); the path of an
    SVCB `dohpath` (RFC 9461 §5), whose `dns` variable must be written. The one expression is `{?dns}`, or
    `{&dns}` after a query: any other RFC 6570 expression is refused, since DoH defines no other variable. No
    user information; a `dns` parameter of its own in the path is refused, as the server would read one of two.
  - A response is a DNS response if its status is 2xx whatever the rcode (§4.2.1), its content type
    `application/dns-message` (parameters and case ignored) and its body a DNS message. TTLs go down by the
    larger of `Age` and the time since `Date` (§5.1, RFC 9111 §4.2.3, without the response delay), to 0 at
    least: a copy a cache kept is not read as fresh. A bad `Age` is ignored (RFC 9111 §5.1); only the
    IMF-fixdate form of `Date` is read (RFC 9110 §5.6.7).
  - A server answers a GET with `cache-control: max-age` of the least TTL of the answer and of the SOA of the
    authority section (least of its TTL and MINIMUM, RFC 2308 §5), 0 without any, and a POST with none, which
    §5.1 makes uncacheable. Errors of the request are statuses without a DNS message: 405, 415, 400, 413.
    Whether the query is a DNS message is the caller's (FORMERR, §4.2.1).
- D83 (amends D62; completes D82; amended by D79, D109, D119) The client asks DoH over HTTP/3, `Transport::Https` in `dedens-net::http3`. RFC 9114 over a
  QUIC connection with ALPN `h3`, TLS 1.3 and the trust of D60 (RFC 8484 §3, strict profile).
  - One connection per server and certificate name, opened on first use and shared by concurrent queries, one
    request stream each. It is opened again after a GOAWAY or a close; a request a reused connection refused
    (GOAWAY, `H3_REQUEST_REJECTED`, closed) goes once more on a new one, as D61. The endpoints and dialing are
    `dial.rs`, shared with DoQ; HTTP/3 lets the server open 16 unidirectional streams (control, QPACK), DoQ none.
  - No retry of its own: D27's rules for stream transports, ID 0, timeouts as QUIC. A status other than 2xx, a
    wrong content type or a body that is no DNS message is an error of the exchange, not a response (D82).
  - The CLI writes `https://HOST[:PORT][/PATH][#NAME]`, port 443; the path is that of the URL, else of
    `+https=PATH`, else `/dns-query`. `+https`, `+https-get` (default) and `+https-post` turn it on for any
    server, as `+tls` does. `+https` is refused with `+tcp`, `+tls`, `+quic` (one transport each), `+trace` (D40)
    and `+noedns` (the padding, D60); `+https-get` with `+https-post`.
  - HTTP/3 is the one version: there is no `+http3` option yet. HTTP/2 (phase 4, step 23) adds the version
    choice and may make HTTP/2 the default of `https://` (RFC 8484 §5.2), HTTP/3 on `+http3`.
  - A response reports transport `DoH`, `-v` and JSON `exchange.http` the HTTP version and status.
  - `providers.yaml`: `https` URLs are asked over HTTP/3 by `just providers`; `https_h2` holds those of servers
    where HTTP/3 does not answer (November 2026: no `h3` in Alt-Svc, or a handshake that stalls), parsed only,
    until HTTP/2 (D67).
- D78 (amends D69; amended by D79) ODoH crypto (RFC 9230) is `dedens-odoh`, sans-IO, for the one suite RFC 9230 §9 requires:
  DHKEM(X25519, HKDF-SHA256) (0x0020), HKDF-SHA256 (1), AES-128-GCM (1). HPKE (RFC 9180) is the `hpke` crate
  (0.15.1, MIT or Apache-2.0, RustCrypto primitives, features `aes`, `alloc`, `x25519` only, passes `cargo deny`);
  the response's AES-GCM (RFC 9230 §6.2 `derive_secrets`) is `ring`'s, which D71 has already, so two AES-GCM
  implementations are in the tree (`hpke`'s for HPKE, which `ring` cannot serve; `ring`'s for the response).
  Accepted: each has one job, and a second `ring` AES-GCM inside HPKE is the thing `ring` cannot offer. HKDF is
  ours, one HMAC of `ring` per `Extract` or `Expand` of at most one block (RFC 5869, tested on its A.1 vector):
  `ring`'s `Prk` cannot be wiped and its `expand` returns a `Result` that an infallible length would only
  `expect`. Rejected: HPKE on `ring` (its agreement API holds no static X25519 key and has no `DeriveKeyPair`: a
  target could not keep a key), our own HPKE (a key schedule to keep right for no gain; the crate passes RFC 9180
  Appendix A.1.1 here), the `odoh-rs` crate (D3: protocol code is ours; its code was read for the scheme only),
  `aws-lc-rs` (a second native crypto library next to `ring`; not evaluated further).
  - Configs: `Configs::parse` keeps the configs of version 1 with that suite and skips every other, as
    §5 tells clients and `odoh-rs` does: another version, KEM, KDF or AEAD, and one of ours that is malformed (a
    field past its config, bytes after its fields, an empty key or one that is not 32 bytes). A list whose own
    framing is broken (truncated, trailing bytes, empty) is an error, as is a list with no usable config
    (`WireError::NoUsableConfig`), so a caller never holds an empty list. `parse` then `encode` drops what was
    skipped. The key ID (§6.1) is computed once, with the config. How a client finds the list is out of scope of
    RFC 9230 §5; it is not specified here.
  - Messages: the bounds of §6.1 are checked when a message is built, so writing cannot fail. A plaintext holds
    the padding as a length: non-zero padding cannot be built, and one received is refused (§7, §8), as are
    trailing bytes and any message type but 1 and 2.
  - Padding: the caller chooses it; `query_padding` and `response_padding` round the DNS message to 128 and 468
    bytes (RFC 8467 §4.1, as D60 for DoH), as §11 tells implementations. Inside the encryption, so messages of
    one block have one size on the wire (tested). The live target of Cloudflare answers without padding.
  - Randomness comes in as an argument (`CryptoRng`), so tests replay RFC 9180's ephemeral key and odoh-go's
    response nonces; a target key is derived from a 32-byte secret the caller keeps (`DeriveKeyPair`), so no key
    generation or storage lives here. The docs of `encrypt_query` and `encrypt_response` warn that a replayed
    generator repeats the ephemeral key or the response nonce. `ResponseContext` is consumed by its response
    (`encrypt_response` is the one call that encrypts under the secrets, so a second would reuse the nonce
    input). `QueryContext` is borrowed by `decrypt_response`: opening encrypts nothing, and a proxy's forged
    answer must not cost the client the context of a query still waiting for the target's.
  - Secrets: the exporter secret, the retained query plaintext (it salts the response keys), the HKDF output,
    the AEAD key bytes, nonce and salt are `Zeroizing`, wiped when dropped. `hpke` wipes its own (shared
    secret, exporter secret, AEAD key and nonce, private key). Not wiped: `ring`'s HMAC keys, its `LessSafeKey`
    schedule and the HMAC tag buffer, the plaintext DNS messages, the serialized query before it is sealed
    (`seal` copies it), and copies the allocator moved. Best effort, not a guarantee. No `unwrap`, `expect` or `as` in non-test code:
    the lengths are typed (`Field`, constant prefixes).
  - `ExchangeError::UnknownKey` is the 401 of §4.3 and every other failure of `decrypt_query` the 400. HTTP (the
    media type, §4.1's ban on caching, discovery) belongs to `dedens-net`.
  - Tests: RFC 9180 A.1.1, the vectors of `cloudflare/odoh-go` (the target side, byte for byte), the config
    Cloudflare serves, and round trips (`tests/odoh.rs`); the client side reads the odoh-go responses through
    the target's secrets (the vectors hold no ephemeral key). Failure paths are tested: small-order keys,
    ciphertext shorter than the tag, non-zero padding in a response, bounds. Fuzz targets `parse_odoh_configs`,
    `parse_odoh_message`, `odoh_decrypt` (seeded with a valid odoh-go query and response). A query encrypted here was answered by `odoh.cloudflare-dns.com` and its
    response decrypted (2026-11-01, one-off, not a test). Bench: `docs/benchmarks.md`.

- D79 (amends D69, D78, D83; amended by D94, D115, D117) ODoH over HTTP/3 (RFC 9230 §3, §4), `odoh` feature, off by default: `dedens` asks a target
  through a proxy, `dedensd` serves as a target. `dedens-proto::Transport::Odoh` is the transport, reported `ODoH`.
  - Messages: a client sends the encrypted query by POST to the proxy (RFC 9230 §4.1: media type
    `application/oblivious-dns-message` as content type and accept, `targethost` and `targetpath` in the query of the
    proxy's URI, which `+odoh-proxy=URI` gives as a plain `https://HOST[:PORT][/PATH][#NAME]`); `targetpath` keeps `/`
    unescaped, as the RFC's example, and escapes every other reserved character. Without a proxy (tests, a target
    asked directly) the POST goes to the target's URI. The query is ID 0 (RFC 8484 §4.1; RFC 9230 does not ask for
    it, DoH does, and a target answers the same) and not padded with EDNS: the padding is inside the encryption
    (`query_padding`, `response_padding`, D78), so the message is one block of its own. A response is read only from
    a 2xx of the media type (§4.3); a 3xx is an error (no redirect is followed). The request carries
    `content-length`: Cloudflare's target answers 400 to an HTTP/3 POST without it (found by the live check).
  - Configurations: fetched by GET from `/.well-known/odohconfigs` of the target (a convention, RFC 9230 §5 leaves
    discovery out; Cloudflare, `odoh-rs` and `odoh-go` use it) and kept per target. The fetch goes straight to the
    target, not through the proxy: a proxy relays POSTs of oblivious messages only (§4.1), and public ones relay no
    GET. Cost: the target sees the client's address (never a query, which is all §8 protects) and may link the query
    that follows to it by timing, so the fetch must be rare: the lifetime is `Cache-Control: max-age` less `Age` and
    the age `Date` shows (RFC 9111 §4.2.1), but never under an hour (`MIN_KEPT`) nor over a day (`MAX_KEPT`), whatever
    the target says, `no-store` and `no-cache` without field names included: the configurations are public keys, and
    Cloudflare's `no-cache, no-store` would otherwise cost a fetch per exchange; a skewed clock only shortens the
    lifetime, to the hour. `no-cache="field"` does not forbid keeping. At most 64 targets are kept (expired first,
    then the soonest to expire). A client of one exchange per process (`dedens`) fetches each run anyway: when the
    target forbids keeping and a proxy is used, it prints a warning on stderr (`odoh::Notice::ConfigsNotToBeKept`,
    from `Client::take_odoh_notices`), and `+odoh-config=FILE` (a file of the configurations as the target serves
    them, `Client::pin_odoh_configs`) fetches nothing: pinned ones never expire and are never fetched again, a 401 is
    an error then. `dedens` reads each such file once per run and pins it before the first query (`--repeat` asks
    again from memory; a target given two files keeps the later one's); a file that cannot be read or is no
    `ObliviousDoHConfigs` (§6) is a usage error (exit 2, D33), and no query is sent. Other discovery (through the proxy, SVCB) is in `docs/TODECIDE.md`.
  - Errors: a 401 (the target does not hold the key, §4.3) after configurations kept from the cache fetches them
    again and asks once more, when the target made it: with a proxy, a response
    with a `Proxy-Status` header holding an `error` parameter (RFC 9209) is the proxy's (`OdohError::Proxy`) and ends
    the exchange (a proxy that answers 401 for its own reasons must not make the client leak its address). A response
    that does not decrypt, and any error of the encryption, end it: the configurations are not at fault. After
    configurations fetched for this exchange, or pinned, a 401 ends it too (no loop, no second fetch). The cache is
    the client's own (`Client`, per target address and authority), not shared between `Client`s.
  - Client API: `Client::exchange_oblivious(query, target, proxy, options)` (not `exchange`, which refuses
    `Transport::Odoh` with `ClientError::OdohWithoutProxy`: the proxy is a second server). Randomness is
    `odoh::Entropy`, 64 bytes read from the OS when the exchange starts and wiped when dropped, so an OS failure is
    an error (`OdohError::Random`); `encrypt_query` draws 32 bytes, `encrypt_response` 16 (tested), and a draw beyond
    the 64 gives zeros and fails `Entropy::finish`, which the caller asks after the encryption, so that no draw panics
    and none is silently weak. The proxy URI is a plain one, not an RFC 9230 §4.1 URI Template: one that already
    holds `targethost` or `targetpath` is refused (`OdohError::ProxyVariables`). A message may be a kilobyte over
    a DNS message's cap (`odoh::MAX_BODY`: the header, the encapsulated key, the tag and the padding), at the HTTP
    reader and at `classify`. The HTTP side is sans-IO functions in `dedens-net::odoh` (`request`, `configs_request`, `response`, `configs_lifetime`, `classify`,
    `target_response`, `configs_response`) over `http` types, tested without a socket; the fuzz target
    `read_odoh_http` covers the readers of outside data.
  - CLI: `+odoh-proxy=URI` with an `https://` target server (D83's); usage errors (exit 2) without such a target, with
    `+tcp`, `+tls`, `+quic`, `+https-get` or `+trace`; `+noedns` is accepted (the padding is not EDNS's); a build
    without the feature refuses the option.
  - `dedensd`, feature `odoh`: a section `odoh:` makes each `https://` listener a target at its path (default
    `/dns-query`): a POST of the media type is opened, asked of the pipeline as a query over `Transport::Odoh`
    (padded replies are the encryption's, so the pipeline's EDNS padding is off for it) and answered sealed with
    `Cache-Control: no-cache, no-store` (§4.1); a key that is not the target's is 401 and a message that does not
    open 400 (§4.3, D78). `GET /.well-known/odohconfigs` answers the configurations with `max-age=3600`, unless the
    listener's own path is that one (the listener wins). Plain DoH stays served at the same path. The key is the
    secret of `odoh.key`, a file of 64 hexadecimal digits (`openssl rand -hex 32`; at most 256 bytes, read into a
    buffer wiped on drop; a file others can access is refused and one its group can access warned about on Unix, D115), else a random one made at
    start (so the configurations change at each start). A reload keeps the key and never reads the file again: a
    changed `odoh` section (the key file's path) is ignored with a warning (it takes a restart), and a key file that
    went bad fails no reload. `odoh` without an `https://` listener is an error. Metrics: `dedensd_doh_queries_total`
    gains status 401 and counts no configurations GET (not a `DoH` query). The unauthenticated decapsulation per
    POST is bounded since D117.
  - Not here: HTTP/2. The proxy role is D94's.
  - Checked live (2026-11-01, `dedens @https://TARGET/PATH +odoh-proxy=PROXY example.com A`, the targets and
    relays of `DNSCrypt/dnscrypt-resolvers` `v3/odoh-servers.md` and `odoh-relays.md`): every target below answers
    HTTP/3 and serves, at `/.well-known/odohconfigs`, one config of version 1 with the one suite of D78 (no other
    suite, no unusable config, in any of the five or the dnscry.pt ones): `odoh.cloudflare-dns.com` (`no-cache,
    no-store`, so the warning above; its key is the one of `testdata/odoh/odohconfigs-cloudflare.bin`),
    `odoh.crypto.sx`, `doh.tiar.app` (path `/odoh`), `dope.snowstorm.love` and `doh.tiarap.org` (path `/odoh`); the others send `max-age=86400` or no `cache-control`, so no warning. Each answered the CLI asked directly (the target as
    its own proxy) and through `odoh-relay.edgecompute.app` (Fastly, path `/`, HTTP/3: `targethost` and `targetpath`
    with `/odoh` and `/dns-query` accepted), except `doh.tiarap.org`, which this relay refuses (403 for that
    `targethost`, also with a plain `curl`). The other listed relay, `odoh-relay.numa.rs/relay`, advertises `h3` in
    Alt-Svc but answers no QUIC packet from here (`aioquic` too), so every try times out (exit 9); over HTTP/2 it
    answers (`curl`: 400 for a bad message), which waits for step 23. A wrong key (the configurations of another
    target, `+odoh-config=`) is a 401 from Cloudflare and `doh.tiar.app`, direct and through the Fastly relay, so
    the exit is 10 with the 401 and no second fetch, as pinned configurations say. Pinned right ones
    (`+odoh-config=` on the file `curl` saved) fetch nothing and work through the relay, with or without EDNS.
    The responses decrypted every time; those of `odoh.crypto.sx`, `doh.tiar.app` and `doh.tiarap.org` carry their
    own EDNS padding to 132 bytes, the other two none. Checked live later, 2026-11-01 (`just odoh-live`): a key rotation
    cannot be provoked on a real target, but a key it does not hold stands for one: `Client::keep_odoh_configs`
    keeps such configurations as a fetch (pinned ones never refetch), and `odoh.cloudflare-dns.com` and
    `doh.tiar.app` each answered 401, then the real ones were fetched once and the query was answered; pinned,
    the same configurations ended in the 401. Our `dedensd` as a target for a client that is not ours: Cloudflare's
    `odoh-rs` 1.0.5 sealed three captured queries at paddings 0, 17 and 400 to its configurations over HTTP/3
    (`aioquic`) and opened every response; 401 for a key it does not hold, 400 for a damaged ciphertext
    (`tests/interop/odoh.py`). Not checked live: that a target refuses a badly padded query (tests only), and the
    size on the wire of our padded query.
  - Tests: `crates/dedens-net/tests/odoh.rs` (the request of §4.2, §4.3's statuses, the captured Cloudflare
    headers and configurations, a loopback target direct and through a loopback proxy, the 401 refetch, and the
    ignored live one), `tests/interop/odoh.py` (by hand: `odoh-rs` against `dedensd`),
    `apps/dedensd/tests/odoh.rs` (the real `dedensd` as target), `apps/dedens/tests/odoh.rs` (the command).

- D80 (amends D69) CoAP is our own sans-IO codec, `dedens_net::coap` (RFC 7252, RFC 7959, RFC 8132), for DoC (RFC 9953):
  no crate of CoAP is pulled in, since DoC needs a small part of it and the rest would carry its own socket, clock
  and randomness, which D26 keeps out of the exchanges. It is not behind the `doc` feature: the module has no
  dependency, and the fuzz target and tests build it anyway. The socket is step 13's.
  - `Message` parses and writes every datagram of the RFC, options kept in order whether known or not, so a message
    of minimal encodings writes back byte for byte. An unknown critical option is reported (`unknown_critical`),
    never dropped (RFC 7252 §5.4.1); the answer is the caller's.
  - `exchange::Exchange` is the client of one request, confirmable only, fed time and datagrams like D26's: the
    caller passes the first message ID, the token and a seed, the jitter between ACK_TIMEOUT and 1.5 times it
    being a xorshift of that seed. Piggybacked and separate responses (empty ACK, then a confirmable response it
    acknowledges), RST, duplicates and a response of an unknown token (RST) follow RFC 7252 §4-5. A separate
    response is waited for `separate_timeout` (93 s, MAX_TRANSMIT_WAIT: the RFC gives none).
  - Block-wise (RFC 7959): Block2 responses are reassembled up to 65535 bytes, a follow-up asking for the next
    block in a new message ID and the same token; the server's smaller block size is followed. The ETag is
    compared across blocks (a change is `Failure::ETagChanged`), and `Params::require_etag` (off by default, the
    RFC only asks the server for one) makes a first block with More set and no ETag `Failure::MissingETag`: without
    it two versions of a body would be put together unseen. A request over `block1_size` goes in Block1 blocks, 2.31 answered by the next one, the server's
    smaller size followed. A follow-up for a Block2 carries the request's payload when the request went whole, as
    a FETCH body is part of the cache key (RFC 8132 §2) and a server keeping nothing needs the query again;
    aiocoap's and libcoap's clients send none, and their servers do not need it (libcoap's
    `coap-server` answers our follow-ups with the body as well). Block1 requests' follow-ups carry none (RFC 7959
    Figure 10).
  - `server::Dedup` remembers the reply to a confirmable request by (endpoint, message ID) for EXCHANGE_LIFETIME
    (247 s), at most a given number of entries, the oldest dropped first, only for a message that is new; a duplicate
    gets the same reply, at most `MAX_RETRANSMIT` times (D105).
  - Fuzz: `parse_coap` reads arbitrary datagrams; `coap_doc` is stateful, an `Exchange` against a model of the
    listener (`coap::dns::query` and `response`, a `Dedup`, the Block1 and Block2 sizes, a body that changes between two
    blocks, retransmission, duplicates, time, bytes of any kind for a reply) holding that a body is one of the
    server's, whole.
  - `docpath` is `SvcParam::DocPath(Vec<Box<[u8]>>)` (RFC 9953 §3.2, key 10): the wire is `alpn`'s with empty
    segments allowed, the text a comma-separated list, no segment the root path. One empty segment prints in the
    `key10="\000"` form, a single empty item being no different from the empty list in the text.
  - Tests read datagrams captured from aiocoap (`capture.py`) and from libcoap 4.3.5b (`capture_libcoap.py`, its
    `coap-server` and `coap-client` through a logging proxy, `testdata/coap/`; the real DNS answers of 2808 and
    1280 bytes it blocks are DoH captures). Checked live against libcoap: our client against `coap-server` (FETCH
    of a stored DNS answer, Block2 in 3 blocks of 1024, Max-Age 60 by default), and `coap-client` against
    `dedensd` (below, D81). Taken from the captures: libcoap's client sends an empty token, Uri-Port and Request-Tag
    on every request; its server blocks at 1024 by itself with ETag and Size2, answers a Block1 PUT 2.31 per block
    then 2.01, sends a separate response as an empty ACK then a CON, a NON request a NON response; a lost request or
    ACK is sent again after 2.4 s. Not checked: DTLS, OSCORE (not built), Observe.
- D81 (completes D80; amended by D95, D105, D109) DoC, DNS over unprotected CoAP over UDP (RFC 9953), behind
  the `doc` feature of `dedens`, `dedensd` and `dedens-net` (D69): the client `Transport::Coap`
  (`dedens_net::doc`), the `dedens` options `@coap://HOST[:PORT][/PATH]` and `+coap` (port 5683, the root path
  unless given), the `dedensd` listener `coap://ADDR[:PORT][/PATH]`. The sans-IO halves are D80's `coap::dns`: the
  client's `request`, the server's `query`, `response`, `error`.
  - Client: one confirmable FETCH per query on a UDP socket of its own, DNS ID 0 (§4.2.2), Content-Format and
    Accept 553, no Uri-Host or Uri-Port (the server is the one named). A response in blocks must carry an ETag
    and keep it (`require_etag`, D80): a server that sends none is refused beyond the first block. The retransmission is CoAP's (RFC 7252
    §4.2), so the DNS tries are 1 (§4.2). The Max-Age of a 2.05, 60 s when absent, is added to each TTL, to at most
    2^31 - 1 (§4.3.2); a response in blocks is put together. A code other than 2.05, another content format and a
    body that is no DNS message are errors of the exchange (§4.3.1), not responses. Over `+trace`, `+tcp`, `+tls`,
    `+quic`, `+https` it is a usage error. Built without `doc`, asking for CoAP is a local error. The report says
    `CoAP`, JSON `coap`; `-v` logs the code, Max-Age and blocks (`tracing` debug).
  - Server: a FETCH, or a POST (RFC 9953 defines FETCH only; accepted as the same query), to the listener's path.
    Codes (§4.3.1): 4.04 another path, 4.05 another method (GET included), 4.15 a content format other than 553 or
    none, 4.06 another one accepted, 4.02 a critical option unknown, a Uri-Query or a bad block, 4.00 no body,
    4.13 a body in Block1 blocks (a server keeps no request state, a query fits one datagram), and from RFC 7252
    §5.7.2, §5.10.8: 5.05 for a Proxy-Uri or Proxy-Scheme (no forward-proxy, and no own names to take a proxy
    request for itself as local), 4.12 for an If-None-Match, or an If-Match with a tag (the resource has no stable
    tag to match; an empty one, any representation, passes). Uri-Host and Uri-Port are accepted, whatever they
    say: one resource tree serves every authority. A DNS failure
    upstream is the pipeline's SERVFAIL in a 2.05 (§4.3.1). The Max-Age is the least TTL, which is taken from every
    TTL (§4.3.2, the RECOMMENDED algorithm). A response over 1024 bytes goes in Block2 blocks of 1024, each cut
    again from a new query (the follow-up carries it, D80), or of the size a request asks; each block carries
    an ETag, the FNV-1a hash (8 bytes, written out so that servers of two versions agree) of the body as cut, so
    TTLs less their least: an answer that changed between two blocks fails the client's transfer (RFC 7959 §2.4),
    its Max-Age, which moves with the clock, not part of it. libcoap's and aiocoap's
    clients send no body with the follow-ups, so a FETCH or POST with no body that asks for a Block2 past the first
    (`coap::dns::Query::Block`) is answered from the response sent in blocks, kept by (endpoint, Request-Tag, RFC 9175
    §3.2; empty if none), 64 per socket (`server::Blocks`), from the first block and not moved by the follow-ups, for
    `EXCHANGE_LIFETIME` at most, and served a bounded number of times (D105): found by libcoap's `coap-client`
    getting 4.00 for the second block of a 2649-byte answer, as the RFCs do not say how a server finds the response
    again. No such response kept is 4.00. CON requests are
    deduplicated (`Dedup`, 4096 entries, `EXCHANGE_LIFETIME`; the NON ones for `NON_LIFETIME`, D105) and answered
    by a piggybacked ACK, never a separate
    response; a NON request gets a NON response, its message ID from a counter that starts at random (RFC 7252
    §4.4); a ping, and a CON message with a format error whose ID can be read (`Message::reject`, §4.2), get a RST;
    a NON one, or one of another version, is dropped. The path is read as written, no
    percent-decoding; `?` and `#` in it are refused at configuration.
  - Unprotected: `dedensd` logs a warning at start for each `coap://` address, NOT RECOMMENDED (§6). DTLS and
    OSCORE are not built; the proxy parts (§9.2 redirects, §9.3 hop limit) are ignored: see `docs/TODECIDE.md`.
  - Checked live: libcoap 4.3.5b's `coap-client` against `dedensd` (`listen: ['coap://127.0.0.1:56840/dns/query']`,
    forwarding to 8.8.8.8): FETCH of a small query (`gmail.com MX`) 2.05 with the content format and a Max-Age;
    a 2649-byte answer (`cloudflare.com TXT`) in 3 blocks of 1024 and with `-b 64`, whole; NON gets NON; a lost
    request (`-l 60%`) is sent again and answered; 4.04 for another path or the root, 4.15 for another content
    format, 4.06 for another accept, 4.05 for GET. A lost ACK (a duplicate) is checked by the test only.
  - Not done: GET with `?dns=`, which the RFC does not define; a `coap://` upstream of the `forward` stage; the
    discovery by SVCB `docpath` (§3.2, D95).
- D95 (amends D81; amended by D109) DoC discovery by `rt=core.dns` in `/.well-known/core` (RFC 9953 §3.1, RFC 6690), the `dedensd`
  listener's answer and `dedens +doc-discover`, behind the `doc` feature:
  - Server (`coap::dns::discovery`, before D81's `query`): a GET of `/.well-known/core` answers 2.05 in Content-Format
    40 with one link, `<PATH>;rt=core.dns;ct=553`, `PATH` the listener's path (a socket has one: one link per DoC
    listener); the root path is `</>`, a path that starts with an empty segment is written after `/.` (else the
    link would read as an authority), and bytes a path cannot hold are percent-encoded. A `rt=` query filters (RFC 6690
    §4.1) on a complete value or a `*` prefix; no match is 2.05 with an empty payload, and any other query is ignored,
    as §4.1 allows. 4.05 for another method, 4.02 for an unknown critical option, 4.06 for an Accept other than 40,
    4.12 as D81 for the preconditions; a NON request gets a NON response; a request with a Proxy-Uri or Proxy-Scheme
    is not the listing and goes on to the forwarding refusal of D81. A listener path of `/.well-known/core`, or with a
    segment `.` or `..` (a Uri-Path is never one, RFC 7252 §5.10.1: no request could reach it), is refused at
    configuration.
  - Client: `Client::discover_doc(server, timeout)` sends a GET with Accept 40 and `rt=core.dns` and returns the paths of the
    links to take, in the order listed. `coap::link::parse` reads RFC 6690 §2 (whitespace tolerated around `;`, `,`
    and `=`, as the RFC's own examples need): `rt`, `if`, `sz` and `ct` once, a repeated `rel` takes the first,
    `ct` a u16 or a list of them, other attributes checked and dropped; a syntax error is `DocError::Links`, a payload
    that is not Content-Format 40 `DocError::NotLinks(format)`. A link is taken when it has the type `core.dns`, a
    `ct` with 553 or none, no `anchor` and a `rel` of `hosts` or none. A link's target is resolved against
    `coap://SERVER/.well-known/core` (RFC 3986 §5.2) and taken only when it is a path on the same IP address and port
    (a host name never matches: no lookup); a link to another server is refused, since a forged list must not send
    the queries away, and does not fail the lot when another link is fine. Each segment is percent-decoded after the
    dot segments are removed (RFC 7252 §6.4); a `?`, a `#`, a bad percent-encoding or a decoded `.`/`..` is refused.
    The fuzz target `parse_link_format` reads arbitrary bytes, and the list the server writes for any path back
    to that path: it found the encoding and the empty first segment above.
  - `dedens +doc-discover @coap://HOST[:PORT]` (or `+coap`; option `doc_discover`, `--doc-discover`): before each
    query, the server is asked and the first path is the Uri-Path of the FETCH; the report says `(discovered /PATH)`,
    JSON `doc_path`. Never automatic: §6 allows discovery only from a trusted source, and `dedens` does not tell
    one from another, so the user asks for it for the server they name. It is a usage error with a path in the URI
    (the path is found, not given), with a non-CoAP server or with none (exit 2); a failed discovery, an empty list or
    no resource of that type is an error of the exchange (exit 9).
  - Cut: discovery by SVCB `docpath` (§3.2). The request is built from the ALPN, `coap` for CoAP over TLS (RFC 8323) or `co`
    for CoAP over DTLS (RFC 9952), and the unprotected CoAP of D81 has none: neither is built, so the key stays
    parsed and unused. See `docs/TODECIDE.md`.
  - Checked live: libcoap 4.3.5b's `coap-client -m get coap://127.0.0.1:56840/.well-known/core` against `dedensd`
    (listener `coap://127.0.0.1:56840/dns/query`) gets `</dns/query>;rt=core.dns;ct=553`, with `?rt=core.dns` the
    same and with `?rt=other` an empty payload, 4.05 for `-m post`, 4.06 for `-A 41`; `dedens +doc-discover
    @coap://127.0.0.1:56840 example.com` finds `/dns/query` and gets the answer.
- D105 (amends D81; amended by D113) `dedensd` CoAP server limits (audit S7, S9, L10, E7), as D47 bounds the other listeners:
  - Replays (RFC 7252 §4.5, §4.8): `Dedup` sends the kept reply again at most `MAX_RETRANSMIT` = 4 times per entry
    (`coap::MAX_RETRANSMIT`, shared with the client's `Params`), the retransmissions a client makes, so every one of a
    client's is answered; then the message is still a duplicate (never processed again) but gets silence, until the
    entry expires. A duplicate arriving before the reply is kept is silent and costs none. Without it a spoofed source
    got a ~1 KB reply for each ~40-byte datagram repeated for `EXCHANGE_LIFETIME`; the same CON sent 100 times is now
    answered 5 times at most. NON requests are deduplicated too, for `NON_LIFETIME` (145 s; §4.5 SHOULD, §4.8.2), with
    no reply kept: a duplicate is dropped. Not covered: a message with a new ID, CON or NON, is a new request, so a
    spoofed source is amplified as with plain UDP DNS; D113 limits the rate of a source network, and sends a source over it nothing.
  - Block2 follow-ups (D81): the response kept in `Blocks` is served at most `(1 + MAX_RETRANSMIT)` times its size in
    bytes (`Found::Spent`, then silence), whatever the message IDs, and a follow-up neither stores it again nor moves its
    clock. Bytes, not blocks: the client picks the block size, a 64-byte client of a 2649-byte answer needs 42 requests,
    which a count of blocks at 1024 would cut off. By design (audit L10): a follow-up replays the TTLs of the
    response as it was cut at first, not re-resolved, so the data a client reads may be up to `EXCHANGE_LIFETIME` (247 s)
    old, the time the entry is kept from the first block; the ETag of the blocks stays the same.
  - Parsing: `Message::parse` reads at most `MAX_OPTIONS` = 64 options, past it `ParseError::TooManyOptions`, a format
    error like the others (a CON gets the RST of §4.2). The RFC sets no limit; a DoC request has about ten options. A
    datagram of zeros made ~65 K empty options, a list of 32-byte entries of ~2 MB per datagram (an empty option
    allocates nothing). The client reads responses with the same limit. Not done: the audit's other idea, option
    values as ranges into the datagram.
  - Receive buffer: 2048 bytes (`MAX_REQUEST`), plus one to tell a datagram over it from one that fits. A datagram over
    it is parsed from its first 2048 bytes: a CON or NON request gets 4.13 with Size1 = 1024 (RFC 7959 §2.9.3, §4),
    anything else is dropped. The largest legitimate request is a query of 1024 bytes (`BLOCK_SIZE`; a DNS query is far
    under, EDNS padding included) with 4 bytes of header, 8 of token and options of a few dozen bytes: the other 1024 are
    slack. The server also takes a body of 1025 to ~2030 bytes with no Block1; it advertises 1024. RFC 7252 §4.6 says a
    message SHOULD fit one IP packet, and suggests 1152 bytes for a path of unknown MTU: a bound the 2048 is over.
  - Tasks: 256 requests are answered at once per socket (`Slots`, as D47's TCP connections), so a thread answers at
    most n listeners × 256 (four `coap://` listeners reach its 1024 upstream queries; one is the usual case). The
    `Dedup` is looked up first, so a duplicate is answered from what was kept even with the slots full; a new request
    takes a slot and is noted only then: past 256, it is dropped silently, not noted, and its retransmission is asked.
    Silent, with no 5.03 (a deviation from §4.2, in `coverage.md`), as D47 drops past its limits: answering under
    overload costs more than the request, and a 5.03 still costs a send.
  - E7: the first response is sent, then the buffer `send_to` gives back is kept in `Dedup`: no copy for it. A copy
    of the DNS response goes to `Blocks` only when its block has more after it (`coap::dns::more_blocks`, which reads
    the request as `response` does: a malformed Block2 is no block); the follow-up path copies the kept response once,
    as `response` needs a `Vec` to take the TTLs off.
  - Tests: the trigger datagrams are built by hand from the audit's (zeros after a header, a bare FETCH), not captured:
    they hold no DNS data, and what they check is the server's count and bounds (AGENTS.md's real-data rule is for
    the DNS content, which the existing captures keep). Fuzz: `parse_coap` asserts the options cap, and `coap_doc` the
    replays per message ID and `more_blocks` against the reply.
- D109 (amends D61, D81, D83, D95; amended by D119, D175) The client's QUIC, HTTP/3 and CoAP exchanges are bounded by what the server sends and
  by the query's deadline (audit step 06):
  - DoH over HTTP/3 (RFC 9114 §4.2.2, §7.2.4.1): the client's SETTINGS carry `SETTINGS_MAX_FIELD_SECTION_SIZE` of
    8 KiB (`MAX_RESPONSE_FIELD_SECTION`, `http3.rs`), where h3 states none; a response with a larger header section
    is refused as a stream error (`Http3Error::Stream`), the request not sent again. 8 KiB is ten times the largest
    header section of the responses captured from Cloudflare, Google, Quad9 and AdGuard (797 bytes, counted as
    RFC 9114 §4.2.2 does: name, value and 32 per field; `testdata/doh/*.headers`) and what servers commonly
    take of a request; a server that sends more is no DoH server worth asking. The body limit is unchanged, and the
    QUIC receive windows are step 12's.
  - DoQ (RFC 9250 §4.3.3): a response stream that is not one message behind its length closes the connection with
    `DOQ_PROTOCOL_ERROR` (2). The pool does not reuse it (a closed connection is not, D61), and the query is not sent
    again on a new connection (D27's retry is for a connection found closed, not for one closed here): the error is
    the server's.
  - DoC (RFC 7252 §4.8, §5.2.2; RFC 7959 §2.4): the CoAP exchange, with its retransmissions, the wait for a separate
    response after an empty ACK (93 s) and the blocks, ends at the DNS exchange's deadline, as over the other
    transports: `DocError::TimedOut`, which the client turns into the exchange's timeout, `Failure::TimedOut` with
    one send (D81: the DNS tries are 1). A blackholed server holds a query for the timeout, not for 93 s or more.
    The discovery (D95) is bounded the same way: `Client::discover_doc` takes a timeout and ends at its deadline
    with `DocError::TimedOut`; `dedens` gives it the query's `+time`, so a silent server holds `+doc-discover` for
    the timeout, then the query for another, and the CLI exits 9 (D33's no reply).
- D175 (amends D61, D109) A DoQ response whose Message ID is not 0 (RFC 9250 §4.2.1) is a protocol error, as D109's
  framing error: the client closes the connection with `DOQ_PROTOCOL_ERROR` (2) and fails the try with
  `QuicError::MessageId`, the query not sent again (§4.3.3 SHOULD). Passed on to the exchange, such a
  response was dropped as not answering ID 0, and the next try went on the connection that broke the protocol. Not
  checked: a response carrying edns-tcp-keepalive (§4.3.3, §5.5.2).
