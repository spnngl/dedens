# dedensd

The server binary (D42, D44): `src/main.rs` parses flags and starts the threads (never dropping a runtime),
`src/log.rs` writes the events and logs the driver, warning on Linux when it is `poll`, `src/config/` reads the YAML
configuration into a pipeline (D44): `mod.rs` the file, its bounds and the build, one file a part (`listen`,
`upstream`, `limits`, `access`, `sources`, `env` for `${VAR}`, `keys` with the key-file check shared with
`src/odoh.rs`, D115), `src/serve/` binds the sockets and runs the tasks around `dedens_server::Pipeline`, one file a
transport: `udp`, `tcp` (and TLS), `quic` (DoQ), `http3` (DoH and ODoH), `coap` (DoC, feature `doc`: its replays,
blocks and slots are bounded, D105), and `upstream` for the queries asked upstream; UDP replies go through each
socket's `Outbox`, one sender a socket, two tasks receiving (D123); `isolate.rs` isolates a task's panic and restarts a
listener that ended (D121), `h3_budget.rs` rotates an HTTP/3 connection past its byte budget (D119). `src/reload.rs`
swaps the pipeline and the TLS certificate on SIGHUP (D55, D66) and once the lists `src/download.rs` fetches (D57, D104)
changed, waking each thread to take it (D107). `src/lists.rs` keeps the lists read across reloads, one `Names` per
source and one merged set per stage side, so that a reload reads the lists that changed and no other (D120).
`src/privileges/mod.rs` resolves `user` and `group` before the sockets are bound and drops root after (D122);
`privileges/unix.rs` makes its calls, `privileges/not_unix.rs` stands in for them off Unix.
`access` (D91) is read in `src/config/access.rs`; `Config::warn_access` warns at start (`src/main.rs`) and at each
reload (`src/reload.rs`) of a public listen address with no `access`, and of an empty `allow`; the listeners in
`src/serve/` close or ignore a client that a `drop` denial denies, before it takes a slot. `src/config/` reads
`rrl` and `cookies` (D113, `limits.rs`), `client_share` (`upstream.rs`) and `odoh.budget`/`odoh.client_budget` (D117,
`keys.rs`), and the cache's `max_entry_bytes`, `min_ttl` and `max_ttl` (D116, D124, `sources.rs`) too.
`src/flights.rs` shares the validator's upstream questions in flight between the queries that need them (D86).
`src/sync.rs` names the `Arc`, `Mutex`, atomics and one-message channel of `reload.rs` and `flights.rs`: std's and
flume's, loom's under `--cfg dedens_loom` (`just loom`, D135); use it for state those two share between threads.
`src/odoh.rs`, feature `odoh`, is the Oblivious DoH target on the HTTP/3 listeners, `odoh::Service`: its key, its
configurations, and opening and sealing messages (D79); `src/odoh/proxy.rs` is its proxy role: the listed targets, their
resolution and the forward (D94). RFC behaviour belongs in `crates/dedens-server` and its sans-IO tests.

Tests:

- `tests/serve.rs`, `tests/reload.rs` and `tests/end_to_end.rs` run the binary on loopback against a responder
  answering captured bytes (`tests/common/mod.rs`), reading its events as JSON, the default log format
  (`Server::event`); `tests/end_to_end.yaml`, a `dedens` query file, holds what the replies must be.
- `tests/lists.rs` serves lists from a loopback HTTP server; `tests/reload.rs` also counts the lists a reload reads
  (`list parsed` events, D120).
- `tests/encrypted.rs` asks upstream over TLS and QUIC, with the responder of `apps/dedens/tests/common` and its test
  certificates.
- `tests/listeners.rs` answers over TLS and QUIC with the certificates of `dedens_testkit::certificates`, and checks
  that a TLS key others can read is refused (D115); every test that writes a key file goes through
  `common::write_key`, which makes it 0600.
- `tests/rfc8484.rs` serves DoH over HTTP/3; `tests/rfc9230.rs` the target and the proxy; `tests/rfc9953.rs` DoC
  (feature `doc`).
- `tests/blocklists.rs` checks `docs/blocklists/blocklists.yaml` (D87).
- `tests/access.rs` the access lists over loopback UDP, TCP, DoH and DoC (feature `doc`), their default, their reload
  and the configurations refused (D91).
- `tests/cookies.rs` that Server Cookies are given and loopback is never rate-limited (D113).
- Loom tests beside `src/reload.rs` and `src/flights.rs`: `just loom` (D135).
- `tests/flights.rs` that queries needing the same DS or DNSKEY of one server at once send it once (D86).
- `tests/rfc9221.rs` that QUIC advertises no datagram support (D107); `tests/rfc9114.rs` that an HTTP/3 peer declaring
  a frame it never ends is closed and a busy honest connection is rotated, not closed (D119).
- `tests/rfc7766.rs` that a broken TCP frame (a length with no message, half a length, a message trickling in, a length
  of 0) costs no CPU (`ps` time of the server) and leaves other clients served, and that a malformed message gets FORMERR
  on a connection that stays (D47).
- `tests/privileges.rs` checks `user`, the refusals and the user already running; its `#[ignore]`d tests, run as root
  on Linux (CI: `sudo -E env "PATH=$PATH" cargo test -p dedensd --test privileges -- --ignored`), check that every
  thread has the user's four ids, no root group, no capability, `NoNewPrivs` 1, that :53 answers over UDP and TCP, that
  the downloads directory is the user's, that a reload works, and that a configuration the user cannot read ends the
  start (D122).
- `tests/serve.rs` expects the `io_uring` driver on Linux, unless `DEDENS_TEST_ALLOW_POLL` is set, as in a container
  whose seccomp filter refuses it.
- `benches/doh3.rs` measures DoH over HTTP/3 and `benches/udp.rs` UDP (`docs/benchmarks.md`).

Measure a change to `src/serve/` with `just bench-dnsperf <base> <mode>` (modes in the justfile) and record it
in `docs/benchmarks.md`.
