# CLI

Decisions; the rules and the index are in [`README.md`](README.md).

- D17 (superseded by D36) Query files in JSON or YAML, picked by extension or `--format`.
- D36 (supersedes D17) Query files (`dedens-scenario`), so the server's tests reuse them: one serde model (queries, options,
  optional expectations; a failed one makes `dedens` exit non-zero) read as YAML 1.2 by serde-saphyr, `-` for
  stdin. JSON is YAML 1.2, so JSON files read too, at the price of YAML-worded errors; no input format flag, no
  second reader. `dedens` drops dig's layout (`--dig`): JSON and YAML serve scripts, the human output people, and
  dig itself a side-by-side comparison. Rejected: serde_yaml (archived 2024-03), serde-yaml-ng (no commit in a
  year).
- D18 `dedens`, dig but better: dig argv (`@server name type class +opts`) and long flags; query files;
  output for humans by default, JSON or YAML for scripts (D37), `+short`, color; several names, types or servers
  per run, concurrent, side by side; timing, transport, sizes, EDNS, cookies and EDE in words; `+trace`;
  `--repeat N` with latency percentiles; `--save-wire` (the source of captured test data); default server from
  `/etc/resolv.conf`. `-x ADDR` asks PTR for the `in-addr.arpa` or `ip6.arpa` name of an address (RFC 1035 §3.5,
  RFC 3152). The `resolv.conf` search list (`search`, `domain`, `ndots`) applies only with `+search`, as in dig: a
  debugging tool asks for the name typed. Unicode names are converted to A-labels (IDNA2008, RFC 5891 and 5895) and
  shown as such, with labels mixing scripts flagged (IDN homographs).
- D32 (amended by D76, D169) CLI arguments: a pre-pass turns dig tokens into long flags (`@srv` → `--server srv`, `+opt` → `--opt`,
  `+noopt` → `--opt=false` for an on/off flag only, `+opt=v` → `--opt=v`, `opt` any unique prefix as in dig;
  `-t TYPE`, `-c CLASS`, `-q NAME` → words; `-p PORT` for a server without one), leaving the value of a flag and
  anything after `--` alone, then clap parses. One option set for both spellings (clap derived on
  `dedens_scenario::Options` behind its `clap` feature), one help. An option needing EDNS (`bufsize`, `dnssec`,
  `nsid`, `cookie`) with `+noedns` is a usage error; AXFR/IXFR are refused until supported; several
  `@servers`: D38. At most 64 queries in flight; each result prints, in argument order, as soon as it is ready.
  Several names and types per run go concurrently on one compio runtime; as in dig, a name is asked the types
  written after it, and one without any the types written before the first name, else A. Output formats: D37;
  color with anstream/anstyle, `--color auto|always|never`, `NO_COLOR` honoured. IDNA with the `idna` crate (UTS 46
  nontransitional, near RFC 5895) and `unicode-script` for mixed-script labels (Han with kana, Hangul or Bopomofo,
  and Latin, being one writing, UTS 39 §5.2), both in `apps/dedens`: the library stays ASCII. `resolv.conf` read by
  our own parser (`nameserver`, `search`, `domain`, `ndots`), `DEDENS_RESOLV_CONF` overriding its path for tests;
  no Windows yet. `+search` tries the next candidate on NXDOMAIN. A class word applies to every query of the run.
  `-f FILE --only ID` runs some queries of a file.
- D169 (amends D32; builds on D30) `NO_COLOR` turns colour off only when set to a value, as
  [no-color.org](https://no-color.org/) says: set empty, it is as unset. anstream decides for every stream:
  `dedens`'s output, its `-v` events (both after `--color`) and `dedensd`'s text log, so `CLICOLOR`,
  `CLICOLOR_FORCE` and `TERM=dumb` steer them alike. Rejected: any value (against the convention); a hand-written
  check for stderr (it took any value and drifted from anstream on the same run's stdout).
- D33 Exit codes of `dedens`: 0 a response came, whatever its rcode (as dig); 1 an expectation failed; 2 usage,
  a file an option names that cannot be used too, found before any query (`+odoh-config`, D79, `run::Usage`);
  9 no reply (timeout, a refused or reset connection); 10 any other error, a failed `--save-wire` write too,
  which leaves the other results.
- D34 (amended by D76) Query file schema (D36): top-level `server` and `options`, then `queries`, each with `id` (the
  `--save-wire` file name, so no `/`, `\`, `.` or `..`, unique in the file; default `name_type`, `root_type`
  for the root), `name`, `type`, its own `server`/`options`, and `expect`: `rcode`, `flags` that must be set,
  and `answer`/`authority`/`additional` as presentation lines compared as lists in any order, a line written
  twice expecting two records, the TTL compared only when written. `--save-wire DIR` writes the response to
  `DIR/<id>.bin`. Options are dig's `+` options by name (`tcp`, `ignore`, `recurse`, `cdflag`, `adflag`, `edns`,
  `bufsize`, `dnssec`, `nsid`, `cookie`, `time`, `tries`), each one left out inherited (command line, query, file,
  dig's default); `cookie` is `true`, `false` or a fixed cookie in hex, so captures repeat. `+ignore` and
  `+nocookie` need `dedens-net` exchange options `tcp_fallback` and `cookies`.
- D35 (superseded by D37) `--json` as JSON lines, every field present however empty.
- D37 (supersedes D35; amended by D76) `dedens --format human|short|json|yaml` (`+short`, `--json`, `--yaml` its shorthands, one at most), each
  response printed as it is ready. `human`, the default, is for reading: a status line (question, rcode in color
  and in words unless NOERROR, RTT, server without port 53, transport), then each non-empty section under its
  name, a record's owner shown once per run of the same owner and its TTL as a duration (`45m41s`); `no records`
  for an empty NOERROR answer; one quiet line of the flags worth a word (authoritative, truncated, recursion
  unavailable, DNSSEC-validated, checking disabled), EDNS and the sizes; EDE, violations and failures in red, one
  per line. `json` (one object per line) and `yaml` (one `---` document each) are for programs and stay short:
  the `dedens-scenario` report, TTLs in seconds, RTT in microseconds, an empty list or string and EDNS version 0
  left out, an absent field meaning empty. Server, transport, RTT (`rtt_us`), sends and query size sit in an
  `exchange` object, absent for a response read from a file; each record is `{name, ttl, class, type, data}`
  with `data` its presentation text; EDNS options are typed (`nsid`, `cookie`, `ede`, else `other` with the data
  in words, EDE text with control characters escaped); protocol violations (D9) go in `violations`, broken
  expectations in `failures`. Serialized only, until the server's tests need to read it back. Replaces D35,
  whose objects held every field however empty.
- D38 (amended by D177) Several `@servers`: each query is asked of each, the blocks of one query together in argument order,
  each id then `name_type@server` (port left out when 53, `+tls` or `+quic` after it for a `tls://` or
  `quic://` server) so `--save-wire` keeps them apart. A query file's
  queries go to the command line's servers when given. The human format ends a query's blocks with
  `servers disagree: a, b vs c` when the rcodes or answer records, TTL and order aside, differ; JSON and YAML
  leave the comparison to their reader. A server that does not answer is left out of it.
- D177 (amends D38) Each report of a run has its own id, its `--save-wire` file and its name in `servers disagree`.
  A server's part of the id is its address, the transport its scheme forces (`+tls`, `+quic`, `+https`, `+odoh`,
  `+coap`), then the path of a `DoH` template other than `/dns-query` or of a CoAP URI, each `/` a `_`:
  `example.com_A@127.0.0.1:8443+https_a` for `https://127.0.0.1:8443/a`. Two queries with one id, as `dedens
  example.com example.com` makes, are refused before any is asked: `two queries with id example.com_A`, exit 10,
  as D34 refuses them in a file. Rejected: asking the duplicate once, since the command line then says something
  other than what runs; numbering the files, since the id names the query. `servers disagree` names each server
  by that part of its id: two paths at one address told apart. Tests: `apps/dedens/tests/files.rs`
  (`save_wire_never_overwrites_a_response`), unit tests of `output.rs`.
- D39 `--repeat N` (`+repeat=N`): each query is asked of each server N times in a row, not concurrently, so
  the round trips are the server's and not our queue's. The last response is printed, with a `latency` object
  when N > 1: `sent`, `errors` (left out when 0) and `min_us`/`p50_us`/`p90_us`/`p99_us`/`max_us`, nearest
  rank over the answered round trips; the human format shows them in milliseconds on one line. Exit code 0 when
  any answer came, else the last error's.
- D40 (amended by D76) `+trace`: each query asked from the root servers (IANA's `named.root`, bundled; `just root-hints`
  refreshes it) without RD, down the referrals (RFC 1034 §4.3.2: NOERROR, no answer, no AA, NS and no SOA in
  the authority section, a SOA being NODATA per RFC 2308 §2.2), one report per hop, until an answer, NXDOMAIN,
  NODATA or an authoritative response. A referral that comes no closer, an error rcode or a lame response sends
  the hop to the next address (RFC 1034 §5.3.3), three at most, IPv4 and IPv6 in turn so either route works.
  Glue is an address record of a name server inside the answering server's zone (RFC 2181 §5.4.1), unlike dig;
  name servers without glue are looked up the same way, A then AAAA, at most 4 deep, those inside the referred
  zone skipped (they lead back to the same referral). A trace makes 100 exchanges at most. No DNSSEC
  validation (`+validate` is refused, D76), no CNAME following. Refused with `@server`, `-f`, `--repeat`, `--search`, `+tls` and `+quic`. The human format
  counts the additional records of a referral hop instead of listing them. `DEDENS_ROOTS` replaces the roots
  for tests.
- D67 Public resolvers live in `docs/providers/providers.yaml`: a provider's facts (operator, country,
  privacy) and its resolvers, each with what it blocks and what it does with a broken DNSSEC signature, both
  measured, not announced (Quad9's "unsecured" validates, CleanBrowsing's servers disagree, Comodo blocks
  nothing, DNS4EU's child variants block gambling), and its endpoints per transport, DoH URLs asked over HTTP/3
  (D83), those of servers without it kept as data until HTTP/2. `apps/dedens/tests/providers.rs` reads it into
  typed structs: `cargo test` checks the file offline; `just providers` (an ignored test, outside `just check`, which stays offline) asks, through one
  `dedens -f -` run (2 tries), `example.com` of every endpoint, `dnssec-failed.org` of each resolver, and
  each resolver the canaries of each category: one blocked if `blocks` lists the category, all answered if not.
  Blocked is NXDOMAIN, EDE 15 to 17, no address, `0.0.0.0`, loopback or a listed block page. No provider
  publishes a canary its peers block, and threat feeds differ (HaGeZi's lists EICAR's test site, not WICAR's),
  so the canaries are names measured to split the resolvers so. An address family without a route is skipped
  (IPv6 on CI); half the queries failing stops the test, the network being down. Each failure is then asked
  again alone with 8 tries, 16 runs at once, since public servers drop queries (Comodo half of them) and
  QUIC connections sharing a socket stall (`docs/TODECIDE.md`). A REFUSED with EDE 16 (Censored) passes: the
  resolver answered, the law where the test runs refused (OpenDNS from France). A resolver whose packet cache
  answers with an earlier client's cookie (UncensoredDNS), which `dedens` drops as forged (RFC 7873 §5.3,
  D68), is marked `stale_cookies` and asked without a cookie. Rejected: a query file generated from it (a file
  to keep in step), a test per endpoint (a process each, hundreds).
- D89 Loopback test servers count queries, not datagrams, and no test frees a port to get a closed one. The system
  hands a port out again as soon as its socket closes, and tests run side by side (in one process, `just check`'s
  other work, other worktrees): a QUIC server keeps sending, after its client exited, to the client's old port, which
  another test's server then holds (seen: a log of three queries with a fourth that was 31 bytes of QUIC), and a
  client of a port freed to be closed is answered by whoever took it (seen: `a_closed_port_exits_9` exit 0). So
  the UDP servers of `dedens_testkit::responder` and `crates/dedens-net/tests/util` and the CoAP one of
  `coap.rs` skip a datagram that is not a query, and closed-port tests use `127.0.0.1:1`,
  which the system never hands out. Rejected: a retry or a sleep (the stray is not late, it is not ours), a port
  range per test (the stray's sender does not know it). On macOS a datagram is queued without the control data
  (destination address, ECN) of the socket options set after it arrived, and `compio-quic` panics on one
  (`compio-io` 0.10.1 `CMsgIter::new`: `buffer too short`). `dedensd` bound its sockets, logged `serving` and set the
  options when its threads built the QUIC endpoints, so a client at once could kill the process (seen: 6 of 3840
  runs of `s3_the_path_is_the_listeners` under load, `connected: TimedOut`); it now logs `serving` once every
  thread has its endpoints. A datagram that reaches a socket before its owner set the options stays a risk, a
  startup one on macOS only (a restart ends it), and for a client of a test too.
