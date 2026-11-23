# Authoritative service: dedens, Knot DNS, NSD and BIND

`dedensd`'s authoritative stage (D208) set against the three servers it is measured and tested against, feature by
feature, from their code. Throughput, memory and load time are in [`../benchmarks.md`](../benchmarks.md), section
"Authoritative service against Knot and NSD" (D213).

Read on 2026-11-23:

| Server | Version | Commit |
|---|---|---|
| dedens | `main` with the phase's steps 01 to 07 (D203 to D209) | 885c6762 |
| Knot DNS | v3.6.2 (benched as its image, `docker.io/cznic/knot:v3.6.2`) | a6dada0 |
| NSD | 4.15.4 | f8f15490 |
| BIND 9 | 9.21.29-dev, `main`; read only, not run | e68fc6f |

How:

- Each cell cites code: a path in the server's repository and the function, type or option, for dedens the decision
  (Dnn) too. "no" means a search of the code and the manual found nothing; "planned" is a step of the authoritative
  phase not merged yet, which the REFUSED or NOTIMP of the cited code stands for until it lands.
- Differences of answers (what a server adds to a positive answer, which rcode it gives) are the captures' and
  D203's: [`../../testdata/authoritative/README.md`](../../testdata/authoritative/README.md).
- A newer version of any side outdates the cells: read again, and change the table above.

## Zone loading and answers

| Feature | dedens | Knot DNS | NSD | BIND |
|---|---|---|---|---|
| Zone checks at load | a failing zone refused with file, line and column: no, two or misplaced SOA, no apex NS, CNAME with other data, two CNAMEs or DNAMEs, CNAME with DNAME, DNAME with NS, data outside the zone, a broken or missing NSEC chain, NSEC3 iterations past 150; warned and served: TTLs of an `RRset` differing (the lowest kept), missing glue, names below a DNAME, NSEC3 iterations past 0 (`crates/dedens-zone/src/error.rs` `ErrorKind`, `WarningKind`; D204, D209) | mandatory: SOA, CNAME and other data, multiple CNAME or DNAME, DNAME with children or NS; opt-in: missing glue, apex NS, NSEC3, DNSSEC validation; `soft` turns errors into warnings (`src/knot/zone/semantic-check.c` `CHECK_FUNCTIONS`, `doc/reference.rst` `semantic-checks`) | refused on CNAME and other data, multiple CNAME or DNAME, SOA faults, out-of-zone data, DNAME with data below; warnings only on a secondary; no glue check (`zonec.c` `zonec_commit_rrset`, `check_dname`) | after load, each fail, warn or ignore: SOA, NS, `check-integrity` (glue, MX, SRV), `check-dup-records`, `check-wildcard`, `check-mx`, `check-names` (`lib/dns/zone.c` `zone_postload`, `integrity_checks`; `doc/arm/reference.rst`) |
| Wildcards (RFC 4592) | closest encloser's `*` child expands; a wildcard delegation refers (`crates/dedens-zone/src/answer.rs` `Zone::wildcard`; D206) | `NODE_FLAGS_WILDCARD_CHILD`, expanded on a name not found, a wildcard CNAME followed with loop detection (`src/knot/nameserver/internet.c` `name_not_found`, `wildcard_has_visited`) | synthesised from the closest encloser's `*` child, NSEC3 proof with DO (`query.c` `answer_authoritative`, `nsec3.c` `nsec3_answer_wildcard`) | wildcard bit on the parent node, blocked by empty non-terminals (`lib/dns/qpzone.c` `find_wildcard`, `wildcard_blocked`) |
| DNAME (RFC 6672) | CNAME synthesised, YXDOMAIN when the name grows past 255 bytes, chains up to 11 links (`answer.rs` `Zone::dname`, `End::YxDomain`, `MAX_CHAIN`; D206) | CNAME synthesised, YXDOMAIN, chain of 5 (`internet.c` `dname_cname_synth`, `CNAME_CHAIN_MAX`) | the same, chain of 18 at configure time (`query.c` `answer_authoritative`, `configure.ac` `max_cname_chain`) | `query_dname`, YXDOMAIN, bounded by `max-query-restarts`, 11 (`lib/ns/query.c` `query_dname`, `lib/dns/view.c` `DEFAULT_MAX_RESTARTS`) |
| NSEC and NSEC3 proofs of a signed zone | served as stored, Knot's choice of proofs from an index built at load, opt-out chains, chains checked closed, TC when a proof does not fit (`crates/dedens-zone/src/denial.rs` `Denial`, `reply.rs` `Answer::fill`; D209) | a separate `nsec3_nodes` tree; opt-out aware (`src/knot/nameserver/nsec_proofs.c` `nsec3_encloser`, `ds_optout`) | hashes and covers precompiled at load (`nsec3.c` `nsec3_precompile_newparam`, `nsec3_add_ds_proof`) | stored NSEC3 served (`lib/dns/nsec3.c`) |
| NSEC3 iterations | above 0 warned, above 150 refused, as the validator (`limits.rs` `nsec3_iterations`; D74, D209) | above 256 refused on `NSEC3PARAM` load (`src/knot/zone/contents.c` `zone_contents_load_nsec3param`, `CONF_NSEC3_MAX_ITERS`) | no limit but an `assert` at 65536 (`nsec3.c`) | warned above 50 at load, refused above 50 by the validator (`lib/dns/include/dns/nsec3.h` `DNS_NSEC3_MAXITERATIONS`) |
| Signing | no: pre-signed zones only (D209) | online, automatic: policies, keystores, rollovers, NSEC3 (`src/knot/dnssec/zone-events.c` `knot_dnssec_zone_sign`, `key-events.c`) | no: pre-signed only | yes: `dnssec-policy`, `inline-signing` (`lib/dns/zone.c` `zone_sign`, `lib/dns/keymgr.c`) |
| Positive answer's authority and additional | no apex NS set; the addresses of the NS and MX targets the answer or referral holds in the additional section (`crates/dedens-zone/src/reply.rs`; D206) | minimal always (`internet.c` `solve_authority`) | the apex NS set and its addresses unless `minimal-responses: yes` (`options.c`, `query.c`) | the apex NS set and addresses when RD is clear, `no-auth-recursive` (`lib/ns/query.c` `query_addns`) |
| Zone in memory | sorted `Vec` of nodes in canonical order, found by bisection; a reload swaps an `Arc<Zone>` (`crates/dedens-zone/src/zone.rs`, D204, D206) | QP-trie of nodes and another for NSEC3 (`src/knot/zone/contents.h`, `zone-tree.h`) | radix tree, `--disable-radix-tree` for an rbtree (`namedb.h`) | QP trie (`lib/dns/qpzone.c`) |
| Reload | a changed zone file reloaded, the others kept; a failing one keeps its last version (`apps/dedensd/src/zones.rs`, `reload.rs`; D208) | `knotc zone-reload`, mtime compared (`src/knot/events/handlers/load.c`) | `nsd-control reload`, SIGHUP; mtime compared (`dbaccess.c` `namedb_read_zonefile`) | `rndc reload`; unchanged files skipped by mtime (`lib/dns/zone.c`) |
| UDP workers | one thread a core, each its own sockets (`apps/dedensd/src/serve/udp.rs`, D47) | `udp-workers`, a thread per CPU (`src/knot/conf/conf.c` `conf_udp_threads_txn`) | `server-count` processes, 1 by default (`options.c`) | one loop thread per CPU (`bin/named/main.c`) |

## Transfers, dynamic updates and access

| Feature | dedens | Knot DNS | NSD | BIND |
|---|---|---|---|---|
| AXFR and IXFR out | no: planned; REFUSED to a transfer today (`crates/dedens-server/src/pipeline/mod.rs`, D114) | AXFR, IXFR from the journal with AXFR as fallback, over TCP; NOTIMP over UDP for AXFR (`src/knot/nameserver/axfr.c`, `ixfr.c`) | AXFR; IXFR only from stored files with `store-ixfr` (`axfr.c` `answer_axfr_ixfr`, `ixfr.c` `query_ixfr`) | AXFR and IXFR from the journal, `allow-transfer` (`lib/ns/xfrout.c` `ns_xfr_start`) |
| Transfer in (secondary zones) | no: planned; the difference of two zones and the journal of them exist (`crates/dedens-zone/src/difference.rs`, `journal/`; D207) | yes, by remote, with `master` ACLs (`src/knot/events/handlers/refresh.c`) | yes, in the `xfrd` process (`xfrd.c`) | yes, `primaries` (`lib/dns/zone.c`, `lib/dns/xfrin.c`) |
| XoT (RFC 9103) | no: planned | yes: `listen-tls`, a remote's `tls`, ACL `protocol` (`src/knot/conf/schema.c`) | yes: `tls-service-pem`, `tls-auth`, `tls-auth-xfr-only` (`nsd.conf.5.in`) | yes: strict, opportunistic and mutual (`doc/arm/reference.rst`, `lib/ns/query.c`) |
| NOTIFY (RFC 1996) | no: NOTIMP to the opcode (`pipeline/mod.rs`); planned | both ways, ACL `notify` (`src/knot/events/handlers/notify.c`, `src/knot/nameserver/notify.c`) | both ways, `allow-notify` (`xfrd-notify.c`, `query.c` `answer_notify`) | both ways, `also-notify`, `allow-notify` (`lib/dns/zone.c` `zone_notify`) |
| Dynamic UPDATE (RFC 2136) | no: NOTIMP to the opcode; planned. The difference and the journal it will write exist (D207) | yes: prerequisites, TSIG ACL, journal (`src/knot/updates/ddns.c`, `src/knot/nameserver/update.c`) | no: NOTIMP, or dropped (`query.c`, `drop-updates`) | yes: `allow-update`, `update-policy`, SIG(0), journal (`lib/ns/update.c` `ns_update_start`) |
| TSIG (RFC 8945) | SHA-1 (interop), SHA-256, 384 and 512, no MD5; RFC 8945 §5.2's order of checks; a library for now, no stage uses it yet (`crates/dedens-tsig/src/`, D205) | hmac-md5 to sha512, default sha256 (`src/knot/conf/schema.c`) | the same six through OpenSSL (`tsig-openssl.c`) | the six and truncated forms (`lib/dns/include/dns/tsig.h`) |
| Catalog zones (RFC 9432) | no: planned | consumer and producer (`src/knot/catalog/interpret.c`, `generate.c`) | consumer and producer (`xfrd-catalog-zones.c`) | consumer only (`lib/dns/catz.c`) |
| Response rate limiting | per client network, not per answer: TC to a source over its rate on UDP, so a spoofed flood cannot dodge it by varying the name; no per-answer limit (`crates/dedens-server/src/rrl.rs`, D113) | module `mod-rrl`, `rate-limit`, `slip`, off by default (`src/knot/modules/rrl/rrl.c`) | built in, `rrl-ratelimit`, `rrl-slip` (`rrl.c`) | `rate-limit {}`, per answer and class (`lib/dns/rrl.c` `dns_rrl`) |
| Access by client | lists of networks before the zones, `deny` or `drop`; zones answer every client that passes (`crates/dedens-server/src/access.rs`, D91, D208) | ACLs by action and network, TSIG key (`src/knot/conf/schema.c`) | `allow-notify`, `provide-xfr`, `request-xfr` by network and key (`nsd.conf.5.in`) | `allow-query`, `allow-transfer`, `allow-update` by ACL and view (`lib/isccfg/`) |

## Gaps

Where dedens is behind, and what lands in the authoritative phase:

- Transfers out and in, XoT, NOTIFY, UPDATE, catalog zones: planned, each its own step of the authoritative phase,
  with its own decision, per-zone access lists and TSIG on every one of them.
- Signing: not planned. A pre-signed zone is what the stage serves (D209); keys and rollovers belong to a signer
  (`kzonesign` and `keymgr` of Knot sign this bench's zone).
- Speed: on one core, `dedensd` answers at a third to six tenths of the rate of Knot and NSD in `just
  bench-compare authoritative`, [`../benchmarks.md`](../benchmarks.md) has the measurements and
  [`../TODECIDE.md`](../TODECIDE.md) the question.

Where dedens differs by design: no per-answer rate limit (D113), DNAME chains of 11 where Knot stops at 5 and NSD
at 18 (D206), no glue or authority sections added to a positive answer.
