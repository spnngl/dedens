# DNSSEC captures

Real responses from `1.1.1.1` for the tests of validation (RFC 4033-4035, 5155, 9824). `capture.yaml` lists the
queries; `<id>.bin` is the response to the query `id`, as `just capture-dnssec` saved it (never edit by hand).
Every query set DO and CD, so each response holds the records and proofs as the zone served them, whatever their
signatures. `captured_at` is the Unix time of the run: the tests pass it as "now", or the signatures that were
valid would be out of their window.

Verdicts are those of RFC 4035 §4.3 for the response alone, given the chain files below it and the root KSK of
`root_dnskey` as the only trust anchor; `dedens_dnssec::validator` (D75) gives them, `tests/validator.rs` checks them.
They were checked on 2026-11-01 (the wildcard rows, `delv` of BIND included, and the captures of `ph`, `ws`, `internet.nl` and
`nist.gov`, on 2026-11-01 too) against 8.8.8.8 and 9.9.9.9 without CD (`ad` set: Secure, no `ad`: Insecure,
SERVFAIL: Bogus). One difference: those resolvers set `ad` on an answer an opt-out NSEC3 leaves open, and the
validator does not (RFC 5155 §9.2): the rows say Insecure (opt-out) where it is so. A recapture keeps the coverage, not the bytes: names and
types stay, keys, signatures and denial records change. To test the window alone, give a Secure capture a "now"
before its inception or after its expiration: Bogus.

`ids` below are file names; `<zone>` is the zone's name with `_` for `.`. `crates/dedens-dnssec/tests/captured.rs`
reads the set.

## Chain of trust

`<zone>_ds` is the DS RRset in the parent (signed by the parent), `<zone>_dnskey` the DNSKEY RRset (signed by the
zone). The link from a parent's DS to a zone's key is Secure unless the row says otherwise.

| Zone | Algorithm | Shows |
|---|---|---|
| `root_dnskey` | 8 | Two KSKs and a ZSK, self-signed: the trust anchor |
| `com`, `net`, `nl` | 13 | TLDs signed with ECDSA P-256; DS signed by the root (8) |
| `org`, `dev`, `stream` | 8 | RSA/SHA-256 TLDs; `org_dnskey` is over 1232 bytes (read over TCP) |
| `cat` | 10 | RSA/SHA-512 TLD |
| `la` | 7 | RSASHA1-NSEC3-SHA1: DS digests 1 and 2, seven keys, over TCP; Secure (SHA-1 is validated, D71) |
| `cr` | 13 | DS digests 2 and 4 (SHA-384): the only digest 4 |
| `nlnetlabs_nl` | 8 | NSEC zone |
| `internet_nl` | 13 | NSEC zone with a wildcard (`*.internet.nl`) |
| `gov`, `nist_gov` | 8 | `nist.gov` (NSEC) signs every name it answers on demand: no wildcard expansion |
| `ph`, `ws` | 13, 8 | TLDs with an opt-out NSEC3 and a wildcard of their own (`ws`: 10 iterations) |
| `cloudflare_com`, `sidnlabs_nl`, `example_nl`, `icann_org`, `cloudflare_net`, `ripe_net`, `verteiltesysteme_net` | 13 | Targets of the answers below |
| `fedoraproject_org` | 14 | ECDSA P-384 |
| `ed25519_nl` | 15 | Ed25519 |
| `ed448_nl` | 16 | Ed448: `ring` lacks it, so the zone is Insecure (RFC 4035 §5.2, D71) |
| `debian_org` | 8 and 13 | Two algorithms at once: either validating is Secure |
| `rootcanary_net` | 8 | The only RootCanary zone served: no per-algorithm or bogus names in it |
| `ippacket_stream`, `rsa2048_ippacket_stream` | 8 | `stream` → `ippacket.stream` → `rsa2048-sha256.ippacket.stream`: a chain three zones deep |
| `dnssec_failed_org` | 13 | The DS matches no DNSKEY: Bogus. The DNSKEY set also holds an expired signature |
| `rhybar_cz` | 5 and 7 | The DS (13) matches no DNSKEY, and every signature ended in October 2025: Bogus |
| `cz` | 13 | Parent of `rhybar.cz`, DS signed by the root |
| `wb_sidnlabs_nl`, `bad_dnssec_wb_sidnlabs_nl`, `sigexpired_wb_sidnlabs_nl` | 8 | SIDN Labs' test zones, `sidnlabs.nl` → `wb` → `bad-dnssec.wb` → `sigexpired.bad-dnssec.wb`: a sound chain down to the last zone, whose DNSKEY signature and A ended in December 2019: Bogus (signature expired) |

## Unsigned delegations

| Id | Shows | Verdict |
|---|---|---|
| `google_com_ds` | DS NODATA from `com`: NSEC3 opt-out, closest provable encloser (RFC 5155 §8.6, §8.9) | Insecure (opt-out): `google.com` is unsigned |
| `google_com_a` | The unsigned answer below it: no RRSIG | Insecure |
| `referral_signed`, `referral_unsigned` | Referrals as an authoritative server of the parent gives them, without recursion (asked of a `nl` server for `www.nlnetlabs.nl`, and of a `com` server for `www.google.com`): the DS of the signed child, and the proof that the unsigned one has none (opt-out) | Referral to a secure zone; referral to an insecure one |
| `jm_ds` | DS NODATA from the root with NSEC (RFC 4035 §5.2) | Secure proof that `jm` has no DS: the delegation is insecure |
| `edgekey_net_ds`, `akamaiedge_net_ds` | Same, from `net` (NSEC3 opt-out), for the zones of `cname_to_insecure` | Insecure (opt-out) |

## Signed answers

| Id | Shows | Verdict |
|---|---|---|
| `alg8_a` | `nlnetlabs.nl` A, RSA/SHA-256 | Secure |
| `alg13_a` | `cloudflare.com` A, ECDSA P-256 | Secure |
| `alg10_soa` | `cat` SOA, RSA/SHA-512 | Secure |
| `alg14_a` | `fedoraproject.org` A (11 addresses), ECDSA P-384 | Secure |
| `alg15_a` | `ed25519.nl` A, Ed25519 | Secure |
| `alg7_soa` | `la` SOA, RSASHA1-NSEC3-SHA1 | Secure |
| `alg8_13_a` | `debian.org` A: one RRSIG per algorithm | Secure |
| `alg16_a` | `ed448.nl` A, Ed448 | Insecure |
| `rootcanary_soa` | `rootcanary.net` SOA | Secure |

## Denial of existence

Each needs the zone's DNSKEY (and the chain to it) above. The name that does not exist is in `capture.yaml`.

| Id | Shows | Verdict |
|---|---|---|
| `nxdomain_root_nsec` | NXDOMAIN under the root: two NSEC, one covering the name, one the wildcard | Secure NXDOMAIN |
| `nxdomain_nsec` | NXDOMAIN with NSEC in a non-root zone (`nlnetlabs.nl`) | Secure NXDOMAIN |
| `nxdomain_nsec3` | NXDOMAIN with NSEC3 (`debian.org`: no opt-out, no salt, 0 iterations, two algorithms) | Secure NXDOMAIN |
| `nxdomain_nsec3_optout` | NXDOMAIN with opt-out NSEC3 (`com`): the proof is the closest provable encloser (RFC 5155 §8.3) | Insecure (opt-out): the name may be an unsigned delegation (RFC 5155 §9.2) |
| `nxdomain_nsec3_salt` | Opt-out and an 8-byte salt (`org`) | Insecure (opt-out) |
| `nxdomain_nsec3_iterations` | One extra iteration and an 8-byte salt (`dev`) | Secure NXDOMAIN |
| `nxname_cloudflare` | Compact denial (RFC 9824 §3.1): NOERROR, empty answer, an NSEC of the name with `RRSIG NSEC NXNAME` | Secure NXDOMAIN, whatever the RCODE |
| `nodata_compact` | Compact NODATA (RFC 9824 §3.2): the NSEC of the existing name lists its types | Secure NODATA |
| `nodata_root_nsec` | NODATA at the root: NSEC of the apex | Secure NODATA |
| `nodata_nsec` | NODATA with NSEC (`nlnetlabs.nl`) | Secure NODATA |
| `nodata_nsec3` | NODATA with NSEC3 (`debian.org`): matching NSEC3 without the type | Secure NODATA |
| `nodata_nsec3_optout` | NODATA at the apex of `com`: opt-out flag set | Secure NODATA |
| `nodata_nsec3_iterations` | NODATA at `rootcanary.net`: one extra iteration | Secure NODATA |
| `ent_nsec` | Empty non-terminal with NSEC: the NSEC that covers it (`_tcp.nlnetlabs.nl`) | Secure NODATA |
| `ent_nsec3` | Empty non-terminal with NSEC3: a matching NSEC3 with an empty bitmap (`_tcp.sidnlabs.nl`) | Secure NODATA |
| `wildcard_answer` | MX from `*.sidnlabs.nl`: RRSIG labels below the owner's, NSEC3 proving the next closer name absent (RFC 5155 §8.8) | Secure |
| `wildcard_nodata` | Another type at the same name: the wildcard's NSEC3 and the proof of the next closer name (RFC 5155 §8.7) | Secure NODATA |
| `wildcard_answer_nsec` | TXT from `*.internet.nl`: RRSIG labels below the owner's, an NSEC covering the name and one proving the wildcard's own name (RFC 4035 §3.1.3.3, §5.3.4) | Secure |
| `wildcard_nodata_nsec` | A at the same name: the wildcard's NSEC without the type | Secure NODATA |
| `synthesized_nist_gov_txt` | TXT of `wildcard-test.nist.gov`: signed for the name itself (labels equal, no proof sent, no expansion) | Secure |
| `wildcard_answer_optout`, `wildcard_answer_optout_ws` | A from the wildcards of the TLDs `ph` (labels 1) and `ws`: the proof of the next closer name is an opt-out NSEC3, so the name may exist unsigned (RFC 5155 §9.2) | Insecure (opt-out) |
| `wildcard_nodata_optout` | MX at the same name in `ph`: the wildcard's no data, the same proof | Insecure (opt-out) |

## Answers across zones

| Id | Shows | Verdict |
|---|---|---|
| `cname_cross_zone` | `www.icann.org` CNAME (org, 13) to `…cdn.cloudflare.net` A (net, 13) | Secure |
| `cname_deep_zone` | `verteiltesysteme.net` CNAME (13) to `rsa2048-sha256.ippacket.stream` A (8) | Secure |
| `cname_to_insecure` | Signed CNAME from `ripe.net` to an unsigned CNAME in `edgekey.net` and an unsigned A in `akamaiedge.net` (neither has a DS) | First CNAME Secure, the rest Insecure |
| `dname_rr` | `dname.sidnlabs.nl` DNAME, signed | Secure |
| `dname_answer` | The DNAME with its signature, the CNAME synthesized from it (unsigned, RFC 6672 §3.1) and the signed AAAA in `example.nl`. Asked of 8.8.8.8: 1.1.1.1 answers it NXDOMAIN half the time | Secure |

## Bogus

| Id | Shows | Verdict |
|---|---|---|
| `bogus_no_key` | `dnssec-failed.org` A: signed, but its DS matches no DNSKEY | Bogus |
| `bogus_expired` | `rhybar.cz` A: RRSIGs (5 and 7) expired in October 2025, the DS matches no key | Bogus |
| `bogus_signature` | `sigfail.verteiltesysteme.net` CNAME, then an A whose RRSIG does not verify; the chain is sound | Bogus |
| `bogus_sigexpired` | `sigexpired.bad-dnssec.wb.sidnlabs.nl` A: the zone's signatures, its DNSKEY set's included, expired in 2019; the chain down to its DS is sound | Bogus (signature expired) |

## Leaves of the chain of trust

`leaf_*_ds` are the DS queries a validator asks for the owner of each `RRset` of the answers above: the owner's own zone cut, or none. What the resolver returns depends on the name: NODATA or a name error with the parent's proof; the signed CNAME where the name is a CNAME (`www.icann.org`, `www.ripe.net`, the two `sigok` and `sigfail` names), which a DS query reaches as any type; a wildcard no data (`leaf_wildcard_sidnlabs_ds`); a name error under an opt-out span (`leaf_nxdomain_com_ds`, `leaf_nxdomain_org_ds`) proving a delegation without DS: insecure, opt-out; `leaf_wildcard_internet_nl_ds` is the wildcard's no data, `leaf_synthesized_nist_gov_ds` a plain no data, and `leaf_wildcard_ph_ds` and `leaf_wildcard_ws_ds` an insecure delegation by opt-out.

## A name of 34 labels

`ip6_ptr` is the PTR of an IPv6 reverse name (RIPE NCC's `www.ipv6.ripe.net`, 34 labels under `ip6.arpa`, signed by `8.e.2.0.c.7.6.0.1.0.0.2.ip6.arpa`, 13), Secure. The validator asks the DS of each label below `arpa`: `ip6_ds_N` is that of the suffix of N labels (`ip6_ds_1` is `arpa`), a DS at the zone cuts (`arpa`, `ip6.arpa`, `6.0.1.0.0.2.ip6.arpa`, `8.e.2.0.c.7.6.0.1.0.0.2.ip6.arpa`) and a signed NODATA elsewhere; `arpa_dnskey`, `ip6_arpa_dnskey`, `ip6_1_0_0_2_dnskey` and `ripe_ip6_arpa_dnskey` are the keys of those zones.
