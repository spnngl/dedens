# Recursive resolutions

Real resolutions from the root servers, the test data of the recursive resolver (D188). `<id>.yaml` holds every
exchange an iterator had to resolve one name, as `just capture-recursion` wrote it (never edit by hand):
`dedens_testkit::recursion` reads it, its `Authorities` replays it. Each starts with priming (RFC 8109 §3) and the
root's DNSKEY, then asks each zone's DS at its parent and its DNSKEY at the zone. A question goes to one server of
each family; queries set DO alone and advertise 1232 bytes. `captured_at` is the Unix time of the end of the run:
the signatures of the responses are valid then. A recapture keeps the cases, not the bytes, nor always the servers. The
resolver's own minimised resolutions are in [`minimised/`](minimised/README.md) (D198).

| Id | Question | Shows |
|---|---|---|
| `priming` | `. NS` | Priming: the root's servers and their glue |
| `signed-com` | `example.com A` | A signed name under com |
| `signed-nl` | `sidn.nl A` | A signed name under nl |
| `unsigned` | `google.com A` | An unsigned delegation: com's NSEC3 denies its DS |
| `cname` | `www.microsoft.com A` | A CNAME chain across microsoft.com, edgekey.net and akamaiedge.net |
| `dname` | `www.dname.dns.netmeister.org A` | A DNAME (RFC 6672) in signed netmeister.org, its target in the child dns.netmeister.org |
| `glueless` | `netmeister.org A` | A glueless delegation: its servers are under gandi.net |
| `nxdomain-signed` | `dedens-nxdomain.sidn.nl A` | NXDOMAIN denied by NSEC |
| `nxdomain-nsec3` | `dedens-nxdomain.nl A` | NXDOMAIN from a TLD, denied by NSEC3 |
| `nxdomain-unsigned` | `dedens-nxdomain.google.com A` | NXDOMAIN in an unsigned zone |
| `nodata-signed` | `sidn.nl SRV` | NODATA denied by NSEC |
| `nodata-unsigned` | `google.com SRV` | NODATA in an unsigned zone |
| `truncated` | `microsoft.com TXT` | An answer over 1232 bytes: truncated over UDP, asked again over TCP |
| `rrsig` | `sidn.nl RRSIG` | An answer of signatures alone, no `RRset` of their own (D176) |

No zone served by IPv6 servers alone was found (D188).
