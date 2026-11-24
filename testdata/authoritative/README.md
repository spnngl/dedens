# Authoritative captures

What Knot DNS 3.6.2 and NSD 4.15.4 answer and do, and what public servers transfer: the test data of the
authoritative server (D203). `just capture-authoritative [stages]` writes it (never edit by hand; `just
authoritative-images` builds the two images of the [`Containerfile`](Containerfile) first). The example is
`capture_authoritative` of `dedens-testkit`; `dedens_testkit::authoritative` reads the files.

| Stage | Writes | From |
|---|---|---|
| `sources` | `zones/`, `recordings/axfr-root.yaml`, `recordings/axfr-zonetransfer.me.yaml` | AXFR of `.` (`lax.xfr.dns.icann.org`, then `iad`, `b` and `f.root-servers.net`) and of `zonetransfer.me.` (`nsztm1.digi.ninja`, a zone made for it); the previous root zone from the Wayback Machine's copy of `internic.net/domain/root.zone` |
| `answers` | `answers/<zone>.yaml` | one Knot and one NSD container per zone |
| `exchanges` | `recordings/<scenario>.yaml` | a Knot container, a recording proxy between it and `kdig` or `knsupdate` |
| `root-ixfr` | `recordings/root-ixfr.yaml` | Knot loading the previous root zone, then the current one as a difference, and `kdig` asking IXFR |
| `signed-stream` | `recordings/axfr-tsig-stream.yaml` | Knot serving the first 1200 records of the root zone to a key's holder, and `kdig` signing the AXFR |
| `signed` (`just capture-signed`, not a default stage) | `zones/nsec3_signed.zone`, `answers/nsec3_signed.yaml` | Knot's `kzonesign` signing `../zones/nsec3_source.zone`, then one Knot and one NSD container serving the result |

## Zones

`zones/root.zone` (serial 2026112201) and `zones/zonetransfer.me.zone` are the records of their transfer, as
`dedens-proto` prints them, in the order of the transfer (SOA first, the closing SOA dropped). `zones/root-previous.zone`
is the root zone of serial 2026111401 (2026-11-14 22:18 UTC), the first of the IXFR: the root changes twice a day, so the
second serial of an IXFR cannot wait for a capture, and the archive's copy is the only one with a serial to go from. Its
ZONEMD records are in generic form (`TYPE63 \# n hex`, RFC 3597 §5), as the other two's, because `dedens-proto`'s text
parser does not know the type yet. `zones/nsec3_signed.zone` is the NSEC3 chain of a real signer (D209):
`testdata/zones/nsec3_source.zone`, RFC 5155 Appendix A's names, signed by `kzonesign` with ECDSA P-256, NSEC3 of 0
iterations, no salt and the opt-out flag, with the signer's clock set to Unix time 1780000000 (2026-05-28 20:26:40
UTC), so every signature starts 90 minutes before it and lasts 14 days from it. The keys are new each run: the stage
is run once and its files kept, and the tests of `dedens-zone` run the validator at that time. The zones of
`testdata/zones/` are served too: RFC 4035 and RFC 5155's appendices; the RFC 1035 ISI zone is refused by Knot (MB
and MG are obsolete types it does not load), and the zone of every type by both (Knot: `unsupported record
type`; NSD: `only class IN is supported`), so no answers exist for it.

## Answers

`answers/<zone>.yaml`: the versions of the two servers, the zones each refused, and for each question the response of
each server, as bytes. The questions of a zone are, for every owner name, each type present, `ANY` and one absent type
(NODATA); for a delegation, `www.` below it, its `DS` and its `SOA`; for a DNAME, a name and a deeper one below it; for a
wildcard, names it expands to (every type, `dedens-wild` as the label) and one two labels deeper; the empty non-terminals;
and at the apex a name that does not exist, a deeper one, the SOA in mixed case and, but for the root, a name outside the
zone (REFUSED). The root's owners are the apex, three TLD delegations with a DS, three without and two names holding
glue. Every question goes over UDP without DO and with DO, both advertising 1232 bytes; the apex questions and those
whose answer with DO is over 300 bytes go also over UDP without EDNS (512 bytes), over UDP advertising 512 bytes with
DO, and over TCP. Queries have ID `0x1234`, no RD, and are the question and the OPT record.

## Recordings

A recording is the messages of one exchange between a client and Knot (or, for NOTIFY, between Knot and NSD), as bytes,
each with its time in milliseconds from the first, its transport and its direction; TCP messages without their length
prefix. Zones: `zonetransfer.me.` is served for the holder of the key `dedens-test-key` (hmac-sha256; its secret is
`TSIG_KEY` in `dedens_testkit::authoritative`), RFC 4035's `example.` to all addresses without TSIG. A scenario that
changes a zone ends with an AXFR of the result. Each scenario runs on a fresh Knot, so a recapture changes only what
varies by run: IDs, TSIG times and MACs, times between messages.

| Scenario | Shows |
|---|---|
| `axfr-root`, `axfr-zonetransfer.me` | The AXFR a client sees from a public server (RFC 5936 §2) |
| `axfr-open` | AXFR without TSIG |
| `axfr-tsig` | AXFR signed: the one response carries a TSIG (RFC 8945 §5.3, RFC 5936 §2.2) |
| `axfr-tsig-stream` | AXFR signed, 1200 records of the root: five messages, each signed over the one before (RFC 8945 §5.3.1) |
| `axfr-tsig-bad-secret`, `axfr-tsig-unknown-key`, `axfr-tsig-bad-time` | NOTAUTH with BADSIG, BADKEY, BADTIME (a clock 600 s behind) |
| `axfr-unsigned-refused` | A zone for a key's holder, asked without TSIG: NOTAUTH, unsigned |
| `ixfr-uptodate`, `ixfr-tsig-uptodate` | IXFR from the serial held: one SOA |
| `ixfr-unknown-serial` | IXFR from a serial never held: the full zone, AXFR-style (RFC 1995 §4) |
| `ixfr-difference-tcp`, `ixfr-difference-udp` | IXFR after an UPDATE: the difference |
| `root-ixfr` | IXFR between two root serials: 99 messages |
| `update-*` | UPDATE (RFC 2136): each prerequisite form met and unmet, adds, deletes, the cases ignored or refused, signed and not |
| `notify-load`, `notify-command`, `notify-after-update` | The NOTIFY Knot sends (RFC 1996 §3.11) |
