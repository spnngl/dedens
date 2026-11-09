# Presentation format

Decisions; the rules and the index are in [`README.md`](README.md).

- D25 Zone text (`dedens-proto::text`, RFC 1035 §5, RFC 2308 §4, RFC 3597 §5): own lexer, base64 and hex.
  Read: BIND TTL units, `\#` for every type (known ones typed), case as written. Written: one tab-separated
  line per record, absolute names, TTL in seconds, `\#` on request (`generic()`). `ZoneReader` hands
  `$INCLUDE` to the caller (no file I/O in the library; the caller bounds depth and vets paths) and stops at
  the first error, with line and column. No `$GENERATE`. Stricter than BIND where BIND only warns: TTL over
  2³¹−1 is an error, no SOA-minimum fallback, query and meta types and classes (RFC 6895 §3.1-3.2) and RDATA
  over 65535 bytes are refused. A `"` opens a quoted part at a token's start, or after the first `=` in SVCB
  parameters only (RFC 9460 §2.1), as BIND; a `\` ending a line outside quotes is an error (it joins entries).
  `\#` RDATA its type refuses stays opaque with the reason (`DecodedRecord`), as on the wire (D9). RFC 1035
  §5.2 zone checks belong to the zone-loading layer.
- D29 A quoted part ends on its line: an unescaped newline inside quotes is an error, as in BIND (`isc_lex`
  without `ISC_LEXOPT_QSTRINGMULTILINE`, how it reads zone files); `\` before the newline keeps it in the
  text. RFC 1035 §5.1 leaves it open; a missing `"` would otherwise swallow the entries after it silently.
