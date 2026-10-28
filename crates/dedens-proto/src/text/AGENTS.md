# text

Presentation format (D25): records as zone-file text and zone files. The lexer yields tokens lazily, so the
field being read decides how its token is lexed (SVCB `key="value"`). The zone reader is benched in
`crates/dedens-bench/benches/zone.rs` against `domain`: check it after a lexer change.
