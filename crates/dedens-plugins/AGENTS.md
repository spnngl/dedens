# dedens-plugins

Plugin stages (D54), sans-IO: each is built from text its caller read (`apps/dedensd` reads the files) and
implements `dedens_server::Plugin`, answering without allocating. One module per plugin, its tests in
`tests/<plugin>.rs` on real files (`tests/testdata`).

- `src/blocklist.rs`: the blocklist stage; `Names` (one list read once, D120), `Merged` (a stage side's set, D110), the
  CNAME and DNAME targets it reviews (D118).
- `src/hosts.rs`: the hosts stage. `src/text.rs`: the line reader both share. Fuzzed by `parse_lists`.
