# interop

Checks of dedens against implementations that are not ours, run by hand: they need the network and tools outside
`just check`.

- `odoh.py`: `dedensd` as an Oblivious DoH target for Cloudflare's `odoh-rs`, over HTTP/3 with `aioquic`
  (`just odoh-interop`; D79). The header says what it checks.
- `odoh-rs/`: its scratch crate, its own workspace, `odoh-rs` pinned from crates.io: seals a query and opens a
  response, nothing else.
