# dedens-net

DNS transports on compio (D4, D60, D61, D81, D83); `src/lib.rs` sorts the modules into sans-IO cores and those on
compio. Measure a transport change with `just bench-dnsperf <base> forward` or `forward-tcp`.

- `DNSCrypt` (D98) is no `Transport`: `client.rs` sends the sealed packet through the plain UDP and TCP loop
  (`Via::DnsCrypt`), and `dnscrypt.rs` owns the certificates and the sealing. A new way a try can fail to open
  (silence, a closed connection, a response that does not authenticate) must mark the resolver `stale`, or a
  rotated key is asked with until the hour is out. The test resolver of `tests/dnscrypt.rs` is D97's resolver half:
  keep it so, not a second implementation of the draft.
