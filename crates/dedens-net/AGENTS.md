# dedens-net

DNS transports on compio (D4, D60, D61, D81, D83); `src/lib.rs` sorts the modules into sans-IO cores and those on
compio. Measure a transport change with `just bench-dnsperf <base> forward` or `forward-tcp`.
