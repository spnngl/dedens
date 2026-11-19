# dedens-server

The server's query pipeline (D23, D41, D43), sans-IO: `Pipeline::query` and `Pipeline::receive` return a `Step`
that `apps/dedensd` carries out with `dedens-net`; `Step::Resolve` hands it a resolution to step, send and feed
back, `Pipeline::resolved` writing the reply (D195). Measure a change to the rate limit with
`crates/dedens-bench/benches/rrl.rs`.

## Invariants

- `Pipeline::receive` checks the QR bit, opcode and question of each upstream response itself, trusting no
  transport; the ID is the transport's (D111).
- Only a `Secure` verdict sets AD; the upstream's AD is never read. A secure response is cut by
  `dedens_dnssec::covered` to the records the verdict covers: the validator ignores the rest, so it must not come
  out under AD or be cached as secure (D77).
- A query past its network's `Budget` share is shed in `Pipeline::query`, before any question (D117); one past the
  validator's `Allowance` is `Step::Park`, holding its share's unit until `Pipeline::unpark` or `Pipeline::shed`
  (D186).
- A client the access lists deny is answered before any stage (D91); a valid Server Cookie skips the rate limit
  (D113).
- A hit a `Plugin::reviewer` reviewed is marked with the pipeline's id (`Cache::mark`) and decoded once (D118).
- ANY over UDP and DoC is answered empty with TC (D114).
- A recurse stage's reply TTLs are bounded once (D195): `Resolved` holds them so, a TTL fresh from a reply bounded
  by the cache's `lifetime`, one from the RRset cache its time left. Never floor them again: the cache stage stores
  them with `Cache::insert_bounded` (`Ttls::Bounded`), not `insert`. A pipeline has a forward or a recurse stage,
  never both (`dedensd`'s config).
- A validating recurse stage (D197) is never parked (D186): past the allowance it is SERVFAIL EDE 14. Its verdict
  is the resolution's (`Resolved::checked`, `Failure::Bogus`), presented by `Finish::deliver` with `Ttls::Bounded`;
  a bogus one is SERVFAIL with its EDE, never stale data.
