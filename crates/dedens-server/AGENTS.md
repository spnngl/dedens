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
- A client the access lists deny is answered before any stage (D91), but past the authoritative stages that open a
  pipeline: they answer every client, so `Pipeline::denial` and `drops` say nothing then, and the RA of a reply is
  `Pipeline::recursion`'s, never set by hand (D208). A valid Server Cookie skips the rate limit (D113).
- A reply to a signed request is built for `Client::room`, never `Client::limit`: the room keeps the TSIG's
  `Key::record_len` out, and `Signed::seal` drops a reply it cannot sign within the limit (D211). A signed request
  never reaches a stage past the zones: it could not be signed there.
- `Transfer::next` takes the running pipeline for each message, and signs only while its keyring holds the key
  (`Pipeline::signing_time`): a caller that keeps one pipeline for a whole transfer lets a revoked key sign on
  (D211, D214). A transfer holds its zone's `Arc<Zone>`, never the stage.
- A hit a `Plugin::reviewer` reviewed is marked with the pipeline's id (`Cache::mark`) and decoded once (D118).
- ANY over UDP and DoC is answered empty with TC (D114).
- A recurse stage's reply TTLs are bounded once (D195): `Resolved` holds them so, a TTL fresh from a reply bounded
  by the cache's `lifetime`, one from the RRset cache its time left. Never floor them again: the cache stage stores
  them with `Cache::insert_bounded` (`Ttls::Bounded`), not `insert`. A pipeline has a forward or a recurse stage,
  never both (`dedensd`'s config).
- A validating recurse stage (D197) is never parked (D186): past the allowance it is SERVFAIL EDE 14. Its verdict
  is the resolution's (`Resolved::checked`, `Failure::Bogus`), presented by `Finish::deliver` with `Ttls::Bounded`;
  a bogus one is SERVFAIL with its EDE, never stale data.
  A bound reached while validating is indeterminate, EDE 5, not EDE 22 (D197). `Resolution::validation_cost` is
  cumulative across the resolution's retries: `Charging::charge` charges its growth, never resets it.
