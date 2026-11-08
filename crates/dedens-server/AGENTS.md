# dedens-server

The server's query pipeline (D23, D41, D43), sans-IO: `Pipeline::query` and `Pipeline::receive` return a `Step`
that `apps/dedensd` carries out with `dedens-net`. Measure a change to the rate limit with
`crates/dedens-bench/benches/rrl.rs`.

## Invariants

- `Pipeline::receive` checks the QR bit, opcode and question of each upstream response itself, trusting no
  transport; the ID is the transport's (D111).
- Only a `Secure` verdict sets AD; the upstream's AD is never read. A secure response is cut by
  `dedens_dnssec::covered` to the records the verdict covers: the validator ignores the rest, so it must not come
  out under AD or be cached as secure (D77).
- A query past the validator's `Allowance` or its network's `Budget` share is shed in `Pipeline::query`, before any
  question (D117).
- A client the access lists deny is answered before any stage (D91); a valid Server Cookie skips the rate limit
  (D113).
- A hit a `Plugin::reviewer` reviewed is marked with the pipeline's id (`Cache::mark`) and decoded once (D118).
- ANY over UDP and DoC is answered empty with TC (D114).
