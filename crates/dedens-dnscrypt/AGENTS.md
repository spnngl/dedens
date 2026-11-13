# dedens-dnscrypt

DNSCrypt v2 (draft-denis-dprive-dnscrypt, D97): the sans-IO core of both classical systems, no socket and no clock.
`src/lib.rs` maps the items. Stamps and the exchange over UDP, TCP and relays are other crates' (the relay's prefix is here, `anonymized.rs`,
D100), and so is the resolver's serving and key rotation (`apps/dedensd`, D99).

- Cite the draft by section name, never by number: the numbers move between revisions (the revision read is pinned in
  `docs/rfc/list.md`). Where the draft is silent, `docs/rfc/archive/dnscrypt-v2-protocol.txt` is the 2023 text.
- A `Certificate` is only ever a verified one: `parse` and `from_txt` check the signature, the validity order and the
  client magic. The time is a parameter, never read.
- A packet that fails any check is dropped without a reply (resolver) or ignored (client). The errors say which check,
  for logs and tests, never for the peer.
- The secretbox is the NaCl layout (Poly1305 key from the first 32 keystream bytes), not the AEAD of RFC 8439: the tag
  is checked, in constant time, before anything is decrypted.
- A shared key costs a scalar multiplication: `ClientSession` and `ResolverKey::shared_key` make it once per client
  key. It is zeroized on drop and no `Debug` shows it.
