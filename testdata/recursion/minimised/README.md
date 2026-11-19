# Minimised resolutions

Real resolutions from the root servers with their questions minimised (RFC 9156, D198), the test data of QNAME
minimisation. `<id>.yaml` has the format of `../README.md` and is read as `minimised/<id>`, but the resolver itself
asked, through `just capture-minimisation` (never edit by hand): no priming, no DS or DNSKEY, one server per zone
recorded, the root's from the bundled hints. Strict minimisation, so that a timeout does not change the questions.

| Id | Question | Shows |
|---|---|---|
| `ent` | `_xmpp-server._tcp.jabber.org SRV` | The empty non-terminal `_tcp.jabber.org` answering NODATA to its minimised question |
| `ip6` | `8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa PTR` | 34 labels: one label at a time, then several, the tenth question the full name |
