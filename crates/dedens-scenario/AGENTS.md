# dedens-scenario

Query files (D17, D34) from JSON or YAML and the report of a response (D35), shared by `dedens` and the server's
tests. No I/O: callers read the file and run the queries.

- `src/file.rs`: `QueryFile`, `Query`, `Format`; serde with `deny_unknown_fields`.
- `src/options.rs`: `Options`, dig's `+` options, one set for files and the command line; builds the query and
  the `dedens-net` exchange options.
- `src/expect.rs`: `Expect`, checked against a decoded response into failures in words.
- `src/report.rs`: `Report`, what `dedens --json` prints; built from a `dedens_net` response or a decoded message.
- `tests/query_file.rs`: both formats, and expectations against captured responses.

Fuzz target: `parse_query_file`.
