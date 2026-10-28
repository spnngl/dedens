# dedens-scenario

Query files (D34, D36) read as YAML 1.2, so JSON too, and the report of a response (D37), shared by `dedens`
and the server's tests. No I/O: callers read the file and run the queries.

- `src/file.rs`: `QueryFile`, `Query`, `Id`; serde with `deny_unknown_fields`.
- `src/options.rs`: `Options`, dig's `+` options, one set for files and the command line (clap flags behind the
  `clap` feature); builds the query and the `dedens-net` exchange options.
- `src/expect.rs`: `Expect`, checked against a decoded response into failures in words.
- `src/report.rs`: `Report`, what `dedens --json` and `--yaml` print; built from a `dedens_net` response or a decoded message.
- `tests/query_file.rs`: YAML and JSON files, and expectations against captured responses.

Fuzz target: `parse_query_file`.
