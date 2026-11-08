# dedens-scenario

Query files and reports (D34, D36, D37), described in `src/lib.rs`. No I/O and no validation: callers read the file,
run the queries and validate (`apps/dedens`, D76); this crate describes what they asked for and checks what came
back.
