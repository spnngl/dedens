# edns

EDNS(0) (RFC 6891): the OPT record as `Edns` (owned) and `EdnsView` (in place), and one file per typed option
(D12). An option invalid inside its well-delimited bytes is kept as `Unknown` with a violation (D9).
