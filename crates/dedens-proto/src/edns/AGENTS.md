# edns

EDNS(0) (RFC 6891): the OPT record as `Edns` (owned) and `EdnsView` (in place), and the typed options (D12): a
file for each with a type of its own, an arm of `EdnsOption` for the others (D159). An option invalid inside its
well-delimited bytes is kept as `Unknown` with a violation (D9).
