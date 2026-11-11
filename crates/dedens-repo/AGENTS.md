# dedens-repo

The repository checks (D140, D163), in the gate through `just check`'s tests: `tests/repo.rs` reads the tracked
files (`git ls-files`), so a new file is checked once it is added. A new check is a function of text, run once on a
small broken input beside the tree's. `std` only.
