# dedens-testkit

What the tests, benches and simulations of more than one package share (D161); `src/lib.rs` says
what it holds and the trap of `dedens-proto`'s unit tests. A package reaches another's test code through here, never
by `#[path]`. The shared helpers at the root, a public module per larger concern, each item at one path (D160):
nothing is re-exported.

The responder's delays are wall-clock time, for the tests of the `dedensd` process alone (D161): a test of a library
timer runs on `dedens-sim`'s clock, not against a slow responder.

The integration tests need the feature `recursion` (`required-features`): `cargo test -p dedens-testkit` alone skips
them; the gate's `--all-features` runs them.
