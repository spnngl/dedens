# interop

Checks of dedens against implementations that are not ours, run by hand (`just odoh-interop`, D79): they need the
network and tools outside `just check`. Each script's header says what it checks and how to run it; `odoh-rs/` is
its own workspace, with `odoh-rs` pinned from crates.io.
