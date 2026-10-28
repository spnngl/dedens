//! Writes the zone of `benches/zone.rs` to stdout, for the benches outside Rust (`unbound/`).

use std::io::Write as _;

use dedens_bench::{ZONE_HOSTS, zone};

fn main() -> std::io::Result<()> {
    std::io::stdout()
        .lock()
        .write_all(zone(ZONE_HOSTS).as_bytes())
}
