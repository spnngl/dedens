//! Targets of dedens-roots: a fresh copy of the root hints and of the TLD list (D126).

use dedens_roots::{RootHints, Tlds};

/// Arbitrary bytes as root hints: `RootHints::read` answers, and hints it reads have a root server with an address.
///
/// # Panics
///
/// On a panic of `dedens-roots`, or on hints without an address.
pub fn parse_root_hints(data: &[u8]) {
    if let Ok(hints) = RootHints::read(data) {
        assert!(
            hints
                .servers()
                .iter()
                .any(|server| server.addresses().next().is_some()),
            "hints read without an address"
        );
    }
}

/// Arbitrary bytes as a `tlds.json`: `Tlds::read` answers, and each TLD of a list it reads is what a lookup of its
/// name finds.
///
/// # Panics
///
/// On a panic of `dedens-roots`, or on a TLD a lookup misses.
pub fn parse_tlds_json(data: &[u8]) {
    let Ok(tlds) = Tlds::read(data) else {
        return;
    };
    for tld in &tlds {
        assert_eq!(tlds.get(tld.name()), Some(tld), "{}", tld.name());
    }
}
