//! Inputs shared by the benches of `dedens-proto` against other DNS libraries (D14): the Rust ones in
//! `benches/`, the Go `miekg/dns` (the codec of `CoreDNS`) in `go/`, Unbound's C codec in `unbound/`.

/// Captured responses, smallest to largest: one A record; MX records with their A glue; a TXT answer of
/// 1.2 kB.
pub const CASES: [&str; 3] = ["a", "mx", "txt_large"];

/// The captured response `case` from `crates/dedens-proto/tests/testdata/`.
///
/// # Panics
///
/// When the file cannot be read: the benches have nothing to measure.
#[must_use]
#[expect(
    clippy::panic,
    reason = "a bench without its input has nothing to measure"
)]
pub fn wire(case: &str) -> Vec<u8> {
    let path = format!(
        "{}/../dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("captured response {path}: {e}"))
}

/// Hosts in the benched zone: about three records each, so about 100 000 records.
pub const ZONE_HOSTS: u32 = 33_334;

/// A zone file of `hosts` hosts under `example.`, about three records each: what a large authoritative zone or a
/// local data file looks like. It has a SOA first, `$TTL`, relative names, owners left out and a mix of A, AAAA,
/// MX, TXT, CNAME and SRV. TTLs are plain seconds, as `domain` does not read units such as `1h`, and come before
/// the class, as Unbound does not read the other order RFC 1035 §5.1 allows.
#[must_use]
pub fn zone(hosts: u32) -> String {
    let mut text = String::from(concat!(
        "$ORIGIN example.\n",
        "$TTL 3600\n",
        "@ IN SOA ns1 hostmaster (\n",
        "    2026102701 ; serial\n",
        "    7200 900 1209600 300 )\n",
        "  NS ns1\n",
        "  NS ns2.example.net.\n",
        "ns1 A 192.0.2.53\n",
    ));
    for i in 0..hosts {
        let [_, _, a, b] = i.to_be_bytes();
        let line = match i % 4 {
            0 => format!(
                "h{i} A 10.0.{a}.{b}\n  AAAA 2001:db8::{i:x}\n  MX 10 mail\n  TXT \"host {i}\" \"v=1\"\n"
            ),
            1 => format!("h{i} 300 A 10.1.{a}.{b}\n  A 10.2.{a}.{b}\n"),
            2 => format!(
                "www.h{i} CNAME h{}\n_sip._tcp.h{i} SRV 10 60 5060 h{i}\n  TXT text\\032with\\\"escapes\\\"\n",
                i - 1
            ),
            _ => format!("h{i} 600 IN AAAA 2001:db8:1::{i:x}\n  A 10.3.{a}.{b}\n  MX 20 mx.h{i}\n"),
        };
        text.push_str(&line);
    }
    text
}
