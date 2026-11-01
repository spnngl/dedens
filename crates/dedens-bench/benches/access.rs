//! The access lists (D91) in a table of 10 000 networks: the verdict on an address, in the table or not, IPv4, IPv6
//! and IPv4-mapped, and `Pipeline::query` for a denied client, REFUSED before any stage, without allocating.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::{Edns, Message, Question, RecordType};
use dedens_server::{Access, Denial, Network, Pipeline, Step, Transport};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// Networks in the table: 8 000 IPv4 `/24` of `10.0.0.0/8` and 2 000 IPv6 `/48` of `2001:db8::/32`, allowed but
/// for every tenth, denied.
const NETWORKS: u32 = 10_000;

fn main() {
    divan::main();
}

fn access(denial: Denial) -> Access {
    let network = |text: String| text.parse::<Network>().expect("a network");
    let (mut allow, mut deny) = (Vec::new(), Vec::new());
    for i in 0..NETWORKS {
        let text = if i < 8_000 {
            format!("{}/24", Ipv4Addr::from(0x0A00_0000 + (i << 8)))
        } else {
            format!(
                "{}/48",
                Ipv6Addr::new(
                    0x2001,
                    0xdb8,
                    u16::try_from(i - 8_000).expect("fits"),
                    0,
                    0,
                    0,
                    0,
                    0
                )
            )
        };
        if i % 10 == 9 { &mut deny } else { &mut allow }.push(network(text));
    }
    Access::new(allow, deny, denial)
}

/// Addresses: allowed in the table, denied in it, IPv6 in it, IPv4-mapped in it, and in no network.
const ADDRESSES: [(&str, bool); 5] = [
    ("10.7.100.9", true),
    ("10.7.97.9", false),
    ("2001:db8:1f4::1", true),
    ("::ffff:10.7.100.9", true),
    ("192.0.2.1", false),
];

#[divan::bench(args = ADDRESSES)]
fn permits(bencher: divan::Bencher<'_, '_>, (address, expected): (&str, bool)) {
    let access = access(Denial::Refuse);
    let address: IpAddr = address.parse().expect("an address");
    bencher.bench_local(|| assert_eq!(access.permits(black_box(address)), expected));
}

/// The query of a denied client: REFUSED with EDE 18, made before any stage, with no allocation.
#[divan::bench]
fn denied_query(bencher: divan::Bencher<'_, '_>) {
    let pipeline = Pipeline::default().with_access(access(Denial::Refuse));
    let name = "www.example.com.".parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, RecordType::A));
    query.edns = Some(Edns::default());
    let query = query.to_vec().expect("a query fits");
    let from = IpAddr::from([192, 0, 2, 1]);
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(black_box(&query), Transport::Udp, from, 0, &mut out);
        assert!(matches!(step, Step::Reply(_)));
    });
}
