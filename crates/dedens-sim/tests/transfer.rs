//! `dedensd`'s serving loop sending a zone transfer (D214): the AXFR of the captured root zone (RFC 5936 §2.2), 86
//! messages, read by `dedens-net`'s transfer client (D210) over a TCP connection with the seed's latencies, by a
//! client that reads as fast as it can and by one that pauses before each message. Each gets the zone whole: the
//! loop makes a message when its writer has room, whatever the pace of the reader.

use std::sync::Arc;
use std::time::Duration;

use dedens_net::transfer::stream::{Asked, Reader, Step as Read};
use dedens_net::transfer::{self, Limits, Transfer};
use dedens_proto::{Name, RecordType, Ttl};
use dedens_server::{Action, Authoritative, Grant, Pipeline, Stage, ZoneAccess};
use dedens_sim::{framing, seed};
use dedens_zone::{Source, Zone};

use crate::util::SEEDS;

/// The ID of the request.
const ID: u16 = 0x0b0e;

/// The step of the simulation, and the pause of the slow reader before each message: the 86 messages take it 8.6 s,
/// within `TCP_WRITE` (10 s) for each.
const TICK: Duration = Duration::from_millis(10);
const PAUSE: Duration = Duration::from_millis(100);

/// The captured root zone, records without a TTL at `dedensd`'s 3600 seconds (D208).
fn root() -> Arc<Zone> {
    let text =
        std::fs::read(dedens_testkit::path("authoritative/zones/root.zone")).expect("the zone");
    let source = Source {
        name: "root.zone",
        text: &text,
        default_ttl: Some(Ttl::from_wire(3600)),
    };
    let mut include = |_: &str| Err("no $INCLUDE".to_owned());
    let loaded = Zone::load(
        Name::root(),
        source,
        &mut include,
        &dedens_zone::Limits::default(),
    );
    Arc::new(loaded.expect("the zone loads").zone)
}

/// An authoritative stage serving `zone`, its transfers open to every client.
fn primary(zone: &Arc<Zone>) -> Pipeline {
    let networks = [
        "0.0.0.0/0".parse().expect("a network"),
        "::/0".parse().expect("a network"),
    ];
    let access = ZoneAccess::default().with(Action::Transfer, [Grant::new(networks, None)]);
    let stage = Authoritative::guarded([(Arc::clone(zone), access)]).expect("one zone");
    Pipeline::new(vec![Stage::Authoritative(stage)])
}

#[test]
fn rfc5936_2_2_the_root_zone_is_transferred_whole_to_a_fast_and_a_slow_reader() {
    let zone = root();
    seed::each(SEEDS, |seed| {
        let served = Arc::clone(&zone);
        let mut world = dedens_sim::topology::Topology::new()
            .resolver(move |_| primary(&served))
            .dedensd()
            .tick(TICK)
            .build(seed);
        let resolver = world.resolver;
        for pause in [Duration::ZERO, PAUSE] {
            let records = zone.record_count();
            world.client(async move |_| {
                let mut stream = turmoil::net::TcpStream::connect(resolver).await?;
                let request = transfer::query(&Name::root(), RecordType::AXFR, None, ID);
                framing::write(&mut stream, &request).await?;
                let asked = Asked::Axfr(None);
                let mut reader = Reader::new(Name::root(), ID, asked, None, &Limits::default());
                let transfer = loop {
                    tokio::time::sleep(pause).await;
                    let message = framing::read(&mut stream).await?;
                    match reader.message(&message, 0)? {
                        Read::More(more) => reader = more,
                        Read::Done(transfer) => break transfer,
                    }
                };
                let Transfer::Full(loaded) = transfer else {
                    return Err(format!("not the whole zone: {transfer:?}").into());
                };
                assert_eq!(loaded.zone.record_count(), records);
                Ok(())
            });
        }
        world.run().expect("the run passes its checks");
    });
}
