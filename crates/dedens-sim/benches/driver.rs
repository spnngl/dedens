//! What the driver costs for one run (D133, D164), under seed 0: one client asks `example.com A` over UDP of a
//! resolver forwarding to one upstream server. `answered`: the server answers, so the run is its fixed cost, the hosts,
//! the pipeline and its cache built and one exchange. `silent`: the server never does, so the query runs through the
//! resolver's tries, 6 s of simulated time that turmoil steps a millisecond at a time: the waits that make a scenario
//! long.
//! The families' own times, in `just check`'s debug build, are `just sim-time`'s. Run with
//! `cargo bench -p dedens-sim --bench driver`; numbers go to `docs/benchmarks.md`.

use std::time::Duration;

use dedens_proto::RecordType;
use dedens_sim::client::Carrier;
use dedens_sim::seed::Seed;
use dedens_sim::stub::question;
use dedens_sim::topology::Topology;
use dedens_sim::upstream::Answers;

fn main() {
    divan::main();
}

/// The run, and how long it lasted in simulated time.
fn run(answers: Answers) -> Duration {
    let mut world = Topology::new().upstream(answers).build(Seed(0));
    world.client(async |stub| {
        stub.ask(question("example.com", RecordType::A), Carrier::Udp)
            .await?;
        Ok(())
    });
    let events = world.run().expect("the run passes its checks");
    events.last().map(|event| event.at).unwrap_or_default()
}

#[divan::bench]
fn answered() -> Duration {
    run(Answers::new().captured("a"))
}

#[divan::bench]
fn silent() -> Duration {
    run(Answers::new().captured("a").silent())
}
