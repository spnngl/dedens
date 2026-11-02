//! One seed gives one trace in every process (D133): nothing the cores draw per process (hash seeds, counters)
//! shows in what the hosts do. The test runs a scenario with a fault, an attacker and the cache, here and in a
//! second process, a new run of this test binary, and compares the digests of the traces.

use std::io::Write;
use std::process::Command;
use std::time::Duration;

use dedens_proto::RecordType;
use dedens_sim::attacker::{Attacker, Injection};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node};
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::question;
use dedens_sim::topology::Topology;
use dedens_sim::trace;
use dedens_sim::upstream::Answers;

const SEEDS: &[u64] = &[0, 7, 2026];

/// Set to a seed in the second process: it runs that seed, prints the digest of the trace and ends.
const CHILD_VAR: &str = "DEDENS_SIM_PRINT_DIGEST";

const DIGEST_PREFIX: &str = "trace-digest=";

const NAME: &str = "one_seed_gives_one_trace_in_two_processes";

/// The digest of the trace of a run that asks twice (the cache answers the second), with a partition at a time the
/// seed picks and an attacker that repeats each answer on the server's host.
fn digest(seed: Seed) -> u64 {
    let attacker = Attacker::new(|seen| {
        seen.genuine
            .map(|genuine| Injection {
                after: Duration::from_millis(5),
                wire: genuine.to_vec(),
            })
            .into_iter()
            .collect()
    });
    let answers = Answers::new().captured("a").attacked_by(attacker);
    let mut world = Topology::new().upstream(answers).build(seed);
    let at = world.pick(Duration::ZERO, Duration::from_millis(500));
    world.fault(at, Fault::Partition(Node::Resolver, Node::Upstream(0)));
    world.fault(
        at + Duration::from_secs(1),
        Fault::Repair(Node::Resolver, Node::Upstream(0)),
    );
    world.client(async move |stub| {
        for _ in 0..2 {
            stub.ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
        }
        Ok(())
    });
    trace::digest(&world.run().expect("the run passes its checks"))
}

#[test]
fn one_seed_gives_one_trace_in_two_processes() {
    if let Ok(seed) = std::env::var(CHILD_VAR) {
        let seed = Seed(seed.parse().expect("a seed"));
        let mut out = std::io::stdout().lock();
        writeln!(out, "{DIGEST_PREFIX}{:016x}", digest(seed)).expect("stdout is open");
        return;
    }
    let exe = std::env::current_exe().expect("the test binary has a path");
    seed::each(SEEDS, |seed| {
        let output = Command::new(&exe)
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD_VAR, seed.0.to_string())
            .output()
            .expect("the test binary runs");
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let there = stdout
            .lines()
            .find_map(|line| line.strip_prefix(DIGEST_PREFIX))
            .expect("the second process printed its digest");
        assert_eq!(there, format!("{:016x}", digest(seed)), "{stdout}");
    });
}
