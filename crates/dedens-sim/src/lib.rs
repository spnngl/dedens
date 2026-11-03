//! Simulation tests (D133): the sans-IO cores of the client, `dedens_net::exchange`, and of the server,
//! `dedens_server::Pipeline`, driven over [turmoil](https://docs.rs/turmoil)'s simulated UDP and TCP by a
//! test-only driver, under a seed. Lost, late, reordered and forged packets, partitions and crashes meet the real
//! exchange, pipeline and cache; a failing run replays with `DEDENS_SIM_SEED=<n>`.
//!
//! The driver mirrors `dedensd`'s glue, `apps/dedensd/src/serve.rs`, and runs `dedens-net`'s own client on the
//! simulated network (D134): the [`client`] on [`io::Sim`], the [`resolver`] host, the [`upstream`] and [`dot`]
//! hosts; [`topology`] builds a run, [`stub`] checks its queries, and [`trace`] records it.

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]

pub mod attacker;
pub mod client;
pub mod dot;
pub mod fault;
pub mod framing;
pub mod io;
pub mod oracle;
mod port;
pub mod resolver;
pub mod seed;
pub mod stub;
pub mod topology;
pub mod trace;
pub mod upstream;
