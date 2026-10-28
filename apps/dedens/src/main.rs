//! `dedens`: a dig-like DNS client (D18, D32).
//!
//! Exit codes (D33): 0 a response came, whatever its rcode; 1 an expectation failed; 2 usage; 9 no reply; 10 any
//! other error.

#![forbid(unsafe_code)]

mod args;
mod idn;
mod output;
mod run;
mod trace;

use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = args::Cli::parse_dig(std::env::args_os());
    run::run(&cli).unwrap_or_else(|error| {
        eprintln!("dedens: {error:#}");
        ExitCode::from(10)
    })
}
