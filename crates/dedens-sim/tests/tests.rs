//! The simulations of `dedens-sim`, one binary (D162): a module per family of scenarios, each within its own
//! wall-time budget (D133).

mod baseline;
mod crash;
mod dnssec;
mod dot;
mod forged;
mod internet;
mod limits;
mod loss;
mod partition;
mod pools;
mod recurse;
mod recursion;
mod replay;
mod serving;
mod util;
