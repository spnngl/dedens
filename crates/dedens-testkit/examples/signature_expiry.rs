//! Says when the signatures of the captures of `testdata/recursion/` end, run by `just captures-expiry` (D188, D197):
//! the tests validate them at their own time, so this is no failure, it is the age after which `just
//! recapture-signed` is due.
//!
//! Prints each capture with the days from now to the earliest end of validity of its RRSIGs, the earliest first,
//! then the line to read: the days left of the earliest of all, negative once past.

use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_testkit::recursion::Resolution;

/// Seconds in a day.
const DAY: i64 = 86_400;

fn main() -> Result<(), Box<dyn Error>> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let days = |end: u32| (i64::from(end) - now).div_euclid(DAY);
    let mut expiries: Vec<(String, u32)> = Resolution::all()
        .into_iter()
        .filter_map(|(id, resolution)| Some((id, resolution.earliest_expiration()?)))
        .collect();
    expiries.sort_by_key(|(_, end)| *end);
    for (id, end) in &expiries {
        println!("{:>5} days  {id}", days(*end));
    }
    let (id, end) = expiries.first().ok_or("no signed capture")?;
    println!(
        "earliest: {} days left ({id}); `just recapture-signed` before",
        days(*end)
    );
    Ok(())
}
