//! Names kept answered in the cache without a client (D96): the pipeline lists the questions (`prewarm` of a cache
//! stage), this task asks each when its entry is due a refresh, through the whole pipeline as a client's query goes.
//!
//! One task of one thread runs it, so a name is asked once whatever the threads: the cache is shared. Its queries
//! are [`IN_FLIGHT`] at most at a time, so a long list leaves the rest of the thread's upstream queries (D47) to
//! clients. The refresh point is the cache's (`Cache::refresh_at`), in the seconds of its clock (D43): a name whose
//! TTL is a few seconds may expire before it is asked again.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::Cache;
use dedens_net::io::Io;
use dedens_proto::Transport;
use dedens_server::{Pipeline, Stage, Warm, Warmth};
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;

use super::upstream::answer;
use super::{Thread, pause};

/// Prewarm queries by result: `ok` for an answer now kept, `error` for one that was not.
const QUERIES: &str = "dedensd_prewarm_queries_total";

/// The most prewarm queries in flight: 16 of a thread's 1024 upstream queries (D47) keep the list's share small, and
/// at the 20 ms an upstream answers in, ask 800 names a second.
const IN_FLIGHT: usize = 16;

/// How long after a failure the name is asked again, doubled by each further failure up to the cache's
/// `failure_max`: the first retry of RFC 9520 §3.2's holds for clients, at the minute.
const RETRY: u32 = 60;

/// How long the task sleeps with nothing to do, so that a reload is seen within it.
const TICK: Duration = Duration::from_secs(1);

/// Describes the metrics of this module.
pub(crate) fn describe() {
    metrics::describe_counter!(
        QUERIES,
        "Questions asked to keep names in the cache, by result: ok when the answer is kept, error when it is not."
    );
}

/// Keeps `thread`'s pipeline's `prewarm` names answered, until the end of the thread.
pub(super) async fn run<N: Io>(thread: Rc<Thread<N>>) {
    let schedule = RefCell::new(Schedule::default());
    let mut asking = FuturesUnordered::new();
    loop {
        let pipeline = thread.pipeline();
        let now = thread.now();
        schedule
            .borrow_mut()
            .follow(thread.generation(), &pipeline, now);
        while asking.len() < IN_FLIGHT {
            let Some((warm, epoch)) = schedule.borrow_mut().next(now) else {
                break;
            };
            let (thread, pipeline) = (&thread, Rc::clone(&pipeline));
            asking.push(async move {
                let outcome = ask(thread, &pipeline, &warm).await;
                (warm, epoch, outcome)
            });
        }
        if asking.is_empty() {
            pause(&thread.io, TICK).await;
            continue;
        }
        let deadline = thread.io.now() + TICK;
        if let Ok(Some((warm, epoch, outcome))) =
            thread.io.timeout_at(deadline, asking.next()).await
        {
            match outcome {
                Outcome::Asked(_) => metrics::counter!(QUERIES, "result" => "ok").increment(1),
                Outcome::Failed => metrics::counter!(QUERIES, "result" => "error").increment(1),
                Outcome::Local | Outcome::Fresh(_) | Outcome::Busy => {}
            }
            schedule
                .borrow_mut()
                .finish(&warm, epoch, outcome, thread.now());
        }
    }
}

/// What came of asking one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// A stage before the cache answers it, or no stage asks for it: nothing to keep.
    Local,
    /// The cache holds it, to be refreshed at that time: nothing was asked.
    Fresh(u32),
    /// Asked, and the cache holds the answer now, to be refreshed at that time.
    Asked(u32),
    /// Asked, and the cache does not hold an answer: no answer, or one that is not kept.
    Failed,
    /// No upstream query left to ask with.
    Busy,
}

/// Asks for `warm` if its entry is due, through `pipeline`, and says whether the cache holds it then.
async fn ask<N: Io>(thread: &Thread<N>, pipeline: &Pipeline, warm: &Warm) -> Outcome {
    let upstream = match pipeline.prewarm(warm, thread.now()) {
        Warmth::Local | Warmth::Refused => return Outcome::Local,
        Warmth::Fresh(at) => return Outcome::Fresh(at),
        Warmth::Upstream(upstream) => upstream,
    };
    let Some(_slot) = thread.upstream.take() else {
        return Outcome::Busy;
    };
    // Over TCP, so that the answer is whole: the cache keeps it as it is and truncates what a UDP client gets.
    answer(
        thread,
        pipeline,
        upstream,
        Transport::Tcp,
        async |_reply| {},
    )
    .await;
    match pipeline.prewarm(warm, thread.now()) {
        Warmth::Fresh(at) => Outcome::Asked(at),
        _ => Outcome::Failed,
    }
}

/// A name and when it is asked again.
#[derive(Debug)]
struct Entry {
    warm: Warm,
    /// When to ask, `None` while a stage answers it, or it is being asked.
    due: Option<u32>,
    /// Asks failed in a row.
    failures: u32,
    /// A query is in flight.
    asking: bool,
}

/// When each name is asked again: a schedule that lasts as long as its cache does.
#[derive(Debug, Default)]
struct Schedule {
    /// The generation of the pipeline the entries are of.
    generation: Option<u64>,
    /// The cache they fill: another one is empty, and each name is asked at once.
    cache: Option<Arc<Cache>>,
    /// Longest wait to ask a failed name again.
    failure_max: u32,
    /// Bumped by a new cache, so that the queries in flight for the old one are not heard.
    epoch: u64,
    entries: Vec<Entry>,
    index: HashMap<Warm, usize>,
    /// The entries to ask, by time, with their place in `entries`.
    queue: BTreeSet<(u32, usize)>,
}

impl Schedule {
    /// Takes the names of `pipeline`, of `generation`, after a reload: the schedule of those still listed stays
    /// while the cache does, new ones are asked at once, removed ones are dropped.
    fn follow(&mut self, generation: u64, pipeline: &Pipeline, now: u32) {
        if self.generation == Some(generation) {
            return;
        }
        self.generation = Some(generation);
        let cache = pipeline.stages().iter().find_map(|stage| match stage {
            Stage::Cache(cache) => Some(cache),
            _ => None,
        });
        self.failure_max = cache.map_or(RETRY, |cache| cache.config().failure_max);
        let kept = match (&self.cache, cache) {
            (Some(old), Some(new)) => Arc::ptr_eq(old, new),
            _ => false,
        };
        self.cache = cache.cloned();
        let mut old: HashMap<Warm, Entry> = if kept {
            self.entries
                .drain(..)
                .map(|entry| (entry.warm.clone(), entry))
                .collect()
        } else {
            self.epoch += 1;
            HashMap::new()
        };
        self.entries.clear();
        self.index.clear();
        self.queue.clear();
        for warm in pipeline.warmed() {
            let mut entry = old.remove(warm).unwrap_or_else(|| Entry {
                warm: warm.clone(),
                due: Some(now),
                failures: 0,
                asking: false,
            });
            // A name a stage answered may not be any more.
            if entry.due.is_none() && !entry.asking {
                entry.due = Some(now);
            }
            let place = self.entries.len();
            self.index.insert(warm.clone(), place);
            if let Some(due) = entry.due {
                self.queue.insert((due, place));
            }
            self.entries.push(entry);
        }
    }

    /// The name most overdue at `now`, taken to be asked, with the epoch it is asked in.
    fn next(&mut self, now: u32) -> Option<(Warm, u64)> {
        let &(due, place) = self.queue.first()?;
        if due > now {
            return None;
        }
        self.queue.pop_first();
        let entry = &mut self.entries[place];
        entry.due = None;
        entry.asking = true;
        Some((entry.warm.clone(), self.epoch))
    }

    /// Takes what came of asking `warm` in `epoch`, at `now`.
    fn finish(&mut self, warm: &Warm, epoch: u64, outcome: Outcome, now: u32) {
        if epoch != self.epoch {
            return;
        }
        let Some(&place) = self.index.get(warm) else {
            return;
        };
        let entry = &mut self.entries[place];
        entry.asking = false;
        let due = match outcome {
            Outcome::Local => None,
            // At least a second on: a TTL too short for a refresh point is asked once a second, not in a loop.
            Outcome::Fresh(at) | Outcome::Asked(at) => {
                entry.failures = 0;
                Some(at.max(now.saturating_add(1)))
            }
            Outcome::Failed => {
                entry.failures = entry.failures.saturating_add(1);
                let wait = RETRY
                    .saturating_mul(1 << entry.failures.saturating_sub(1).min(20))
                    .min(self.failure_max.max(1));
                Some(now.saturating_add(wait))
            }
            Outcome::Busy => Some(now.saturating_add(1)),
        };
        entry.due = due;
        if let Some(due) = due {
            self.queue.insert((due, place));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::read;
    use crate::lists::Store;

    /// A pipeline of a cache with `cache` lines of settings that prewarms `entries`, read after `previous`.
    fn pipeline(entries: &str, cache: &str, previous: &Pipeline) -> Pipeline {
        let text = format!(
            "listen: ['127.0.0.1:0']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n{cache}    prewarm:\n      entries: [{entries}]\n      types: [A]\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
        );
        read(&text, |_| None, previous, &mut Store::default())
            .expect("a configuration")
            .pipeline
    }

    /// The names of `schedule` due at `now`, taken to be asked.
    fn taken(schedule: &mut Schedule, now: u32) -> Vec<String> {
        let mut names = Vec::new();
        while let Some((warm, _)) = schedule.next(now) {
            names.push(warm.question().name.to_string());
        }
        names.sort();
        names
    }

    #[test]
    fn each_name_is_taken_once_at_the_start() {
        let mut schedule = Schedule::default();
        schedule.follow(
            1,
            &pipeline("a.example, b.example", "", &Pipeline::default()),
            0,
        );
        assert_eq!(taken(&mut schedule, 0), ["a.example.", "b.example."]);
        assert_eq!(taken(&mut schedule, 100), Vec::<String>::new());
    }

    #[test]
    fn a_failure_is_retried_after_a_minute_then_two_up_to_the_cache_failure_max() {
        let mut schedule = Schedule::default();
        schedule.follow(
            1,
            &pipeline("a.example", "    failure_max: 100\n", &Pipeline::default()),
            0,
        );
        let mut at = 0;
        let mut waits = Vec::new();
        for _ in 0..4 {
            let (warm, epoch) = schedule.next(at).expect("due");
            schedule.finish(&warm, epoch, Outcome::Failed, at);
            let wait = (at..=at + 1000)
                .find(|now| schedule.queue.first().is_some_and(|&(due, _)| due <= *now))
                .expect("a retry")
                - at;
            waits.push(wait);
            at += wait;
        }
        assert_eq!(waits, [60, 100, 100, 100]);
    }

    #[test]
    fn a_reload_keeps_the_schedule_of_the_names_still_listed_while_the_cache_stays() {
        let first = pipeline("a.example, b.example", "", &Pipeline::default());
        let mut schedule = Schedule::default();
        schedule.follow(1, &first, 0);
        for _ in 0..2 {
            let (warm, epoch) = schedule.next(0).expect("due");
            schedule.finish(&warm, epoch, Outcome::Fresh(500), 0);
        }
        // `b.example` is dropped, `c.example` added: only it is asked at once.
        let second = pipeline("a.example, c.example", "", &first);
        schedule.follow(2, &second, 10);
        assert_eq!(taken(&mut schedule, 10), ["c.example."]);
        assert_eq!(taken(&mut schedule, 500), ["a.example."]);
    }

    #[test]
    fn a_replaced_cache_has_every_name_asked_again() {
        let first = pipeline("a.example, b.example", "", &Pipeline::default());
        let mut schedule = Schedule::default();
        schedule.follow(1, &first, 0);
        for _ in 0..2 {
            let (warm, epoch) = schedule.next(0).expect("due");
            schedule.finish(&warm, epoch, Outcome::Fresh(500), 0);
        }
        let second = pipeline("a.example, b.example", "    min_ttl: 5\n", &first);
        schedule.follow(2, &second, 10);
        assert_eq!(taken(&mut schedule, 10), ["a.example.", "b.example."]);
    }

    #[test]
    fn what_a_query_of_an_older_cache_found_is_not_heard() {
        let first = pipeline("a.example", "", &Pipeline::default());
        let mut schedule = Schedule::default();
        schedule.follow(1, &first, 0);
        let (warm, epoch) = schedule.next(0).expect("due");
        let second = pipeline("a.example", "    min_ttl: 5\n", &first);
        schedule.follow(2, &second, 1);
        schedule.finish(&warm, epoch, Outcome::Fresh(500), 1);
        assert_eq!(taken(&mut schedule, 1), ["a.example."]);
    }
}
