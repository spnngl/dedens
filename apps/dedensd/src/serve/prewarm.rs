//! Names kept answered in the cache without a client (D96): the pipeline lists the questions (`prewarm` of a cache
//! stage), this task asks each when its entry is due a refresh, through the whole pipeline as a client's query goes.
//!
//! One task of one thread runs it, so a name is asked once whatever the threads: the cache is shared. Its queries
//! are [`IN_FLIGHT`] at most at a time, so a long list leaves the rest of the thread's upstream queries (D47) to
//! clients. The refresh point is the cache's (`Cache::refresh`, [`Pipeline::prewarm`]), in the seconds of its clock
//! (D43). The task sleeps until the next one, or a reload (D107), and follows the reloads in the place of
//! [`super::follow`], which the thread does not run beside it: both would take the same wake-up.

use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dedens_cache::Cache;
use dedens_net::io::Io;
use dedens_server::{Pipeline, Stage, Warm, Warmth};
use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;

use super::Thread;
use super::upstream::answer;

/// Prewarm queries by result: `ok` for an answer now kept, `error` for one that was not.
const QUERIES: &str = "dedensd_prewarm_queries_total";

/// The most prewarm queries in flight: 16 of a thread's 1024 upstream queries (D47) keep the list's share small, and
/// at the 20 ms an upstream answers in, ask 800 names a second.
const IN_FLIGHT: usize = 16;

/// How long after a failure the name is asked again, doubled by each further failure up to the cache's
/// `failure_max`: the first retry of RFC 9520 §3.2's holds for clients, at the minute.
const RETRY: u32 = 60;

/// Describes the metrics of this module.
pub(crate) fn describe() {
    metrics::describe_counter!(
        QUERIES,
        "Questions asked to keep names in the cache, by result: ok when the answer is kept, error when it is not."
    );
}

/// Keeps `thread`'s pipeline's `prewarm` names answered, until the end of the thread.
pub(super) async fn run<N: Io>(thread: Rc<Thread<N>>) {
    let mut schedule = Schedule::default();
    let mut asking = FuturesUnordered::new();
    loop {
        let pipeline = thread.pipeline();
        let now = thread.now();
        schedule.follow(thread.generation(), &pipeline, now);
        while room(asking.len()) {
            let Some((warm, epoch)) = schedule.next(now) else {
                break;
            };
            let (thread, pipeline) = (&thread, Rc::clone(&pipeline));
            asking.push(async move {
                let outcome = ask(thread, &pipeline, &warm).await;
                (warm, epoch, outcome)
            });
        }
        // Not held while waiting: the thread would keep the pipeline a reload replaced (D107).
        drop(pipeline);
        // Full, only an end frees a place; else the next name due is the next thing to do.
        let due = if room(asking.len()) {
            schedule.due()
        } else {
            None
        };
        let deadline = due.map(|due| thread.started + Duration::from_secs(u64::from(due)));
        if asking.is_empty() {
            wait_for_reload(&thread, deadline).await;
            continue;
        }
        let ended = match deadline {
            Some(deadline) => thread
                .io
                .timeout_at(deadline, asking.next())
                .await
                .ok()
                .flatten(),
            None => asking.next().await,
        };
        if let Some((warm, epoch, outcome)) = ended {
            if let Some(result) = outcome.result() {
                metrics::counter!(QUERIES, "result" => result).increment(1);
            }
            schedule.finish(&warm, epoch, outcome, thread.now());
        }
    }
}

/// Whether another query may be in flight beside the `asking` ones.
const fn room(asking: usize) -> bool {
    asking < IN_FLIGHT
}

/// Returns when a reload replaced the pipeline, or at `deadline`; at no time if there is none and no reload.
async fn wait_for_reload<N: Io>(thread: &Thread<N>, deadline: Option<Instant>) {
    let reloaded = async {
        // Disconnected: no reload will come.
        if thread.reloads.recv_async().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    match deadline {
        Some(deadline) => {
            let _ = thread.io.timeout_at(deadline, reloaded).await;
        }
        None => reloaded.await,
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
    /// Asked, and the cache does not hold an answer: no answer, or one that is not kept; a bogus one is not either.
    Failed,
    /// No upstream query left to ask with, or the allowance of validation spent: asked again at once.
    Busy,
}

impl Outcome {
    /// The `result` of the metric for what was asked, `None` if nothing was.
    const fn result(self) -> Option<&'static str> {
        match self {
            Self::Asked(_) => Some("ok"),
            Self::Failed => Some("error"),
            Self::Local | Self::Fresh(_) | Self::Busy => None,
        }
    }
}

/// Asks for `warm` if its entry is due, through `pipeline`, and says whether the cache holds it then.
async fn ask<N: Io>(thread: &Thread<N>, pipeline: &Pipeline, warm: &Warm) -> Outcome {
    // Before the pipeline: its query takes a unit of the validator's allowance, which a name left unasked would waste.
    let Some(_slot) = thread.upstream.take() else {
        return Outcome::Busy;
    };
    let upstream = match pipeline.prewarm(warm, thread.now()) {
        Warmth::Local | Warmth::Unaskable => return Outcome::Local,
        Warmth::Fresh(at) => return Outcome::Fresh(at),
        Warmth::Shed => return Outcome::Busy,
        Warmth::Upstream(upstream) => upstream,
    };
    answer(
        thread,
        pipeline,
        upstream,
        Warm::TRANSPORT,
        async |_reply| {},
    )
    .await;
    // Read only: asking again would spend the allowance once more, to find an entry that is there.
    pipeline
        .warm_until(warm, thread.now())
        .map_or(Outcome::Failed, Outcome::Asked)
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

    /// When the first name is due, `None` if none waits.
    fn due(&self) -> Option<u32> {
        self.queue.first().map(|&(due, _)| due)
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
        // A name taken out and listed again while its query was in flight is another entry, queued already.
        if !entry.asking {
            return;
        }
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
            let wait = schedule.due().expect("a retry") - at;
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

    #[test]
    fn only_what_was_asked_counts_and_by_its_result() {
        assert_eq!(Outcome::Asked(5).result(), Some("ok"));
        assert_eq!(Outcome::Failed.result(), Some("error"));
        for nothing in [Outcome::Local, Outcome::Fresh(5), Outcome::Busy] {
            assert_eq!(nothing.result(), None, "{nothing:?}");
        }
    }

    #[test]
    fn the_next_name_due_is_the_time_to_wake_for() {
        let mut schedule = Schedule::default();
        assert_eq!(schedule.due(), None);
        schedule.follow(
            1,
            &pipeline("a.example, b.example", "", &Pipeline::default()),
            7,
        );
        assert_eq!(schedule.due(), Some(7));
        let (warm, epoch) = schedule.next(7).expect("due");
        schedule.finish(&warm, epoch, Outcome::Fresh(500), 7);
        let (warm, epoch) = schedule.next(7).expect("due");
        schedule.finish(&warm, epoch, Outcome::Fresh(300), 7);
        assert_eq!(schedule.due(), Some(300));
    }

    #[test]
    fn a_busy_name_is_asked_in_a_second_with_no_failure_counted() {
        let mut schedule = Schedule::default();
        schedule.follow(1, &pipeline("a.example", "", &Pipeline::default()), 0);
        let (warm, epoch) = schedule.next(0).expect("due");
        schedule.finish(&warm, epoch, Outcome::Busy, 10);
        assert_eq!(schedule.due(), Some(11));
        assert_eq!(schedule.entries[0].failures, 0);
    }

    /// A name taken out and listed again while its query is in flight is a new entry, due at once and queued once: the
    /// end of the old query neither moves it nor queues it twice.
    #[test]
    fn the_end_of_a_query_for_a_name_listed_again_is_not_heard() {
        let first = pipeline("a.example", "", &Pipeline::default());
        let mut schedule = Schedule::default();
        schedule.follow(1, &first, 0);
        let (warm, epoch) = schedule.next(0).expect("due");
        let without = pipeline("", "", &first);
        schedule.follow(2, &without, 1);
        let again = pipeline("a.example", "", &without);
        schedule.follow(3, &again, 2);
        schedule.finish(&warm, epoch, Outcome::Fresh(500), 3);
        assert_eq!(taken(&mut schedule, 3), ["a.example."]);
        assert_eq!(taken(&mut schedule, 1000), Vec::<String>::new());
    }

    /// The serving tasks describe the metric, through `serve::describe` that `main` calls.
    #[test]
    fn the_counter_is_described() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            super::super::describe();
            metrics::counter!(QUERIES, "result" => "ok").increment(1);
        });
        let described = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .any(|(key, _, description, _)| key.key().name() == QUERIES && description.is_some());
        assert!(described);
    }

    #[test]
    fn no_more_than_the_queries_in_flight_are_asked_at_once() {
        assert!(room(IN_FLIGHT - 1));
        assert!(!room(IN_FLIGHT));
    }

    /// The end of a query of an older cache is not heard even for a name asked again since: the new entry is in flight
    /// too, so only the epoch tells the two queries apart.
    #[test]
    fn the_end_of_an_older_query_does_not_end_the_one_of_the_new_cache() {
        let first = pipeline("a.example", "", &Pipeline::default());
        let mut schedule = Schedule::default();
        schedule.follow(1, &first, 0);
        let (old, old_epoch) = schedule.next(0).expect("due");
        let second = pipeline("a.example", "    min_ttl: 5\n", &first);
        schedule.follow(2, &second, 1);
        let (_, epoch) = schedule.next(1).expect("due");
        assert_ne!(epoch, old_epoch);
        schedule.finish(&old, old_epoch, Outcome::Fresh(500), 2);
        assert_eq!(schedule.due(), None, "the new query is still in flight");
    }

    /// A name a stage answered (`Local`) is asked again after a reload, the stage may not answer it any more.
    #[test]
    fn a_name_a_stage_answered_is_asked_again_after_a_reload() {
        let first = pipeline("a.example", "", &Pipeline::default());
        let mut schedule = Schedule::default();
        schedule.follow(1, &first, 0);
        let (warm, epoch) = schedule.next(0).expect("due");
        schedule.finish(&warm, epoch, Outcome::Local, 0);
        assert_eq!(schedule.due(), None);
        let second = pipeline("a.example", "", &first);
        schedule.follow(2, &second, 5);
        assert_eq!(taken(&mut schedule, 5), ["a.example."]);
    }
}
