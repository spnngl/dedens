//! Upstream questions of the validator in flight, shared between the queries that ask them (D86): the threads of
//! one process validate for many clients, and a cold start or a popular zone makes them ask the same DS and DNSKEY
//! questions at once. One query asks, the others wait for its response.

use std::collections::HashMap;
// Not `sync::Arc`: loom's holds no slice, and the bytes are never written.
use std::sync::Arc;

use dedens_proto::Question;
use dedens_server::Server;

use crate::sync::{self, Mutex, MutexGuard, PoisonError};

/// What makes two questions one: the same question to the same server over the same kind of transport. Over a
/// plain server the client's transport is the upstream's (D65), and a UDP response may be truncated where a TCP
/// one is not.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) server: Server,
    pub(crate) udp: bool,
    pub(crate) question: Question<'static>,
}

/// The response of the query that asked: `None` when it failed for the server's sake (no response), which
/// the others take as they would their own failure.
type Shared = Option<Arc<[u8]>>;

/// The questions in flight, for all threads.
#[derive(Debug, Default)]
pub(crate) struct Flights {
    open: Mutex<HashMap<Key, Vec<sync::Sender<Shared>>>>,
}

/// A query's part in a question in flight.
#[derive(Debug)]
enum Flight<'a> {
    /// Nobody asks it: this query does.
    Lead(Lead<'a>),
    /// Another query asks it: its response comes here, or the channel closes when that query ended without one
    /// (cancelled, or unable to send), and the question is [`Flights::join`]ed again.
    Follow(sync::Receiver<Shared>),
}

/// What a query asking a question does, once it knows whether one is in flight.
#[derive(Debug)]
pub(crate) enum Entered<'a> {
    /// Nobody asks it: this query does, and calls [`Lead::finish`].
    Lead(Lead<'a>),
    /// The response of the query that asked it, `None` when that one failed for the server's sake.
    Shared(Shared),
}

/// The query asking a question in flight.
#[derive(Debug)]
pub(crate) struct Lead<'a> {
    flights: &'a Flights,
    key: Option<Key>,
}

impl Flights {
    /// What a query asking `key` does: asks it, or waits for the response of the query that does. When that query
    /// ended without one (cancelled, or unable to send), the question is joined again, as the first of those left asks
    /// it.
    pub(crate) async fn enter(&self, key: &Key) -> Entered<'_> {
        loop {
            match self.join(key) {
                Flight::Lead(lead) => return Entered::Lead(lead),
                Flight::Follow(response) => {
                    if let Ok(shared) = response.recv_async().await {
                        return Entered::Shared(shared);
                    }
                }
            }
        }
    }

    /// The part of a query asking `key`.
    fn join(&self, key: &Key) -> Flight<'_> {
        let mut open = self.open();
        if let Some(followers) = open.get_mut(key) {
            let (sender, receiver) = sync::slot();
            followers.push(sender);
            return Flight::Follow(receiver);
        }
        open.insert(key.clone(), Vec::new());
        Flight::Lead(Lead {
            flights: self,
            key: Some(key.clone()),
        })
    }

    fn open(&self) -> MutexGuard<'_, HashMap<Key, Vec<sync::Sender<Shared>>>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the flight of `key`, and its followers.
    fn land(&self, key: &Key) -> Vec<sync::Sender<Shared>> {
        self.open().remove(key).unwrap_or_default()
    }
}

impl Lead<'_> {
    /// Ends the flight, with `response` to the followers: call it once the response is in the key cache, so that
    /// a query that follows finds there what it needs. The bytes are copied only if a query follows.
    pub(crate) fn finish(mut self, response: Option<&[u8]>) {
        let Some(key) = self.key.take() else {
            return;
        };
        let followers = self.flights.land(&key);
        let shared: Shared = response.filter(|_| !followers.is_empty()).map(Arc::from);
        for follower in followers {
            // A follower that is gone does not need it; its slot is never full, one message is sent to each.
            let sent = follower.try_send(shared.clone());
            debug_assert!(
                !matches!(sent, Err(sync::TrySendError::Full(_))),
                "a flight sends one message to each follower"
            );
        }
    }
}

impl Drop for Lead<'_> {
    /// Ends the flight without a response: the followers see the channel close.
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            drop(self.flights.land(&key));
        }
    }
}

/// The question of `name` and `qtype` to a plain server over UDP.
#[cfg(test)]
fn key(name: &str, qtype: dedens_proto::RecordType) -> Key {
    use std::net::{Ipv4Addr, SocketAddr};

    Key {
        server: Server {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            via: dedens_server::Via::Plain,
        },
        udp: true,
        question: Question {
            name: name.parse().expect("a name"),
            qtype,
            qclass: dedens_proto::Class::IN,
        },
    }
}

#[cfg(test)]
#[cfg(not(dedens_loom))]
mod tests {
    use std::pin::{Pin, pin};
    use std::task::{Context, Poll, Waker};
    use std::thread;

    use dedens_proto::RecordType;

    use super::*;

    #[test]
    fn the_first_leads_the_others_follow_and_get_its_response() {
        let flights = Flights::default();
        let key = key("example.", RecordType::DNSKEY);
        let Flight::Lead(lead) = flights.join(&key) else {
            panic!("the first query leads");
        };
        let followers: Vec<_> = (0..3)
            .map(|_| match flights.join(&key) {
                Flight::Follow(receiver) => receiver,
                Flight::Lead(_) => panic!("a question in flight is followed"),
            })
            .collect();
        lead.finish(Some(b"response"));
        for follower in followers {
            assert_eq!(
                follower.recv().expect("sent").as_deref(),
                Some(&b"response"[..])
            );
        }
        assert!(
            matches!(flights.join(&key), Flight::Lead(_)),
            "a landed flight is asked again by the next query"
        );
    }

    #[test]
    fn a_failure_is_shared_and_a_dropped_lead_frees_the_followers_to_ask() {
        let flights = Flights::default();
        let key = key("example.", RecordType::DS);
        let Flight::Lead(lead) = flights.join(&key) else {
            panic!("the first query leads");
        };
        let Flight::Follow(failed) = flights.join(&key) else {
            panic!("a question in flight is followed");
        };
        lead.finish(None);
        assert_eq!(failed.recv().expect("sent"), None);

        let Flight::Lead(lead) = flights.join(&key) else {
            panic!("the first query leads");
        };
        let Flight::Follow(cancelled) = flights.join(&key) else {
            panic!("a question in flight is followed");
        };
        drop(lead);
        assert!(cancelled.recv().is_err(), "nothing was sent");
        assert!(matches!(flights.join(&key), Flight::Lead(_)));
    }

    #[test]
    fn questions_of_other_names_types_servers_or_transports_do_not_share() {
        let flights = Flights::default();
        let first = key("example.", RecordType::DS);
        let mut over_tcp = first.clone();
        over_tcp.udp = false;
        let mut elsewhere = first.clone();
        elsewhere.server.addr.set_port(54);
        let keys = [
            first,
            key("example.", RecordType::DNSKEY),
            key("other.", RecordType::DS),
            over_tcp,
            elsewhere,
        ];
        let leads: Vec<_> = keys
            .into_iter()
            .map(|key| match flights.join(&key) {
                Flight::Lead(lead) => lead,
                Flight::Follow(_) => panic!("each is its own flight"),
            })
            .collect();
        assert_eq!(leads.len(), 5);
    }

    #[test]
    fn threads_asking_at_once_share_one_flight() {
        let flights = Arc::new(Flights::default());
        let key = key("example.", RecordType::DNSKEY);
        let Flight::Lead(lead) = flights.join(&key) else {
            panic!("the first query leads");
        };
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (flights, key) = (Arc::clone(&flights), key.clone());
                thread::spawn(move || match flights.join(&key) {
                    Flight::Follow(receiver) => receiver.recv().ok().flatten(),
                    Flight::Lead(_) => None,
                })
            })
            .collect();
        // All of them followed before the lead lands: the map holds the flight until then.
        while flights
            .open()
            .get(&key)
            .is_some_and(|followers| followers.len() < 8)
        {
            thread::yield_now();
        }
        lead.finish(Some(b"response"));
        for thread in threads {
            assert_eq!(
                thread.join().expect("no panic").as_deref(),
                Some(&b"response"[..])
            );
        }
    }

    #[test]
    fn an_entry_takes_the_response_or_asks_again_when_the_lead_is_dropped() {
        let flights = Flights::default();
        let key = key("example.", RecordType::DS);
        let Entered::Lead(lead) = poll_ready(&flights, &key) else {
            panic!("the first query leads");
        };
        let (mut first, mut second) = (pin!(flights.enter(&key)), pin!(flights.enter(&key)));
        assert!(poll(first.as_mut()).is_pending() && poll(second.as_mut()).is_pending());
        drop(lead);
        // The first to see the channel close asks, the other follows it.
        let Poll::Ready(Entered::Lead(lead)) = poll(first.as_mut()) else {
            panic!("a dropped lead is replaced by the first of its followers");
        };
        assert!(poll(second.as_mut()).is_pending());
        lead.finish(Some(b"response"));
        let Poll::Ready(Entered::Shared(shared)) = poll(second.as_mut()) else {
            panic!("a landed flight answers its followers");
        };
        assert_eq!(shared.as_deref(), Some(&b"response"[..]));
    }

    fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// What a query asking `key` does, when nothing is in flight.
    fn poll_ready<'a>(flights: &'a Flights, key: &Key) -> Entered<'a> {
        let Poll::Ready(entered) = poll(pin!(flights.enter(key))) else {
            panic!("nothing to wait for");
        };
        entered
    }
}

/// Every interleaving of the threads that ask one question or two (D135, `just loom`). They end by asking, as
/// `serve/upstream.rs` does, so that a query a flight strands is a deadlock loom reports.
#[cfg(test)]
#[cfg(dedens_loom)]
mod loom_tests {
    use dedens_proto::RecordType;
    use loom::future::block_on;
    use loom::sync::atomic::{AtomicUsize, Ordering};
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    use super::*;
    use crate::sync::model;

    /// A question the threads of a test ask.
    struct Asking {
        key: Key,
        name: &'static str,
        /// The leads of `key` between their asking and their landing: one at most.
        leading: AtomicUsize,
        /// What the leads of `key` sent, each its own bytes, before landing.
        sent: Mutex<Vec<Vec<u8>>>,
    }

    /// What a query got.
    struct Asked {
        led: bool,
        response: Shared,
    }

    impl Asking {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                key: key(name, RecordType::DS),
                name,
                leading: AtomicUsize::new(0),
                sent: Mutex::new(Vec::new()),
            })
        }

        /// The bytes of the next lead, which no other lead of any question sends.
        fn response(&self) -> Vec<u8> {
            let mut sent = self.sent.lock().expect("no panic");
            let response = format!("{}#{}", self.name, sent.len()).into_bytes();
            sent.push(response.clone());
            response
        }

        /// A query as `fetch` in `serve/upstream.rs` makes it: asks, and lands the flight with its own bytes at once, or
        /// takes the response of the query that asks.
        fn ask(&self, flights: &Flights) -> Asked {
            match block_on(flights.enter(&self.key)) {
                Entered::Lead(lead) => {
                    assert_eq!(self.leading.fetch_add(1, Ordering::SeqCst), 0, "two leads");
                    let response = self.response();
                    // Before landing: a query that joins after leads anew, and must find none.
                    self.leading.fetch_sub(1, Ordering::SeqCst);
                    lead.finish(Some(&response));
                    Asked {
                        led: true,
                        response: Some(response.as_slice().into()),
                    }
                }
                Entered::Shared(response) => Asked {
                    led: false,
                    response,
                },
            }
        }

        /// Every response a query that did not lead holds is what a lead of this question sent.
        fn assert_shared(&self, asked: &[Asked]) {
            let sent = self.sent.lock().expect("no panic");
            for response in asked.iter().filter_map(|asked| asked.response.as_deref()) {
                assert!(
                    sent.iter().any(|sent| sent == response),
                    "a response of its own question"
                );
            }
        }
    }

    /// Runs `ask` on a thread of its own.
    fn spawn_ask(flights: &Arc<Flights>, asking: &Arc<Asking>) -> thread::JoinHandle<Asked> {
        let (flights, asking) = (Arc::clone(flights), Arc::clone(asking));
        thread::spawn(move || asking.ask(&flights))
    }

    /// The first query of `asking`, led by the test.
    fn lead<'a>(flights: &'a Flights, asking: &Asking) -> Lead<'a> {
        match flights.join(&asking.key) {
            Flight::Lead(lead) => lead,
            Flight::Follow(_) => panic!("the first query leads"),
        }
    }

    /// Three queries of one key, in any order: one leads while the others are in flight, and each gets the bytes
    /// of a lead; one that comes after the flight landed leads anew, and no two lead at once.
    #[test]
    fn queries_of_one_key_share_the_response_of_their_lead() {
        model(|| {
            let flights = Arc::new(Flights::default());
            let asking = Asking::new("example.");
            let others = [spawn_ask(&flights, &asking), spawn_ask(&flights, &asking)];
            let mut asked = vec![asking.ask(&flights)];
            asked.extend(
                others
                    .into_iter()
                    .map(|other| other.join().expect("no panic")),
            );
            assert!(asked.iter().any(|asked| asked.led), "someone asked");
            assert!(
                asked.iter().all(|asked| asked.response.is_some()),
                "each got a response"
            );
            asking.assert_shared(&asked);
            assert!(flights.open().is_empty(), "every flight landed");
        });
    }

    /// A lead dropped without finishing: each follower sees the channel close, and one of them leads on rejoin,
    /// the other taking its response, or leading in turn.
    #[test]
    fn a_dropped_lead_frees_its_followers_and_one_asks_again() {
        model(|| {
            let flights = Arc::new(Flights::default());
            let asking = Asking::new("example.");
            let lead = lead(&flights, &asking);
            let followers = [spawn_ask(&flights, &asking), spawn_ask(&flights, &asking)];
            drop(lead);
            let asked: Vec<_> = followers
                .into_iter()
                .map(|follower| follower.join().expect("no panic"))
                .collect();
            // The dropped lead sent nothing: a response is one a rejoined query led.
            assert!(
                asked.iter().any(|asked| asked.led),
                "one of them asked again"
            );
            assert!(
                asked.iter().all(|asked| asked.response.is_some()),
                "each got a response"
            );
            asking.assert_shared(&asked);
            assert!(flights.open().is_empty(), "every flight landed");
        });
    }

    /// A lead that fails for the server's sake lands with no response, which a follower takes as its own failure; one
    /// that comes after leads anew.
    #[test]
    fn a_failed_lead_gives_its_followers_no_response() {
        model(|| {
            let flights = Arc::new(Flights::default());
            let asking = Asking::new("example.");
            let lead = lead(&flights, &asking);
            let follower = spawn_ask(&flights, &asking);
            lead.finish(None);
            let asked = follower.join().expect("no panic");
            assert_eq!(
                asked.led,
                asked.response.is_some(),
                "no response unless it led"
            );
            asking.assert_shared(&[asked]);
            assert!(flights.open().is_empty(), "every flight landed");
        });
    }

    /// A query racing the landing of a flight takes its response or leads anew; one that comes once it landed leads
    /// anew.
    #[test]
    fn a_join_after_the_flight_landed_leads_anew() {
        model(|| {
            let flights = Arc::new(Flights::default());
            let asking = Asking::new("example.");
            let lead = lead(&flights, &asking);
            let racing = spawn_ask(&flights, &asking);
            lead.finish(Some(&asking.response()));
            let asked = racing.join().expect("no panic");
            assert!(asked.response.is_some());
            asking.assert_shared(&[asked]);
            assert!(
                matches!(flights.join(&asking.key), Flight::Lead(_)),
                "nothing is in flight any more"
            );
        });
    }

    /// A follower gone before the lead lands, as a cancelled query is, costs the lead and the others nothing.
    #[test]
    fn a_follower_that_goes_does_not_stop_the_lead() {
        model(|| {
            let flights = Arc::new(Flights::default());
            let asking = Asking::new("example.");
            let lead = lead(&flights, &asking);
            let Flight::Follow(going) = flights.join(&asking.key) else {
                panic!("a question in flight is followed");
            };
            let leaving = thread::spawn(move || drop(going));
            let staying = spawn_ask(&flights, &asking);
            lead.finish(Some(&asking.response()));
            leaving.join().expect("no panic");
            let asked = staying.join().expect("no panic");
            assert!(asked.response.is_some());
            asking.assert_shared(&[asked]);
            assert!(flights.open().is_empty(), "every flight landed");
        });
    }

    /// Questions of two keys in flight together: each query gets the bytes of a lead of its own key.
    #[test]
    fn two_keys_never_mix() {
        model(|| {
            let flights = Arc::new(Flights::default());
            let (one, two) = (Asking::new("one."), Asking::new("two."));
            let (first, second) = (lead(&flights, &one), lead(&flights, &two));
            let (asking_one, asking_two) = (spawn_ask(&flights, &one), spawn_ask(&flights, &two));
            first.finish(Some(&one.response()));
            second.finish(Some(&two.response()));
            let (asked_one, asked_two) = (
                asking_one.join().expect("no panic"),
                asking_two.join().expect("no panic"),
            );
            one.assert_shared(&[asked_one]);
            two.assert_shared(&[asked_two]);
        });
    }
}
