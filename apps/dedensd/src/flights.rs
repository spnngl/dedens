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
            match self.join(key.clone()) {
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
    fn join(&self, key: Key) -> Flight<'_> {
        let mut open = self.open();
        if let Some(followers) = open.get_mut(&key) {
            let (sender, receiver) = sync::slot();
            followers.push(sender);
            return Flight::Follow(receiver);
        }
        open.insert(key.clone(), Vec::new());
        Flight::Lead(Lead {
            flights: self,
            key: Some(key),
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
            let _ = follower.try_send(shared.clone());
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
        let Flight::Lead(lead) = flights.join(key.clone()) else {
            panic!("the first query leads");
        };
        let followers: Vec<_> = (0..3)
            .map(|_| match flights.join(key.clone()) {
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
            matches!(flights.join(key), Flight::Lead(_)),
            "a landed flight is asked again by the next query"
        );
    }

    #[test]
    fn a_failure_is_shared_and_a_dropped_lead_frees_the_followers_to_ask() {
        let flights = Flights::default();
        let key = key("example.", RecordType::DS);
        let Flight::Lead(lead) = flights.join(key.clone()) else {
            panic!("the first query leads");
        };
        let Flight::Follow(failed) = flights.join(key.clone()) else {
            panic!("a question in flight is followed");
        };
        lead.finish(None);
        assert_eq!(failed.recv().expect("sent"), None);

        let Flight::Lead(lead) = flights.join(key.clone()) else {
            panic!("the first query leads");
        };
        let Flight::Follow(cancelled) = flights.join(key.clone()) else {
            panic!("a question in flight is followed");
        };
        drop(lead);
        assert!(cancelled.recv().is_err(), "nothing was sent");
        assert!(matches!(flights.join(key), Flight::Lead(_)));
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
            .map(|key| match flights.join(key) {
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
        let Flight::Lead(lead) = flights.join(key.clone()) else {
            panic!("the first query leads");
        };
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (flights, key) = (Arc::clone(&flights), key.clone());
                thread::spawn(move || match flights.join(key) {
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

/// Every interleaving of the threads that ask one question or two (D135, `just loom`); they end by asking, as
/// `serve.rs` does, so that a query a flight strands is a deadlock loom reports.
#[cfg(test)]
#[cfg(dedens_loom)]
mod loom_tests {
    use dedens_proto::RecordType;
    use loom::future::block_on;
    use loom::sync::atomic::AtomicUsize;
    use loom::thread;

    use super::*;
    use crate::sync::{Arc as Shares, Ordering};

    /// A question the threads of a test ask, and the response its lead sends.
    struct Asking {
        key: Key,
        response: &'static [u8],
        /// The leads of `key` at this moment: one at most.
        leads: AtomicUsize,
    }

    /// What a query got.
    struct Asked {
        led: bool,
        response: Shared,
    }

    impl Asking {
        fn new(name: &str, response: &'static [u8]) -> Shares<Self> {
            Shares::new(Self {
                key: key(name, RecordType::DS),
                response,
                leads: AtomicUsize::new(0),
            })
        }

        /// A query as `fetch` in `serve.rs` makes it: asks, and lands the flight with the response at once, or
        /// takes the response of the query that asks.
        fn ask(&self, flights: &Flights) -> Asked {
            match block_on(flights.enter(&self.key)) {
                Entered::Lead(lead) => {
                    assert_eq!(self.leads.fetch_add(1, Ordering::SeqCst), 0, "two leads");
                    // Before landing: a query that joins after leads anew, and must find none.
                    self.leads.fetch_sub(1, Ordering::SeqCst);
                    lead.finish(Some(self.response));
                    Asked {
                        led: true,
                        response: Some(Arc::from(self.response)),
                    }
                }
                Entered::Shared(response) => Asked {
                    led: false,
                    response,
                },
            }
        }
    }

    /// Runs `ask` on a thread of its own.
    fn spawn_ask(flights: &Shares<Flights>, asking: &Shares<Asking>) -> thread::JoinHandle<Asked> {
        let (flights, asking) = (Shares::clone(flights), Shares::clone(asking));
        thread::spawn(move || asking.ask(&flights))
    }

    /// Three queries of one key, in any order: one leads while the others are in flight, and each gets its response;
    /// one that comes after the flight landed leads anew, and no two lead at once.
    #[test]
    fn queries_of_one_key_share_one_response() {
        loom::model(|| {
            let flights = Shares::new(Flights::default());
            let asking = Asking::new("example.", b"response");
            let others = [spawn_ask(&flights, &asking), spawn_ask(&flights, &asking)];
            let mut asked = vec![asking.ask(&flights)];
            asked.extend(
                others
                    .into_iter()
                    .map(|other| other.join().expect("no panic")),
            );
            assert!(asked.iter().any(|asked| asked.led), "someone asked");
            for asked in asked {
                assert_eq!(asked.response.as_deref(), Some(asking.response));
            }
            assert!(flights.open().is_empty(), "every flight landed");
        });
    }

    /// A lead dropped without finishing: each follower sees the channel close, and one of them leads on rejoin,
    /// the other taking its response, or leading in turn.
    #[test]
    fn a_dropped_lead_frees_its_followers_and_one_asks_again() {
        loom::model(|| {
            let flights = Shares::new(Flights::default());
            let asking = Asking::new("example.", b"response");
            let Flight::Lead(lead) = flights.join(asking.key.clone()) else {
                panic!("the first query leads");
            };
            let followers = [spawn_ask(&flights, &asking), spawn_ask(&flights, &asking)];
            drop(lead);
            let asked: Vec<_> = followers
                .into_iter()
                .map(|follower| follower.join().expect("no panic"))
                .collect();
            assert!(
                asked.iter().any(|asked| asked.led),
                "the dropped lead sent nothing: one of them asked"
            );
            for asked in asked {
                assert_eq!(asked.response.as_deref(), Some(asking.response));
            }
            assert!(flights.open().is_empty(), "every flight landed");
        });
    }

    /// A query racing the landing of a flight takes its response or leads anew; one that comes once it landed leads
    /// anew.
    #[test]
    fn a_join_after_the_flight_landed_leads_anew() {
        loom::model(|| {
            let flights = Shares::new(Flights::default());
            let asking = Asking::new("example.", b"response");
            let Flight::Lead(lead) = flights.join(asking.key.clone()) else {
                panic!("the first query leads");
            };
            let racing = spawn_ask(&flights, &asking);
            lead.finish(Some(asking.response));
            let asked = racing.join().expect("no panic");
            assert_eq!(asked.response.as_deref(), Some(asking.response));
            assert!(
                matches!(flights.join(asking.key.clone()), Flight::Lead(_)),
                "nothing is in flight any more"
            );
        });
    }

    /// Questions of two keys in flight together: each query gets the response of its own key, the leads being of
    /// both at once.
    #[test]
    fn two_keys_never_mix() {
        loom::model(|| {
            let flights = Shares::new(Flights::default());
            let (one, two) = (Asking::new("one.", b"one"), Asking::new("two.", b"two"));
            let (Flight::Lead(first), Flight::Lead(second)) =
                (flights.join(one.key.clone()), flights.join(two.key.clone()))
            else {
                panic!("the first query of each key leads");
            };
            let (asking_one, asking_two) = (spawn_ask(&flights, &one), spawn_ask(&flights, &two));
            first.finish(Some(one.response));
            second.finish(Some(two.response));
            let (asked_one, asked_two) = (
                asking_one.join().expect("no panic"),
                asking_two.join().expect("no panic"),
            );
            assert_eq!(asked_one.response.as_deref(), Some(one.response));
            assert_eq!(asked_two.response.as_deref(), Some(two.response));
        });
    }
}
