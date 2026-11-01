//! Upstream questions of the validator in flight, shared between the queries that ask them (D86): the threads of
//! one process validate for many clients, and a cold start or a popular zone makes them ask the same DS and DNSKEY
//! questions at once. One query asks, the others wait for its response.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use dedens_proto::Question;
use dedens_server::Server;

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
    open: Mutex<HashMap<Key, Vec<flume::Sender<Shared>>>>,
}

/// A query's part in a question in flight.
#[derive(Debug)]
pub(crate) enum Flight<'a> {
    /// Nobody asks it: this query does, and calls [`Lead::finish`].
    Lead(Lead<'a>),
    /// Another query asks it: its response comes here, or the channel closes when that query ended without one
    /// (cancelled, or unable to send), and the question is [`Flights::join`]ed again.
    Follow(flume::Receiver<Shared>),
}

/// The query asking a question in flight.
#[derive(Debug)]
pub(crate) struct Lead<'a> {
    flights: &'a Flights,
    key: Option<Key>,
}

impl Flights {
    /// The part of a query asking `key`.
    pub(crate) fn join(&self, key: Key) -> Flight<'_> {
        let mut open = self.open();
        if let Some(followers) = open.get_mut(&key) {
            let (sender, receiver) = flume::bounded(1);
            followers.push(sender);
            return Flight::Follow(receiver);
        }
        open.insert(key.clone(), Vec::new());
        Flight::Lead(Lead {
            flights: self,
            key: Some(key),
        })
    }

    fn open(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Vec<flume::Sender<Shared>>>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ends the flight of `key`, and its followers.
    fn land(&self, key: &Key) -> Vec<flume::Sender<Shared>> {
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
            // A follower that is gone does not need it.
            let _ = follower.send(shared.clone());
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::thread;

    use dedens_proto::{Class, RecordType};
    use dedens_server::Via;

    use super::*;

    fn key(name: &str, qtype: RecordType) -> Key {
        Key {
            server: Server {
                addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
                via: Via::Plain,
            },
            udp: true,
            question: Question {
                name: name.parse().expect("a name"),
                qtype,
                qclass: Class::IN,
            },
        }
    }

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
}
