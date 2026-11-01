//! What a CoAP server keeps between messages: the CON messages it has seen (RFC 7252 §4.5).

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// `EXCHANGE_LIFETIME`: how long a CON message ID may come again, 247 seconds (RFC 7252 §4.8.2).
pub const EXCHANGE_LIFETIME: Duration = Duration::from_secs(247);

/// Whether a CON message is new (RFC 7252 §4.5).
#[derive(Debug, PartialEq, Eq)]
pub enum Seen<'a> {
    /// Not seen within the lifetime: process it, then [`Dedup::reply`] with what was sent back.
    New,
    /// Seen: do not process it again; send the reply to the first one again, if there is one yet.
    Duplicate(Option<&'a [u8]>),
}

/// The CON messages seen from each endpoint, by message ID, for [`EXCHANGE_LIFETIME`] and at most a number
/// (RFC 7252 §4.5).
///
/// When it is full the oldest message is forgotten even if its lifetime is not over, so a flood of requests
/// weakens the detection of duplicates, never the server's memory.
#[derive(Debug)]
pub struct Dedup {
    lifetime: Duration,
    capacity: NonZeroUsize,
    /// In the order seen, so by time.
    order: VecDeque<((SocketAddr, u16), Instant)>,
    replies: HashMap<(SocketAddr, u16), Option<Vec<u8>>>,
}

impl Dedup {
    /// Keeps up to `capacity` messages for `lifetime`.
    #[must_use]
    pub fn new(lifetime: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            lifetime,
            capacity,
            order: VecDeque::new(),
            replies: HashMap::new(),
        }
    }

    /// Notes the CON message `id` from `endpoint` at `now`, and tells whether it was seen.
    pub fn check(&mut self, endpoint: SocketAddr, id: u16, now: Instant) -> Seen<'_> {
        while let Some((key, at)) = self.order.front().copied() {
            if now.saturating_duration_since(at) < self.lifetime
                && self.order.len() < self.capacity.get()
            {
                break;
            }
            self.order.pop_front();
            self.replies.remove(&key);
        }
        let key = (endpoint, id);
        if self.replies.contains_key(&key) {
            return Seen::Duplicate(self.replies.get(&key).and_then(Option::as_deref));
        }
        // A key at most once in `order`: it is not in `replies`.
        self.order.push_back((key, now));
        self.replies.insert(key, None);
        Seen::New
    }

    /// Keeps `reply`, the datagram sent for the message `id` from `endpoint`, to send again for a duplicate.
    ///
    /// Nothing happens if the message is forgotten.
    pub fn reply(&mut self, endpoint: SocketAddr, id: u16, reply: Vec<u8>) {
        if let Some(slot) = self.replies.get_mut(&(endpoint, id)) {
            *slot = Some(reply);
        }
    }
}
