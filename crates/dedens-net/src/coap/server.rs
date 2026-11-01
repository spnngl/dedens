//! What a CoAP server keeps between messages: the messages it has seen (RFC 7252 §4.5), and the responses it sends in
//! blocks.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use super::block::Block;
use super::exchange::MAX_RETRANSMIT;

/// `EXCHANGE_LIFETIME`: how long a CON message ID may come again, 247 seconds (RFC 7252 §4.8.2).
pub const EXCHANGE_LIFETIME: Duration = Duration::from_secs(247);

/// `NON_LIFETIME`: how long a NON message ID may come again, 145 seconds (RFC 7252 §4.8.2).
pub const NON_LIFETIME: Duration = Duration::from_secs(145);

/// Whether a message is new (RFC 7252 §4.5).
#[derive(Debug, PartialEq, Eq)]
pub enum Seen<'a> {
    /// Not seen within the lifetime: process it, then [`Dedup::reply`] with what was sent back.
    New,
    /// Seen: do not process it again; send the reply to the first one again, if there is one yet and it was not sent
    /// again [`MAX_RETRANSMIT`] times already (D105).
    Duplicate(Option<&'a [u8]>),
}

/// The messages seen from each endpoint, by message ID, for a lifetime ([`EXCHANGE_LIFETIME`] for CON messages,
/// [`NON_LIFETIME`] for NON ones) and at most a number (RFC 7252 §4.5).
///
/// When it is full the oldest message is forgotten even if its lifetime is not over, so a flood of requests
/// weakens the detection of duplicates, never the server's memory.
#[derive(Debug)]
pub struct Dedup {
    lifetime: Duration,
    capacity: NonZeroUsize,
    /// In the order seen, so by time.
    order: VecDeque<((SocketAddr, u16), Instant)>,
    replies: HashMap<(SocketAddr, u16), Entry>,
}

/// What is kept of a message: the reply, once there is one, and how many times it was sent again.
#[derive(Debug, Default)]
struct Entry {
    reply: Option<Vec<u8>>,
    replays: u8,
}

impl Entry {
    /// The reply to send again, counting it: none before there is one, and none past [`MAX_RETRANSMIT`], when the
    /// message is still a duplicate, not processed again, but gets no reply.
    fn replay(&mut self) -> Option<&[u8]> {
        let reply = self.reply.as_deref()?;
        if self.replays >= MAX_RETRANSMIT {
            return None;
        }
        self.replays += 1;
        Some(reply)
    }
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

    /// Tells whether the message `id` from `endpoint` was seen at `now`, without noting it: a caller that may refuse a
    /// new message (it has no room to answer it) [`Dedup::note`]s it only once it takes it, so that the client's
    /// retransmission is asked.
    pub fn lookup(&mut self, endpoint: SocketAddr, id: u16, now: Instant) -> Seen<'_> {
        self.expire(now);
        match self.replies.get_mut(&(endpoint, id)) {
            Some(entry) => Seen::Duplicate(entry.replay()),
            None => Seen::New,
        }
    }

    /// Notes the new message `id` from `endpoint` at `now`; nothing happens if it is noted already.
    pub fn note(&mut self, endpoint: SocketAddr, id: u16, now: Instant) {
        self.expire(now);
        let key = (endpoint, id);
        if self.replies.contains_key(&key) {
            return;
        }
        // Only a new message makes room, so a full table still knows every message it holds.
        while self.order.len() >= self.capacity.get() {
            let Some((oldest, _)) = self.order.pop_front() else {
                break;
            };
            self.replies.remove(&oldest);
        }
        // A key at most once in `order`: it is not in `replies`.
        self.order.push_back((key, now));
        self.replies.insert(key, Entry::default());
    }

    /// [`Dedup::lookup`], then [`Dedup::note`] if the message is new.
    pub fn check(&mut self, endpoint: SocketAddr, id: u16, now: Instant) -> Seen<'_> {
        self.expire(now);
        if !self.replies.contains_key(&(endpoint, id)) {
            self.note(endpoint, id, now);
            return Seen::New;
        }
        self.lookup(endpoint, id, now)
    }

    /// Keeps `reply`, the datagram sent for the message `id` from `endpoint`, to send again for a duplicate.
    ///
    /// Nothing happens if the message is forgotten.
    pub fn reply(&mut self, endpoint: SocketAddr, id: u16, reply: Vec<u8>) {
        if let Some(entry) = self.replies.get_mut(&(endpoint, id)) {
            entry.reply = Some(reply);
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some((key, at)) = self.order.front().copied() {
            if now.saturating_duration_since(at) < self.lifetime {
                break;
            }
            self.order.pop_front();
            self.replies.remove(&key);
        }
    }
}

/// The responses a server is sending in blocks, for the client to ask for the next blocks without the request
/// again: libcoap and aiocoap send a FETCH with its body for the first block only (RFC 8132 §2.5, RFC 7959 §2.4).
///
/// A response is found by the endpoint and the Request-Tag of the request asking for it (RFC 9175 §3.2, empty
/// if there is none), and kept for `lifetime` from the time it is kept, and at most a number: when it is full the
/// oldest is forgotten. Asking for blocks does not keep it longer (D105), nor serve it more than [`Blocks::get`]
/// says.
#[derive(Debug)]
pub struct Blocks {
    lifetime: Duration,
    capacity: NonZeroUsize,
    /// In the order kept, so by time.
    kept: VecDeque<Kept>,
}

/// A response kept for a request.
#[derive(Debug)]
struct Kept {
    endpoint: SocketAddr,
    tag: Box<[u8]>,
    at: Instant,
    response: Vec<u8>,
    /// The bytes of blocks it may still be asked for.
    budget: usize,
}

impl Kept {
    fn is_for(&self, endpoint: SocketAddr, tag: &[u8]) -> bool {
        self.endpoint == endpoint && *self.tag == *tag
    }
}

/// What [`Blocks::get`] finds.
#[derive(Debug, PartialEq, Eq)]
pub enum Found<'a> {
    /// Nothing kept for the request, or kept too long ago.
    Unknown,
    /// Served all it may be: no more is sent, so that a request for blocks costs the server no more than the client
    /// sent it (D105).
    Spent,
    /// The response to cut the block from.
    Response(&'a [u8]),
}

impl Blocks {
    /// Keeps up to `capacity` responses for `lifetime`.
    #[must_use]
    pub fn new(lifetime: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            lifetime,
            capacity,
            kept: VecDeque::new(),
        }
    }

    /// Keeps `response` for the request of `endpoint` tagged `tag` at `now`, in place of the one it kept for them.
    ///
    /// The blocks asked for after the first may add up to `1 + MAX_RETRANSMIT` times its size: the client reading it
    /// whole, and as many times again as it retransmits.
    pub fn keep(&mut self, endpoint: SocketAddr, tag: &[u8], now: Instant, response: Vec<u8>) {
        self.kept.retain(|kept| !kept.is_for(endpoint, tag));
        self.forget(now);
        if self.kept.len() >= self.capacity.get() {
            self.kept.pop_front();
        }
        self.kept.push_back(Kept {
            endpoint,
            tag: tag.into(),
            at: now,
            budget: response
                .len()
                .saturating_mul(1 + usize::from(MAX_RETRANSMIT)),
            response,
        });
    }

    /// The response kept for the request of `endpoint` tagged `tag`, if it is not older than the lifetime at `now`, to
    /// answer the request for the block `requested`.
    ///
    /// The bytes of the block are taken off what the response may still be asked for, whatever the block size: a
    /// client reading 64-byte blocks is served as much as one reading 1024 (a count of blocks would cut it off).
    /// Past the budget, [`Found::Spent`].
    pub fn get(
        &mut self,
        endpoint: SocketAddr,
        tag: &[u8],
        requested: Block,
        now: Instant,
    ) -> Found<'_> {
        self.forget(now);
        let Some(kept) = self.kept.iter_mut().find(|kept| kept.is_for(endpoint, tag)) else {
            return Found::Unknown;
        };
        let served = requested
            .size()
            .bytes()
            .min(kept.response.len().saturating_sub(requested.offset()));
        let Some(left) = kept.budget.checked_sub(served) else {
            return Found::Spent;
        };
        kept.budget = left;
        Found::Response(&kept.response)
    }

    fn forget(&mut self, now: Instant) {
        while let Some(kept) = self.kept.front() {
            if now.saturating_duration_since(kept.at) < self.lifetime {
                break;
            }
            self.kept.pop_front();
        }
    }
}
