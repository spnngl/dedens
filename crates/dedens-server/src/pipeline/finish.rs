//! Writing the reply: what a response from upstream ends in once known, stored, reviewed and validated (D43, D77,
//! D118; RFC 9520 §3.2 for a failure), and the replies the pipeline makes itself: REFUSED with EDE 18 (RFC 8914
//! §4.19), SERVFAIL, and the slip of a query over its rate (D113, RFC 7873 §5.2.3).

use dedens_cache::{Cache, Checked, Key, StalePolicy};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Decoded, Flags, Header, Message, Query, Rcode, Transport, Ttl};

use super::{Pipeline, Purpose, Step};
use crate::cache::{self, Looked, Read};
use crate::plugin::Answer;
use crate::reply::Client;
use crate::validate::{Outcome, present};

/// Why no upstream query was made for a client's.
pub(super) enum Refused {
    /// The forward stage has no server, or the query no question.
    NoServer,
    /// The allowance of the validating forward stage is spent (D77): SERVFAIL "not ready", nothing held.
    Shed,
}

/// What a response is answered with, and where it goes, once known.
pub(super) struct Finish<'a> {
    pub(super) pipeline: &'a Pipeline,
    pub(super) query: &'a Query<'a>,
    pub(super) client: &'a Client<'a>,
    /// The forward stage the response came from.
    pub(super) forward: usize,
    /// The cache stage before it, if any.
    pub(super) cache: Option<usize>,
    pub(super) purpose: Purpose,
    pub(super) now: u32,
}

impl Finish<'_> {
    /// The cache stage storing the response, if any.
    fn store(&self) -> Option<&Cache> {
        self.cache.and_then(|index| self.pipeline.cache(index))
    }

    /// Ends the query with a response nothing validated (no validator at this forward stage): stored, reviewed and
    /// replied as D118 says.
    pub(super) fn plain(&self, mut decoded: Decoded<'_>, out: &mut [u8]) -> Step {
        let (pipeline, query, client, now) = (self.pipeline, self.query, self.client, self.now);
        // No validator: upstream's AD is its word over a channel we cannot vouch for, never ours (RFC 6840
        // §5.8, RFC 4035 §3.2.3, D114). The cache clears it as well, for a response stored as unchecked.
        decoded.message.header.flags = decoded.message.header.flags.without(Flags::AD);
        // A stored response answers as a hit does, without encoding it again, but not counted a use: a name
        // asked once stays the first evicted (D43). Some are not stored (RFC 2308, D22): the reply goes out all
        // the same.
        // A response a plugin refuses is stored all the same, unmarked, for the hit to refuse again: not
        // storing it would send each repeat upstream. Not when the plugin sits after the cache stage, which a
        // hit does not ask (D118).
        let blocked = pipeline.review(self.forward, query, &decoded.message);
        let keep = blocked
            .as_ref()
            .is_none_or(|&(at, _)| self.cache.is_some_and(|cache| at < cache));
        let mark = if blocked.is_none() { pipeline.id } else { 0 };
        let stored = self
            .store()
            .filter(|cache| keep && cache.insert(query, &decoded, now, mark).is_ok());
        if let Some((_, answer)) = blocked {
            return self.blocked(&answer, out);
        }
        if self.purpose != Purpose::Reply {
            return Step::Drop;
        }
        if let Some(cache) = stored
            && let Looked::Reply { len, .. } =
                cache::look(cache, query, client, now, Read::Stored, out)
        {
            return Step::Reply(len);
        }
        let rcode = decoded.message.rcode();
        reply(client, decoded.message, rcode, out)
    }

    /// Ends the query with the `answer` a plugin gave instead of the response (D118): nothing is stored, and the
    /// client has it unless it was answered already.
    pub(super) fn blocked(&self, answer: &Answer<'_>, out: &mut [u8]) -> Step {
        if self.purpose != Purpose::Reply {
            return Step::Drop;
        }
        self.client
            .answer(self.query.wire(), answer, out)
            .map_or(Step::Drop, Step::Reply)
    }

    /// Ends the query with `outcome` for `decoded`, upstream's answer, its TTLs at most `cap` (D77): stored in the
    /// cache stage with what the verdict made of it, and replied unless the client was answered already.
    pub(super) fn deliver(
        &self,
        outcome: Outcome,
        mut decoded: Decoded<'static>,
        cap: Option<Ttl>,
        out: &mut [u8],
    ) -> Step {
        let checked = match outcome {
            Outcome::Secure => Checked::Secure,
            Outcome::Insecure => Checked::Insecure,
            Outcome::Bogus(code) => Checked::Bogus(code),
            Outcome::Indeterminate(code) => return self.failed(Some(code), out),
        };
        // A refresh that fails validation leaves the entry it refreshes: bad data kept for 60 s must not replace
        // data that is still good, as Unbound keeps it (RFC 4035 §4.7).
        if self.purpose != Purpose::Reply && matches!(checked, Checked::Bogus(_)) {
            return Step::Drop;
        }
        // A bogus response is not reviewed: it is not served, and its copy for clients that check for themselves
        // has no mark, so that a hit reviews it.
        let mark = if matches!(checked, Checked::Bogus(_)) {
            0
        } else if let Some((_, answer)) =
            self.pipeline
                .review(self.forward, self.query, &decoded.message)
        {
            return self.blocked(&answer, out);
        } else {
            self.pipeline.id
        };
        present(&mut decoded.message, outcome, cap, self.client.dnssec());
        let rcode = decoded.message.rcode();
        let stored = self.store().filter(|cache| {
            cache
                .insert_checked(self.query, &decoded, self.now, checked, mark)
                .is_ok()
        });
        if self.purpose != Purpose::Reply {
            return Step::Drop;
        }
        if let Checked::Bogus(code) = checked {
            return servfail(self.client, code, out);
        }
        if let Some(cache) = stored
            && let Looked::Reply { len, .. } =
                cache::look(cache, self.query, self.client, self.now, Read::Stored, out)
        {
            return Step::Reply(len);
        }
        reply(self.client, decoded.message, rcode, out)
    }

    /// Ends the query without a verdict because the allowance is in debt (D106): the reply is SERVFAIL "not ready",
    /// as for a query refused at the start, and nothing is held or stored: the response is not at fault.
    pub(super) fn shed(&self, out: &mut [u8]) -> Step {
        match self.purpose {
            Purpose::Reply => servfail(self.client, InfoCode::NOT_READY, out),
            Purpose::Prefetch | Purpose::Stale => Step::Drop,
        }
    }

    /// Ends the query after the last server failed, or without a verdict, `error` then the reason: the failure is
    /// held in the cache (RFC 9520 §3.2), and the reply is the expired data it keeps, or SERVFAIL with `error`.
    pub(super) fn failed(&self, error: Option<InfoCode>, out: &mut [u8]) -> Step {
        if self.purpose == Purpose::Prefetch {
            return Step::Drop;
        }
        if let Some(index) = self.cache
            && let Some(cache) = self.pipeline.cache(index)
            && let Some(key) = Key::of(self.query)
        {
            cache.fail(&key, self.now);
            if self.purpose == Purpose::Reply
                && let Looked::Reply { len, .. } = self.pipeline.look(
                    index,
                    self.query,
                    self.client,
                    self.now,
                    Read::Lookup(StalePolicy::IfFailing),
                    out,
                )
            {
                return Step::Reply(len);
            }
        }
        match self.purpose {
            Purpose::Reply => self
                .client
                .reply(Message::default(), Rcode::SERVFAIL, error, out)
                .map_or(Step::Drop, Step::Reply),
            Purpose::Prefetch | Purpose::Stale => Step::Drop,
        }
    }
}

/// REFUSED with EDE 18 (Prohibited) to the query `wire`, which is no response and holds a header at least. Allocates
/// nothing for a query that reads, the usual one: the question is copied from the wire. A query that does not read,
/// or has no question, gets a reply of the header alone.
pub(super) fn prohibit(wire: &[u8], transport: Transport, out: &mut [u8]) -> Step {
    let Some(header) = Header::peek(wire).filter(|header| !header.flags.contains(Flags::QR)) else {
        return Step::Drop;
    };
    let query = Query::read(wire);
    let client = match &query {
        Ok(query) => Client::of(query, transport),
        Err(_) => Client::unread(header, transport),
    };
    let refused = Answer {
        rcode: Rcode::REFUSED,
        records: None,
        authoritative: false,
        error: Some(InfoCode::PROHIBITED),
    };
    client
        .answer(wire, &refused, out)
        .or_else(|| {
            client.reply(
                Message::default(),
                Rcode::REFUSED,
                Some(InfoCode::PROHIBITED),
                out,
            )
        })
        .map_or(Step::Drop, Step::Reply)
}

/// SERVFAIL with the extended error `code` (RFC 8914).
pub(super) fn servfail(client: &Client<'_>, code: InfoCode, out: &mut [u8]) -> Step {
    client
        .reply(Message::default(), Rcode::SERVFAIL, Some(code), out)
        .map_or(Step::Drop, Step::Reply)
}

/// The reply to `client`: `message` with `rcode`.
pub(super) fn reply<'a>(
    client: &Client<'a>,
    message: Message<'a>,
    rcode: Rcode,
    out: &mut [u8],
) -> Step {
    client
        .reply(message, rcode, None, out)
        .map_or(Step::Drop, Step::Reply)
}

/// The reply to a query over its rate that is not dropped (D113): BADCOOKIE with a Server Cookie when it had a
/// Client Cookie, which a real client takes to retry with it and then no longer limited (RFC 7873 §5.2.3); else
/// an empty reply with TC=1, which sends it to TCP (RFC 1035 §4.2.1).
pub(super) fn slip(client: &Client<'_>, out: &mut [u8]) -> Step {
    let rcode = if client.cookie.is_some() {
        Rcode::BADCOOKIE
    } else {
        Rcode::NOERROR
    };
    let Some(len) = client.reply(Message::default(), rcode, None, out) else {
        return Step::Drop;
    };
    if client.cookie.is_none()
        && let Some(flags) = out.get_mut(2)
    {
        // The high byte of the flags word: TC is in it.
        *flags |= Flags::TC.bits().to_be_bytes()[0];
    }
    Step::Reply(len)
}
