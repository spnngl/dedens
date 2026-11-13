//! Names kept in the cache without a client asking (D96): the questions a pipeline is given, and the queries it
//! makes of them. The caller owns the schedule: it asks [`Pipeline::prewarm`] what to do with each question when it
//! is due, and sends the [`Upstream`] it gets as any other.

use std::net::{IpAddr, Ipv6Addr};

use dedens_cache::Refresh;
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::{Class, Flags, Message, Query, Question, Transport};

use super::finish::Refused;
use super::{Pipeline, Purpose, Stage, Upstream};
use crate::validate::Source;

/// Seconds before an entry expires at which it is due, at the latest: a refresh takes the time of a round trip, and
/// the cache's seconds are whole ones, so an entry due at its last second would lapse (D96).
const MARGIN: u32 = 2;

/// Where the server's own validation work is charged from (D117): an address no client has, proven (a client's
/// network that spends its share does not shed prewarm, nor prewarm the clients), so that prewarm spends one
/// network's share of the allowance, and the global one up to it.
const OWN: Source = Source {
    address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    proven: true,
};

/// A question to keep in the cache, as one client query asks it: the cache's keys hold the DO bit (D43), so a name
/// is kept once without DO and, when the forward stage validates, once with it. CD is never set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Warm {
    question: Question<'static>,
    dnssec: bool,
}

impl Warm {
    /// The transport the question is asked over, UDP as most clients do: a truncated response is asked again over TCP
    /// (`dedens_net`'s exchange), so the answer is whole, and the validator's questions are shared with the
    /// clients' (D86).
    pub const TRANSPORT: Transport = Transport::Udp;

    /// The question asked.
    #[must_use]
    pub const fn question(&self) -> &Question<'static> {
        &self.question
    }

    /// Whether the query has DO set.
    #[must_use]
    pub const fn dnssec(&self) -> bool {
        self.dnssec
    }

    /// The query a client would send: RD, DO if [`Warm::dnssec`].
    fn query(&self) -> Option<Vec<u8>> {
        let mut query = Message::query(0, self.question.clone());
        query.header.flags = Flags::RD;
        if self.dnssec {
            query.edns = Some(Edns {
                flags: EdnsFlags::DO,
                ..Edns::default()
            });
        }
        query.to_vec().ok()
    }
}

/// What to do with a [`Warm`] question at second `now`: see [`Pipeline::prewarm`].
#[derive(Debug)]
#[must_use]
pub enum Warmth {
    /// A stage before the cache answers it: a list's own data, nothing to keep.
    Local,
    /// The cache holds a fresh response; ask again at this second: when a prefetch would, or `MARGIN` seconds
    /// before it expires if that is earlier.
    Fresh(u32),
    /// Cannot be asked, whenever: no forward stage after the cache.
    Unaskable,
    /// The allowance of validation is spent, the share of prewarm's or the global one: try again soon.
    Shed,
    /// Send [`Upstream::request`] to [`Upstream::server`] and hand the response to [`Pipeline::receive`], which ends
    /// in [`Step::Drop`](super::Step::Drop): the cache keeps the response, and no failure is held.
    Upstream(Box<Upstream>),
}

/// The second `refresh` is asked again at.
fn due(refresh: Refresh) -> u32 {
    refresh.at.min(refresh.expires.saturating_sub(MARGIN))
}

impl Pipeline {
    /// Keeps `questions` for [`Pipeline::warmed`]: each without DO, and with DO as well when the forward stage
    /// validates a question of class IN (D96, D77).
    #[must_use]
    pub fn with_prewarm(mut self, questions: impl IntoIterator<Item = Question<'static>>) -> Self {
        let checking = self.stages.iter().any(
            |stage| matches!(stage, Stage::Forward(forward) if forward.validation().is_some()),
        );
        self.warmed = questions
            .into_iter()
            .flat_map(|question| {
                let both = checking && question.qclass == Class::IN;
                [false, true]
                    .into_iter()
                    .filter(move |&dnssec| !dnssec || both)
                    .map(move |dnssec| Warm {
                        question: question.clone(),
                        dnssec,
                    })
            })
            .collect();
        self
    }

    /// What [`Pipeline::with_prewarm`] was given, expanded: the queries to keep in the cache.
    #[must_use]
    pub fn warmed(&self) -> &[Warm] {
        &self.warmed
    }

    /// Runs `warm` through the stages as a client's query would, with none of the client's checks: the stages
    /// before the cache answer what they hold ([`Warmth::Local`]), a fresh entry of the cache is left alone and
    /// says when to come back ([`Warmth::Fresh`], not counted a hit nor a use), and otherwise the forward stage's
    /// query is made, over [`Warm::TRANSPORT`], validating if the stage does, with an allowance of the server's own:
    /// a share as of a client network (D96, D117). Each [`Warmth::Upstream`] holds a unit of it, as a client's does.
    pub fn prewarm(&self, warm: &Warm, now: u32) -> Warmth {
        let Some(wire) = warm.query() else {
            return Warmth::Unaskable;
        };
        let Ok(query) = Query::read(&wire) else {
            return Warmth::Unaskable;
        };
        let client = crate::reply::Client::of(&query, Warm::TRANSPORT);
        let mut cache = None;
        for (index, stage) in self.stages.iter().enumerate() {
            match stage {
                Stage::Plugin(plugin) => {
                    if plugin.answer(&query).is_some() {
                        return Warmth::Local;
                    }
                }
                Stage::Cache(kept) => match kept.refresh(&query, now).map(due) {
                    Some(at) if at > now => return Warmth::Fresh(at),
                    _ => cache = Some(index),
                },
                Stage::Forward(_) => {
                    return match self.upstream(index, &query, &client, (OWN, now), cache) {
                        Ok(mut upstream) => {
                            upstream.purpose = Purpose::Prefetch;
                            Warmth::Upstream(upstream)
                        }
                        Err(Refused::Shed) => Warmth::Shed,
                        Err(Refused::NoServer) => Warmth::Unaskable,
                    };
                }
            }
        }
        Warmth::Unaskable
    }

    /// The second to ask `warm` again, from what the cache stage holds for it at `now`: read only, nothing asked and
    /// no allowance spent, to check that a response [`Pipeline::prewarm`] sent was kept. `None` when the cache holds
    /// no fresh answer for it: none came, one the cache does not keep (a TTL of 0, a SERVFAIL), or a bogus one,
    /// which only a client's query stores and SERVFAIL is served from (D77, RFC 4035 §4.7).
    pub fn warm_until(&self, warm: &Warm, now: u32) -> Option<u32> {
        let wire = warm.query()?;
        let query = Query::read(&wire).ok()?;
        let cache = self.stages.iter().find_map(|stage| match stage {
            Stage::Cache(cache) => Some(cache),
            Stage::Plugin(_) | Stage::Forward(_) => None,
        });
        let refresh = cache?.refresh(&query, now)?;
        (!refresh.bogus).then(|| due(refresh))
    }
}
