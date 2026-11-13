//! Names kept in the cache without a client asking (D96): the questions a pipeline is given, and the queries it
//! makes of them. The caller owns the schedule: it asks [`Pipeline::prewarm`] what to do with each question when it
//! is due, and sends the [`Upstream`] it gets as any other.

use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::{Class, Flags, Message, Query, Question, Transport};

use super::{Pipeline, Purpose, Stage, Upstream};

/// A question to keep in the cache, as one client query asks it: the cache's keys hold the DO bit (D43), so a name
/// is kept once without DO and, when the forward stage validates, once with it. CD is never set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Warm {
    question: Question<'static>,
    dnssec: bool,
}

impl Warm {
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
    /// The cache holds a fresh response; ask again at this second, when a prefetch would.
    Fresh(u32),
    /// Cannot be asked: no forward stage after the cache, or the allowance of validation is spent. Try later.
    Refused,
    /// Send [`Upstream::request`] to [`Upstream::server`] and hand the response to [`Pipeline::receive`], which ends
    /// in [`Step::Drop`](super::Step::Drop): the cache keeps the response, and no failure is held.
    Upstream(Box<Upstream>),
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
    /// query is made, validating if the stage does, its share of the allowance none: the server's own (D96).
    pub fn prewarm(&self, warm: &Warm, now: u32) -> Warmth {
        let Some(wire) = warm.query() else {
            return Warmth::Refused;
        };
        let Ok(query) = Query::read(&wire) else {
            return Warmth::Refused;
        };
        // A reliable transport: nothing here is ever truncated for the client, who is nobody.
        let client = crate::reply::Client::of(&query, Transport::Tcp);
        let mut cache = None;
        for (index, stage) in self.stages.iter().enumerate() {
            match stage {
                Stage::Plugin(plugin) => {
                    if plugin.answer(&query).is_some() {
                        return Warmth::Local;
                    }
                }
                Stage::Cache(kept) => match kept.refresh_at(&query, now) {
                    Some(at) if at > now => return Warmth::Fresh(at),
                    _ => cache = Some(index),
                },
                Stage::Forward(_) => {
                    return match self.upstream(index, &query, &client, (None, now), cache) {
                        Ok(mut upstream) => {
                            upstream.purpose = Purpose::Prefetch;
                            Warmth::Upstream(upstream)
                        }
                        Err(_) => Warmth::Refused,
                    };
                }
            }
        }
        Warmth::Refused
    }
}
