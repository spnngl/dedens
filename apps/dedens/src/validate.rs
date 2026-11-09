//! `+validate` (D76): `dedens` as a validating stub resolver (RFC 4035 §4.9). The server is a transport, never
//! trusted: its AD flag is not read. This is glue over `dedens_dnssec::Validator`, which owns the chain of trust;
//! it asks each question the validation wants, of the server the query went to, and follows a CNAME chain that
//! the response leaves unfinished, validating each answer on its own.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use dedens_dnssec::{Limits, MAX_CHASES, Next, TrustAnchors, Validator, Verdict};
use dedens_proto::edns::{ExtendedError, InfoCode};
use dedens_proto::{Message, Name, Question};
use dedens_scenario::{DnssecReport, DnssecStatus, Options};

/// The validators of a run: one for each set of trust anchors, so that queries with the same share it, and the
/// clock (`DEDENS_NOW`, Unix seconds, for tests).
pub(crate) struct Judges {
    now: Option<u64>,
    built: Vec<(Anchors, Judge)>,
}

/// What a validator is built from: the anchor file and the negative anchors.
type Anchors = (Option<PathBuf>, Vec<Name<'static>>);

impl Judges {
    /// No validator yet; reads `DEDENS_NOW`.
    pub(crate) fn new() -> anyhow::Result<Self> {
        let now = std::env::var("DEDENS_NOW")
            .ok()
            .map(|text| {
                text.parse::<u64>()
                    .with_context(|| format!("DEDENS_NOW={text}"))
            })
            .transpose()?;
        Ok(Self {
            now,
            built: Vec::new(),
        })
    }

    /// The judge of queries asked with `options`: none unless they validate.
    pub(crate) fn of(&mut self, options: &Options) -> anyhow::Result<Option<Judge>> {
        if !options.validating() {
            return Ok(None);
        }
        let key = (
            options.trust_anchor.clone(),
            options.insecure.clone().unwrap_or_default(),
        );
        if let Some((_, judge)) = self.built.iter().find(|(built, _)| *built == key) {
            return Ok(Some(judge.clone()));
        }
        let mut anchors = match &options.trust_anchor {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read {}", path.display()))?;
                TrustAnchors::read(&text).with_context(|| format!("{}", path.display()))?
            }
            None => TrustAnchors::root(),
        };
        for name in &key.1 {
            anchors.add_negative(name.clone());
        }
        let judge = Judge {
            validator: Validator::new(anchors, Limits::default()),
            now: self.now,
        };
        self.built.push((key, judge.clone()));
        Ok(Some(judge))
    }
}

/// A validator and the clock.
#[derive(Clone)]
pub(crate) struct Judge {
    validator: Validator,
    now: Option<u64>,
}

impl Judge {
    /// The verdict on `response`, the answer to `question`. `send` asks a query of the server the question went to.
    pub(crate) async fn judge(
        &self,
        options: &Options,
        question: &Question<'static>,
        response: &Message<'_>,
        send: impl AsyncFn(Message<'static>) -> anyhow::Result<Vec<u8>>,
    ) -> DnssecReport {
        let now = self.now.unwrap_or_else(unix_seconds);
        let verdict = self.run(options, question, response, now, &send).await;
        let verdict = chase(question, verdict, async |question| {
            match send(options.query(question.clone())).await {
                Err(error) => indeterminate(format!("no answer for {}: {error:#}", question.name)),
                Ok(wire) => match Message::decode(&wire) {
                    Err(error) => {
                        indeterminate(format!("unreadable answer for {}: {error}", question.name))
                    }
                    Ok(decoded) => {
                        self.run(options, question, &decoded.message, now, &send)
                            .await
                    }
                },
            }
        })
        .await;
        report(&verdict)
    }

    /// Drives one validation: each question it asks is sent, its response given back, until the verdict.
    async fn run(
        &self,
        options: &Options,
        question: &Question<'static>,
        response: &Message<'_>,
        now: u64,
        send: &impl AsyncFn(Message<'static>) -> anyhow::Result<Vec<u8>>,
    ) -> Verdict {
        let mut validation = self.validator.start(question, response, now);
        loop {
            let ask = match validation.step() {
                Next::Done(verdict) => return verdict,
                Next::Ask(ask) => ask,
            };
            tracing::debug!(name = %ask.name, qtype = %ask.qtype, "validation asks");
            let wire = match send(options.query(ask)).await {
                Ok(wire) => Some(wire),
                Err(error) => {
                    tracing::debug!("no answer: {error:#}");
                    None
                }
            };
            let decoded = wire.as_deref().map(Message::decode).and_then(|decoded| {
                decoded
                    .inspect_err(|error| tracing::debug!("unreadable answer: {error}"))
                    .ok()
            });
            validation.answer(decoded.as_ref().map(|decoded| &decoded.message));
        }
    }
}

/// Follows the CNAME chain `verdict` leaves unfinished, the name it goes on at asked for the type and class of
/// `question` and its verdict that of `validate`, up to [`MAX_CHASES`] names: a verdict that asks for one more is
/// indeterminate (D76).
///
/// Apart from [`Judge::judge`] so that a test can give it the verdicts of a chain longer than the limit, which only
/// signatures make and no capture holds.
async fn chase(
    question: &Question<'static>,
    mut verdict: Verdict,
    validate: impl AsyncFn(&Question<'static>) -> Verdict,
) -> Verdict {
    let mut question = question.clone();
    for _ in 0..MAX_CHASES {
        let Verdict::Incomplete { next, .. } = verdict else {
            return verdict;
        };
        tracing::debug!(%next, "validation follows a CNAME");
        question = Question {
            name: next,
            qtype: question.qtype,
            qclass: question.qclass,
        };
        verdict = validate(&question).await;
    }
    match verdict {
        Verdict::Incomplete { .. } => {
            indeterminate(format!("the CNAME chain is longer than {MAX_CHASES}"))
        }
        verdict => verdict,
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn indeterminate(text: String) -> Verdict {
    Verdict::Indeterminate {
        ede: ExtendedError {
            code: InfoCode::DNSSEC_INDETERMINATE,
            text: text.into(),
        },
    }
}

/// The report of `verdict`: what the user is told, in the words of the report (D76).
fn report(verdict: &Verdict) -> DnssecReport {
    let ede = verdict.ede();
    let (status, reason) = match verdict {
        Verdict::Secure { .. } => (DnssecStatus::Secure, None),
        Verdict::Insecure { reason } => (DnssecStatus::Insecure, Some(reason.to_string())),
        Verdict::Bogus { .. } => (DnssecStatus::Bogus, None),
        Verdict::Indeterminate { .. } => (DnssecStatus::Indeterminate, None),
        // `judge` follows an incomplete verdict, and only `start_referral` gives a referral one.
        Verdict::Incomplete { .. } | Verdict::Referral { .. } => {
            return report(&indeterminate(
                "the validator gave no final verdict".to_owned(),
            ));
        }
    };
    DnssecReport::new(status, ede.as_ref(), reason)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use dedens_proto::{RecordType, Ttl};

    use super::*;

    /// The name the `hop`th CNAME of a chain goes on at.
    fn hop(hop: u8) -> Name<'static> {
        format!("hop{hop}.example.").parse().expect("a name")
    }

    /// What `chase` makes of a chain that goes on for `names` names past the first, each validated incomplete but
    /// the last, secure: the verdict, and the questions it asked.
    fn chased(names: u8) -> (Verdict, Vec<Question<'static>>) {
        let asked = RefCell::new(Vec::new());
        let incomplete = |at| Verdict::Incomplete {
            next: hop(at),
            ttl: Ttl::MAX,
        };
        let validate = async |question: &Question<'static>| {
            asked.borrow_mut().push(question.clone());
            let at = u8::try_from(asked.borrow().len()).expect("a short chain");
            if at < names {
                incomplete(at + 1)
            } else {
                Verdict::Secure { ttl: Ttl::MAX }
            }
        };
        let question = Question::new(hop(0), RecordType::AAAA);
        let verdict = compio::runtime::Runtime::new()
            .expect("a runtime")
            .block_on(chase(&question, incomplete(1), validate));
        (verdict, asked.into_inner())
    }

    /// RFC 1034 §3.6.2, D76: a CNAME chain is followed, [`MAX_CHASES`] names and no more, or a loop of them would
    /// never end: the verdict that asks for one more is indeterminate. Each name is asked for the type first asked.
    #[test]
    fn a_cname_chain_is_chased_up_to_max_chases_names() {
        let names: Vec<_> = (1..=MAX_CHASES)
            .map(|at| Question::new(hop(at), RecordType::AAAA))
            .collect();
        let (verdict, asked) = chased(MAX_CHASES);
        assert!(matches!(verdict, Verdict::Secure { .. }), "{verdict:?}");
        assert_eq!(asked, names);
        let (verdict, asked) = chased(MAX_CHASES + 1);
        let Verdict::Indeterminate { ede } = verdict else {
            panic!("{verdict:?}");
        };
        assert_eq!(ede.code, InfoCode::DNSSEC_INDETERMINATE);
        assert_eq!(asked, names);
    }
}
