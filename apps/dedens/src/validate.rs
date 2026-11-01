//! `+validate` (D76): `dedens` as a validating stub resolver (RFC 4035 §4.9). The server is a transport, never
//! trusted: its AD flag is not read. This is glue over `dedens_dnssec::validator`, which owns the chain of trust;
//! it asks each question the validation wants, of the server the query went to, and follows a CNAME chain that
//! the response leaves unfinished, validating each answer on its own.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::validator::{Limits, Next, Validator, Verdict};
use dedens_proto::edns::{ExtendedError, InfoCode};
use dedens_proto::{Class, Decoded, Message, Name, Question, RecordType};
use dedens_scenario::{DnssecReport, DnssecStatus, Options};

/// The CNAME chains one query follows past its first response, as far as a resolver follows one.
const CHASE: usize = 8;

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
        let mut question = question.clone();
        let mut verdict = self.run(options, &question, response, now, &send).await;
        for hop in 0.. {
            let Verdict::Incomplete { next, .. } = verdict else {
                break;
            };
            if hop == CHASE {
                verdict = indeterminate(format!("the CNAME chain is longer than {CHASE}"));
                break;
            }
            tracing::debug!(%next, "validation follows a CNAME");
            question = Question {
                name: next,
                qtype: question.qtype,
                qclass: question.qclass,
            };
            verdict = match send(options.query(question.clone())).await {
                Err(error) => indeterminate(format!("no answer for {}: {error:#}", question.name)),
                Ok(wire) => match Message::decode(&wire) {
                    Err(error) => {
                        indeterminate(format!("unreadable answer for {}: {error}", question.name))
                    }
                    Ok(decoded) => {
                        self.run(options, &question, &decoded.message, now, &send)
                            .await
                    }
                },
            };
        }
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

/// `decoded` as far as a secure verdict covers it: the answer and authority sections in class IN, without the
/// CNAME a server makes of a DNAME (RFC 6672 §3.1), and without the additional section (D75, RFC 4035 §3.2.3).
pub(crate) fn covered<'a>(decoded: &Decoded<'a>) -> Decoded<'a> {
    let mut covered = decoded.clone();
    let message = &mut covered.message;
    message.additional.clear();
    message.authority.retain(|record| record.class == Class::IN);
    let dnames: Vec<_> = message
        .answer
        .iter()
        .filter(|record| record.rtype() == RecordType::DNAME)
        .map(|record| record.name.clone())
        .collect();
    message.answer.retain(|record| {
        record.class == Class::IN
            && !(record.rtype() == RecordType::CNAME
                && dnames
                    .iter()
                    .any(|dname| record.name != *dname && record.name.is_within(dname)))
    });
    covered
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
    use dedens_proto::Record;

    use super::*;

    /// A DNAME and the CNAME the server synthesizes from it (RFC 6672 §3.1).
    #[test]
    fn what_a_secure_verdict_covers_is_the_signed_data_only() {
        let wire = include_bytes!("../../../crates/dedens-dnssec/tests/testdata/dname_answer.bin");
        let decoded = Message::decode(wire).expect("captured");
        let types = |message: &Message<'_>| -> Vec<RecordType> {
            message.answer.iter().map(Record::rtype).collect()
        };
        assert!(types(&decoded.message).contains(&RecordType::CNAME));
        let covered = covered(&decoded);
        assert!(!types(&covered.message).contains(&RecordType::CNAME));
        assert!(types(&covered.message).contains(&RecordType::DNAME));
        assert_eq!(covered.message.additional.len(), 0);
    }
}
