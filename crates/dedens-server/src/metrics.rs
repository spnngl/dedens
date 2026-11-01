//! Counters through the `metrics` facade (D30, D77, D91), compiled in by the `metrics` feature; without it every
//! method is empty and compiles away.
//!
//! - `dedensd_access_denied_total{action}`: queries of clients the access lists deny, by `refuse` or `drop` (D91).
//!   Named for the daemon, which is where the lists are read; only the core sees the verdict.
//! - `dedens_validations_total{verdict}`: responses validated, by `secure`, `insecure`, `bogus`,
//!   `indeterminate` or `shed` (the allowance of D77 was spent, or in debt, D106: not validated, or not to the end).
//! - `dedens_validation_questions_total`: DS and DNSKEY questions sent upstream for validation, chased names too.
//!
//! Handles are taken once, when the forward stage's validator or the access lists are built, from the recorder
//! installed then.

use crate::access::Denial;
use crate::validate::Outcome;

/// The counter of denied queries.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(crate) struct Denied {
    refused: metrics::Counter,
    dropped: metrics::Counter,
}

/// The counter of denied queries: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub(crate) struct Denied;

#[cfg(feature = "metrics")]
impl Denied {
    pub(crate) fn new() -> Self {
        const DENIED: &str = "dedensd_access_denied_total";
        metrics::describe_counter!(
            DENIED,
            "Queries of clients the access lists deny, by action: refuse or drop."
        );
        Self {
            refused: metrics::counter!(DENIED, "action" => "refuse"),
            dropped: metrics::counter!(DENIED, "action" => "drop"),
        }
    }

    pub(crate) fn count(&self, denial: Denial) {
        match denial {
            Denial::Refuse => &self.refused,
            Denial::Drop => &self.dropped,
        }
        .increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
impl Denied {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn count(&self, _: Denial) {}
}

/// The counters of one validating forward stage.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(crate) struct Metrics {
    secure: metrics::Counter,
    insecure: metrics::Counter,
    bogus: metrics::Counter,
    indeterminate: metrics::Counter,
    shed: metrics::Counter,
    questions: metrics::Counter,
}

/// The counters of one validating forward stage: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub(crate) struct Metrics;

#[cfg(feature = "metrics")]
impl Metrics {
    pub(crate) fn new() -> Self {
        const VALIDATIONS: &str = "dedens_validations_total";
        const QUESTIONS: &str = "dedens_validation_questions_total";
        metrics::describe_counter!(
            VALIDATIONS,
            "Responses validated, by verdict: secure, insecure, bogus, indeterminate or shed."
        );
        metrics::describe_counter!(
            QUESTIONS,
            "DS and DNSKEY questions sent upstream for validation."
        );
        Self {
            secure: metrics::counter!(VALIDATIONS, "verdict" => "secure"),
            insecure: metrics::counter!(VALIDATIONS, "verdict" => "insecure"),
            bogus: metrics::counter!(VALIDATIONS, "verdict" => "bogus"),
            indeterminate: metrics::counter!(VALIDATIONS, "verdict" => "indeterminate"),
            shed: metrics::counter!(VALIDATIONS, "verdict" => "shed"),
            questions: metrics::counter!(QUESTIONS),
        }
    }

    pub(crate) fn outcome(&self, outcome: Outcome) {
        match outcome {
            Outcome::Secure => &self.secure,
            Outcome::Insecure => &self.insecure,
            Outcome::Bogus(_) => &self.bogus,
            Outcome::Indeterminate(_) => &self.indeterminate,
        }
        .increment(1);
    }

    pub(crate) fn question(&self) {
        self.questions.increment(1);
    }

    pub(crate) fn shed(&self) {
        self.shed.increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
impl Metrics {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn outcome(&self, _: Outcome) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn question(&self) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn shed(&self) {}
}
