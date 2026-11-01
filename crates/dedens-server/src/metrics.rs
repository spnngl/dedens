//! Validation counters through the `metrics` facade (D30, D77), compiled in by the `metrics` feature; without it
//! every method is empty and compiles away.
//!
//! - `dedens_validations_total{verdict}`: responses validated, by `secure`, `insecure`, `bogus` or
//!   `indeterminate`.
//! - `dedens_validation_questions_total`: DS and DNSKEY questions sent upstream for validation, chased names too.
//!
//! Handles are taken once, when the forward stage's validator is built, from the recorder installed then.

use crate::validate::Outcome;

/// The counters of one validating forward stage.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(crate) struct Metrics {
    secure: metrics::Counter,
    insecure: metrics::Counter,
    bogus: metrics::Counter,
    indeterminate: metrics::Counter,
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
            "Responses validated, by verdict: secure, insecure, bogus or indeterminate."
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
}
