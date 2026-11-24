//! Counters through the `metrics` facade (D30, D77, D91, D113), compiled in by the `metrics` feature; without it
//! every method is empty and compiles away.
//!
//! - `dedensd_access_denied_total{action}`: queries of clients the access lists deny, by `refuse` or `drop` (D91).
//!   Named for the daemon, which is where the lists are read; only the core sees the verdict.
//! - `dedensd_rrl_limited_total{action}`: UDP and `DoC` queries of a source over its rate (D113), by `slip` (answered
//!   with TC=1 or BADCOOKIE) or `drop` (not answered).
//! - `dedensd_cookies_total{outcome}`: queries by what they carry (RFC 7873 §5.2, D113): `none` (no COOKIE option),
//!   `client_only`, `invalid` (a Server Cookie that does not verify) or `valid`.
//! - `dedens_validations_total{verdict}`: responses validated, by `secure`, `insecure`, `bogus`,
//!   `indeterminate`, `shed` (the allowance of D77 was spent, or in debt, D106: not validated, or not to the end)
//!   or `shed_share` (the same for the client's network share of it, D117).
//! - `dedens_validation_questions_total`: DS and DNSKEY questions sent upstream for validation, chased names too.
//! - `dedens_validations_parked_total`: client queries that found the allowance of D77 spent and waited for it
//!   (D186); those given up past their wait are counted `shed` too.
//!
//! - `dedensd_authoritative_answers_total{kind}`: answers of the authoritative stage (D208), by where the way from
//!   the name asked ends: `data`, `nodata`, `nxdomain`, `referral`, `yxdomain`, `synthesized` (the CNAME of a
//!   DNAME asked for) or `open` (a chain leaving the zone).
//!
//! Handles are taken once, when the forward stage's validator, the access lists, the rate limit, the cookies or the
//! authoritative stage are built, from the recorder installed then.

use dedens_zone::End;

use crate::access::Denial;
use crate::cookie::Standing;
use crate::rrl::Admission;
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

/// The counters of limited queries.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(crate) struct Limited {
    slipped: metrics::Counter,
    dropped: metrics::Counter,
}

/// The counters of limited queries: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub(crate) struct Limited;

#[cfg(feature = "metrics")]
impl Limited {
    pub(crate) fn new() -> Self {
        const LIMITED: &str = "dedensd_rrl_limited_total";
        metrics::describe_counter!(
            LIMITED,
            "Queries of a source over its rate, by action: slip (TC or BADCOOKIE) or drop."
        );
        Self {
            slipped: metrics::counter!(LIMITED, "action" => "slip"),
            dropped: metrics::counter!(LIMITED, "action" => "drop"),
        }
    }

    pub(crate) fn count(&self, admission: Admission) {
        match admission {
            Admission::Pass => return,
            Admission::Slip => &self.slipped,
            Admission::Drop => &self.dropped,
        }
        .increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
impl Limited {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn count(&self, _: Admission) {}
}

/// The counters of the authoritative stage's answers, by kind.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(crate) struct Answers {
    data: metrics::Counter,
    nodata: metrics::Counter,
    nxdomain: metrics::Counter,
    referral: metrics::Counter,
    yxdomain: metrics::Counter,
    synthesized: metrics::Counter,
    open: metrics::Counter,
    unavailable: metrics::Counter,
}

/// The counters of the authoritative stage's answers: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub(crate) struct Answers;

#[cfg(feature = "metrics")]
impl Answers {
    pub(crate) fn new() -> Self {
        const ANSWERS: &str = "dedensd_authoritative_answers_total";
        metrics::describe_counter!(
            ANSWERS,
            "Answers of the authoritative stage, by kind: data, nodata, nxdomain, referral, yxdomain, synthesized, \
             open, or unavailable (SERVFAIL for a zone without a version)."
        );
        Self {
            data: metrics::counter!(ANSWERS, "kind" => "data"),
            nodata: metrics::counter!(ANSWERS, "kind" => "nodata"),
            nxdomain: metrics::counter!(ANSWERS, "kind" => "nxdomain"),
            referral: metrics::counter!(ANSWERS, "kind" => "referral"),
            yxdomain: metrics::counter!(ANSWERS, "kind" => "yxdomain"),
            synthesized: metrics::counter!(ANSWERS, "kind" => "synthesized"),
            open: metrics::counter!(ANSWERS, "kind" => "open"),
            unavailable: metrics::counter!(ANSWERS, "kind" => "unavailable"),
        }
    }

    /// Counts a SERVFAIL for a zone without a version (D215).
    pub(crate) fn unavailable(&self) {
        self.unavailable.increment(1);
    }

    pub(crate) fn count(&self, end: &End<'_>) {
        match end {
            // Not an answer: the query goes on to the next stage.
            End::NotAuth => return,
            End::Data { .. } => &self.data,
            End::NoData { .. } => &self.nodata,
            End::NxDomain { .. } => &self.nxdomain,
            End::Referral { .. } => &self.referral,
            End::YxDomain { .. } => &self.yxdomain,
            End::Synthesized => &self.synthesized,
            End::Open { .. } => &self.open,
        }
        .increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
impl Answers {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn count(&self, _: &End<'_>) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn unavailable(&self) {}
}

/// The counters of queries by cookie.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub(crate) struct Cookied {
    none: metrics::Counter,
    client_only: metrics::Counter,
    invalid: metrics::Counter,
    valid: metrics::Counter,
}

/// The counters of queries by cookie: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub(crate) struct Cookied;

#[cfg(feature = "metrics")]
impl Cookied {
    pub(crate) fn new() -> Self {
        const COOKIES: &str = "dedensd_cookies_total";
        metrics::describe_counter!(
            COOKIES,
            "Queries by cookie: none, client_only, invalid (Server Cookie) or valid."
        );
        Self {
            none: metrics::counter!(COOKIES, "outcome" => "none"),
            client_only: metrics::counter!(COOKIES, "outcome" => "client_only"),
            invalid: metrics::counter!(COOKIES, "outcome" => "invalid"),
            valid: metrics::counter!(COOKIES, "outcome" => "valid"),
        }
    }

    pub(crate) fn count(&self, standing: Standing) {
        match standing {
            Standing::NoCookie => &self.none,
            Standing::ClientOnly => &self.client_only,
            Standing::Invalid => &self.invalid,
            Standing::Valid => &self.valid,
        }
        .increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
impl Cookied {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn count(&self, _: Standing) {}
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
    shed_share: metrics::Counter,
    questions: metrics::Counter,
    parked: metrics::Counter,
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
        const PARKED: &str = "dedens_validations_parked_total";
        metrics::describe_counter!(
            VALIDATIONS,
            "Responses validated, by verdict: secure, insecure, bogus, indeterminate, shed or shed_share."
        );
        metrics::describe_counter!(
            QUESTIONS,
            "DS and DNSKEY questions sent upstream for validation."
        );
        metrics::describe_counter!(
            PARKED,
            "Client queries that waited for the validation allowance."
        );
        Self {
            secure: metrics::counter!(VALIDATIONS, "verdict" => "secure"),
            insecure: metrics::counter!(VALIDATIONS, "verdict" => "insecure"),
            bogus: metrics::counter!(VALIDATIONS, "verdict" => "bogus"),
            indeterminate: metrics::counter!(VALIDATIONS, "verdict" => "indeterminate"),
            shed: metrics::counter!(VALIDATIONS, "verdict" => "shed"),
            shed_share: metrics::counter!(VALIDATIONS, "verdict" => "shed_share"),
            questions: metrics::counter!(QUESTIONS),
            parked: metrics::counter!(PARKED),
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

    pub(crate) fn shed_share(&self) {
        self.shed_share.increment(1);
    }

    pub(crate) fn parked(&self) {
        self.parked.increment(1);
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

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn shed_share(&self) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn parked(&self) {}
}
