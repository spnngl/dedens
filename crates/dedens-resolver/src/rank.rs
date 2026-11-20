//! How far the resolver trusts an `RRset`, from where it was read (RFC 2181 §5.4.1): [`scrub()`](crate::scrub())
//! gives the rank, the [`RrsetCache`](crate::RrsetCache) reads it to decide what replaces what.

/// How far an `RRset` is trusted, from where it was read: RFC 2181 §5.4.1, least trusted first, so that a greater
/// rank replaces a lesser one.
///
/// The RFC puts the additional section of an authoritative answer and the authority and additional sections of a
/// non-authoritative one at one level; they are three here, as in Unbound (`rrset_trust`): authoritative data first,
/// then the authority section over the additional. The ranks of zone data (a primary zone, a transfer, their glue)
/// are not here: the resolver holds no zone. Data a validator proved secure is trusted above every rank (RFC 2181
/// §5.4.1: "Unauthenticated RRs received and cached from the least trustworthy of those groupings [...] should not
/// be cached in preference to authenticated data"), which
/// [`Checked::Secure`](dedens_cache::Checked::Secure) says.
///
/// The section an `RRset` came in does not give its rank alone: the answer section of an authoritative answer is
/// authoritative only at the name the server is authoritative for (RFC 1035 §4.1.1), and data out of the zone asked
/// is not to be kept at all. [`scrub()`](crate::scrub()) ranks what it keeps, and only it. A response without AA is
/// a referral or lame there (D192): no rank is that of a non-authoritative answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// The additional section of a referral: its glue.
    AdditionalNonAuthoritative,
    /// The authority section of a referral: its NS records, and its DS records or the NSEC or NSEC3 records proving
    /// it has none.
    AuthorityNonAuthoritative,
    /// The additional section of an authoritative answer.
    AdditionalAuthoritative,
    /// The answer section of an authoritative answer past its first owner name, which is all AA covers (RFC 1035
    /// §4.1.1): the rest of a CNAME and DNAME chain, and the data at its end. Never the answer section of a response
    /// without AA, which is lame (D192, a deviation from Unbound). The least rank that answers a client.
    AnswerNonAuthoritative,
    /// The authority section of an authoritative answer: above the answer non-authoritative in trust, yet it
    /// answers no client, whatever its section's data (an NSEC at a cut is the parent's, not the child's answer).
    AuthorityAuthoritative,
    /// The answer section of an authoritative answer, at the name asked or the first owner name (a DNAME's); or the
    /// DS records of a referral to the name asked for them, which the parent holds as authoritative data (RFC 4035
    /// §2.3), AA or not.
    AnswerAuthoritative,
}
