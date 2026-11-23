//! The client side: signing a request (RFC 8945 §5.1) and verifying the response, a message or a stream of them
//! (§5.4, §5.3.1).

use dedens_proto::{Class, DecodeError, TsigError, find_tsig};

use crate::digest::{Digest, SignError, Signature, matches, sign};
use crate::key::Key;
use crate::{FUDGE, MAX_UNSIGNED};

/// Signs the request `wire` in place at time `now` and keeps what the response is checked against: the MAC and the
/// key (RFC 8945 §5.1).
///
/// # Errors
///
/// [`SignError`] when `wire` is no message or has no room for the record.
pub fn sign_request<'k>(
    key: &'k Key,
    wire: &mut Vec<u8>,
    now: u64,
) -> Result<ResponseVerifier<'k>, SignError> {
    let signature = Signature {
        time_signed: now,
        fudge: FUDGE,
        error: TsigError::NOERROR,
        other: &[],
        timers_only: false,
    };
    let mac = sign(key, Digest::new(key), wire, &signature)?;
    Ok(ResponseVerifier::new(key, &mac))
}

/// A response that cannot be accepted: over TCP the client closes the connection, over UDP it keeps waiting
/// (RFC 8945 §5.4); the verifier is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResponseError {
    /// The message or its TSIG record cannot be read.
    #[error("malformed TSIG: {0}")]
    Malformed(DecodeError),
    /// The first message of the response has no TSIG (RFC 8945 §5.4).
    #[error("the response has no TSIG")]
    Missing,
    /// The TSIG record's class is not `ANY` or its TTL is not 0 (RFC 8945 §4.2).
    #[error("TSIG record with a class other than ANY or a TTL other than 0")]
    ClassOrTtl,
    /// The TSIG is of another key or algorithm than the request's (RFC 8945 §5.4.1).
    #[error("the TSIG is of another key or algorithm than the request's")]
    Key,
    /// A MAC that is not the full output of the algorithm: a server signs in full (D205).
    #[error("the TSIG MAC is not the full length of the algorithm's output")]
    MacSize,
    /// The MAC is not the one computed (RFC 8945 §5.4.2).
    #[error("the TSIG MAC does not verify")]
    BadSig,
    /// The time signed is further from the client's than the fudge (RFC 8945 §5.4.3). The client never adjusts
    /// its clock from it.
    #[error("the TSIG time signed is outside its fudge: {time_signed} against {now}")]
    BadTime {
        /// The time signed in the message.
        time_signed: u64,
        /// The client's time.
        now: u64,
    },
    /// A message of a stream is signed at a time before the one before it (RFC 8945 §5.3.1: successive Time
    /// Signed values do not decrease).
    #[error("the TSIG time signed {time_signed} is before the previous message's {previous}")]
    TimeDecreased {
        /// The time signed in the message.
        time_signed: u64,
        /// The time signed of the message before.
        previous: u64,
    },
    /// More than 99 messages in a row without a TSIG (RFC 8945 §5.3.1).
    #[error("more than {MAX_UNSIGNED} messages in a row without a TSIG")]
    TooManyUnsigned,
    /// The response ended on a message with no TSIG (RFC 8945 §5.3.1).
    #[error("the response ended without a TSIG on its last message")]
    UnsignedEnd,
    /// The server answered with a TSIG error: it did not serve the request. `authenticated` is whether the
    /// message is signed and verifies; an unauthenticated one may be forged (RFC 8945 §5.4).
    #[error("the server answered TSIG error {error}")]
    Refused {
        /// BADKEY, BADSIG, BADTIME, BADTRUNC or another code.
        error: TsigError,
        /// Whether the answer is signed and verifies.
        authenticated: bool,
    },
}

/// What a message of the response is, once accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// A signed message, which verifies it and the unsigned ones before it.
    Signed,
    /// A message with no TSIG, within the 99 a client accepts; the next TSIG covers it. It is **not yet
    /// authenticated**: the caller does not act on it (apply an AXFR's records, say) until a later
    /// [`Verified::Signed`], and the response is complete only after [`ResponseVerifier::finish`].
    Unsigned,
}

/// Verifies the messages of one response in order (RFC 8945 §5.4, §5.3.1): the first message is a standard answer
/// to the request, a later one is chained to the previous MAC; up to 99 in a row may carry no TSIG.
///
/// A clone keeps the state at that point: over UDP, a datagram is verified on a clone, so that a forged one leaves
/// the original to verify the real response.
#[derive(Debug, Clone)]
pub struct ResponseVerifier<'k> {
    key: &'k Key,
    prior: Vec<u8>,
    digest: Digest,
    first: bool,
    unsigned: usize,
    /// The Time Signed of the last signed message: a stream's never decrease (RFC 8945 §5.3.1).
    last_time: u64,
}

impl<'k> ResponseVerifier<'k> {
    /// The verifier of the response to a request signed with `key` whose MAC was `request_mac`: for a request
    /// [`sign_request`] did not sign, such as one read back from a capture.
    #[must_use]
    pub fn new(key: &'k Key, request_mac: &[u8]) -> Self {
        let mut verifier = Self {
            key,
            prior: request_mac.to_vec(),
            digest: Digest::new(key),
            first: true,
            unsigned: 0,
            last_time: 0,
        };
        verifier.digest.mac(&verifier.prior);
        verifier
    }

    /// Accepts or refuses the next message of the response, at time `now`.
    ///
    /// A refused message leaves the verifier as it was: over UDP keep waiting for the real response (RFC 8945
    /// §5.4), over TCP close the connection.
    ///
    /// # Errors
    ///
    /// [`ResponseError`] when the message is not one to accept.
    pub fn verify(&mut self, wire: &[u8], now: u64) -> Result<Verified, ResponseError> {
        let Some(record) = find_tsig(wire).map_err(ResponseError::Malformed)? else {
            if self.first {
                return Err(ResponseError::Missing);
            }
            if self.unsigned == MAX_UNSIGNED {
                return Err(ResponseError::TooManyUnsigned);
            }
            self.unsigned += 1;
            self.digest.bytes(wire);
            return Ok(Verified::Unsigned);
        };
        let tsig = &record.tsig;
        if tsig.error != TsigError::NOERROR && tsig.mac().is_empty() {
            return Err(ResponseError::Refused {
                error: tsig.error,
                authenticated: false,
            });
        }
        if record.class != Class::ANY || record.ttl != 0 {
            return Err(ResponseError::ClassOrTtl);
        }
        if record.name != *self.key.name() || tsig.algorithm != self.key.algorithm().name() {
            return Err(ResponseError::Key);
        }
        if tsig.mac().len() != self.key.algorithm().mac_len() {
            return Err(ResponseError::MacSize);
        }
        let mut digest = self.digest.clone();
        digest.stripped(wire, &record);
        if self.first {
            digest.variables(&record.name, tsig);
        } else {
            digest.timers(tsig.time_signed(), tsig.fudge);
        }
        if !matches(&digest.finish(), tsig.mac()) {
            return Err(ResponseError::BadSig);
        }
        if now.abs_diff(tsig.time_signed()) > u64::from(tsig.fudge) {
            return Err(ResponseError::BadTime {
                time_signed: tsig.time_signed(),
                now,
            });
        }
        if tsig.time_signed() < self.last_time {
            return Err(ResponseError::TimeDecreased {
                time_signed: tsig.time_signed(),
                previous: self.last_time,
            });
        }
        if tsig.error != TsigError::NOERROR {
            return Err(ResponseError::Refused {
                error: tsig.error,
                authenticated: true,
            });
        }
        self.prior = tsig.mac().to_vec();
        self.digest = Digest::new(self.key);
        self.digest.mac(&self.prior);
        self.last_time = tsig.time_signed();
        self.first = false;
        self.unsigned = 0;
        Ok(Verified::Signed)
    }

    /// Ends the response: its last message must have been signed (RFC 8945 §5.3.1).
    ///
    /// # Errors
    ///
    /// [`ResponseError::Missing`] when no message came, [`ResponseError::UnsignedEnd`] when the last had no TSIG.
    pub fn finish(self) -> Result<(), ResponseError> {
        if self.first {
            Err(ResponseError::Missing)
        } else if self.unsigned > 0 {
            Err(ResponseError::UnsignedEnd)
        } else {
            Ok(())
        }
    }
}
