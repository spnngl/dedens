//! The server side: verifying a request (RFC 8945 §5.2), signing the response or the stream of responses (§5.3,
//! §5.3.1) and the error returns (§5.3.2).

use dedens_proto::{Class, DecodeError, Name, Tsig, TsigError, find_tsig};

use crate::FUDGE;
use crate::digest::{Digest, SignError, Signature, append, matches, original_id, sign};
use crate::key::{Key, Keyring};

/// A request that is not to be served as a signed one, with the answer it is owed.
#[derive(Debug, Clone)]
pub enum Refusal<'k> {
    /// FORMERR, no TSIG in the response: the message is dropped (RFC 8945 §5.2).
    Format(FormatError),
    /// NOTAUTH with a TSIG error (RFC 8945 §5.2.1 to §5.2.4).
    NotAuth(NotAuth<'k>),
}

/// A request whose TSIG is malformed (RFC 8945 §5.2, §5.2.2.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// The message or its TSIG record cannot be read, or the TSIG is not alone and last.
    #[error("malformed TSIG: {0}")]
    Malformed(DecodeError),
    /// The TSIG record's class is not `ANY` or its TTL is not 0 (RFC 8945 §4.2).
    #[error("TSIG record with a class other than ANY or a TTL other than 0")]
    ClassOrTtl,
    /// A MAC longer than the hash's output or shorter than the larger of 10 bytes and half of it.
    #[error("TSIG MAC size outside what the algorithm allows")]
    MacSize,
}

/// The TSIG error of a NOTAUTH response, and how to put it in the response.
///
/// The caller builds the response, the request's question with RCODE NOTAUTH and no records, and calls
/// [`NotAuth::sign`] on its bytes.
#[derive(Debug, Clone)]
pub struct NotAuth<'k> {
    error: TsigError,
    owner: Name<'static>,
    algorithm: Name<'static>,
    /// The request's Time Signed, which both kinds of answer carry.
    time: u64,
    signed: Option<Signed<'k>>,
}

/// What a signed error return is made from (RFC 8945 §5.3.2).
#[derive(Debug, Clone)]
struct Signed<'k> {
    key: &'k Key,
    request_mac: Vec<u8>,
    fudge: u16,
}

impl NotAuth<'_> {
    /// BADKEY, BADSIG, BADTIME or BADTRUNC.
    #[must_use]
    pub const fn error(&self) -> TsigError {
        self.error
    }

    /// Whether the response is signed: BADTIME and BADTRUNC are, BADKEY and BADSIG are not (RFC 8945 §5.3.2).
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signed.is_some()
    }

    /// Appends the TSIG record to the response `wire`, at time `now`.
    ///
    /// An unsigned error has an empty MAC and the request's Time Signed, as Knot's `knot_tsig_add` writes it (RFC
    /// 8945 §5.3.2 gives none). A BADTIME carries the request's Time Signed and Fudge and the server's time as Other
    /// Data (§5.2.3); a BADTRUNC the request's Fudge and `now`.
    ///
    /// # Errors
    ///
    /// [`SignError`] when `wire` is no message or has no room for the record.
    pub fn sign(&self, wire: &mut Vec<u8>, now: u64) -> Result<(), SignError> {
        let Some(signed) = &self.signed else {
            let id = original_id(wire)?;
            let tsig = Tsig::new(
                self.algorithm.clone(),
                self.time,
                FUDGE,
                &[],
                id,
                self.error,
                &[],
            )?;
            return append(wire, &self.owner, &tsig);
        };
        let mut digest = Digest::new(signed.key);
        digest.mac(&signed.request_mac);
        let server_time = now.to_be_bytes();
        let (time_signed, other) = if self.error == TsigError::BADTIME {
            (self.time, &server_time[2..])
        } else {
            (now, &[][..])
        };
        let signature = Signature {
            time_signed,
            fudge: signed.fudge,
            error: self.error,
            other,
            timers_only: false,
        };
        sign(signed.key, digest, wire, &signature).map(drop)
    }
}

/// Reads and checks the TSIG of a request, in the order of RFC 8945 §5.2: key, MAC, time, truncation policy.
///
/// `now` is the time in seconds since 1970. `None` is a request with no TSIG: whether to serve it is the caller's
/// policy. A MAC shorter than the full output is permitted by the RFC when long enough; D205 refuses it all with
/// BADTRUNC, after the MAC and the time check out.
///
/// # Errors
///
/// A [`Refusal`] when the TSIG is there and wrong.
pub fn verify_request<'k>(
    keys: &'k Keyring,
    wire: &[u8],
    now: u64,
) -> Result<Option<Request<'k>>, Refusal<'k>> {
    let Some(record) = find_tsig(wire).map_err(|e| Refusal::Format(FormatError::Malformed(e)))?
    else {
        return Ok(None);
    };
    if record.class != Class::ANY || record.ttl != 0 {
        return Err(Refusal::Format(FormatError::ClassOrTtl));
    }
    let tsig = &record.tsig;
    let not_auth = |error, signed| {
        Refusal::NotAuth(NotAuth {
            error,
            owner: record.name.clone().into_owned(),
            algorithm: tsig.algorithm.clone().into_owned(),
            time: tsig.time_signed(),
            signed,
        })
    };
    let key = keys
        .get(&record.name)
        .filter(|key| key.algorithm().name() == tsig.algorithm)
        .ok_or_else(|| not_auth(TsigError::BADKEY, None))?;
    let algorithm = key.algorithm();
    let mac = tsig.mac();
    if mac.len() > algorithm.mac_len() || mac.len() < algorithm.min_mac_len() {
        return Err(Refusal::Format(FormatError::MacSize));
    }
    let mut digest = Digest::new(key);
    digest.stripped(wire, &record);
    digest.variables(&record.name, tsig);
    if !matches(&digest.finish(), mac) {
        return Err(not_auth(TsigError::BADSIG, None));
    }
    let signed = || {
        Some(Signed {
            key,
            request_mac: mac.to_vec(),
            fudge: tsig.fudge,
        })
    };
    if now.abs_diff(tsig.time_signed()) > u64::from(tsig.fudge) {
        return Err(not_auth(TsigError::BADTIME, signed()));
    }
    if mac.len() < algorithm.mac_len() {
        return Err(not_auth(TsigError::BADTRUNC, signed()));
    }
    Ok(Some(Request {
        key,
        mac: mac.to_vec(),
    }))
}

/// A request that carried a valid TSIG.
#[derive(Debug, Clone)]
pub struct Request<'k> {
    key: &'k Key,
    mac: Vec<u8>,
}

impl<'k> Request<'k> {
    /// The key that signed the request.
    #[must_use]
    pub const fn key(&self) -> &'k Key {
        self.key
    }

    /// The MAC of the request.
    #[must_use]
    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /// The signer of the response, which is a message or a stream of them.
    #[must_use]
    pub fn signer(&self) -> ResponseSigner<'k> {
        ResponseSigner {
            key: self.key,
            prior: self.mac.clone(),
            first: true,
        }
    }
}

/// Signs the messages of one response in order, each with the MAC of the one before (RFC 8945 §5.3, §5.3.1).
#[derive(Debug, Clone)]
pub struct ResponseSigner<'k> {
    key: &'k Key,
    prior: Vec<u8>,
    first: bool,
}

impl ResponseSigner<'_> {
    /// Appends the TSIG record to `wire`, a message of the response, at time `now`.
    ///
    /// The first message takes the request MAC and the TSIG variables, the next ones the previous MAC and the
    /// timers alone. Every message is signed: the server never leaves one for a client's tolerance of 99 (RFC 8945
    /// §5.3.1).
    ///
    /// # Errors
    ///
    /// [`SignError`] when `wire` is no message or has no room for the record; the signer is unchanged then.
    pub fn sign(&mut self, wire: &mut Vec<u8>, now: u64) -> Result<(), SignError> {
        let mut digest = Digest::new(self.key);
        digest.mac(&self.prior);
        let signature = Signature {
            time_signed: now,
            fudge: FUDGE,
            error: TsigError::NOERROR,
            other: &[],
            timers_only: !self.first,
        };
        self.prior = sign(self.key, digest, wire, &signature)?;
        self.first = false;
        Ok(())
    }
}
