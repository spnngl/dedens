//! Signed requests (D211): the TSIG of a request checked before the core's own checks, whatever its opcode (RFC
//! 8945 §5.2), its failures answered as §5.3.2 says, and the reply to a signed request signed with its key (§5.3).

use std::fmt;

use dedens_proto::edns::InfoCode;
use dedens_proto::{Message, Rcode};
use dedens_tsig::{Key, Keyring, Refusal, Request, SignError, verify_request};

use super::Step;
use super::finish::reply;
use crate::reply::Client;
use crate::validate::Clock;

/// The keys requests are verified with, and the clock their times are checked against (Unix seconds).
#[derive(Clone)]
pub(super) struct Keys {
    keys: Keyring,
    clock: Clock,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

/// The key a request was verified as signed with (RFC 8945 §5.2). Only a verification makes one, so what asks who
/// may do what ([`ZoneAccess::permits`](crate::ZoneAccess::permits)) is never given a key found by the name a
/// request claims.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedKey<'k>(&'k Key);

impl<'k> VerifiedKey<'k> {
    /// The key of the request `wire`, signed with a key of `keys` and verified at time `now`, as the pipeline
    /// verifies it; `None` for a request that is unsigned or that does not verify.
    #[must_use]
    pub fn from_request(keys: &'k Keyring, wire: &[u8], now: u64) -> Option<Self> {
        let request = verify_request(keys, wire, now).ok()??;
        Some(Self(request.key()))
    }

    /// The key.
    #[must_use]
    pub const fn key(self) -> &'k Key {
        self.0
    }
}

/// A request verified as signed, and the time it was: its reply is signed with its key at that time.
pub(super) struct Signed<'k> {
    request: Request<'k>,
    now: u64,
}

impl Keys {
    pub(super) fn new(keys: Keyring, clock: Clock) -> Self {
        Self { keys, clock }
    }

    pub(super) const fn keyring(&self) -> &Keyring {
        &self.keys
    }

    /// Checks the TSIG of the request `wire` from `client`, if it has one: `Ok(None)` when it has none. A TSIG that
    /// is not alone and last or is malformed is answered FORMERR, unsigned (RFC 8945 §5.2); an unknown key or a
    /// wrong MAC NOTAUTH, unsigned, BADKEY or BADSIG in the TSIG; a time outside the fudge or a truncated MAC
    /// NOTAUTH, signed, BADTIME or BADTRUNC (§5.2.1 to §5.2.4, §5.3.2). The error is written into `out`.
    pub(super) fn verify(
        &self,
        wire: &[u8],
        client: &Client<'_>,
        out: &mut [u8],
    ) -> Result<Option<Signed<'_>>, Step> {
        let now = (self.clock)();
        match verify_request(&self.keys, wire, now) {
            Ok(request) => Ok(request.map(|request| Signed { request, now })),
            Err(Refusal::Format(_)) => Err(reply(client, Message::default(), Rcode::FORMERR, out)),
            Err(Refusal::NotAuth(not_auth)) => {
                let len = client.reply(Message::default(), Rcode::NOTAUTH, None, out);
                Err(seal(client, len, out, |wire| not_auth.sign(wire, now)))
            }
        }
    }
}

impl<'k> Signed<'k> {
    /// The key the request is signed with.
    pub(super) const fn key(&self) -> VerifiedKey<'k> {
        VerifiedKey(self.request.key())
    }

    /// The reply of `len` bytes in `out` to `client`, signed (RFC 8945 §5.3).
    pub(super) fn seal(&self, client: &Client<'_>, len: usize, out: &mut [u8]) -> Step {
        seal(client, Some(len), out, |wire| {
            self.request.signer().sign(wire, self.now)
        })
    }
}

/// The reply to a signed request past the zones (D211): REFUSED with EDE 20 (Not Authoritative, RFC 8914 §4.21),
/// for a later stage answers from upstream, later, and its reply is not ours to sign. `None` for an unsigned
/// request, which goes on.
pub(super) fn past_zones(client: &Client<'_>, out: &mut [u8]) -> Option<Step> {
    client.key()?;
    let len = client.reply(
        Message::default(),
        Rcode::REFUSED,
        Some(InfoCode::NOT_AUTHORITATIVE),
        out,
    );
    Some(len.map_or(Step::Drop, Step::Reply))
}

/// The reply of `len` bytes in `out` to `client`, signed in place by `sign`. Dropped when the record does not fit
/// the reply's limit: the replies keep room for it ([`Client::with_key`]), but for the errors of an unknown key,
/// whose names are the request's.
fn seal(
    client: &Client<'_>,
    len: Option<usize>,
    out: &mut [u8],
    sign: impl FnOnce(&mut Vec<u8>) -> Result<(), SignError>,
) -> Step {
    let Some(len) = len else {
        return Step::Drop;
    };
    // A copy, for the signing takes a vector: signed requests are the few a server is configured for, transfers
    // and updates, not the queries of the many.
    let mut wire = out[..len].to_vec();
    let limit = client.limit().min(out.len());
    if sign(&mut wire).is_err() || wire.len() > limit {
        return Step::Drop;
    }
    out[..wire.len()].copy_from_slice(&wire);
    Step::Reply(wire.len())
}
