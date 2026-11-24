//! UPDATE requests in the pipeline (RFC 2136 §3, D216): read whole, their zone found and their client permitted
//! here; the server makes them and asks [`Pipeline::updated`] for the reply.

use std::net::IpAddr;

use dedens_proto::edns::{Cookie, InfoCode};
use dedens_proto::{Message, Query, Rcode, Transport, Update};

use super::finish::reply;
use super::{Pipeline, Signed, Stage, Step};
use crate::reply::Client;
use crate::zone_access::Action;

/// An UPDATE the pipeline admitted (D216): well formed, of a zone a stage serves, from a client its access list
/// permits. The server makes it against the zone's last version, one update of a zone at a time (RFC 2136 §3.7),
/// stores the result before the reply (§3.5), then hands it to [`Pipeline::updated`] with the RCODE.
#[derive(Debug)]
#[must_use]
pub struct Updating {
    /// The request, as received: read again for the reply, and its TSIG verified again to sign it.
    request: Box<[u8]>,
    transport: Transport,
    /// The Server Cookie made for the client, if any.
    cookie: Option<Cookie>,
    /// Whether recursion is available to the client: RA.
    recursion: bool,
    update: Update<'static>,
}

impl Updating {
    /// The update: its zone, prerequisites and changes.
    #[must_use]
    pub const fn update(&self) -> &Update<'static> {
        &self.update
    }
}

impl Pipeline {
    /// The step of the UPDATE `query` from `client` at `from`, after the core's checks: FORMERR or NOTZONE to a
    /// malformed one (RFC 2136 §3.1.1, §3.4.1.3); NOTAUTH to one of a zone no stage serves (§3.1.1); REFUSED with
    /// EDE 18 to a client the zone's access list does not permit (§3.3, RFC 3007 §3, D211); else
    /// [`Step::Update`]. Knot checks in the same order (`src/knot/nameserver/update.c`, `update_process_query`).
    pub(super) fn update(
        &self,
        query: &Query<'_>,
        client: &Client<'_>,
        from: IpAddr,
        out: &mut [u8],
    ) -> Step {
        // Read once already: `Query::read` and `Message::decode` agree, so this reads too.
        let Ok(decoded) = Message::decode(query.wire()) else {
            return reply(client, Message::default(), Rcode::FORMERR, out);
        };
        let update = match Update::read(decoded.message) {
            Ok(update) => update,
            Err(error) => return reply(client, Message::default(), error.rcode(), out),
        };
        let zones = self.stages.get(..self.zones).unwrap_or_default();
        let held = zones.iter().find_map(|stage| match stage {
            Stage::Authoritative(zones) => zones
                .access(update.zone())
                .filter(|(zone, _)| zone.apex() == update.zone()),
            _ => None,
        });
        let Some((_, access)) = held else {
            return reply(client, Message::default(), Rcode::NOTAUTH, out);
        };
        if !access.permits(Action::Update, from, client.key()) {
            return client
                .reply(
                    Message::default(),
                    Rcode::REFUSED,
                    Some(InfoCode::PROHIBITED),
                    out,
                )
                .map_or(Step::Drop, Step::Reply);
        }
        Step::Update(Box::new(Updating {
            request: query.wire().into(),
            transport: client.transport,
            cookie: client.cookie,
            recursion: client.recursion(),
            update: update.into_owned(),
        }))
    }

    /// The reply to `updating` with `rcode`, and the extended error `error` if any, written into `out` (RFC 2136
    /// §3.8): the header and the zone section of the request, no other record; signed with the key of a signed
    /// request, its TSIG verified again at the clock's time (RFC 8945 §5.3): past the window of `Time Signed`
    /// the reply is BADTIME, though the update was made.
    ///
    /// `updating` comes from this pipeline.
    pub fn updated(
        &self,
        updating: &Updating,
        rcode: Rcode,
        error: Option<InfoCode>,
        out: &mut [u8],
    ) -> Step {
        // Read once already: this reads it again.
        let Ok(query) = Query::read(&updating.request) else {
            return Step::Drop;
        };
        let client = Client::of(&query, updating.transport)
            .with_cookie(updating.cookie)
            .with_recursion(updating.recursion);
        let signed = match self
            .keys
            .as_ref()
            .map(|keys| keys.verify((&query, &updating.request), &client, out))
        {
            None | Some(Ok(None)) => None,
            Some(Ok(Some(signed))) => Some(signed),
            Some(Err(step)) => return step,
        };
        let client = client.with_key(signed.as_ref().map(Signed::key));
        let Some(len) = client.reply(Message::default(), rcode, error, out) else {
            return Step::Drop;
        };
        match &signed {
            Some(signed) => signed.seal(&client, len, out),
            None => Step::Reply(len),
        }
    }
}
