//! The client's side of Oblivious `DoH` (RFC 9230 §4, §7, D79): the configurations of each target, fetched over
//! [`Http3Pool`] and kept an hour to a day (D79), and the exchange that encrypts a query under them, sends it through
//! the proxy or to the target, and decrypts the response (§4.1, §4.3, §6.2). The HTTP of each message is
//! [`super`]'s, which sends nothing itself.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use dedens_odoh::{MessageType, WireError, decrypt_response, encrypt_query, query_padding};
use http::Version;
use http::uri::Authority;

#[cfg(doc)]
use super::Lifetime;
use super::{
    Entropy, MAX_BODY, MIN_KEPT, Notice, OdohError, configs_lifetime, configs_request,
    names_target, proxy_error, request, response,
};
use crate::client::Server;
use crate::doh::Template;
use crate::exchange::Http;
use crate::http3::{Http3Pool, Reply};

/// The targets whose configurations are kept at most.
const MAX_TARGETS: usize = 64;

/// A target's configurations and when they stop being fresh.
#[derive(Debug)]
struct Known {
    configs: dedens_odoh::Configs,
    until: Instant,
}

/// The identity of a target: its address and authority.
type Key = (SocketAddr, Authority);

/// The configurations of the targets a client asked, kept as [`Lifetime::keep`] says, and those it was given.
#[derive(Debug, Default)]
pub(crate) struct Configs {
    /// Fetched, at most [`MAX_TARGETS`].
    known: RefCell<HashMap<Key, Known>>,
    /// Given by the caller, never fetched again nor dropped: a 401 for them is an error.
    pinned: RefCell<HashMap<Key, dedens_odoh::Configs>>,
    /// Not yet taken by [`Configs::take_notices`].
    notices: RefCell<Vec<Notice>>,
}

impl Configs {
    /// Asks `target`, through `proxy` when there is one, for the answer to `wire`, a DNS query with ID 0 and no
    /// padding of its own (D79).
    ///
    /// The configurations are the pinned ones, the kept ones, else fetched from the target. A 401 the target made
    /// under kept ones may mean it changed its key: they are fetched again, once (RFC 9230 §4.3). A response that
    /// does not decrypt, or an error of the proxy's, is no reason to.
    ///
    /// # Errors
    ///
    /// [`OdohError`]: no template, a proxy URI that sets the target, no randomness, a failed request,
    /// configurations that are none, a response that is not one, or no response before `deadline`.
    pub(crate) async fn exchange(
        &self,
        https: &Http3Pool,
        target: &Server,
        proxy: Option<&Server>,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Reply, OdohError> {
        let target_template = target.template()?;
        let proxy_template = proxy.map(Server::template).transpose()?;
        if proxy_template.as_ref().is_some_and(names_target) {
            return Err(OdohError::ProxyVariables);
        }
        let key = (target.addr, target_template.authority().clone());
        let pinned = self.pinned.borrow().get(&key).cloned();
        let mut cached = pinned.clone().or_else(|| self.fresh(&key));
        loop {
            let from_cache = cached.is_some() && pinned.is_none();
            let configs = match cached.take() {
                Some(configs) => configs,
                None => {
                    self.fetch(
                        https,
                        (target, &target_template),
                        proxy.is_some(),
                        &key,
                        deadline,
                    )
                    .await?
                }
            };
            let asked = ask(
                https,
                (target, &target_template),
                (proxy, proxy_template.as_ref()),
                &configs,
                wire,
                deadline,
            )
            .await;
            match asked {
                Err(error) if from_cache && error.stale_configs() => {
                    debug!(error = %error, "configurations out of date: fetching them again");
                    self.known.borrow_mut().remove(&key);
                }
                asked => return asked,
            }
        }
    }

    /// Keeps `bytes`, encoded configurations, for `target` for good: they are not fetched, nor dropped.
    ///
    /// # Errors
    ///
    /// [`OdohError::Template`] for a target with no template, [`OdohError::Wire`] for bytes that are no
    /// configurations.
    pub(crate) fn pin(&self, target: &Server, bytes: &[u8]) -> Result<(), OdohError> {
        let key = (target.addr, target.template()?.authority().clone());
        let configs = dedens_odoh::Configs::parse(bytes)?;
        self.pinned.borrow_mut().insert(key, configs);
        Ok(())
    }

    /// Keeps `bytes`, encoded configurations, for `target` as if it had served them: for [`MIN_KEPT`], and fetched
    /// again after a 401 or when they expire, which pinned ones never are.
    ///
    /// # Errors
    ///
    /// [`OdohError::Template`] for a target with no template, [`OdohError::Wire`] for bytes that are no
    /// configurations.
    pub(crate) fn keep_given(&self, target: &Server, bytes: &[u8]) -> Result<(), OdohError> {
        let key = (target.addr, target.template()?.authority().clone());
        self.keep(&key, &dedens_odoh::Configs::parse(bytes)?, MIN_KEPT);
        Ok(())
    }

    /// The notices since the last call.
    pub(crate) fn take_notices(&self) -> Vec<Notice> {
        std::mem::take(&mut *self.notices.borrow_mut())
    }

    /// The configurations of `key` while they are fresh.
    fn fresh(&self, key: &Key) -> Option<dedens_odoh::Configs> {
        self.known
            .borrow()
            .get(key)
            .filter(|known| known.until > Instant::now())
            .map(|known| known.configs.clone())
    }

    /// Fetches the configurations from `target` directly, and keeps them as [`Lifetime::keep`] says. `proxied` tells
    /// that the queries go through a proxy: the fetch gives the target the address of the client, and a target that
    /// asks for no keeping then makes a [`Notice`].
    async fn fetch(
        &self,
        https: &Http3Pool,
        (target, template): (&Server, &Template),
        proxied: bool,
        key: &Key,
        deadline: Instant,
    ) -> Result<dedens_odoh::Configs, OdohError> {
        let request = configs_request(template).map_err(OdohError::Request)?;
        let (head, body) = https
            .send(
                target.addr,
                target.certified(),
                &request,
                MAX_BODY,
                deadline,
            )
            .await?;
        if !head.status().is_success() {
            return Err(OdohError::Configs(head.status()));
        }
        let configs = dedens_odoh::Configs::parse(&body)?;
        let lifetime = configs_lifetime(head.headers(), SystemTime::now());
        if proxied && lifetime.forbidden {
            let notice = Notice::ConfigsNotToBeKept(key.1.clone());
            let mut notices = self.notices.borrow_mut();
            if !notices.contains(&notice) {
                notices.push(notice);
            }
        }
        self.keep(key, &configs, lifetime.keep);
        Ok(configs)
    }

    /// Keeps `configs` for `key` for `keep`, dropping what is stale, and the soonest to be stale when there are
    /// [`MAX_TARGETS`].
    fn keep(&self, key: &Key, configs: &dedens_odoh::Configs, keep: Duration) {
        let now = Instant::now();
        let mut known = self.known.borrow_mut();
        known.retain(|_, known| known.until > now);
        if known.len() >= MAX_TARGETS
            && !known.contains_key(key)
            && let Some(soonest) = known
                .iter()
                .min_by_key(|(_, known)| known.until)
                .map(|(key, _)| key.clone())
        {
            known.remove(&soonest);
        }
        known.insert(
            key.clone(),
            Known {
                configs: configs.clone(),
                until: crate::exchange::after(now, keep),
            },
        );
    }
}

/// Encrypts `wire` under the most preferred of `configs`, sends it to `proxy` or, without one, to `target`, and
/// decrypts the response.
async fn ask(
    https: &Http3Pool,
    (target, target_template): (&Server, &Template),
    (proxy, proxy_template): (Option<&Server>, Option<&Template>),
    configs: &dedens_odoh::Configs,
    wire: &[u8],
    deadline: Instant,
) -> Result<Reply, OdohError> {
    let config = configs.configs().first().ok_or(WireError::NoUsableConfig)?;
    let mut entropy = Entropy::new().map_err(OdohError::Random)?;
    let (message, context) = encrypt_query(config, wire, query_padding(wire.len()), &mut entropy)?;
    entropy.finish().map_err(OdohError::Random)?;
    let request = request(proxy_template, target_template, &message).map_err(OdohError::Request)?;
    let server = proxy.unwrap_or(target);
    let (head, body) = https
        .send(
            server.addr,
            server.certified(),
            &request,
            MAX_BODY,
            deadline,
        )
        .await?;
    if proxy.is_some() && !head.status().is_success() && proxy_error(head.headers()) {
        return Err(OdohError::Proxy(head.status()));
    }
    let message = response(&head, &body)?;
    debug_assert_eq!(message.message_type(), MessageType::Response);
    let plaintext = decrypt_response(&context, &message)?;
    Ok(Reply {
        wire: plaintext.into_dns_message(),
        http: Http {
            version: Version::HTTP_3,
            status: head.status(),
        },
    })
}

#[cfg(test)]
mod tests {
    use dedens_odoh::TargetKey;

    use super::*;

    /// The kept configurations are at most [`MAX_TARGETS`], however many targets are asked.
    #[test]
    fn the_kept_configurations_are_bounded() {
        let configs = Configs::default();
        let parsed = dedens_odoh::Configs::new(vec![TargetKey::derive(&[7; 32]).config().clone()]);
        for port in 0..u16::try_from(MAX_TARGETS * 2).expect("a small number") {
            let key = (
                SocketAddr::from(([127, 0, 0, 1], 1000 + port)),
                Authority::from_static("a.example"),
            );
            configs.keep(&key, &parsed, MIN_KEPT);
        }
        assert_eq!(configs.known.borrow().len(), MAX_TARGETS);
    }
}
