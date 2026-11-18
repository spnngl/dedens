//! The cookies of a client (RFC 7873 §5.1, §5.3), per pair of source address and server, in a table of bounded
//! size: past [`Jar`]'s bound, the pair used longest ago goes, and its next query starts again with a client cookie
//! alone, as a first query does (D190).

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;

use dedens_proto::Message;
use dedens_proto::edns::{Cookie, EdnsOption};

/// The source address and the server a cookie belongs to: the client cookie changes with either (RFC 7873 §5.1).
pub(crate) type Pair = (IpAddr, SocketAddr);

/// The pairs a [`Jar`] keeps by default: 4096 pairs of about 100 bytes each, 400 KiB a thread. A forwarder asks a
/// few servers; a recursive resolver as many as Unbound's infra cache keeps hosts (`infra-cache-numhosts: 10000`,
/// `util/config_file.c:config_create`), those asked least often losing a cookie that costs them a round trip at
/// worst (D190).
pub(crate) const COOKIES: NonZeroUsize = NonZeroUsize::new(4096).expect("4096 is not zero");

/// Client cookies drawn and server cookies returned, for at most `most` pairs.
#[derive(Debug)]
pub(crate) struct Jar {
    most: NonZeroUsize,
    pairs: HashMap<Pair, Cookies>,
    /// The pairs by their last use, the oldest first.
    order: BTreeMap<u64, Pair>,
    /// The tick of the next use.
    tick: u64,
}

/// The cookies of one pair.
#[derive(Debug)]
struct Cookies {
    client: [u8; 8],
    /// The last cookie returned, its client cookie checked by the exchange.
    returned: Option<Cookie>,
    /// The tick of its last use, its key in [`Jar::order`].
    used: u64,
}

impl Jar {
    /// No pair yet; at most `most` kept.
    pub(crate) fn new(most: NonZeroUsize) -> Self {
        Self {
            most,
            pairs: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
        }
    }

    /// Adds a cookie to a query with EDNS and none of its own, and returns the pair it belongs to: the last one
    /// the server returned, or the client cookie alone, `fresh` for a pair not kept.
    ///
    /// # Errors
    ///
    /// The error of `fresh`.
    pub(crate) fn add<E>(
        &mut self,
        query: &mut Message<'_>,
        pair: Pair,
        fresh: impl FnOnce() -> Result<[u8; 8], E>,
    ) -> Result<Option<Pair>, E> {
        let Some(edns) = &mut query.edns else {
            return Ok(None);
        };
        if edns
            .options
            .iter()
            .any(|option| matches!(option, EdnsOption::Cookie(_)))
        {
            return Ok(None);
        }
        let tick = self.tick;
        self.tick += 1;
        let cookies = if let Some(known) = self.pairs.get_mut(&pair) {
            self.order.remove(&known.used);
            known.used = tick;
            known
        } else {
            let client = fresh()?;
            if self.pairs.len() >= self.most.get()
                && let Some((_, oldest)) = self.order.pop_first()
            {
                self.pairs.remove(&oldest);
            }
            self.pairs.entry(pair).or_insert(Cookies {
                client,
                returned: None,
                used: tick,
            })
        };
        self.order.insert(tick, pair);
        let cookie = cookies.returned.unwrap_or_else(|| {
            Cookie::new(cookies.client, None).expect("a client cookie alone is valid")
        });
        edns.options.push(EdnsOption::Cookie(cookie));
        Ok(Some(pair))
    }

    /// Keeps the server cookie of `cookie`, if it has one, for the next query of `pair` (RFC 7873 §5.3): a cookie
    /// with the client cookie alone leaves the known one.
    pub(crate) fn keep(&mut self, pair: Option<Pair>, cookie: Option<Cookie>) {
        if let (Some(pair), Some(cookie)) = (pair, cookie)
            && cookie.server().is_some()
            && let Some(cookies) = self.pairs.get_mut(&pair)
        {
            cookies.returned = Some(cookie);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::num::NonZeroUsize;

    use dedens_proto::edns::{Cookie, EdnsOption};
    use dedens_proto::{Message, Name, Question, RecordType};

    use super::{Jar, Pair};

    fn pair(port: u16) -> Pair {
        (
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), port),
        )
    }

    /// The cookie `jar` puts in a query for `pair`, drawing `fresh` as the client cookie of a pair not kept.
    fn sent(jar: &mut Jar, pair: Pair, fresh: [u8; 8]) -> Cookie {
        let mut query = Message::query(1, Question::new(Name::root(), RecordType::NS));
        jar.add(&mut query, pair, || Ok::<_, Infallible>(fresh))
            .expect("drawn");
        query
            .edns
            .into_iter()
            .flat_map(|edns| edns.options)
            .find_map(|option| match option {
                EdnsOption::Cookie(cookie) => Some(cookie),
                _ => None,
            })
            .expect("a cookie added")
    }

    #[test]
    fn the_pair_used_longest_ago_goes_past_the_bound() {
        let mut jar = Jar::new(NonZeroUsize::new(2).expect("not zero"));
        let returned = Cookie::new(*b"client.a", Some(b"server.a".as_slice())).expect("valid");
        assert_eq!(sent(&mut jar, pair(1), *b"client.a").client(), *b"client.a");
        jar.keep(Some(pair(1)), Some(returned));
        sent(&mut jar, pair(2), *b"client.b");
        // Pair 1 used again: pair 2 is the oldest when pair 3 comes.
        assert_eq!(sent(&mut jar, pair(1), *b"unused.1"), returned);
        sent(&mut jar, pair(3), *b"client.c");
        assert_eq!(sent(&mut jar, pair(1), *b"unused.1"), returned);
        assert_eq!(sent(&mut jar, pair(2), *b"client.d").client(), *b"client.d");
    }
}
