//! `dedensd` as an Oblivious `DoH` proxy (RFC 9230 §4, D94): the targets it forwards to, and the forwarding of a
//! request to one over HTTP/3.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use compio::net::ToSocketAddrsAsync as _;
use dedens_net::http3::Http3Pool;
use dedens_net::odoh::MAX_BODY;
use dedens_net::odoh::proxy::{
    Destination, Host, ProxyError, Target, failure, forward_request, forwarded,
};
use dedens_net::tls::Trust;
use http::Response;

/// How long a forward may take, the name's resolution, the connection and the target's response together, unless
/// the configuration says (D94).
const TIMEOUT: Duration = Duration::from_secs(5);

/// How long a thread keeps a connection to a target it has no request for (RFC 9230 §11.2 asks for connections kept
/// and shared).
const IDLE: Duration = Duration::from_secs(30);

/// How long the address a listed name resolved to is used before the name is resolved again (D94).
const RESOLVED_FOR: Duration = Duration::from_secs(60);

/// How many forwards a thread has in flight at once, apart from the questions it asks upstream (D94).
const MAX_FORWARDS: usize = 256;

/// The settings of a proxy: the targets it forwards to and how long it waits for one. A reload builds them again
/// and compares: they are fixed at start (D79).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    targets: Vec<Target>,
    timeout: Duration,
}

impl Settings {
    /// The settings of the `targets`, each `HOST[:PORT]`, and a `timeout_ms` for a forward. The targets are kept
    /// sorted and once each, so that the order of the list is no change.
    ///
    /// # Errors
    ///
    /// No target, or one that is not `HOST[:PORT]` (a name that is not a valid host name included).
    pub(crate) fn new(targets: &[String], timeout_ms: Option<NonZeroU32>) -> anyhow::Result<Self> {
        ensure!(!targets.is_empty(), "`odoh.proxy.targets` lists no target");
        let mut targets = targets
            .iter()
            .map(|text| {
                text.parse::<Target>()
                    .with_context(|| format!("`odoh.proxy.targets`: `{text}`"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        targets.sort_by_cached_key(ToString::to_string);
        targets.dedup();
        Ok(Self {
            targets,
            timeout: timeout_ms.map_or(TIMEOUT, |ms| Duration::from_millis(ms.get().into())),
        })
    }
}

/// What a serving thread keeps to forward: its connections to targets, the addresses it has checked and its count
/// of forwards in flight (D94).
#[derive(Debug)]
pub(crate) struct Forwarder {
    pool: Http3Pool,
    resolved: RefCell<HashMap<Target, (SocketAddr, Instant)>>,
    in_flight: Cell<usize>,
}

impl Forwarder {
    /// A forwarder checking the certificates of targets against `trust`.
    pub(crate) fn new(trust: Trust) -> Self {
        Self {
            pool: Http3Pool::new(IDLE).trusting(trust),
            resolved: RefCell::default(),
            in_flight: Cell::new(0),
        }
    }

    /// The address kept for `target` while `now` is before the end of the time it is used for.
    fn recall(&self, target: &Target, now: Instant) -> Option<SocketAddr> {
        let resolved = self.resolved.borrow();
        let &(addr, until) = resolved.get(target)?;
        (now < until).then_some(addr)
    }

    /// Keeps `addr`, checked at `now`, for `target`, for [`RESOLVED_FOR`].
    fn remember(&self, target: &Target, addr: SocketAddr, now: Instant) {
        self.resolved
            .borrow_mut()
            .insert(target.clone(), (addr, now + RESOLVED_FOR));
    }

    /// A place among the forwards in flight, if any is left.
    fn enter(&self) -> Option<InFlight<'_>> {
        let count = self.in_flight.get();
        (count < MAX_FORWARDS).then(|| {
            self.in_flight.set(count + 1);
            InFlight(&self.in_flight)
        })
    }
}

/// A forward in flight, counted until this is dropped.
struct InFlight<'a>(&'a Cell<usize>);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// The proxy: forwards to the targets it was set up with and no other.
#[derive(Debug)]
pub(crate) struct Proxy {
    settings: Settings,
}

impl Proxy {
    pub(crate) const fn new(settings: Settings) -> Self {
        Self { settings }
    }

    /// The response to a request for `destination` with the encrypted query `body`: the target's, or the error the
    /// proxy made (RFC 9230 §4.1, §4.3). Connections to targets are `forwarder`'s, so that requests share them
    /// (§11.2).
    pub(crate) async fn forward(
        &self,
        forwarder: &Forwarder,
        destination: &Destination,
        body: &[u8],
    ) -> Response<Vec<u8>> {
        match self.try_forward(forwarder, destination, body).await {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(error = error.token(), "ODoH forward failed");
                failure(error.status(), error)
            }
        }
    }

    async fn try_forward(
        &self,
        forwarder: &Forwarder,
        destination: &Destination,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>, ProxyError> {
        // Not a question of the target's name or port in the request, only of the list: a refused port is refused
        // as any target not listed (RFC 9230 §4.1 may refuse non-standard ports).
        if !self.settings.targets.contains(&destination.target) {
            return Err(ProxyError::HttpRequestDenied);
        }
        let _in_flight = forwarder
            .enter()
            .ok_or(ProxyError::ConnectionLimitReached)?;
        let deadline = Instant::now() + self.settings.timeout;
        let addr = address(forwarder, &destination.target, deadline).await?;
        let name = destination.target.server_name();
        let request =
            forward_request(destination, body).map_err(|_| ProxyError::ProxyInternalError)?;
        // The connection first, so that a timeout says which it was: the connection's or the response's.
        forwarder
            .pool
            .connect(addr, name.clone(), deadline)
            .await
            .map_err(|error| ProxyError::of(&error, false))?;
        let (head, body) = forwarder
            .pool
            .send(addr, name, &request, MAX_BODY, deadline)
            .await
            .map_err(|error| ProxyError::of(&error, true))?;
        Ok(forwarded(&head, body))
    }
}

/// Where to connect for `target`: a listed address as it is, a name's first address that is global (D94).
///
/// A name is resolved by the system resolver, once a minute at most per name: the address checked is kept, so that a
/// request does not wait for a lookup, and a name that points elsewhere later is checked again. A host whose
/// resolver is `dedensd` itself sends the lookup through its own pipeline, and a lookup that then needs a forward
/// waits for the one it came from: that is the deployment's to avoid (D94).
async fn address(
    forwarder: &Forwarder,
    target: &Target,
    deadline: Instant,
) -> Result<SocketAddr, ProxyError> {
    let name = match target.host() {
        Host::Address(ip) => return Ok(SocketAddr::new(*ip, target.port().get())),
        Host::Name(name) => name,
    };
    if let Some(addr) = forwarder.recall(target, Instant::now()) {
        return Ok(addr);
    }
    let resolved = compio::time::timeout_at(
        deadline,
        (name.as_str(), target.port().get()).to_socket_addrs_async(),
    )
    .await
    .map_err(|_| ProxyError::DnsTimeout)?
    .map_err(|_| ProxyError::DnsError)?
    .collect::<Vec<_>>();
    if resolved.is_empty() {
        return Err(ProxyError::DnsError);
    }
    let addr = resolved
        .into_iter()
        .find(|addr| is_global(addr.ip()))
        .ok_or(ProxyError::DestinationIpProhibited)?;
    forwarder.remember(target, addr, Instant::now());
    Ok(addr)
}

/// Whether `ip` is one the Internet routes: not in the IANA special-purpose registries (RFC 6890, RFC 5737,
/// RFC 3849, RFC 4193, RFC 9637), nor multicast; IPv6 addresses that embed an IPv4 one as their last 32 bits, as
/// the mapped and the NAT64 ones, are judged by it.
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_v4(ip),
        IpAddr::V6(ip) => is_global_v6(ip),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        // This network (0/8), private (10/8), shared (100.64/10), loopback (127/8), link-local (169.254/16).
        // Multicast (224/4) and reserved (240/4), the broadcast address with it.
        (0 | 10 | 127 | 224..=255, ..) | (100, 64..=127, _) | (169, 254, _)
        // Private (172.16/12), protocol assignments (192.0.0/24: the whole block, on purpose, although 192.0.0.9 and
        // 192.0.0.10 are globally reachable: no listed target needs them), documentation (192.0.2/24,
        // 198.51.100/24, 203.0.113/24), the deprecated 6to4 relay anycast (192.88.99/24), private (192.168/16),
        // benchmarking (198.18/15).
        | (172, 16..=31, _) | (192, 0, 0 | 2) | (192, 88, 99) | (192, 168, _)
        | (198, 18 | 19, _) | (198, 51, 100) | (203, 0, 113)
    )
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let [first, second, third, fourth, fifth, sixth, high, low] = ip.segments();
    let embedded = || {
        let ([a, b], [c, d]) = (high.to_be_bytes(), low.to_be_bytes());
        Ipv4Addr::new(a, b, c, d)
    };
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_global_v4(mapped);
    }
    if (first, second, third, fourth, fifth, sixth) == (0x64, 0xff9b, 0, 0, 0, 0) {
        return is_global_v4(embedded());
    }
    // Global unicast is 2000::/3, less protocol assignments (2001::/23), documentation (2001:db8::/32, 3fff::/20)
    // and 6to4 (2002::/16, deprecated by RFC 7526).
    first & 0xe000 == 0x2000
        && !(first == 0x2001 && (second < 0x200 || second == 0xdb8))
        && first != 0x2002
        && !(first == 0x3fff && second < 0x1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the special-purpose registries keep out, and the addresses around them that are in.
    #[test]
    fn addresses_that_are_not_global_are_refused() {
        for refused in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "100::1",
            "2001:db8::1",
            "2001::1",
            "2001:1ff::1",
            "2002::1",
            "3fff::1",
            "3fff:fff::1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "fec0::1",
        ] {
            let ip = refused.parse().expect("an address");
            assert!(!is_global(ip), "{refused}");
        }
        for global in [
            "1.1.1.1",
            "9.9.9.9",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.0.1.1",
            "192.88.98.1",
            "192.88.100.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2620:fe::fe",
            "2001:200::1",
            "3fff:1000::1",
            "2001:4860:4860::8888",
            "::ffff:1.1.1.1",
            "64:ff9b::101:101",
        ] {
            let ip = global.parse().expect("an address");
            assert!(is_global(ip), "{global}");
        }
    }

    /// D94: a forward takes a place, given back when it ends, and there are `MAX_FORWARDS` of them.
    #[test]
    fn forwards_in_flight_are_counted_up_to_the_most() {
        let forwarder = Forwarder::new(Trust::default());
        let mut places = (0..MAX_FORWARDS)
            .map(|_| forwarder.enter().expect("a place"))
            .collect::<Vec<_>>();
        assert_eq!(forwarder.in_flight.get(), MAX_FORWARDS);
        assert!(forwarder.enter().is_none());
        drop(places.pop());
        assert_eq!(forwarder.in_flight.get(), MAX_FORWARDS - 1);
        let place = forwarder.enter();
        assert!(place.is_some());
        assert!(forwarder.enter().is_none());
        drop(place);
        drop(places);
        assert_eq!(forwarder.in_flight.get(), 0);
    }

    /// D94: the address a name resolved to is used for `RESOLVED_FOR`, from when it was checked, and not after.
    #[test]
    fn a_resolved_address_is_used_for_a_minute() {
        let forwarder = Forwarder::new(Trust::default());
        let target = "odoh.example".parse::<Target>().expect("a target");
        let addr = SocketAddr::from(([1, 1, 1, 1], 443));
        let checked = Instant::now();
        assert_eq!(forwarder.recall(&target, checked), None);
        forwarder.remember(&target, addr, checked);
        let second = Duration::from_secs(1);
        for at in [checked, checked + RESOLVED_FOR.saturating_sub(second)] {
            assert_eq!(forwarder.recall(&target, at), Some(addr));
        }
        for at in [checked + RESOLVED_FOR, checked + RESOLVED_FOR + second] {
            assert_eq!(forwarder.recall(&target, at), None);
        }
        let other = "other.example".parse::<Target>().expect("a target");
        assert_eq!(forwarder.recall(&other, checked), None);
    }

    /// Settings need a target and read each as `HOST[:PORT]`; the order and repeats of the list change nothing.
    #[test]
    fn settings_read_their_targets() {
        let read = |targets: &[&str]| {
            let targets = targets.iter().map(|&t| t.to_owned()).collect::<Vec<_>>();
            Settings::new(&targets, None)
        };
        assert!(read(&["odoh.example", "127.0.0.1:4443"]).is_ok());
        assert!(read(&[]).is_err());
        for bad in [
            "a b",
            "a_b.example",
            "-a.example",
            "a..example",
            "a.example:0",
        ] {
            let error = read(&["odoh.example", bad]).unwrap_err();
            assert!(
                format!("{error:#}").contains(&format!("`{bad}`")),
                "{error:#}"
            );
        }
        assert_eq!(
            read(&["b.example", "A.example", "b.example:443", "a.example."]).unwrap(),
            read(&["a.example", "b.example"]).unwrap()
        );
    }
}
