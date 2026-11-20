//! The infrastructure cache: what the resolver learned of each authoritative server, and which one to ask next.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use dedens_cache::{ConfigError, Cost, Store};
use dedens_proto::{MAX_NAME_LEN, Name, Rcode};
use rand_core::CryptoRng;

use crate::metrics::Infra as Metrics;

/// Whether a server speaks EDNS (RFC 6891 §7), as the transport's `dedens_net::Edns` says (D190).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Edns {
    /// Not seen yet: ask with EDNS.
    #[default]
    Unknown,
    /// It answered an EDNS query with an OPT record.
    Supported,
    /// It answered a query with EDNS by `rejected`, FORMERR or NOTIMP, and no OPT record, then the query without
    /// EDNS by `answered`, NOERROR, NXDOMAIN or YXDOMAIN: ask without EDNS.
    Unsupported {
        /// The rcode of the response to the query with EDNS.
        rejected: Rcode,
        /// The rcode of the response to the query without.
        answered: Rcode,
    },
}

/// What a server showed of itself, which the next query to it goes by: the transport's quirks (recursive step 03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Marks {
    /// Whether it speaks EDNS.
    pub edns: Edns,
    /// It answered a question in another case than asked: no `0x20` for it (RFC 5452 §9.1, D184).
    pub no_case: bool,
    /// It answered BADCOOKIE twice over UDP, then over TCP (RFC 7873 §5.3): ask it over TCP. A truncated response
    /// tells only that the answer was large, and sets no mark (D190).
    pub tcp: bool,
}

impl Marks {
    /// The marks held updated with `seen`: a mark seen stays until the entry expires, and a server that answered
    /// with EDNS keeps it whatever a later answer shows, so that a forged FORMERR cannot turn it off (Unbound's
    /// `infra_edns_update`).
    fn merged(self, seen: Self) -> Self {
        let edns = match (self.edns, seen.edns) {
            (held, Edns::Unknown) | (held @ Edns::Supported, Edns::Unsupported { .. }) => held,
            (_, seen) => seen,
        };
        Self {
            edns,
            no_case: self.no_case || seen.no_case,
            tcp: self.tcp || seen.tcp,
        }
    }
}

/// The server to ask next, how long to wait for it, and how to ask it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice {
    /// Its address.
    pub server: SocketAddr,
    /// How long to wait for its answer: its retransmission timeout, at most the time the resolution has left.
    pub timeout: Duration,
    /// What it showed of itself.
    pub marks: Marks,
}

/// What the cache knows of authoritative servers, shared by threads, within a byte budget: per server address its
/// round-trip time (RFC 6298 §2) and [`Marks`], per server address and zone whether it is lame (RFC 4697 §2.2).
///
/// The store is `dedens-cache`'s (D116, D194), as the `RRset` cache's: sharded, each shard behind its own lock held
/// for one call (never across an `.await`), S3-FIFO eviction. Time comes in as seconds from the caller.
#[derive(Debug)]
pub struct InfraCache {
    store: Store<Entry>,
    capacity: usize,
    metrics: Metrics,
}

impl InfraCache {
    /// The default capacity, in bytes: about 16,000 servers (260 bytes each, with their slot), more than Unbound's
    /// 10,000 (`infra-cache-numhosts`, `util/config_file.c` `config_create`), whose entries are per server and zone
    /// where a server's are here per server only. BIND has no separate budget: its address database sits in `max-cache-size`.
    pub const DEFAULT_CAPACITY: usize = 4 << 20;

    /// The least wait for an answer: as Unbound's `RTT_MIN_TIMEOUT` (`util/rtt.c`). RFC 6298 §2.4's one second is
    /// for TCP, whose retransmissions cost more than a DNS query does. BIND waits at least 800 ms
    /// (`retryinterval`, `lib/dns/resolver.c` `dns_resolver_create`).
    pub const MIN_TIMEOUT: Duration = Duration::from_millis(50);

    /// The most a backed-off timeout grows to: as Unbound's `RTT_MAX_TIMEOUT` (`util/rtt.c`), and twice RFC 6298
    /// §2.5's 60 s least maximum. BIND stops at 9 s (`MAX_SINGLE_QUERY_TIMEOUT`, `lib/dns/resolver.c`).
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(120);

    /// The timeout of a server not yet heard: as Unbound's `UNKNOWN_SERVER_NICENESS` (`iterator/iterator.c`), so
    /// that it falls in [`InfraCache::BAND`] of the fastest server and unknown servers get asked. RFC 6298 §2.1's one
    /// second is TCP's. BIND gives an unknown server a random 1 to 31 µs, so that it is asked first
    /// (`lib/dns/adb.c` `new_adbentry`).
    pub const UNKNOWN_TIMEOUT: Duration = Duration::from_millis(376);

    /// The servers within this of the fastest are drawn from at random: Unbound's `RTT_BAND` (`iterator/iterator.h`,
    /// `iter_filter_order`). A choice of one server, the fastest, would tell a forger where the query goes
    /// (RFC 5452 §4.4). BIND asks the fastest, and ages the others' times by 2 % at each choice so that they get asked
    /// in turn (`DNS_ADB_RTTADJAGE`, `lib/dns/adb.c` `adjustsrtt`).
    pub const BAND: Duration = Duration::from_millis(400);

    /// Timeouts in a row past which a server is skipped until its probe time, its timeout from the last one:
    /// Unbound's `TIMEOUT_COUNT_MAX` (`services/cache/infra.h`), which BIND has for EDNS (`MAX_EDNS0_TIMEOUTS`,
    /// `lib/dns/resolver.c`).
    pub const TIMEOUT_LIMIT: u8 = 3;

    /// Seconds a server's entry lives from when it was made, its time and marks then learned anew: Unbound's
    /// `infra-host-ttl` (`util/config_file.c` `config_create`). Counted from the making and not the last use, so that
    /// the marks of a server asked all the time expire too, and a server since fixed is asked plainly. BIND keeps
    /// an address 60 s past its last use (`dns_adb_entrywindow`, `lib/dns/adb.c`).
    pub const SERVER_TTL: u32 = 900;

    /// Seconds a server stays lame for a zone: the 30 minutes RFC 4697 §2.2.1 recommends at least. Unbound keeps it
    /// with the server and zone's entry, `infra-host-ttl`, 900 s; BIND keeps none (`lame-ttl` disabled,
    /// `bin/named/server.c` `configure_view`).
    pub const LAME_TTL: u32 = 1800;

    /// An empty cache of `capacity` bytes in `shards` shards, a power of two (D116).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Shards`] when `shards` is not a power of two up to 65536, [`ConfigError::Capacity`] when a
    /// shard's share of `capacity` cannot hold the longest entry.
    pub fn new(capacity: usize, shards: usize) -> Result<Self, ConfigError> {
        Ok(Self {
            // An entry is its key alone (`Cost` 0): the longest key is the longest entry.
            store: Store::new(capacity, shards, Some(KEY_LEN), KEY_LEN)?,
            capacity,
            metrics: Metrics::new(),
        })
    }

    /// Learns that `server` answered after `rtt` and showed `seen`, at `now`: its round-trip time is smoothed in
    /// (RFC 6298 §2.3), its timeouts in a row cleared.
    pub fn reply(&self, server: SocketAddr, rtt: Duration, seen: Marks, now: u32) {
        let rtt = millis(rtt);
        self.server(server, now, |held, _| {
            held.rtt = match held.rtt {
                // RFC 6298 §5.7: after backing off, the old estimate is likely wrong.
                Rtt::Measured { srtt, rttvar, .. } if held.timeouts < Self::TIMEOUT_LIMIT => {
                    Rtt::smoothed(srtt, rttvar, rtt)
                }
                _ => Rtt::first(rtt),
            };
            held.timeouts = 0;
            held.marks = held.marks.merged(seen);
        });
    }

    /// Learns that `server` answered, after a time that says nothing of its round trip over the transport its
    /// timeout is for, at `now`: the response came over TCP after the query moved there from UDP (D191, D196), whose
    /// connection setup and size are not the server's UDP time. It showed `seen`, its timeouts in a row are
    /// cleared, and its round-trip time stays as it was.
    pub fn answered(&self, server: SocketAddr, seen: Marks, now: u32) {
        self.server(server, now, |held, _| {
            held.timeouts = 0;
            held.marks = held.marks.merged(seen);
        });
    }

    /// Learns that `server` did not answer within `sent`, the timeout its query was sent with, at `now`. Its timeout
    /// doubles from `sent` (RFC 6298 §5.5), unless an answer since brought it under `sent`, as Unbound's `rtt_lost`
    /// does: the queries in flight together back off once. An entry made anew since the query left, expired or
    /// evicted, doubles from `sent` too, as Unbound's `infra_rtt_update`. Past [`InfraCache::TIMEOUT_LIMIT`]
    /// timeouts in a row, it is skipped until its probe time, its timeout from now.
    pub fn timeout(&self, server: SocketAddr, sent: Duration, now: u32) {
        let sent = millis(sent);
        self.server(server, now, |held, renewed| {
            if renewed {
                held.rtt.back_off(sent);
            }
            let rto = held.rtt.rto();
            if rto >= sent {
                held.rtt.back_off(sent.saturating_mul(2).min(millis(Self::MAX_TIMEOUT)).max(rto));
            }
            held.timeouts = held.timeouts.saturating_add(1);
            if held.timeouts >= Self::TIMEOUT_LIMIT {
                held.probe = now.saturating_add(held.rtt.rto().div_ceil(1000));
                tracing::debug!(%server, timeouts = held.timeouts, probe = held.probe, "server skipped");
            }
        });
    }

    /// Learns at `now` that `server` is lame for `zone`, not authoritative for the zone delegated to it: it is not
    /// asked for the zone for [`InfraCache::LAME_TTL`] seconds, but for its subzones still (RFC 4697 §2.2.1).
    pub fn lame(&self, server: SocketAddr, zone: &Name<'_>, now: u32) {
        let mut key = [0; KEY_LEN];
        let key = lame_key(&mut key, server, zone);
        let until = now.saturating_add(Self::LAME_TTL);
        let ((), evicted) = self
            .store
            .upsert(key, Entry::Lame { until }, |held, offered| {
                if let Some(offered) = offered {
                    *held = offered;
                }
            });
        self.metrics.evicted(evicted);
        tracing::debug!(%server, %zone, "server lame");
    }

    /// The server of `servers`, the addresses of `zone`'s name servers, to ask next at `now`, and how; `None` when
    /// every one is skipped for its timeouts.
    ///
    /// Servers lame for `zone` are left out, unless all are (RFC 4697 §2.2.1); of the rest, one is drawn with `rng`
    /// from those whose timeout is within [`InfraCache::BAND`] of the least, a server not yet heard counted at
    /// [`InfraCache::UNKNOWN_TIMEOUT`]. The draw is unpredictable to a forger (RFC 5452 §4.4, §9.2). The timeout is
    /// the server's, at most `remaining`, the time the resolution has left.
    pub fn select(
        &self,
        servers: &[SocketAddr],
        zone: &Name<'_>,
        remaining: Duration,
        now: u32,
        rng: &mut impl CryptoRng,
    ) -> Option<Choice> {
        let mut candidates = Vec::with_capacity(servers.len());
        for &server in servers {
            let known = self.store.get(&server_key(server), |held| match held {
                Entry::Server(held) => Some(held.at(now)),
                Entry::Lame { .. } => None,
            });
            let (rto, marks) = match known {
                Some(held) if held.timeouts >= Self::TIMEOUT_LIMIT && now < held.probe => continue,
                Some(held) => (held.rtt.rto(), held.marks),
                None => (millis(Self::UNKNOWN_TIMEOUT), Marks::default()),
            };
            candidates.push((server, rto, marks, self.is_lame(server, zone, now)));
        }
        let all_lame = candidates.iter().all(|&(.., lame)| lame);
        candidates.retain(|&(.., lame)| all_lame || !lame);
        let least = candidates.iter().map(|&(_, rto, ..)| rto).min();
        self.metrics.selected(least.is_some());
        let band = least?.saturating_add(millis(Self::BAND));
        candidates.retain(|&(_, rto, ..)| rto <= band);
        let &(server, rto, marks, _) = candidates.get(draw(rng, candidates.len()))?;
        Some(Choice {
            server,
            timeout: Duration::from_millis(u64::from(rto)).min(remaining),
            marks,
        })
    }

    /// Number of entries: servers, and servers lame for a zone.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether there is no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Bytes taken, at most the capacity (D116).
    #[must_use]
    pub fn used(&self) -> usize {
        self.store.used()
    }

    /// The bytes it was made with: a reload keeps a cache of the same capacity (D195).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Whether `server` is lame for `zone` at `now`.
    fn is_lame(&self, server: SocketAddr, zone: &Name<'_>, now: u32) -> bool {
        let mut key = [0; KEY_LEN];
        let key = lame_key(&mut key, server, zone);
        self.store
            .get(key, |held| match held {
                Entry::Lame { until } => Some(now < *until),
                Entry::Server(_) => None,
            })
            .unwrap_or(false)
    }

    /// Changes the entry of `server` at `now`, a new one if none is held or the one held expired, which `change`
    /// is told.
    fn server(&self, server: SocketAddr, now: u32, change: impl FnOnce(&mut Server, bool)) {
        let new = Entry::Server(Server::new(now));
        let ((), evicted) = self
            .store
            .upsert(&server_key(server), new, |held, offered| {
                let (mut changed, renewed) = match held {
                    Entry::Server(held) if offered.is_none() => (*held, true),
                    Entry::Server(held) => (held.at(now), held.expired(now)),
                    Entry::Lame { .. } => (Server::new(now), true),
                };
                change(&mut changed, renewed);
                *held = Entry::Server(changed);
            });
        self.metrics.evicted(evicted);
    }
}

/// The value of a key, its first byte telling which: a server's, or a server's lameness for a zone.
#[derive(Debug)]
enum Entry {
    Server(Server),
    /// Lame until this time.
    Lame {
        until: u32,
    },
}

impl Cost for Entry {
    fn cost(&self) -> usize {
        // All inline, in the slot the store charges.
        0
    }
}

/// What the cache knows of one server.
#[derive(Debug, Clone, Copy)]
struct Server {
    /// When the entry was made, which it lives [`InfraCache::SERVER_TTL`] from.
    born: u32,
    rtt: Rtt,
    timeouts: u8,
    /// Past [`InfraCache::TIMEOUT_LIMIT`] timeouts, the time it is skipped until.
    probe: u32,
    marks: Marks,
}

impl Server {
    fn new(now: u32) -> Self {
        Self {
            born: now,
            rtt: Rtt::Unknown {
                rto: millis(InfraCache::UNKNOWN_TIMEOUT),
            },
            timeouts: 0,
            probe: 0,
            marks: Marks::default(),
        }
    }

    /// The entry as it stands at `now`: itself until [`InfraCache::SERVER_TTL`] after its making, then made anew;
    /// a server backed off to [`InfraCache::MAX_TIMEOUT`] keeps its time, timeouts and probe time, so that its
    /// expiry does not bring a flood of queries on it, as Unbound's `infra_host`. A server backed off less is
    /// heard anew: kept, its timeout would leave it out of the band of a faster server for good, no query to it
    /// ever bringing it back.
    fn at(self, now: u32) -> Self {
        if !self.expired(now) {
            return self;
        }
        let mut new = Self::new(now);
        if self.rtt.rto() >= millis(InfraCache::MAX_TIMEOUT) {
            new.rtt = self.rtt;
            new.timeouts = self.timeouts;
            new.probe = self.probe;
        }
        new
    }

    /// Whether it is [`InfraCache::SERVER_TTL`] old at `now`; a clock gone back keeps it.
    const fn expired(&self, now: u32) -> bool {
        now.saturating_sub(self.born) >= InfraCache::SERVER_TTL
    }
}

/// A server's round-trip time and retransmission timeout, in milliseconds (RFC 6298 §2).
#[derive(Debug, Clone, Copy)]
enum Rtt {
    /// No answer heard: the timeout, [`InfraCache::UNKNOWN_TIMEOUT`] backed off by the timeouts since.
    Unknown { rto: u32 },
    /// The smoothed round-trip time, its variation, and the timeout.
    Measured { srtt: u32, rttvar: u32, rto: u32 },
}

impl Rtt {
    /// From the first measurement `r` (RFC 6298 §2.2).
    fn first(r: u32) -> Self {
        Self::measured(r, r / 2)
    }

    /// `r` smoothed into `srtt` and `rttvar` (RFC 6298 §2.3): `rttvar` first, from the old `srtt`.
    fn smoothed(srtt: u32, rttvar: u32, r: u32) -> Self {
        let rttvar = (3 * u64::from(rttvar) + u64::from(srtt.abs_diff(r))) / 4;
        let srtt = (7 * u64::from(srtt) + u64::from(r)) / 8;
        Self::measured(saturate(srtt), saturate(rttvar))
    }

    /// `srtt` and `rttvar` with their timeout, `srtt + 4 * rttvar` (RFC 6298 §2.3) within the bounds.
    fn measured(srtt: u32, rttvar: u32) -> Self {
        let rto = srtt.saturating_add(rttvar.saturating_mul(4));
        Self::Measured {
            srtt,
            rttvar,
            rto: rto.clamp(
                millis(InfraCache::MIN_TIMEOUT),
                millis(InfraCache::MAX_TIMEOUT),
            ),
        }
    }

    const fn rto(&self) -> u32 {
        match *self {
            Self::Unknown { rto } | Self::Measured { rto, .. } => rto,
        }
    }

    /// Sets the timeout to `backed`, keeping the estimate (RFC 6298 §5.5).
    const fn back_off(&mut self, backed: u32) {
        match self {
            Self::Unknown { rto } | Self::Measured { rto, .. } => *rto = backed,
        }
    }
}

/// `duration` in whole milliseconds, `u32::MAX` at most: 49 days, past any bound here.
fn millis(duration: Duration) -> u32 {
    saturate(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

fn saturate(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// An index below `len` drawn with `rng`; 0 when `len` is 0, which `get` then misses. Lemire's multiply-shift: a
/// bias under `len / 2^32`, nothing a forger can use.
pub(crate) fn draw(rng: &mut impl CryptoRng, len: usize) -> usize {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    usize::try_from((u64::from(rng.next_u32()) * len) >> 32).unwrap_or_default()
}

/// The longest key: a lame key of an IPv6 server and the longest zone.
const KEY_LEN: usize = ADDRESS_LEN + MAX_NAME_LEN;

/// A key's kind, an address family, sixteen bytes of address and the port.
const ADDRESS_LEN: usize = 20;

/// The first byte of a server's key, and of its lame key.
const SERVER: u8 = 0;
const LAME: u8 = 1;

/// The key of `server`'s entry.
fn server_key(server: SocketAddr) -> [u8; ADDRESS_LEN] {
    address(SERVER, server)
}

/// The key of `server`'s lameness for `zone` in `buf`: its address, then the zone's wire form, ASCII letters
/// lowered (RFC 4343); a length byte, at most 63, is below `A` and kept.
fn lame_key<'b>(buf: &'b mut [u8; KEY_LEN], server: SocketAddr, zone: &Name<'_>) -> &'b [u8] {
    buf[..ADDRESS_LEN].copy_from_slice(&address(LAME, server));
    let mut name = [0; MAX_NAME_LEN];
    let wire = zone.to_wire(&mut name);
    let end = ADDRESS_LEN + wire.len();
    buf[ADDRESS_LEN..end].copy_from_slice(wire);
    buf[ADDRESS_LEN..end].make_ascii_lowercase();
    &buf[..end]
}

/// `kind`, then `server`'s family, address and port.
fn address(kind: u8, server: SocketAddr) -> [u8; ADDRESS_LEN] {
    let mut key = [0; ADDRESS_LEN];
    key[0] = kind;
    match server.ip() {
        IpAddr::V4(ip) => {
            key[1] = 4;
            key[2..6].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            key[1] = 6;
            key[2..18].copy_from_slice(&ip.octets());
        }
    }
    key[18..].copy_from_slice(&server.port().to_be_bytes());
    key
}
