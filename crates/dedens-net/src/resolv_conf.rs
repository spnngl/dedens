//! The stub resolver's configuration, `/etc/resolv.conf` (resolv.conf(5)): the servers to ask, and the search
//! list a name with too few dots is tried under (D18, D32).

use std::net::{IpAddr, Ipv6Addr};

use dedens_proto::Name;

/// What a `resolv.conf` says of the servers and the search list; the rest of it is not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvConf {
    /// The `nameserver` addresses, in order, each asked on port 53: an IPv6 one may name its zone (`fe80::1%en0`),
    /// which only the system can turn into an index.
    pub nameservers: Vec<String>,
    /// The `search` domains, or the `domain` one, whichever comes last.
    pub search: Vec<Name<'static>>,
    /// A name with at least this many dots is tried as it is before the search list (`options ndots:N`, at
    /// most 15). Default: 1.
    pub ndots: u8,
}

impl Default for ResolvConf {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            search: Vec::new(),
            ndots: 1,
        }
    }
}

impl ResolvConf {
    /// Reads `resolv.conf` text as the stub resolver does: a line whose keyword is unknown, or whose value does not
    /// read, is skipped; `#` and `;` start comments.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut conf = Self::default();
        for line in text.lines() {
            let line = line.split(['#', ';']).next().unwrap_or_default();
            let mut words = line.split_ascii_whitespace();
            match words.next() {
                Some("nameserver") => {
                    if let Some(address) = words.next().filter(|w| is_address(w)) {
                        conf.nameservers.push(address.to_owned());
                    }
                }
                Some("search") => conf.search = words.filter_map(|w| w.parse().ok()).collect(),
                Some("domain") => {
                    conf.search = words
                        .next()
                        .and_then(|w| w.parse().ok())
                        .into_iter()
                        .collect();
                }
                Some("options") => {
                    let ndots = words
                        .rev()
                        .find_map(|w| w.strip_prefix("ndots:").filter(|n| is_number(n)));
                    if let Some(ndots) = ndots {
                        conf.ndots = ndots.parse().map_or(15, |n: u8| n.min(15));
                    }
                }
                _ => {}
            }
        }
        conf
    }

    /// The names to ask for `name`, in order, as dig's `+search` tries them: none but `name` when it ends with a
    /// dot or the search list is empty; else `name` under each search domain, and `name` itself first when it has
    /// at least [`ndots`](Self::ndots) dots, last otherwise. `None` when `name` does not read.
    #[must_use]
    pub fn candidates(&self, name: &str) -> Option<Vec<Name<'static>>> {
        let absolute: Name<'static> = name.parse().ok()?;
        if name.ends_with('.') || self.search.is_empty() {
            return Some(vec![absolute]);
        }
        let under = self
            .search
            .iter()
            .filter_map(|domain| format!("{name}.{domain}").parse().ok());
        let dots = absolute.label_count().saturating_sub(1);
        Some(if dots >= usize::from(self.ndots) {
            std::iter::once(absolute).chain(under).collect()
        } else {
            under.chain(std::iter::once(absolute)).collect()
        })
    }
}

/// Whether `word` is an IP address, an IPv6 one possibly followed by `%` and its zone.
fn is_address(word: &str) -> bool {
    match word.split_once('%') {
        Some((ip, zone)) => !zone.is_empty() && ip.parse::<Ipv6Addr>().is_ok(),
        None => word.parse::<IpAddr>().is_ok(),
    }
}

/// Whether `text` is decimal digits, as many as they are.
fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(names: &[&str]) -> Vec<Name<'static>> {
        names.iter().map(|n| n.parse().expect("a name")).collect()
    }

    #[test]
    fn reads_servers_search_and_ndots() {
        let conf = ResolvConf::parse(
            "# comment\nnameserver 192.0.2.1\nnameserver 2001:db8::1 ; trailing\nnameserver fe80::1%en0\n\
             nameserver nonsense\ndomain example.org\nsearch example.com corp.example.\noptions rotate ndots:2\n\
             sortlist 130.155.160.0\n",
        );
        assert_eq!(
            conf.nameservers,
            ["192.0.2.1", "2001:db8::1", "fe80::1%en0"]
        );
        assert_eq!(conf.search, names(&["example.com.", "corp.example."]));
        assert_eq!(conf.ndots, 2);
        assert_eq!(
            ResolvConf::parse("search a.example\ndomain b.example").search,
            names(&["b.example."])
        );
        assert_eq!(ResolvConf::parse("options ndots:99").ndots, 15);
        assert_eq!(ResolvConf::parse("options ndots:300").ndots, 15);
        assert_eq!(ResolvConf::parse("options ndots:+3").ndots, 1);
        assert_eq!(
            ResolvConf::parse("nameserver 192.0.2.1%en0\nnameserver fe80::1%").nameservers,
            Vec::<String>::new()
        );
        assert_eq!(ResolvConf::parse(""), ResolvConf::default());
    }

    #[test]
    fn candidates_follow_ndots() {
        let conf = ResolvConf::parse("search example.com example.net\n");
        assert_eq!(
            conf.candidates("www"),
            Some(names(&["www.example.com.", "www.example.net.", "www."]))
        );
        assert_eq!(
            conf.candidates("www.example"),
            Some(names(&[
                "www.example.",
                "www.example.example.com.",
                "www.example.example.net."
            ]))
        );
        assert_eq!(conf.candidates("www."), Some(names(&["www."])));
        // An escaped dot is in a label, not between two: the name is tried under the search list first.
        assert_eq!(
            conf.candidates("a\\.b")
                .and_then(|n| n.first().map(ToString::to_string)),
            Some("a\\.b.example.com.".to_owned())
        );
        assert_eq!(
            ResolvConf::default().candidates("www"),
            Some(names(&["www."]))
        );
        assert_eq!(conf.candidates("a..b"), None);
    }
}
