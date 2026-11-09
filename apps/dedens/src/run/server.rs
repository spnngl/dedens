//! Choosing the servers of the queries: those of the command line, else the first name server of `resolv.conf`,
//! each with its transport, port (RFC 7858 §3.1, RFC 9250 §4.1.1, RFC 9110 §4.2.2, RFC 7252 §6.1), certificate name,
//! `DoH` template (D81 for CoAP) and Oblivious `DoH` proxy (D79).

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use compio::rustls::pki_types::ServerName;
use dedens_net::client::Server;
use dedens_net::coap::dns::path_segments;
use dedens_net::doh::{DEFAULT_PATH, Template, TemplateError};
use dedens_net::resolv_conf::ResolvConf;
use dedens_proto::Transport;
use dedens_scenario::Options;

use super::Endpoint;
use crate::args::Cli;

/// The resolver configuration, from `DEDENS_RESOLV_CONF` when set (for tests), else /etc/resolv.conf.
pub(super) fn resolv_conf() -> anyhow::Result<ResolvConf> {
    let path = std::env::var_os("DEDENS_RESOLV_CONF")
        .map_or_else(|| PathBuf::from("/etc/resolv.conf"), PathBuf::from);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(ResolvConf::parse(&text))
}

/// The servers of the command line, in order, each once.
pub(super) fn servers(cli: &Cli, conf: Option<&ResolvConf>) -> anyhow::Result<Vec<Endpoint>> {
    let mut servers = Vec::new();
    for named in cli.servers() {
        let address = server(Some(named), conf, cli.port, &cli.options)?;
        if !servers.contains(&address) {
            servers.push(address);
        }
    }
    Ok(servers)
}

/// The port of DNS over TLS (RFC 7858 §3.1) and over QUIC (RFC 9250 §4.1.1).
const ENCRYPTED_PORT: u16 = 853;

/// The port of DNS over HTTPS (RFC 8484 §3, RFC 9110 §4.2.2).
const HTTPS_PORT: u16 = 443;

/// The port of CoAP (RFC 7252 §6.1; RFC 9953 §3).
const COAP_PORT: u16 = 5683;

/// The URI template of the `DoH` server `host` (an IPv6 address without brackets) at `port` and `path`.
fn template(host: &str, port: u16, path: &str) -> Result<Template, TemplateError> {
    let brackets = if host.contains(':') {
        ("[", "]")
    } else {
        ("", "")
    };
    let port = if port == HTTPS_PORT {
        String::new()
    } else {
        format!(":{port}")
    };
    Template::parse(&format!(
        "https://{}{host}{}{port}{path}",
        brackets.0, brackets.1
    ))
}

/// `named`, else the first name server of `conf`: an address, IPv6 possibly in brackets or with its zone, or a
/// host name, each with or without a port; `tls://` or `quic://` before it for TLS or QUIC, `https://` and a path
/// after it for DNS over HTTPS (else the path of `options`, else `/dns-query`), `coap://` and a path after it for
/// DNS over CoAP (D81), and `#NAME` after it for the name the server's certificate must hold, else its host name,
/// else its address. With `+odoh-proxy`, the server must be an `https://` one: the target of Oblivious `DoH`
/// through that proxy. Without a port, `port`, else 443 over HTTPS, else 5683 over CoAP, else 853 over TLS or QUIC
/// (`options` or a scheme), else 53.
pub(super) fn server(
    named: Option<&str>,
    conf: Option<&ResolvConf>,
    port: Option<u16>,
    options: &Options,
) -> anyhow::Result<Endpoint> {
    let text = match named {
        Some(text) => text,
        None => conf
            .and_then(|conf| conf.nameservers.first())
            .ok_or_else(|| {
                anyhow!("no server: give @server, or a nameserver in /etc/resolv.conf")
            })?,
    };
    let given = text;
    let (text, forced) = [
        ("tls://", Transport::Tls),
        ("quic://", Transport::Quic),
        ("https://", Transport::Https),
        ("coap://", Transport::Coap),
    ]
    .into_iter()
    .find_map(|(scheme, transport)| Some((text.strip_prefix(scheme)?, Some(transport))))
    .unwrap_or((text, None));
    let (text, name) = match text.rsplit_once('#') {
        Some((text, name)) => (text, Some(name)),
        None => (text, None),
    };
    let https = forced == Some(Transport::Https);
    // The target of Oblivious `DoH` is a server asked over HTTPS, the proxy a URI: both are found as one (D79).
    let proxy = oblivious_proxy(options, forced, given)?;
    let forced = proxy.as_ref().map_or(forced, |_| Some(Transport::Odoh));
    let coap = forced == Some(Transport::Coap) || options.coap == Some(true);
    // CoAP is over UDP and unprotected: no other transport under it.
    if coap
        && (forced.is_some_and(|transport| transport != Transport::Coap)
            || options.tcp == Some(true)
            || options.encrypted()
            || options.https())
    {
        bail!("server {given}: CoAP goes with no TCP, TLS, QUIC, HTTPS or Oblivious DoH");
    }
    let (text, url_path) = match text.split_once('/') {
        Some((host, path)) if https || forced == Some(Transport::Coap) => {
            (host, Some(format!("/{path}")))
        }
        _ => (text, None),
    };
    let doh = https || options.https() || proxy.is_some();
    let encrypted = (forced.is_some() && !coap) || options.encrypted() || doh;
    // `[HOST]:PORT`, `[HOST]`, `HOST:PORT` with a single colon, else the host alone: an IPv6 address among them.
    let (host, written) = match text.strip_prefix('[').and_then(|text| text.split_once(']')) {
        Some((host, "")) => (host, None),
        Some((host, port)) => (host, Some(port.strip_prefix(':').unwrap_or(port))),
        None => match text.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            _ => (text, None),
        },
    };
    let port = match written {
        Some(written) => written
            .parse()
            .with_context(|| format!("server {given}: not a port"))?,
        None => port.unwrap_or(match (doh, coap, encrypted) {
            (true, ..) => HTTPS_PORT,
            (_, true, _) => COAP_PORT,
            (.., true) => ENCRYPTED_PORT,
            _ => 53,
        }),
    };
    // An address, its zone aside, has no name to check.
    let literal = host
        .split_once('%')
        .map_or(host, |(address, _)| address)
        .parse::<IpAddr>()
        .is_ok();
    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        // A host name, or an address with its zone, which the system resolver reads.
        Err(_) => (host, port)
            .to_socket_addrs()
            .with_context(|| format!("server {given}"))?
            .next()
            .ok_or_else(|| anyhow!("server {given}: no address"))?,
    };
    let name = name
        .or((!literal).then_some(host))
        .filter(|_| encrypted)
        .map(|name| ServerName::try_from(name.to_owned()))
        .transpose()
        .with_context(|| format!("server {given}: not a name for TLS"))?;
    let template = doh
        .then(|| {
            let path = url_path
                .as_deref()
                .or(options.https_path())
                .unwrap_or(DEFAULT_PATH);
            template(host, port, path).with_context(|| format!("server {given}"))
        })
        .transpose()?;
    // The segments of the path of a `coap://` URI (RFC 7252 §6.4), the root path having none.
    let docpath = path_segments(url_path.as_deref().filter(|_| coap).unwrap_or_default());
    Ok(Endpoint {
        server: Server {
            addr,
            name,
            doh: template,
            docpath,
        },
        forced,
        proxy,
    })
}

/// The proxy of `+odoh-proxy`, `https://HOST[:PORT][/PATH][#NAME]`, for the target `given` forced to `forced`: none
/// without the option, an error for a target that is not an `https://` server, or without the `odoh` feature (D69).
fn oblivious_proxy(
    options: &Options,
    forced: Option<Transport>,
    given: &str,
) -> anyhow::Result<Option<Box<Server>>> {
    let Some(uri) = options.odoh_proxy.as_deref() else {
        return Ok(None);
    };
    if !cfg!(feature = "odoh") {
        bail!("+odoh-proxy: built without the odoh feature");
    }
    if forced != Some(Transport::Https) {
        bail!("server {given}: +odoh-proxy needs an https:// target server");
    }
    if !uri.starts_with("https://") {
        bail!("+odoh-proxy {uri}: not an https:// URI");
    }
    Ok(Some(Box::new(
        server(Some(uri), None, None, &Options::default())?.server,
    )))
}

#[cfg(test)]
mod tests {
    use dedens_scenario::HttpsOption;

    use super::*;

    /// The endpoint of `text`, with `set` applied to the options, no `resolv.conf` and no `-p`.
    fn endpoint(text: &str, set: impl FnOnce(&mut Options)) -> anyhow::Result<Endpoint> {
        let mut options = Options::default();
        set(&mut options);
        server(Some(text), None, None, &options)
    }

    /// The port of the server `text` names, with `set` applied to the options.
    fn port(text: &str, set: impl FnOnce(&mut Options)) -> u16 {
        endpoint(text, set).unwrap().server.addr.port()
    }

    /// Without a port, the transport's: 53 (RFC 1035 §4.2), 853 over TLS (RFC 7858 §3.1) and QUIC (RFC 9250
    /// §4.1.1), 443 over HTTPS (RFC 9110 §4.2.2), from a scheme or an option, 5683 over CoAP (RFC 7252 §6.1); a port
    /// given wins.
    #[test]
    fn a_server_without_a_port_gets_its_transports() {
        assert_eq!(port("192.0.2.1", |_| ()), 53);
        assert_eq!(port("tls://192.0.2.1", |_| ()), 853);
        assert_eq!(port("quic://192.0.2.1", |_| ()), 853);
        assert_eq!(port("192.0.2.1", |o| o.tls = Some(true)), 853);
        assert_eq!(port("https://192.0.2.1", |_| ()), 443);
        assert_eq!(port("192.0.2.1", |o| o.https = Some(HttpsOption::On)), 443);
        assert_eq!(port("coap://192.0.2.1", |_| ()), 5683);
        assert_eq!(port("192.0.2.1", |o| o.coap = Some(true)), 5683);
        assert_eq!(port("tls://192.0.2.1:8853", |_| ()), 8853);
    }

    /// An IPv6 address is read whole without brackets, and its port after them.
    #[test]
    fn an_ipv6_address_is_read_with_or_without_brackets() {
        let at = |text| endpoint(text, |_| ()).unwrap().server.addr.to_string();
        assert_eq!(at("2001:db8::1"), "[2001:db8::1]:53");
        assert_eq!(at("[2001:db8::1]"), "[2001:db8::1]:53");
        assert_eq!(at("[2001:db8::1]:5353"), "[2001:db8::1]:5353");
    }

    /// The `DoH` template leaves 443 out of its authority, the normal form of an `https` URI (RFC 9110 §4.2.3), and
    /// keeps another port.
    #[test]
    fn the_doh_template_has_the_port_unless_443() {
        let template = |text| endpoint(text, |_| ()).unwrap().server.doh;
        assert_eq!(
            template("https://192.0.2.1"),
            Some(Template::parse("https://192.0.2.1/dns-query").unwrap())
        );
        assert_eq!(
            template("https://[2001:db8::1]:8443/q"),
            Some(Template::parse("https://[2001:db8::1]:8443/q").unwrap())
        );
    }

    /// A path goes after `https://` or `coap://` only: without a scheme, what follows `]` is read as a port.
    #[test]
    fn a_path_without_a_scheme_is_not_a_port() {
        let error = endpoint("[2001:db8::1]/dns-query", |o| {
            o.https = Some(HttpsOption::On);
        })
        .unwrap_err();
        assert!(error.to_string().contains("not a port"), "{error}");
    }

    /// D81: CoAP goes over UDP alone, with no other transport under it.
    #[test]
    fn coap_takes_no_other_transport() {
        let refused = |text, set: fn(&mut Options)| {
            let error = endpoint(text, set).unwrap_err();
            assert!(
                error.to_string().contains("CoAP goes with no"),
                "{text}: {error}"
            );
        };
        refused("tls://192.0.2.1", |o| o.coap = Some(true));
        refused("coap://192.0.2.1", |o| o.tcp = Some(true));
        refused("coap://192.0.2.1", |o| o.quic = Some(true));
        refused("coap://192.0.2.1", |o| o.https = Some(HttpsOption::On));
    }

    /// The name the certificate must hold (RFC 8310 §8.1): the one after `#`, none for an address, and none over a
    /// transport without TLS.
    #[test]
    fn an_address_has_no_name_to_check() {
        let name = |text| endpoint(text, |_| ()).unwrap().server.name;
        assert_eq!(name("tls://192.0.2.1"), None);
        assert_eq!(
            name("tls://192.0.2.1#dns.example"),
            Some(ServerName::try_from("dns.example").unwrap())
        );
        assert_eq!(name("192.0.2.1#dns.example"), None);
    }
}
