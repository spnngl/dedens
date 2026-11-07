//! DNS server discovery by SVCB (RFC 9461): the `dohpath` value as the URI Template of a `DoH` server (§5, §7).

use dedens_net::doh::{Method, Template, TemplateError, request};
use dedens_proto::Record;
use dedens_proto::rdata::{RData, SvcParam, SvcParamKey, Svcb};
use http::uri::Authority;

#[expect(clippy::panic, reason = "a test helper: the text is not a SVCB record")]
/// §7's records, the one at `_dns.<name>` that has `dohpath`, as the owner and RDATA of its text.
fn svcb(text: &str) -> Svcb<'static> {
    let record: Record<'static> = format!("_dns.example. 7200 {text}")
        .parse()
        .expect("a SVCB record");
    match record.data() {
        RData::Svcb(svcb) => svcb.into_owned(),
        other => panic!("{other:?}"),
    }
}

/// The template §5 makes of `svcb`: the authentication name and the `port` for the origin, the `dohpath` for the
/// resource.
fn template(svcb: &Svcb<'_>) -> Result<Template, TemplateError> {
    let name = svcb.target().to_string();
    let host = name.trim_end_matches('.');
    let authority: Authority = match svcb.params().get(SvcParamKey::PORT) {
        Some(SvcParam::Port(port)) => format!("{host}:{port}"),
        _ => host.to_owned(),
    }
    .parse()
    .expect("an authority");
    match svcb.params().get(SvcParamKey::DOHPATH) {
        Some(SvcParam::DohPath(path)) => Template::from_dohpath(authority, &path),
        _ => Err(TemplateError::MissingVariable),
    }
}

/// §7: a DoH-only resolver at `https://doh.example/dns-query{?dns}`.
#[test]
fn s7_doh_only_resolver() {
    let svcb = svcb("IN SVCB 1 doh.example. alpn=h2 dohpath=/dns-query{?dns}");
    let template = template(&svcb).expect("a template");
    assert_eq!(template.to_string(), "https://doh.example/dns-query{?dns}");
    assert_eq!(
        template,
        Template::parse("https://doh.example/dns-query{?dns}").expect("a template")
    );
}

/// §7: the first record of `resolver.example`, `DoH` at `https://resolver.example/q{?dns}`.
#[test]
fn s7_resolver_with_several_transports() {
    let svcb = svcb("IN SVCB 1 resolver.example. alpn=dot,doq,h2,h3 dohpath=/q{?dns}");
    let template = template(&svcb).expect("a template");
    assert_eq!(template.to_string(), "https://resolver.example/q{?dns}");
    let get = request(&template, &[0, 0, 1, 0], Method::Get).expect("a request");
    assert_eq!(
        get.uri().to_string(),
        "https://resolver.example/q?dns=AAABAA"
    );
}

/// §5: the `port` is the one of the origin the requests go to.
#[test]
fn s5_port_gives_the_origin() {
    let svcb = svcb("IN SVCB 1 doh.example. alpn=h2 port=8443 dohpath=/dns-query{?dns}");
    let template = template(&svcb).expect("a template");
    assert_eq!(template.authority().as_str(), "doh.example:8443");
    assert_eq!(
        template.to_string(),
        "https://doh.example:8443/dns-query{?dns}"
    );
}

/// §5: the template is in relative form and has a `dns` variable that makes a valid `:path`.
#[test]
fn s5_a_dohpath_is_a_relative_template_with_the_variable() {
    let authority: Authority = "doh.example".parse().expect("an authority");
    for good in ["/dns-query{?dns}", "/q{?dns}", "/{?dns}", "/a/b?c=d{&dns}"] {
        assert!(
            Template::from_dohpath(authority.clone(), good).is_ok(),
            "{good}"
        );
    }
    // No variable: what DoH URI Template expansion makes of it has no query.
    for (bad, expected) in [
        ("/dns-query", "MissingVariable"),
        ("", "MissingVariable"),
        ("dns-query{?dns}", "NotAbsolute"),
        ("https://other.example/q{?dns}", "NotAbsolute"),
        ("/q{?other}", "Expression"),
        ("/q{?dns,ct}", "Expression"),
        ("/q{dns}", "Expression"),
    ] {
        let error = Template::from_dohpath(authority.clone(), bad).expect_err(bad);
        assert_eq!(
            format!("{error:?}").split('(').next(),
            Some(expected),
            "{bad}"
        );
    }
}
