//! The RDAP answers `dedens` reads (D129, D130): the members of a domain (RFC 9083 §5.3) it prints, its redacted
//! fields (RFC 9537 §4.2), an error (RFC 9083 §6), and IANA's bootstrap file (RFC 9224 §4). Members not read here are
//! ignored (RFC 9083 §2.1, RFC 9224 §3); a member read here with another type is an error.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use serde_json::Value;

/// A domain (RFC 9083 §5.3).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Domain {
    #[serde(rename = "objectClassName")]
    _class: DomainClass,
    /// Its states (RFC 9083 §4.6), as `active`.
    #[serde(default)]
    pub(crate) status: Vec<String>,
    /// Its name servers.
    #[serde(default)]
    pub(crate) nameservers: Vec<Nameserver>,
    /// Its delegation signer records.
    #[serde(default, rename = "secureDNS")]
    pub(crate) secure_dns: SecureDns,
    /// Who holds and runs it.
    #[serde(default)]
    pub(crate) entities: Vec<Entity>,
    /// What happened to it, when.
    #[serde(default)]
    pub(crate) events: Vec<Event>,
    /// Where more is.
    #[serde(default)]
    pub(crate) links: Vec<Link>,
    /// The fields the server redacted (RFC 9537 §4.2).
    #[serde(default)]
    pub(crate) redacted: Vec<Redaction>,
}

/// The `objectClassName` of a domain (RFC 9083 §4.9): another class is no answer to a domain query.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DomainClass {
    Domain,
}

/// A name server (RFC 9083 §5.2), its addresses those a registry holds for glue.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Nameserver {
    /// Its name, in A-labels.
    pub(crate) ldh_name: String,
    /// Its addresses.
    #[serde(default)]
    pub(crate) ip_addresses: IpAddresses,
}

/// The addresses of a name server.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct IpAddresses {
    /// IPv4.
    #[serde(default)]
    pub(crate) v4: Vec<Ipv4Addr>,
    /// IPv6.
    #[serde(default)]
    pub(crate) v6: Vec<Ipv6Addr>,
}

/// The DNSSEC data of a domain (RFC 9083 §5.3), its DS records; key data is not read.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecureDns {
    /// Its DS records.
    #[serde(default)]
    pub(crate) ds_data: Vec<DsData>,
}

/// A DS record (RFC 4034 §5.1), as RDAP gives it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DsData {
    /// The key tag.
    pub(crate) key_tag: u16,
    /// The key's algorithm.
    pub(crate) algorithm: u8,
    /// The digest's type.
    pub(crate) digest_type: u8,
    /// The digest, in hex.
    pub(crate) digest: String,
}

/// A party (RFC 9083 §5.1): its roles and its contact card.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entity {
    /// What it is to the domain (RFC 9083 §10.2.4), as `registrant`.
    #[serde(default)]
    pub(crate) roles: Vec<String>,
    /// Its contact card.
    #[serde(default)]
    pub(crate) vcard_array: Card,
    /// Its identifiers in registries (RFC 9083 §4.8), as a registrar's IANA ID.
    #[serde(default)]
    pub(crate) public_ids: Vec<PublicId>,
}

/// An identifier in a registry (RFC 9083 §4.8).
#[derive(Debug, Deserialize)]
pub(crate) struct PublicId {
    /// The registry, as `IANA Registrar ID`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    /// The identifier there.
    pub(crate) identifier: String,
}

/// A field the server redacted (RFC 9537 §4.2), told by its name: its paths, in JSON path syntax, are not read (§5.1).
#[derive(Debug, Deserialize)]
pub(crate) struct Redaction {
    /// What was redacted.
    pub(crate) name: Term,
    /// How, as received: `removal` when absent.
    #[serde(default = "removal")]
    pub(crate) method: String,
    /// Why.
    #[serde(default)]
    pub(crate) reason: Term,
}

/// The method of a redaction that names none (RFC 9537 §4.2).
fn removal() -> String {
    "removal".to_owned()
}

/// A name or a reason of a redaction: a registered type, or a description (RFC 9537 §4.2).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Term {
    #[serde(rename = "type")]
    kind: Option<String>,
    description: Option<String>,
}

impl Term {
    /// Its type, else its description, else nothing.
    pub(crate) fn text(&self) -> &str {
        self.kind
            .as_deref()
            .or(self.description.as_deref())
            .unwrap_or_default()
    }
}

/// IANA's bootstrap file for domains (RFC 9224 §3, §4): the base URLs of the RDAP servers of each name.
#[derive(Debug, Deserialize)]
pub(crate) struct Bootstrap {
    /// The entries and the base URLs that serve them, both unordered.
    services: Vec<(Vec<String>, Vec<String>)>,
}

impl Bootstrap {
    /// The base URLs serving `name`, lowercase A-labels without the trailing dot, and the labels of the entry they
    /// serve: the label-wise longest match, from the right (RFC 9224 §4); `""` is the root. None when no entry
    /// matches (§7).
    pub(crate) fn servers(&self, name: &str) -> Option<(usize, &[String])> {
        self.services
            .iter()
            .flat_map(|(entries, urls)| entries.iter().map(move |entry| (entry, urls)))
            .filter_map(|(entry, urls)| Some((labels_matched(name, entry)?, urls.as_slice())))
            .max_by_key(|&(labels, _)| labels)
    }
}

/// The labels of `entry` when `name` ends with them, whole labels, in any case.
fn labels_matched(name: &str, entry: &str) -> Option<usize> {
    if entry.is_empty() {
        return Some(0);
    }
    let start = name.len().checked_sub(entry.len())?;
    let (head, tail) = name.as_bytes().split_at(start);
    (tail.eq_ignore_ascii_case(entry.as_bytes()) && (head.is_empty() || head.ends_with(b".")))
        .then(|| entry.split('.').count())
}

/// An event (RFC 9083 §4.5).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Event {
    /// What happened (RFC 9083 §10.2.3), as `registration`.
    pub(crate) event_action: String,
    /// When, an RFC 3339 time.
    pub(crate) event_date: String,
}

/// A link (RFC 9083 §4.2).
#[derive(Debug, Deserialize)]
pub(crate) struct Link {
    /// How it relates, as `alternate`.
    #[serde(default)]
    pub(crate) rel: String,
    /// Where it leads.
    pub(crate) href: String,
    /// The media type there.
    #[serde(default, rename = "type")]
    pub(crate) media_type: String,
}

/// An error (RFC 9083 §6).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Failure {
    /// Its title.
    #[serde(default)]
    pub(crate) title: String,
    /// Its explanation, line by line.
    #[serde(default)]
    pub(crate) description: Vec<String>,
}

/// A contact card in jCard (RFC 7095): `["vcard", [property, ...]]`.
#[derive(Debug, Default, Deserialize)]
#[serde(try_from = "(String, Vec<Property>)")]
pub(crate) struct Card {
    /// Its properties, in order.
    pub(crate) properties: Vec<Property>,
}

impl TryFrom<(String, Vec<Property>)> for Card {
    type Error = &'static str;

    fn try_from((kind, properties): (String, Vec<Property>)) -> Result<Self, Self::Error> {
        if kind != "vcard" {
            return Err("a jCard begins with \"vcard\" (RFC 7095 §3.2)");
        }
        Ok(Self { properties })
    }
}

impl Card {
    /// The values of its properties named `name`, one per property, as [`Property::text`].
    pub(crate) fn texts<'a>(&'a self, name: &'a str) -> impl Iterator<Item = String> + 'a {
        self.properties
            .iter()
            .filter(move |property| property.name == name)
            .map(Property::text)
    }

    /// Its properties named `name`.
    pub(crate) fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> + 'a {
        self.properties
            .iter()
            .filter(move |property| property.name == name)
    }
}

/// A jCard property (RFC 7095 §3.3): `[name, parameters, value type, value, ...]`, its value cut to the text it holds.
#[derive(Debug, Deserialize)]
#[serde(try_from = "Vec<Value>")]
pub(crate) struct Property {
    /// Its name, lowercase (RFC 7095 §3.3).
    pub(crate) name: String,
    /// Its `label` parameter: an address as printed (RFC 6350 §6.3.1).
    pub(crate) label: Option<String>,
    /// Its `type` parameter, as `voice` or `fax` (RFC 6350 §5.6).
    pub(crate) types: Vec<String>,
    /// The parts of its value that are not empty, in order: one for a text, the components of a structured value
    /// (RFC 7095 §3.3.1.3) as `adr`'s.
    pub(crate) values: Vec<String>,
}

impl Property {
    /// Its value, the parts joined by `, `.
    pub(crate) fn text(&self) -> String {
        self.values.join(", ")
    }
}

/// The parameters of a property that `dedens` reads.
#[derive(Debug, Default, Deserialize)]
struct Parameters {
    label: Option<String>,
    #[serde(default, rename = "type")]
    types: OneOrMore,
}

/// A parameter of one value or several (RFC 7095 §3.4).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMore {
    One(String),
    More(Vec<String>),
}

impl Default for OneOrMore {
    fn default() -> Self {
        Self::More(Vec::new())
    }
}

impl TryFrom<Vec<Value>> for Property {
    type Error = String;

    fn try_from(parts: Vec<Value>) -> Result<Self, Self::Error> {
        let mut parts = parts.into_iter();
        let (Some(Value::String(name)), Some(parameters), Some(Value::String(_))) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(
                "a jCard property is a name, parameters, a value type, then values (RFC 7095 §3.3)"
                    .to_owned(),
            );
        };
        let parameters: Parameters =
            serde_json::from_value(parameters).map_err(|e| format!("{name}: {e}"))?;
        let mut values = Vec::new();
        for value in parts {
            flatten(value, &mut values);
        }
        Ok(Self {
            name,
            label: parameters.label,
            types: match parameters.types {
                OneOrMore::One(one) => vec![one],
                OneOrMore::More(more) => more,
            },
            values,
        })
    }
}

/// Pushes the text of `value` to `values`: a string not empty, a number or a boolean written out, each of an
/// array's in turn.
fn flatten(value: Value, values: &mut Vec<String>) {
    match value {
        Value::String(text) if !text.is_empty() => values.push(text),
        Value::Number(number) => values.push(number.to_string()),
        Value::Bool(set) => values.push(set.to_string()),
        Value::Array(items) => {
            for item in items {
                flatten(item, values);
            }
        }
        Value::String(_) | Value::Null | Value::Object(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{Bootstrap, Card};

    /// RFC 9224 §4: the label-wise longest match, `""` the root, `goodexample.com` no match for `example.com`.
    #[test]
    fn rfc9224_s4_the_longest_match_by_label_wins() {
        let bootstrap: Bootstrap = serde_json::from_str(
            r#"{"services": [[[""], ["https://root/"]], [["net", "com"], ["https://com/"]],
                [["example.com"], ["https://example/"]], [["goodexample.com"], ["https://good/"]]]}"#,
        )
        .expect("a bootstrap file");
        let servers = |name| {
            bootstrap
                .servers(name)
                .map(|(labels, urls)| (labels, urls[0].as_str()))
        };
        assert_eq!(servers("a.b.example.com"), Some((2, "https://example/")));
        assert_eq!(servers("EXAMPLE.com"), Some((2, "https://example/")));
        assert_eq!(servers("xexample.com"), Some((1, "https://com/")));
        assert_eq!(servers("example.net"), Some((1, "https://com/")));
        assert_eq!(servers("example.org"), Some((0, "https://root/")));
        let none: Bootstrap =
            serde_json::from_str(r#"{"services": [[["com"], ["https://com/"]]]}"#)
                .expect("a bootstrap file");
        assert!(none.servers("example.org").is_none());
        assert!(none.servers("com").is_some());
    }

    /// RFC 7095 §3.3.1.3: the example address, its empty components left out.
    #[test]
    fn rfc7095_s3_3_1_3_a_structured_value_is_its_components() {
        let card: Card = serde_json::from_str(
            r#"["vcard", [["adr", {}, "text", ["", "", "123 Main Street", "Any Town", "CA", "91921-1234", "U.S.A."]]]]"#,
        )
        .expect("a card");
        let adr: Vec<_> = card.all("adr").map(super::Property::text).collect();
        assert_eq!(adr, ["123 Main Street, Any Town, CA, 91921-1234, U.S.A."]);
    }
}
