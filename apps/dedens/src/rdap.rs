//! The RDAP answers `dedens` reads (D129): the members of a domain (RFC 9083 §5.3) it prints, and an error (RFC 9083
//! §6). Members not read here are ignored (RFC 9083 §2.1); a member read here with another type is an error.

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
