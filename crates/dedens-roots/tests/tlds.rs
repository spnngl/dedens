//! IANA's TLD list, `tlds.json` (schema version 1): the bundled `src/tlds.json`, cut by `just roots`, and
//! `tests/data/tlds.json`, six entries of the same download in full. A TLD is found whatever its case (RFC 4343 §3);
//! the special-use names carry IANA's purpose.

use dedens_proto::{DigestType, Name, SecAlgorithm};
use dedens_roots::{Kind, Status, Tlds, TldsError};

/// Six TLDs of the download `just roots` cut the bundled list from, every member kept.
const COPY: &str = include_str!("data/tlds.json");

fn name(text: &str) -> Name<'static> {
    text.parse().expect("a name")
}

#[test]
fn fr_has_its_name_servers_their_glue_and_its_ds() {
    let fr = Tlds::bundled().get(&name("fr")).expect("fr");
    assert_eq!(
        (fr.kind(), fr.status()),
        (&Kind::CountryCode, Status::Active)
    );
    let d = fr
        .servers()
        .iter()
        .find(|server| server.name() == &name("d.nic.fr"))
        .expect("d.nic.fr");
    assert_eq!(
        d.addresses().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        ["194.0.9.1", "2001:678:c::1"]
    );
    let [ds] = fr.ds() else {
        panic!("one DS: {:?}", fr.ds())
    };
    assert_eq!(
        (ds.key_tag(), ds.algorithm(), ds.digest_type()),
        (65381, SecAlgorithm(13), DigestType(2))
    );
    assert_eq!(ds.digest().first(), Some(&0x81));
}

#[test]
fn rfc4343_s3_a_tld_is_found_whatever_the_case_from_any_name_below_it() {
    let tlds = Tlds::bundled();
    let fr = tlds.get(&name("fr")).expect("fr");
    for below in ["FR", "Fr", "www.example.fr", "D.NIC.FR"] {
        assert_eq!(tlds.get(&name(below)), Some(fr), "{below}");
    }
    assert_eq!(fr.name().to_string(), "fr.");
}

#[test]
fn an_unlisted_tld_and_the_root_have_none() {
    let tlds = Tlds::bundled();
    assert_eq!(tlds.get(&name("example.nosuchtld")), None);
    assert_eq!(tlds.get(&Name::root()), None);
}

#[test]
fn onion_is_special_use_with_its_purpose() {
    let onion = Tlds::bundled().get(&name("onion")).expect("onion");
    let purpose = "Used to access devices over the Tor network";
    assert_eq!(
        onion.kind(),
        &Kind::SpecialUse {
            purpose: Some(purpose.into())
        }
    );
    assert_eq!(onion.status(), Status::Reserved);
    assert!(onion.servers().is_empty() && onion.ds().is_empty());
}

/// D129: `+tld` prints the kind and status of a TLD IANA's RDAP server does not know.
#[test]
fn kinds_and_statuses_are_printed_in_words() {
    let kinds = [
        Kind::Generic,
        Kind::CountryCode,
        Kind::SpecialUse { purpose: None },
        Kind::Test,
    ];
    let kinds: Vec<_> = kinds.iter().map(ToString::to_string).collect();
    assert_eq!(kinds, ["generic", "country code", "special use", "test"]);
    let statuses = [
        Status::Active,
        Status::Retired,
        Status::Eligible,
        Status::Reserved,
    ];
    let statuses: Vec<_> = statuses.iter().map(ToString::to_string).collect();
    assert_eq!(statuses, ["active", "retired", "eligible", "reserved"]);
}

#[test]
fn a_copy_cut_short_is_refused_after_its_unknown_members_are_read() {
    let Err(TldsError::Truncated { read, bundled }) = Tlds::read(COPY.as_bytes()) else {
        panic!("a truncated copy");
    };
    assert_eq!(read, 6);
    assert_eq!(bundled, Tlds::bundled().iter().count());
}

#[test]
fn a_copy_of_the_bundled_list_reads_as_it() {
    let bundled = include_bytes!("../src/tlds.json");
    assert_eq!(
        &Tlds::read(bundled).expect("the bundled list"),
        Tlds::bundled()
    );
}

/// RFC 3339 §5.6 and §5.7: the bundled list with its `meta.generated` replaced; each `just roots` moves the bundled
/// one, so the times are fixed here.
#[test]
fn a_list_is_as_old_as_its_generated_time() {
    let bundled = include_str!("../src/tlds.json");
    let json: serde_json::Value = serde_json::from_str(bundled).expect("JSON");
    let generated = json["meta"]["generated"]
        .as_str()
        .expect("the bundled `meta.generated`");
    let at = |time: &str| {
        Tlds::read(bundled.replacen(generated, time, 1).as_bytes())
            .map(|tlds| tlds.generated())
            .map_err(|error| error.to_string())
    };
    assert_eq!(at(generated), Ok(Tlds::bundled().generated()));
    for same in [
        "2026-11-16T23:49:03+00:00",
        "2026-11-16T23:49:03Z",
        "2026-11-16t23:49:03.999z",
        "2026-11-17T01:19:03+01:30",
        "2026-11-16T22:48:03-01:01",
    ] {
        assert_eq!(at(same), Ok(1_794_872_943), "{same}");
    }
    assert_eq!(at("2024-02-29T00:00:00Z"), Ok(1_709_164_800));
    assert_eq!(at("2000-02-29T00:00:00Z"), Ok(951_782_400));
    assert_eq!(at("2026-04-30T00:00:00Z"), Ok(1_777_507_200));
    assert_eq!(at("1970-01-31T00:59:60Z"), Ok(30 * 86_400 + 3600));
    assert_eq!(at("1970-01-01T23:59:00+23:58"), Ok(60));
    assert_eq!(at("1970-01-02T00:00:00+23:59"), Ok(60));
    for refused in [
        "1969-12-31T23:59:59Z",
        "2026-11-16 23:49:03Z",
        "2026-11-16T23:49:03",
        "2026-11-16T23:49:03+0000",
        "2026-11-16T23:49:03+24:00",
        "2026-11-16T23:49:03+00:60",
        "2026-11-16T23:49:03Z ",
        "2026-00-16T23:49:03Z",
        "2026-13-16T23:49:03Z",
        "2026-11-00T23:49:03Z",
        "2026-11-32T23:49:03Z",
        "2026-02-29T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-11-16T23:49:03.Z",
        "2026-11-16T24:49:03Z",
        "2026-11-16T23:60:03Z",
        "2026-11-16T23:49:61Z",
        "+026-11-16T23:49:03Z",
        "2026-11-16T23:49",
    ] {
        assert_eq!(
            at(refused),
            Err(format!("generated {refused:?} is not a time")),
            "{refused}"
        );
    }
}

#[test]
fn a_copy_of_half_the_bundled_list_reads_one_less_is_refused() {
    let mut json: serde_json::Value =
        serde_json::from_slice(include_bytes!("../src/tlds.json")).expect("the bundled list");
    let half = IntoIterator::into_iter(Tlds::bundled()).count().div_ceil(2);
    let mut cut = |len: usize| {
        if let Some(domains) = json["domains"].as_array_mut() {
            domains.truncate(len);
        }
        Tlds::read(json.to_string().as_bytes())
    };
    assert!(matches!(cut(half).map(|tlds| tlds.iter().count()), Ok(read) if read == half));
    assert!(matches!(cut(half - 1), Err(TldsError::Truncated { read, .. }) if read == half - 1));
}

#[test]
fn a_copy_off_the_schema_is_refused() {
    let read = |from: &str, to: &str| Tlds::read(COPY.replacen(from, to, 1).as_bytes());
    assert!(
        matches!(read(r#""name": "com""#, r#""name": "FR""#), Err(TldsError::Duplicate { tld }) if tld.eq_ignore_ascii_case("fr"))
    );
    assert!(matches!(
        read(r#""name": "com""#, r#""name": """#),
        Err(TldsError::Name { .. })
    ));
    assert!(
        matches!(read(r#""digest": "8163"#, r#""digest": "zz63"#), Err(TldsError::Digest { tld, .. }) if tld == "fr")
    );
    assert!(matches!(
        read(r#""name": "d.nic.fr""#, r#""name": "d..nic.fr""#),
        Err(TldsError::Server { .. })
    ));
    assert!(matches!(
        read(r#""status": "active""#, r#""status": "pending""#),
        Err(TldsError::Json(_))
    ));
    assert!(matches!(
        read(r#""type": "generic""#, r#""type": "brand""#),
        Err(TldsError::Json(_))
    ));
    assert!(matches!(
        read(r#""ds_records""#, r#""ds""#),
        Err(TldsError::Json(_))
    ));
}
