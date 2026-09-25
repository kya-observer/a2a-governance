//! Disclosure encoding and digests, using the examples printed in RFC 9901.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_mandate::sdjwt::{Disclosure, digest};
use serde_json::json;

#[test]
fn object_property_disclosure_digest_matches_rfc_section_5_2() {
    // RFC 9901 §5.2, claim given_name.
    let d = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
    assert_eq!(digest(d), "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4");
    let parsed = Disclosure::parse(d).expect("valid disclosure");
    assert_eq!(parsed.name(), Some("given_name"));
    assert_eq!(parsed.value(), &json!("John"));
}

#[test]
fn array_element_disclosure_digest_matches_rfc_section_5_2() {
    // RFC 9901 §5.2, nationalities array entry "US".
    let d = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";
    assert_eq!(digest(d), "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo");
    let parsed = Disclosure::parse(d).expect("valid disclosure");
    assert_eq!(parsed.name(), None);
    assert_eq!(parsed.value(), &json!("US"));
}

#[test]
fn equivalent_encodings_decode_to_the_same_claim_but_hash_differently() {
    // RFC 9901 §4.2.1: no canonicalization; the digest covers the exact string.
    let variants = [
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0",
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd",
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
        "WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ",
    ];
    let mut digests = std::collections::HashSet::new();
    for v in variants {
        let d = Disclosure::parse(v).expect("valid");
        assert_eq!(d.name(), Some("family_name"));
        assert_eq!(d.value(), &json!("Möbius"));
        digests.insert(digest(v));
    }
    assert_eq!(digests.len(), variants.len());
}

#[test]
fn malformed_disclosures_are_rejected() {
    use base64::Engine;
    let enc = |v: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
    };
    for bad in [
        enc(json!(["salt"])),                 // too short
        enc(json!(["salt", "a", "b", "c"])),  // too long
        enc(json!([1, "name", "value"])),     // salt not a string
        enc(json!(["salt", 7, "value"])),     // name not a string
        enc(json!(["salt", "_sd", "value"])), // reserved claim name
        enc(json!(["salt", "...", "value"])), // reserved claim name
        enc(json!({"salt": "x"})),            // not an array
        "not base64!".to_owned(),
    ] {
        assert!(Disclosure::parse(&bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn disclosures_with_duplicate_keys_are_rejected() {
    // Parsers disagree on which duplicate wins, so the same token could mean
    // different things to different verifiers.
    use base64::Engine;
    let raw = r#"["salt", "limit", {"max": 1, "max": 1000}]"#;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    assert!(Disclosure::parse(&encoded).is_err());
}
