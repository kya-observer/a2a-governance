//! Agent Card signing and verification, per A2A v1.0 §8.4.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_card::{Error, Form, VerifyOptions, canonical_payload, fingerprint, sign, verify};
use a2a_gov_mandate::{PublicJwk, SigningKey};
use base64::Engine;
use serde_json::{Value, json};

fn card() -> Value {
    json!({
        "name": "Example vault agent",
        "description": "Answers questions about a reading history",
        "version": "0.1.0",
        "supportedInterfaces": [{ "url": "https://vault.example.org/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }],
        "capabilities": { "streaming": false, "extensions": [{ "uri": "https://example.org/ext/v1", "required": true }] },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{ "id": "reading", "name": "Reading", "description": "Answers from reading history", "tags": ["reading"] }],
    })
}

fn keys(key: &SigningKey) -> impl Fn(&str) -> Option<PublicJwk> + '_ {
    move |kid| (Some(kid) == key.kid()).then(|| key.public_jwk())
}

fn opts() -> VerifyOptions {
    VerifyOptions::default()
}

// --- §8.4.1 canonicalization ------------------------------------------------------------

#[test]
fn the_specs_worked_example_canonicalizes_as_documented() {
    // A2A v1.0 §8.4.1, "Example of Default Value Removal".
    let fragment = json!({
        "name": "Example Agent",
        "description": "",
        "capabilities": { "streaming": false, "pushNotifications": false, "extensions": [] },
        "skills": [],
    });
    assert_eq!(
        canonical_payload(&fragment).unwrap(),
        r#"{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}"#
    );
}

#[test]
fn implicit_fields_at_their_default_are_removed_and_the_rest_kept() {
    let mut c = card();
    c["supportedInterfaces"][0]["tenant"] = json!(""); // implicit string, default
    c["capabilities"]["extensions"][0]["required"] = json!(false); // implicit bool, default
    c["capabilities"]["extensions"][0]["description"] = json!(""); // implicit string, default
    c["securityRequirements"] = json!([]); // implicit repeated, empty
    c["securitySchemes"] = json!({}); // implicit map, empty
    c["documentationUrl"] = json!(""); // optional, explicitly set: kept
    let payload = canonical_payload(&c).unwrap();
    for gone in [
        "tenant",
        "\"required\":false",
        "securityRequirements",
        "securitySchemes",
    ] {
        assert!(!payload.contains(gone), "{gone} in {payload}");
    }
    assert!(
        payload.contains(r#""extensions":[{"uri":"https://example.org/ext/v1"}]"#),
        "{payload}"
    );
    assert!(payload.contains(r#""documentationUrl":"""#), "{payload}");
    assert!(payload.contains(r#""streaming":false"#), "{payload}");
}

#[test]
fn signatures_are_not_part_of_the_payload() {
    let mut c = card();
    let before = canonical_payload(&c).unwrap();
    c["signatures"] = json!([{ "protected": "x", "signature": "y" }]);
    assert_eq!(canonical_payload(&c).unwrap(), before);
}

#[test]
fn unknown_fields_stay_in_the_signed_payload() {
    // A field this version doesn't know may matter to a newer reader, so it's signed.
    let mut c = card();
    c["futureField"] = json!("x");
    assert!(canonical_payload(&c).unwrap().contains("futureField"));
}

// --- Signing and verifying ----------------------------------------------------------------

#[test]
fn a_signed_card_verifies_and_reports_its_key_and_fingerprint() {
    let key = SigningKey::generate().with_kid("agent-key-1");
    let signed = sign(&card(), &key).unwrap();
    let sig = &signed["signatures"][0];
    let header: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig["protected"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        header,
        json!({ "alg": "ES256", "typ": "JOSE", "kid": "agent-key-1" })
    );
    let verified = verify(&signed, keys(&key), &opts()).unwrap();
    assert_eq!(verified.kid, "agent-key-1");
    assert_eq!(verified.form, Form::Spec);
    assert_eq!(verified.fingerprint, fingerprint(&card()).unwrap());
}

#[test]
fn signing_requires_a_kid() {
    assert!(matches!(
        sign(&card(), &SigningKey::generate()),
        Err(Error::MissingKid)
    ));
}

#[test]
fn any_change_to_signed_content_is_detected() {
    let key = SigningKey::generate().with_kid("k");
    let signed = sign(&card(), &key).unwrap();
    for (path, value) in [
        ("/name", json!("Impostor")),
        (
            "/supportedInterfaces/0/url",
            json!("https://evil.example/a2a"),
        ),
        ("/capabilities/extensions/0/required", json!(false)),
        ("/skills/0/tags/0", json!("payments")),
    ] {
        let mut tampered = signed.clone();
        *tampered.pointer_mut(path).unwrap() = value;
        assert!(
            matches!(
                verify(&tampered, keys(&key), &opts()),
                Err(Error::InvalidSignature)
            ),
            "{path}"
        );
    }
}

#[test]
fn fingerprints_change_with_content_but_not_with_formatting() {
    let a = fingerprint(&card()).unwrap();
    let mut explicit_defaults = card();
    explicit_defaults["supportedInterfaces"][0]["tenant"] = json!("");
    assert_eq!(fingerprint(&explicit_defaults).unwrap(), a);
    let mut changed = card();
    changed["version"] = json!("0.2.0");
    assert_ne!(fingerprint(&changed).unwrap(), a);
}

#[test]
fn keys_come_only_from_the_verifiers_configuration() {
    // §8.4.3 allows fetching `jku`; this implementation never does. A header
    // naming an attacker's key set changes nothing: the key is looked up by kid.
    let key = SigningKey::generate().with_kid("k");
    let attacker = SigningKey::generate().with_kid("k");
    let forged = sign(&card(), &attacker).unwrap();
    assert!(matches!(
        verify(&forged, keys(&key), &opts()),
        Err(Error::InvalidSignature)
    ));
    let unknown = SigningKey::generate().with_kid("other");
    assert!(matches!(
        verify(&sign(&card(), &unknown).unwrap(), keys(&key), &opts()),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn only_es256_signatures_are_accepted() {
    let key = SigningKey::generate().with_kid("k");
    let mut signed = sign(&card(), &key).unwrap();
    for alg in ["none", "HS256", "RS256"] {
        let header = json!({ "alg": alg, "typ": "JOSE", "kid": "k" }).to_string();
        signed["signatures"][0]["protected"] =
            json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header));
        assert!(verify(&signed, keys(&key), &opts()).is_err(), "{alg}");
    }
}

#[test]
fn an_unsigned_card_is_refused() {
    let key = SigningKey::generate().with_kid("k");
    assert!(matches!(
        verify(&card(), keys(&key), &opts()),
        Err(Error::NoSignature)
    ));
}

#[test]
fn one_valid_signature_among_several_is_enough() {
    // §8.4.3: multiple signatures support key rotation.
    let old = SigningKey::generate().with_kid("old");
    let new = SigningKey::generate().with_kid("new");
    let both = sign(&sign(&card(), &old).unwrap(), &new).unwrap();
    assert_eq!(both["signatures"].as_array().unwrap().len(), 2);
    assert_eq!(verify(&both, keys(&new), &opts()).unwrap().kid, "new");
    assert_eq!(verify(&both, keys(&old), &opts()).unwrap().kid, "old");
}

// --- The a2a-sdk's variant canonical form ---------------------------------------------------

#[test]
fn cards_signed_over_the_a2a_sdk_form_verify_only_when_allowed() {
    // The official a2a-sdk also drops empty REQUIRED fields (e.g. description: "")
    // before signing, unlike §8.4.1. Such cards verify, flagged, when allowed.
    let key = SigningKey::generate().with_kid("k");
    let mut c = card();
    c["description"] = json!("");
    let signed = a2a_gov_card::sign_a2a_sdk_form(&c, &key).unwrap();
    let verified = verify(&signed, keys(&key), &opts()).unwrap();
    assert_eq!(verified.form, Form::A2aSdk);
    let strict = VerifyOptions {
        accept_a2a_sdk_form: false,
    };
    assert!(matches!(
        verify(&signed, keys(&key), &strict),
        Err(Error::InvalidSignature)
    ));
}
