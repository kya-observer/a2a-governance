//! Mandate Receipts: AP2's base fields (`docs/ap2/agent_authorization.md`,
//! `schemas/ap2/*_receipt.json`) plus this extension's optional fields.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_mandate::{Disclosable, SigningKey, issue_open, join, present};
use a2a_gov_receipt::{Error, Outcome, Receipt, jwt_only_reference, reference_for};
use serde_json::{Map, Value, json};

const NOW: i64 = 1_790_000_000;

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn chain() -> String {
    let surface = SigningKey::generate();
    let agent = SigningKey::generate();
    let open = issue_open(
        &obj(json!({ "vct": "mandate.access.1", "cnf": { "jwk": agent.public_jwk().to_value() }, "exp": NOW + 60 })),
        &Disclosable::none(),
        &surface,
    )
    .unwrap();
    let closing = present(
        &open,
        &obj(json!({ "vct": "mandate.access.1", "method": "SendMessage" })),
        &Disclosable::none(),
        &agent,
        "aud",
        "nonce",
        NOW,
    )
    .unwrap();
    join(&[&open, &closing])
}

fn success(chain: &str) -> Receipt {
    Receipt::new(
        "https://verifier.example.org",
        NOW,
        Outcome::Success,
        reference_for(chain).unwrap(),
    )
    .with_method("SendMessage")
    .with_task_id("task-1")
    .with_purpose("dpv:ServiceProvision")
    .with_released(["title", "published"])
    .unwrap()
}

#[test]
fn a_signed_receipt_round_trips() {
    let key = SigningKey::generate().with_kid("verifier-1");
    let receipt = success(&chain());
    let jws = receipt.sign(&key);
    assert_eq!(Receipt::verify(&jws, &key.public_jwk()).unwrap(), receipt);
}

#[test]
fn the_payload_carries_ap2_base_fields() {
    let chain = chain();
    let key = SigningKey::generate();
    let payload = Receipt::decode_unverified(&success(&chain).sign(&key)).unwrap();
    assert_eq!(payload["status"], json!("Success"));
    assert_eq!(payload["iss"], json!("https://verifier.example.org"));
    assert_eq!(payload["iat"], json!(NOW));
    assert_eq!(payload["reference"], json!(reference_for(&chain).unwrap()));
    assert!(payload.get("error").is_none());
    assert_eq!(payload["released"], json!(["title", "published"]));
}

#[test]
fn error_receipts_carry_code_and_description() {
    // AP2 schema: error and error_description present if and only if status is Error.
    let key = SigningKey::generate();
    let receipt = Receipt::new(
        "https://verifier.example.org",
        NOW,
        Outcome::Error {
            code: "invalid_mandate".into(),
            description: "out of scope".into(),
        },
        reference_for(&chain()).unwrap(),
    );
    let payload = Receipt::decode_unverified(&receipt.sign(&key)).unwrap();
    assert_eq!(payload["status"], json!("Error"));
    assert_eq!(payload["error"], json!("invalid_mandate"));
    assert_eq!(payload["error_description"], json!("out of scope"));
    assert_eq!(
        Receipt::verify(&receipt.sign(&key), &key.public_jwk()).unwrap(),
        receipt
    );
}

#[test]
fn the_reference_is_the_sd_hash_of_the_closing_hop() {
    // AP2: "hash over the final SD-JWT in the chain ... calculated in the same manner as sd_hash".
    use sha2::Digest;
    let chain = chain();
    let closing = chain.rsplit("~~").next().unwrap();
    let expected = base64_url(&sha2::Sha256::digest(closing.as_bytes()));
    assert_eq!(reference_for(&chain).unwrap(), expected);
    // AP2's samples hash only the closing hop's JWT; recognised, never emitted.
    let jwt = closing.split('~').next().unwrap();
    assert_eq!(
        jwt_only_reference(&chain).unwrap(),
        base64_url(&sha2::Sha256::digest(jwt.as_bytes()))
    );
}

#[test]
fn a_receipt_matches_only_its_own_chain() {
    let (a, b) = (chain(), chain());
    let receipt = success(&a);
    assert!(receipt.matches(&a));
    assert!(!receipt.matches(&b));
}

#[test]
fn receipts_using_ap2_sample_references_still_match() {
    let chain = chain();
    let receipt = Receipt::new(
        "https://verifier.example.org",
        NOW,
        Outcome::Success,
        jwt_only_reference(&chain).unwrap(),
    );
    assert!(receipt.matches(&chain));
}

#[test]
fn a_receipt_signed_by_another_key_is_rejected() {
    let receipt = success(&chain()).sign(&SigningKey::generate());
    let err = Receipt::verify(&receipt, &SigningKey::generate().public_jwk()).unwrap_err();
    assert_eq!(err, Error::Mandate(a2a_gov_mandate::Error::BadSignature));
}

#[test]
fn released_entries_must_be_field_names_not_values() {
    for bad in ["title=Quarterly results", "a b", "", "x\ny"] {
        assert!(
            matches!(
                success(&chain()).with_released([bad]),
                Err(Error::Malformed(_))
            ),
            "{bad:?}"
        );
    }
    assert!(
        success(&chain())
            .with_released(["items[0].title", "start", "calendar/end"])
            .is_ok()
    );
}

#[test]
fn the_spec_prose_result_field_is_accepted() {
    // AP2's prose names the field `result` ("success" | "error"); its schema and SDK use `status`.
    let key = SigningKey::generate();
    let jws = a2a_gov_mandate::jws::sign(
        &obj(json!({ "alg": "ES256", "typ": "JWT" })),
        &obj(
            json!({ "iss": "v", "iat": NOW, "result": "error", "error": "invalid_credential",
                     "error_description": "bad", "reference": "abc" }),
        ),
        &key,
    );
    let receipt = Receipt::verify(&jws, &key.public_jwk()).unwrap();
    assert_eq!(
        receipt.outcome(),
        &Outcome::Error {
            code: "invalid_credential".into(),
            description: "bad".into()
        }
    );
}

#[test]
fn malformed_receipts_are_rejected() {
    let key = SigningKey::generate();
    for payload in [
        json!({ "iss": "v", "iat": NOW, "reference": "abc" }), // no status
        json!({ "iss": "v", "iat": NOW, "status": "Maybe", "reference": "abc" }), // unknown status
        json!({ "iss": "v", "iat": NOW, "status": "Error", "reference": "abc" }), // error without code
        json!({ "iss": "v", "iat": NOW, "status": "Success", "reference": "abc", "error": "x" }), // code on success
        json!({ "iat": NOW, "status": "Success", "reference": "abc" }), // no iss
        json!({ "iss": "v", "status": "Success", "reference": "abc" }), // no iat
        json!({ "iss": "v", "iat": NOW, "status": "Success" }),         // no reference
        json!({ "iss": "v", "iat": NOW, "status": "Success", "result": "error", "reference": "abc" }), // ambiguous
        json!({ "iss": "v", "iat": NOW, "status": "Success", "reference": "abc", "released": ["title=secret"] }), // a value
    ] {
        let jws = a2a_gov_mandate::jws::sign(
            &obj(json!({ "alg": "ES256" })),
            &obj(payload.clone()),
            &key,
        );
        assert!(
            matches!(
                Receipt::verify(&jws, &key.public_jwk()),
                Err(Error::Malformed(_))
            ),
            "{payload}"
        );
    }
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
