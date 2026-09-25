//! Agent Cards signed by the official a2a-sdk (1.1.5) verify here.
//! Vectors: `testdata/a2a/cards.json`, from `interop/a2a/gen_card_vectors.py`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_card::{Form, VerifyOptions, verify};
use a2a_gov_mandate::PublicJwk;
use serde_json::Value;

fn vector(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/a2a/cards.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
        .clone()
}

fn check(name: &str, opts: &VerifyOptions) -> Result<a2a_gov_card::Verified, a2a_gov_card::Error> {
    let v = vector(name);
    let key = PublicJwk::from_value(&v["jwk"]).unwrap();
    let kid = v["kid"].as_str().unwrap().to_owned();
    verify(&v["card"], move |k| (k == kid).then(|| key.clone()), opts)
}

#[test]
fn ordinary_sdk_signed_cards_verify_under_the_spec_form() {
    // Without empty values, the a2a-sdk's payload and §8.4.1's coincide.
    for name in ["plain", "unicode"] {
        assert_eq!(
            check(name, &VerifyOptions::default()).unwrap().form,
            Form::Spec,
            "{name}"
        );
    }
}

#[test]
fn an_sdk_signed_card_with_an_empty_required_field() {
    // The a2a-sdk serializes the card without the empty REQUIRED description, so
    // as received, both payload forms agree.
    assert_eq!(
        check("empty-description", &VerifyOptions::default())
            .unwrap()
            .form,
        Form::Spec
    );

    // Served as §5.7 requires (REQUIRED fields always present), the card carries
    // `"description": ""`, which the §8.4.1 payload keeps and the a2a-sdk's
    // signature didn't cover.
    let mut v = vector("empty-description");
    v["card"]["description"] = serde_json::json!("");
    let key = PublicJwk::from_value(&v["jwk"]).unwrap();
    let kid = v["kid"].as_str().unwrap().to_owned();
    let lookup = |k: &str| (k == kid).then(|| key.clone());
    assert_eq!(
        verify(&v["card"], lookup, &VerifyOptions::default())
            .unwrap()
            .form,
        Form::A2aSdk
    );
    let strict = VerifyOptions {
        accept_a2a_sdk_form: false,
    };
    assert!(verify(&v["card"], lookup, &strict).is_err());
}

#[test]
fn an_empty_extension_param_is_not_covered_by_an_sdk_signature() {
    // The a2a-sdk drops empty values inside `params` before signing; the card as
    // served still carries them. Only the a2a-sdk form verifies, and says so.
    let v = vector("empty-param");
    assert_eq!(
        v["card"]["capabilities"]["extensions"][0]["params"]["note"],
        serde_json::json!("")
    );
    assert_eq!(
        check("empty-param", &VerifyOptions::default())
            .unwrap()
            .form,
        Form::A2aSdk
    );
}

#[test]
fn fields_the_sdk_doesnt_know_are_outside_its_signature() {
    // A server may serve fields a newer spec added; the a2a-sdk signs without them.
    let mut v = vector("plain");
    v["card"]["futureField"] = serde_json::json!("x");
    let key = PublicJwk::from_value(&v["jwk"]).unwrap();
    let kid = v["kid"].as_str().unwrap().to_owned();
    let verified = verify(
        &v["card"],
        |k| (k == kid).then(|| key.clone()),
        &VerifyOptions::default(),
    )
    .unwrap();
    assert_eq!(verified.form, Form::A2aSdk);
}
