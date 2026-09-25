//! Tokens a hostile signer could produce but the public issuing API can't.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Map, Value, json};

use crate::sdjwt::{Builder, SD_ALG, digest, resolve};
use crate::{
    Disclosable, Error, SigningKey, VerifyOptions, b64, issue_open, join, jws, verify_chain,
};

const NOW: i64 = 1_790_000_000;

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn hop_with_typ(prev: &str, mandate: &Map<String, Value>, typ: &str, key: &SigningKey) -> String {
    let mut builder = Builder::new();
    let mut payload = Map::new();
    payload.insert(
        "delegate_payload".into(),
        builder
            .delegate_payload(mandate, &Disclosable::none())
            .unwrap(),
    );
    payload.insert("iat".into(), json!(NOW));
    payload.insert("aud".into(), json!("aud"));
    payload.insert("nonce".into(), json!("nonce"));
    payload.insert("sd_hash".into(), json!(digest(prev)));
    payload.insert("_sd_alg".into(), json!(SD_ALG));
    let header = obj(json!({ "alg": "ES256", "typ": typ }));
    let mut out = jws::sign(&header, &payload, key);
    out.push('~');
    for d in builder.disclosures() {
        out.push_str(d);
        out.push('~');
    }
    out
}

fn verify_forged(typ: &str, with_cnf: bool) -> Error {
    let surface = SigningKey::generate();
    let agent = SigningKey::generate();
    let open = issue_open(
        &obj(json!({ "vct": "v", "cnf": { "jwk": agent.public_jwk().to_value() }, "exp": NOW + 3600 })),
        &Disclosable::none(),
        &surface,
    )
    .unwrap();
    let mut mandate = obj(json!({ "vct": "v" }));
    if with_cnf {
        mandate.insert(
            "cnf".into(),
            json!({ "jwk": SigningKey::generate().public_jwk().to_value() }),
        );
    }
    let hop = hop_with_typ(&open, &mandate, typ, &agent);
    let key = surface.public_jwk();
    verify_chain(
        &join(&[&open, &hop]),
        move |_| Some(key.clone()),
        &VerifyOptions::new("aud", "nonce", NOW),
    )
    .unwrap_err()
}

#[test]
fn a_closing_typed_hop_carrying_cnf_is_rejected() {
    assert_eq!(
        verify_forged("kb+sd-jwt", true),
        Error::Chain("closing hop carries cnf".into())
    );
}

#[test]
fn a_delegation_typed_hop_without_cnf_is_rejected() {
    // Mid-chain, so "chain ends in a delegation" can't be what rejects it.
    let surface = SigningKey::generate();
    let agent = SigningKey::generate();
    let open = issue_open(
        &obj(json!({ "vct": "v", "cnf": { "jwk": agent.public_jwk().to_value() }, "exp": NOW + 3600 })),
        &Disclosable::none(),
        &surface,
    )
    .unwrap();
    let bad = hop_with_typ(&open, &obj(json!({ "vct": "v" })), "kb+sd-jwt+kb", &agent);
    let closing = hop_with_typ(&bad, &obj(json!({ "vct": "v" })), "kb+sd-jwt", &agent);
    let key = surface.public_jwk();
    let err = verify_chain(
        &join(&[&open, &bad, &closing]),
        move |_| Some(key.clone()),
        &VerifyOptions::new("aud", "nonce", NOW),
    )
    .unwrap_err();
    assert_eq!(err, Error::Chain("delegation lacks cnf".into()));
}

#[test]
fn unknown_hop_types_are_rejected() {
    // AP2 also accepts "kb-sd-jwt"; this crate accepts only the forms AP2 emits.
    assert!(matches!(verify_forged("kb-sd-jwt", false), Error::Chain(_)));
    assert!(matches!(verify_forged("JWT", false), Error::Chain(_)));
}

fn disclosure(parts: Value) -> String {
    b64::encode(parts.to_string())
}

#[test]
fn a_digest_referenced_twice_is_rejected() {
    // RFC 9901 §7.1: reject if any digest appears more than once.
    let d = disclosure(json!(["s", "a", 1]));
    let payload = obj(json!({ "_sd": [digest(&d), digest(&d)] }));
    assert!(matches!(resolve(payload, &[&d]), Err(Error::Disclosure(_))));

    let e = disclosure(json!(["s", 1]));
    let payload = obj(json!({ "list": [{ "...": digest(&e) }, { "...": digest(&e) }] }));
    assert!(matches!(resolve(payload, &[&e]), Err(Error::Disclosure(_))));

    let decoy = digest("decoy");
    let payload = obj(json!({ "_sd": [decoy.clone()], "x": { "_sd": [decoy] } }));
    assert!(matches!(resolve(payload, &[]), Err(Error::Disclosure(_))));
}

#[test]
fn withheld_or_decoy_digests_are_refused() {
    // A withheld disclosure and a decoy look the same to a verifier. Either could
    // hide a constraint, so this profile accepts neither.
    let d = disclosure(json!(["s", "a", 1]));
    let payload = obj(json!({ "_sd": [digest(&d), digest("decoy")] }));
    assert!(matches!(resolve(payload, &[&d]), Err(Error::Disclosure(_))));
    let payload = obj(json!({ "list": [{ "...": digest("decoy2") }, 2] }));
    assert!(matches!(resolve(payload, &[]), Err(Error::Disclosure(_))));
    let payload = obj(json!({ "_sd": [digest(&d)], "list": [2] }));
    assert_eq!(
        Value::Object(resolve(payload, &[&d]).unwrap()),
        json!({ "a": 1, "list": [2] })
    );
}

#[test]
fn a_claim_cannot_be_both_plain_and_disclosed() {
    let d = disclosure(json!(["s", "a", 2]));
    let payload = obj(json!({ "a": 1, "_sd": [digest(&d)] }));
    assert!(matches!(resolve(payload, &[&d]), Err(Error::Disclosure(_))));
}

#[test]
fn disclosure_kinds_must_match_their_position() {
    let element = disclosure(json!(["s", 1]));
    let claim = disclosure(json!(["s", "a", 1]));
    assert!(matches!(
        resolve(obj(json!({ "_sd": [digest(&element)] })), &[&element]),
        Err(Error::Disclosure(_))
    ));
    assert!(matches!(
        resolve(obj(json!({ "l": [{ "...": digest(&claim) }] })), &[&claim]),
        Err(Error::Disclosure(_))
    ));
}

#[test]
fn only_sha_256_is_accepted() {
    assert!(matches!(
        resolve(obj(json!({ "_sd_alg": "sha-512" })), &[]),
        Err(Error::Disclosure(_))
    ));
}

#[test]
fn nested_disclosures_resolve_recursively() {
    let inner = disclosure(json!(["s1", "city", "Paris"]));
    let outer = disclosure(json!(["s2", "address", { "_sd": [digest(&inner)] }]));
    let payload = obj(json!({ "_sd": [digest(&outer)] }));
    let resolved = resolve(payload, &[&outer, &inner]).unwrap();
    assert_eq!(
        Value::Object(resolved),
        json!({ "address": { "city": "Paris" } })
    );
}
