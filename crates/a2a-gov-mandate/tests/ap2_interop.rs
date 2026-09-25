//! Chains minted by Google's AP2 Python SDK must verify here, with the same
//! resolved content AP2 put in.
//!
//! Vectors: `testdata/ap2/access_chains.json`, produced by
//! `interop/ap2/gen_ap2_vectors.py` against AP2 commit e1ea56d.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_mandate::{Error, HopKind, PublicJwk, VerifyOptions, verify_chain};
use serde_json::{Value, json};

fn vectors() -> Vec<Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/ap2/access_chains.json"
    );
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("vectors present"))
            .expect("valid JSON");
    file["vectors"].as_array().expect("vectors array").clone()
}

fn root_key(v: &Value) -> PublicJwk {
    PublicJwk::from_value(&v["trusted_surface_jwk"]).expect("valid JWK")
}

fn opts(v: &Value) -> VerifyOptions {
    VerifyOptions::new(
        v["aud"].as_str().unwrap(),
        v["nonce"].as_str().unwrap(),
        v["issued_at"].as_i64().unwrap(),
    )
}

/// Drops fields AP2 adds for binding so we can compare mandate content.
fn content(mut m: serde_json::Map<String, Value>) -> Value {
    m.remove("_sd");
    Value::Object(m)
}

#[test]
fn every_ap2_one_hop_chain_verifies() {
    let vectors = vectors();
    assert!(
        vectors.len() >= 20,
        "need enough vectors to catch signature-shape issues"
    );
    for v in &vectors {
        let chain = verify_chain(
            v["chain"].as_str().unwrap(),
            |_| Some(root_key(v)),
            &opts(v),
        )
        .unwrap_or_else(|e| panic!("AP2 chain rejected: {e}"));
        assert_eq!(chain.hops().len(), 2);
        assert_eq!(chain.hops()[0].kind(), HopKind::Root);
        assert_eq!(chain.hops()[1].kind(), HopKind::Closing);
        assert_eq!(content(chain.open().clone()), v["expected_open"]);
        assert_eq!(content(chain.closed().clone()), v["expected_closed"]);
    }
}

#[test]
fn every_ap2_two_hop_chain_verifies() {
    for v in &vectors() {
        let chain = verify_chain(
            v["two_hop_chain"].as_str().unwrap(),
            |_| Some(root_key(v)),
            &opts(v),
        )
        .unwrap_or_else(|e| panic!("AP2 two-hop chain rejected: {e}"));
        let kinds: Vec<HopKind> = chain.hops().iter().map(|h| h.kind()).collect();
        assert_eq!(
            kinds,
            [HopKind::Root, HopKind::Delegation, HopKind::Closing]
        );
        assert_eq!(
            content(chain.hops()[1].mandate().clone()),
            v["expected_delegated"]
        );
        assert_eq!(content(chain.closed().clone()), v["expected_closed"]);
    }
}

#[test]
fn nested_constraint_disclosures_resolve_in_order() {
    let v = &vectors()[0];
    let chain = verify_chain(
        v["chain"].as_str().unwrap(),
        |_| Some(root_key(v)),
        &opts(v),
    )
    .unwrap();
    let types: Vec<&str> = chain.open()["constraints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        [
            "access.authorization_details",
            "access.purpose",
            "access.release",
            "access.max_uses"
        ]
    );
}

#[test]
fn the_wrong_trusted_surface_key_is_rejected() {
    let all = vectors();
    let (v, other) = (&all[0], &all[1]);
    let err = verify_chain(
        v["chain"].as_str().unwrap(),
        |_| Some(root_key(other)),
        &opts(v),
    )
    .unwrap_err();
    assert_eq!(err, Error::BadSignature);
}

#[test]
fn an_unknown_trusted_surface_is_rejected() {
    let v = &vectors()[0];
    let err = verify_chain(v["chain"].as_str().unwrap(), |_| None, &opts(v)).unwrap_err();
    assert!(matches!(err, Error::UnknownIssuer), "{err}");
}

#[test]
fn audience_and_nonce_must_match_the_verifier() {
    let v = &vectors()[0];
    let chain = v["chain"].as_str().unwrap();
    let issued = v["issued_at"].as_i64().unwrap();
    let wrong_aud = VerifyOptions::new(
        "https://evil.example/a2a",
        v["nonce"].as_str().unwrap(),
        issued,
    );
    let wrong_nonce = VerifyOptions::new(v["aud"].as_str().unwrap(), "replayed-nonce", issued);
    assert_eq!(
        verify_chain(chain, |_| Some(root_key(v)), &wrong_aud).unwrap_err(),
        Error::Audience
    );
    assert_eq!(
        verify_chain(chain, |_| Some(root_key(v)), &wrong_nonce).unwrap_err(),
        Error::Nonce
    );
}

#[test]
fn an_expired_mandate_is_rejected() {
    let v = &vectors()[0];
    let exp = v["expected_open"]["exp"].as_i64().unwrap();
    let late = VerifyOptions::new(
        v["aud"].as_str().unwrap(),
        v["nonce"].as_str().unwrap(),
        exp + 3600,
    )
    .max_closing_age(u32::MAX);
    let err = verify_chain(v["chain"].as_str().unwrap(), |_| Some(root_key(v)), &late).unwrap_err();
    assert_eq!(err, Error::Expired);
}

#[test]
fn a_constraint_cannot_be_stripped_from_the_open_mandate() {
    // The closing hop's sd_hash covers the open mandate's disclosures, so an agent
    // can't drop a constraint (e.g. access.max_uses) it doesn't like.
    let v = &vectors()[0];
    let chain = v["chain"].as_str().unwrap();
    let max_uses = json!({"type": "access.max_uses", "max_uses": 3});
    let (root, rest) = chain.split_once("~~").unwrap();
    let kept: Vec<&str> = root
        .split('~')
        .filter(|seg| {
            a2a_gov_mandate::sdjwt::Disclosure::parse(seg)
                .map(|d| *d.value() != max_uses)
                .unwrap_or(true)
        })
        .collect();
    assert_eq!(
        kept.len(),
        root.split('~').count() - 1,
        "fixture must contain the constraint"
    );
    let tampered = format!("{}~~{rest}", kept.join("~"));
    let err = verify_chain(&tampered, |_| Some(root_key(v)), &opts(v)).unwrap_err();
    assert!(
        matches!(err, Error::Disclosure(_) | Error::Binding(_)),
        "{err}"
    );
}

#[test]
fn a_closing_hop_cannot_be_moved_to_another_chain() {
    let all = vectors();
    let (a, b) = (&all[0], &all[1]);
    let a_root = a["chain"].as_str().unwrap().split_once("~~").unwrap().0;
    let b_closing = b["chain"].as_str().unwrap().split_once("~~").unwrap().1;
    let spliced = format!("{a_root}~~{b_closing}");
    let err = verify_chain(&spliced, |_| Some(root_key(a)), &opts(a)).unwrap_err();
    assert_eq!(err, Error::BadSignature);
}

#[test]
fn an_open_mandate_alone_is_not_a_presentation() {
    let v = &vectors()[0];
    let err = verify_chain(
        v["open_mandate"].as_str().unwrap(),
        |_| Some(root_key(v)),
        &opts(v),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Chain(_)), "{err}");
}

#[test]
fn a_chain_ending_in_a_delegation_is_not_a_presentation() {
    let v = &vectors()[0];
    let two_hop = v["two_hop_chain"].as_str().unwrap();
    let without_closing = &two_hop[..two_hop.rfind("~~").unwrap()];
    let err = verify_chain(
        &format!("{without_closing}~"),
        |_| Some(root_key(v)),
        &opts(v),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Chain(_)), "{err}");
}

#[test]
fn high_s_signatures_from_ap2_are_accepted() {
    // Python's `cryptography` doesn't normalize ECDSA `s`; some verifiers reject
    // high-S signatures. The vectors must contain some, and all verified above.
    const HALF_N: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    use base64::Engine;
    let mut high = 0;
    let mut total = 0;
    for v in vectors() {
        for segment in v["two_hop_chain"].as_str().unwrap().split("~~") {
            let jwt = segment.split('~').next().unwrap();
            let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwt.rsplit('.').next().unwrap())
                .unwrap();
            total += 1;
            if sig[32..] > HALF_N[..] {
                high += 1;
            }
        }
    }
    assert!(
        high > 0 && high < total,
        "{high} of {total} signatures are high-S"
    );
}

#[test]
fn any_change_to_the_open_mandate_after_the_agent_signed_breaks_the_binding() {
    // Reordering keeps every disclosure present and resolvable; only the closing
    // hop's sd_hash notices.
    let v = &vectors()[0];
    let chain = v["chain"].as_str().unwrap();
    let (root, rest) = chain.split_once("~~").unwrap();
    let mut parts: Vec<&str> = root.split('~').collect();
    parts.swap(1, 2);
    let err = verify_chain(
        &format!("{}~~{rest}", parts.join("~")),
        |_| Some(root_key(v)),
        &opts(v),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Binding(_)), "{err}");
}
