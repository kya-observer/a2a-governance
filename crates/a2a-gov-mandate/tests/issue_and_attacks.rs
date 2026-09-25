//! Issuing mandates, and the attacks a verifier must refuse.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_mandate::{
    Disclosable, Error, HopKind, SigningKey, VerifyOptions, issue_open, join, present, verify_chain,
};
use base64::Engine;
use serde_json::{Map, Value, json};

const AUD: &str = "https://agent.example.org/a2a";
const NONCE: &str = "nonce-1";
const NOW: i64 = 1_790_000_000;

struct Fixture {
    surface: SigningKey,
    agent: SigningKey,
    open: String,
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn open_mandate(agent: &SigningKey) -> Map<String, Value> {
    obj(json!({
        "vct": "mandate.access.1",
        "cnf": { "jwk": agent.public_jwk().to_value() },
        "iat": NOW,
        "exp": NOW + 7200,
        "constraints": [
            { "type": "access.purpose", "purpose": "dpv:ServiceProvision" },
            { "type": "access.max_uses", "max_uses": 3 },
        ],
    }))
}

fn closed_mandate() -> Map<String, Value> {
    obj(json!({ "vct": "mandate.access.1", "method": "SendMessage", "task_id": "t-1" }))
}

fn fixture() -> Fixture {
    let surface = SigningKey::generate().with_kid("surface-1");
    let agent = SigningKey::generate();
    let open = issue_open(
        &open_mandate(&agent),
        &Disclosable::array_elements(["constraints"]),
        &surface,
    )
    .unwrap();
    Fixture {
        surface,
        agent,
        open,
    }
}

fn closing(f: &Fixture, item: Map<String, Value>, iat: i64) -> String {
    present(
        &f.open,
        &item,
        &Disclosable::none(),
        &f.agent,
        AUD,
        NONCE,
        iat,
    )
    .unwrap()
}

fn verify(f: &Fixture, chain: &str) -> Result<a2a_gov_mandate::VerifiedChain, Error> {
    let key = f.surface.public_jwk();
    verify_chain(
        chain,
        move |_| Some(key.clone()),
        &VerifyOptions::new(AUD, NONCE, NOW),
    )
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}

#[test]
fn issued_chains_round_trip() {
    let f = fixture();
    let chain = join(&[&f.open, &closing(&f, closed_mandate(), NOW)]);
    let verified = verify(&f, &chain).unwrap();
    assert_eq!(verified.hops().len(), 2);
    assert_eq!(verified.closed()["method"], json!("SendMessage"));
    assert_eq!(verified.open()["constraints"][1]["max_uses"], json!(3));
    assert_eq!(verified.hops()[0].header()["typ"], json!("dc+sd-jwt"));
    assert_eq!(verified.hops()[0].header()["kid"], json!("surface-1"));
}

#[test]
fn delegation_hops_round_trip() {
    let f = fixture();
    let sub = SigningKey::generate();
    let delegated = obj(json!({
        "vct": "mandate.access.1",
        "cnf": { "jwk": sub.public_jwk().to_value() },
        "constraints": [{ "type": "access.max_uses", "max_uses": 1 }],
    }));
    let hop1 = present(
        &f.open,
        &delegated,
        &Disclosable::none(),
        &f.agent,
        "sub",
        "n-sub",
        NOW,
    )
    .unwrap();
    let hop2 = present(
        &hop1,
        &closed_mandate(),
        &Disclosable::none(),
        &sub,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    let verified = verify(&f, &join(&[&f.open, &hop1, &hop2])).unwrap();
    let kinds: Vec<HopKind> = verified.hops().iter().map(|h| h.kind()).collect();
    assert_eq!(
        kinds,
        [HopKind::Root, HopKind::Delegation, HopKind::Closing]
    );
}

#[test]
fn a_hop_signed_by_anyone_but_the_bound_key_is_rejected() {
    let f = fixture();
    let thief = SigningKey::generate();
    let hop = present(
        &f.open,
        &closed_mandate(),
        &Disclosable::none(),
        &thief,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    assert_eq!(
        verify(&f, &join(&[&f.open, &hop])).unwrap_err(),
        Error::BadSignature
    );
}

#[test]
fn a_closing_hop_must_not_carry_cnf() {
    // A hop with cnf is a delegation; ending the chain on one is not a closed mandate.
    let f = fixture();
    let mut item = closed_mandate();
    item.insert(
        "cnf".into(),
        json!({ "jwk": SigningKey::generate().public_jwk().to_value() }),
    );
    let hop = present(
        &f.open,
        &item,
        &Disclosable::none(),
        &f.agent,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        verify(&f, &join(&[&f.open, &hop])).unwrap_err(),
        Error::Chain(_)
    ));
}

#[test]
fn the_mandate_type_cannot_change_along_the_chain() {
    let f = fixture();
    let mut item = closed_mandate();
    item.insert("vct".into(), json!("mandate.payment.1"));
    let hop = present(
        &f.open,
        &item,
        &Disclosable::none(),
        &f.agent,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        verify(&f, &join(&[&f.open, &hop])).unwrap_err(),
        Error::Chain(_)
    ));
}

#[test]
fn stale_closing_hops_are_rejected() {
    // The nonce is the main replay defence; a freshness bound limits the window
    // in which a captured presentation is useful at all.
    let f = fixture();
    let hop = closing(&f, closed_mandate(), NOW - 3600);
    assert_eq!(
        verify(&f, &join(&[&f.open, &hop])).unwrap_err(),
        Error::Stale
    );
}

#[test]
fn hops_issued_in_the_future_are_rejected() {
    let f = fixture();
    let hop = closing(&f, closed_mandate(), NOW + 3600);
    assert_eq!(
        verify(&f, &join(&[&f.open, &hop])).unwrap_err(),
        Error::NotYetValid
    );
}

#[test]
fn a_tampered_disclosure_is_rejected() {
    let f = fixture();
    let chain = join(&[&f.open, &closing(&f, closed_mandate(), NOW)]);
    let forged = b64(&json!(["salt", {"type": "access.max_uses", "max_uses": 999}]).to_string());
    let (root, rest) = chain.split_once("~~").unwrap();
    let mut parts: Vec<&str> = root.split('~').collect();
    parts[1] = &forged;
    let err = verify(&f, &format!("{}~~{rest}", parts.join("~"))).unwrap_err();
    assert!(
        matches!(err, Error::Disclosure(_) | Error::Binding(_)),
        "{err}"
    );
}

#[test]
fn duplicate_disclosures_are_rejected() {
    // RFC 9901 §7.1: a digest may be referenced at most once.
    let f = fixture();
    let first_disclosure = f.open.split('~').nth(1).unwrap().to_owned();
    let doubled = format!("{}{first_disclosure}~", f.open);
    let hop = present(
        &doubled,
        &closed_mandate(),
        &Disclosable::none(),
        &f.agent,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        verify(&f, &join(&[&doubled, &hop])).unwrap_err(),
        Error::Disclosure(_)
    ));
}

#[test]
fn a_cnf_carrying_a_private_key_is_rejected() {
    let surface = SigningKey::generate();
    let agent = SigningKey::generate();
    let mut open = open_mandate(&agent);
    let mut leaked = agent.public_jwk().to_value();
    leaked["d"] = json!(b64("private scalar"));
    open.insert("cnf".into(), json!({ "jwk": leaked }));
    let token = issue_open(&open, &Disclosable::none(), &surface).unwrap();
    let hop = present(
        &token,
        &closed_mandate(),
        &Disclosable::none(),
        &agent,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    let key = surface.public_jwk();
    let err = verify_chain(
        &join(&[&token, &hop]),
        move |_| Some(key.clone()),
        &VerifyOptions::new(AUD, NONCE, NOW),
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidKey(_)), "{err}");
}

#[test]
fn only_es256_is_accepted() {
    // Swap the root header for alg=none; the signature can no longer be checked.
    let f = fixture();
    let chain = join(&[&f.open, &closing(&f, closed_mandate(), NOW)]);
    let header = b64(r#"{"alg":"none","typ":"dc+sd-jwt"}"#);
    let (_, after_header) = chain.split_once('.').unwrap();
    let err = verify(&f, &format!("{header}.{after_header}")).unwrap_err();
    assert!(matches!(err, Error::UnsupportedAlgorithm(_)), "{err}");
}

#[test]
fn oversized_input_is_rejected_before_parsing() {
    let f = fixture();
    let huge = "a".repeat(a2a_gov_mandate::MAX_CHAIN_BYTES + 1);
    assert!(matches!(
        verify(&f, &huge).unwrap_err(),
        Error::Malformed(_)
    ));
}

fn chain_with_delegations(f: &Fixture, delegations: usize) -> String {
    let mut segments = vec![f.open.clone()];
    let mut holder = f.agent.clone();
    for i in 0..delegations {
        let next = SigningKey::generate();
        let item = obj(json!({
            "vct": "mandate.access.1",
            "cnf": { "jwk": next.public_jwk().to_value() },
        }));
        let hop = present(
            segments.last().unwrap(),
            &item,
            &Disclosable::none(),
            &holder,
            "x",
            &format!("n{i}"),
            NOW,
        )
        .unwrap();
        segments.push(hop);
        holder = next;
    }
    let closing = present(
        segments.last().unwrap(),
        &closed_mandate(),
        &Disclosable::none(),
        &holder,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    segments.push(closing);
    let refs: Vec<&str> = segments.iter().map(String::as_str).collect();
    join(&refs)
}

#[test]
fn chains_up_to_the_hop_limit_verify() {
    let f = fixture();
    let chain = chain_with_delegations(&f, a2a_gov_mandate::MAX_HOPS - 2);
    assert_eq!(
        verify(&f, &chain).unwrap().hops().len(),
        a2a_gov_mandate::MAX_HOPS
    );
}

#[test]
fn overlong_chains_are_rejected() {
    let f = fixture();
    let chain = chain_with_delegations(&f, a2a_gov_mandate::MAX_HOPS - 1);
    let err = verify(&f, &chain).unwrap_err();
    assert_eq!(
        err,
        Error::Chain(format!("more than {} hops", a2a_gov_mandate::MAX_HOPS))
    );
}

#[test]
fn an_agent_cannot_smuggle_disclosures_into_the_open_mandate() {
    // The agent signs the closing hop, so it can make sd_hash match anything it
    // appends. Only RFC 9901's "every disclosure must be referenced" rule stops it.
    let f = fixture();
    let forged = b64(&json!(["salt", {"type": "access.max_uses", "max_uses": 999}]).to_string());
    let smuggled = format!("{}{forged}~", f.open);
    let hop = present(
        &smuggled,
        &closed_mandate(),
        &Disclosable::none(),
        &f.agent,
        AUD,
        NONCE,
        NOW,
    )
    .unwrap();
    let err = verify(&f, &join(&[&smuggled, &hop])).unwrap_err();
    assert!(matches!(err, Error::Disclosure(_)), "{err}");
}

#[test]
fn hop_ids_are_stable_across_presentations_of_one_mandate() {
    // Use counting and revocation key on these IDs, so two closing hops over the
    // same open mandate must share its ID, and differ from each other.
    let f = fixture();
    let a = verify(&f, &join(&[&f.open, &closing(&f, closed_mandate(), NOW)])).unwrap();
    let b = verify(&f, &join(&[&f.open, &closing(&f, closed_mandate(), NOW)])).unwrap();
    assert_eq!(a.hops()[0].id(), b.hops()[0].id());
    assert_ne!(a.hops()[1].id(), b.hops()[1].id());
    let jwt = f.open.split('~').next().unwrap();
    assert_eq!(a.hops()[0].id(), a2a_gov_mandate::sdjwt::digest(jwt));
}
