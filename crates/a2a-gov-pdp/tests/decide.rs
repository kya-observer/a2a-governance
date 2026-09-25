//! The decision engine: a verified mandate chain against a concrete A2A call.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use a2a_gov_mandate::{Disclosable, SigningKey, issue_open, join, present};
use a2a_gov_pdp::memory::{MemoryNonces, MemoryRevocations, MemoryUses, StaticSurfaces};
use a2a_gov_pdp::{
    BackendError, Call, ChallengeReason, Decision, DenyReason, Engine, Nonces, Presentation,
    Release, Revocations, UseCounter,
};
use a2a_gov_receipt::Outcome;
use serde_json::{Map, Value, json};

const NOW: i64 = 1_790_000_000;
const AUD: &str = "https://vault.example.org/a2a";

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn reading(actions: &[&str], fields: &[&str]) -> Value {
    json!({ "type": "reading", "actions": actions, "fields": fields })
}

fn default_constraints() -> Value {
    json!([
        { "type": "access.authorization_details",
          "authorization_details": [reading(&["search"], &["title", "published"])] },
        { "type": "access.purpose", "purpose": "dpv:ServiceProvision" },
        { "type": "access.release", "release": "answer-only" },
        { "type": "access.max_uses", "max_uses": 3 },
    ])
}

struct World {
    surface: SigningKey,
    agent: SigningKey,
    open: String,
    nonces: Arc<MemoryNonces>,
    revocations: Arc<MemoryRevocations>,
    uses: Arc<MemoryUses>,
    engine: Engine,
}

fn world_with(constraints: Value) -> World {
    let surface = SigningKey::generate().with_kid("surface-1");
    let agent = SigningKey::generate();
    let sd = if constraints.is_array() {
        Disclosable::array_elements(["constraints"])
    } else {
        Disclosable::none()
    };
    let open = issue_open(
        &obj(json!({
            "vct": "mandate.access.1",
            "cnf": { "jwk": agent.public_jwk().to_value() },
            "iat": NOW, "exp": NOW + 3600,
            "constraints": constraints,
        })),
        &sd,
        &surface,
    )
    .unwrap();
    let nonces = Arc::new(MemoryNonces::default());
    let revocations = Arc::new(MemoryRevocations::default());
    let uses = Arc::new(MemoryUses::default());
    let engine = Engine::new(
        Arc::new(StaticSurfaces::single(surface.public_jwk())),
        nonces.clone(),
        revocations.clone(),
        uses.clone(),
    );
    World {
        surface,
        agent,
        open,
        nonces,
        revocations,
        uses,
        engine,
    }
}

fn world() -> World {
    world_with(default_constraints())
}

fn call() -> Call {
    Call {
        method: "SendMessage".into(),
        task_id: "task-1".into(),
        authorization_details: vec![reading(&["search"], &["title"])],
        purpose: None,
        release: Release::AnswerOnly,
    }
}

fn closed_for(call: &Call) -> Map<String, Value> {
    obj(json!({
        "vct": "mandate.access.1",
        "method": call.method,
        "task_id": call.task_id,
        "authorization_details": call.authorization_details,
    }))
}

/// Issues a fresh nonce and builds the agent's presentation for `closed`.
fn presentation_with(
    w: &World,
    prev: &[&str],
    holder: &SigningKey,
    closed: Map<String, Value>,
) -> (String, String) {
    let nonce = w.nonces.issue();
    let closing = present(
        prev.last().unwrap(),
        &closed,
        &Disclosable::none(),
        holder,
        AUD,
        &nonce,
        NOW,
    )
    .unwrap();
    let mut segments = prev.to_vec();
    segments.push(&closing);
    (join(&segments), nonce)
}

fn decide_closed(w: &World, closed: Map<String, Value>, call: &Call) -> Decision {
    let (chain, nonce) = presentation_with(w, &[&w.open], &w.agent, closed);
    w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        call,
        NOW,
    )
}

fn decide(w: &World, call: &Call) -> Decision {
    decide_closed(w, closed_for(call), call)
}

fn denied(d: &Decision) -> DenyReason {
    match d {
        Decision::Deny { reason, .. } => *reason,
        other => panic!("expected a denial, got {other:?}"),
    }
}

// --- Pass ---------------------------------------------------------------------

#[test]
fn a_call_inside_the_mandate_passes() {
    let w = world();
    match decide(&w, &call()) {
        Decision::Pass(grant) => {
            assert_eq!(grant.purpose.as_deref(), Some("dpv:ServiceProvision"));
            assert_eq!(grant.release, Release::AnswerOnly);
            let jwt = w.open.split('~').next().unwrap();
            assert_eq!(grant.mandate_id, a2a_gov_mandate::sdjwt::digest(jwt));
        }
        other => panic!("{other:?}"),
    }
}

// --- Challenge ------------------------------------------------------------------

#[test]
fn no_mandate_means_approval_is_required() {
    let w = world();
    assert!(matches!(
        w.engine.decide(None, &call(), NOW),
        Decision::Challenge {
            reason: ChallengeReason::ApprovalRequired,
            ..
        }
    ));
}

#[test]
fn an_unknown_constraint_brings_the_user_back_in() {
    // AP2: unknown constraints MUST fail; `unresolved_constraint` MAY fall back to
    // a directly approved mandate.
    let mut constraints = default_constraints();
    constraints
        .as_array_mut()
        .unwrap()
        .push(json!({ "type": "vendor.geofence", "radius_m": 50 }));
    let w = world_with(constraints);
    assert!(matches!(
        decide(&w, &call()),
        Decision::Challenge {
            reason: ChallengeReason::UnresolvedConstraint,
            ..
        }
    ));
}

#[test]
fn a_failing_known_constraint_wins_over_an_unknown_one() {
    let mut constraints = default_constraints();
    constraints
        .as_array_mut()
        .unwrap()
        .push(json!({ "type": "vendor.geofence" }));
    let w = world_with(constraints);
    let mut c = call();
    c.authorization_details = vec![reading(&["delete"], &[])];
    assert_eq!(denied(&decide(&w, &c)), DenyReason::InvalidMandate);
}

// --- The closed mandate must describe this call ---------------------------------

#[test]
fn a_closed_mandate_for_another_call_is_refused() {
    let w = world();
    for mutate in [
        |c: &mut Map<String, Value>| {
            c.insert("method".into(), json!("GetTask"));
        },
        |c: &mut Map<String, Value>| {
            c.insert("task_id".into(), json!("task-2"));
        },
        |c: &mut Map<String, Value>| {
            c.insert(
                "authorization_details".into(),
                json!([reading(&["search"], &["title", "published"])]),
            );
        },
        |c: &mut Map<String, Value>| {
            c.remove("authorization_details");
        },
    ] {
        let mut closed = closed_for(&call());
        mutate(&mut closed);
        assert_eq!(
            denied(&decide_closed(&w, closed, &call())),
            DenyReason::InvalidMandate
        );
    }
}

// --- Constraints ----------------------------------------------------------------

#[test]
fn requests_outside_the_authorization_details_are_refused() {
    let w = world();
    for (actions, fields, kind) in [
        (vec!["delete"], vec!["title"], "reading"), // action not granted
        (vec!["search"], vec!["body"], "reading"),  // field not granted
        (vec!["search"], vec!["title"], "notes"),   // another resource type
    ] {
        let mut c = call();
        c.authorization_details =
            vec![json!({ "type": kind, "actions": actions, "fields": fields })];
        assert_eq!(
            denied(&decide(&w, &c)),
            DenyReason::InvalidMandate,
            "{kind} {actions:?} {fields:?}"
        );
    }
}

#[test]
fn unrestricted_dimensions_allow_anything_and_other_keys_must_match_exactly() {
    let w = world_with(json!([{ "type": "access.authorization_details",
        "authorization_details": [{ "type": "reading", "actions": ["search"], "window": "30d" }] }]));
    let mut c = call();
    c.authorization_details = vec![
        json!({ "type": "reading", "actions": ["search"], "fields": ["body"], "window": "30d" }),
    ];
    assert!(
        matches!(decide(&w, &c), Decision::Pass(_)),
        "fields unrestricted"
    );
    c.authorization_details =
        vec![json!({ "type": "reading", "actions": ["search"], "window": "365d" })];
    assert_eq!(
        denied(&decide(&w, &c)),
        DenyReason::InvalidMandate,
        "window differs"
    );
    c.authorization_details = vec![json!({ "type": "reading", "actions": ["search"] })];
    assert_eq!(
        denied(&decide(&w, &c)),
        DenyReason::InvalidMandate,
        "window missing"
    );
}

#[test]
fn records_cannot_be_released_under_an_answer_only_mandate() {
    let w = world();
    let mut c = call();
    c.release = Release::Records;
    assert_eq!(denied(&decide(&w, &c)), DenyReason::InvalidMandate);
}

#[test]
fn a_different_purpose_is_refused() {
    let w = world();
    let mut c = call();
    c.purpose = Some("dpv:Marketing".into());
    assert_eq!(denied(&decide(&w, &c)), DenyReason::InvalidMandate);
    c.purpose = Some("dpv:ServiceProvision".into());
    assert!(matches!(decide(&w, &c), Decision::Pass(_)));
}

#[test]
fn malformed_constraints_are_refused() {
    for constraints in [
        json!([{ "type": "access.max_uses", "max_uses": 0 }]),
        json!([{ "type": "access.max_uses", "max_uses": "3" }]),
        json!([{ "type": "access.release", "release": "everything" }]),
        json!([{ "no_type": true }]),
        json!("not an array"),
    ] {
        let w = world_with(constraints.clone());
        assert_eq!(
            denied(&decide(&w, &call())),
            DenyReason::InvalidMandate,
            "{constraints}"
        );
    }
}

// --- Use limits, replay -----------------------------------------------------------

#[test]
fn max_uses_is_counted_by_the_verifier() {
    let w = world();
    for _ in 0..3 {
        assert!(matches!(decide(&w, &call()), Decision::Pass(_)));
    }
    assert_eq!(denied(&decide(&w, &call())), DenyReason::InvalidMandate);
}

#[test]
fn a_presentation_cannot_be_replayed() {
    let w = world();
    let (chain, nonce) = presentation_with(&w, &[&w.open], &w.agent, closed_for(&call()));
    let p = || {
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        })
    };
    assert!(matches!(
        w.engine.decide(p(), &call(), NOW),
        Decision::Pass(_)
    ));
    assert_eq!(
        denied(&w.engine.decide(p(), &call(), NOW)),
        DenyReason::InvalidCredential
    );
}

#[test]
fn a_nonce_the_verifier_never_issued_is_refused() {
    let w = world();
    let closing = present(
        &w.open,
        &closed_for(&call()),
        &Disclosable::none(),
        &w.agent,
        AUD,
        "made-up",
        NOW,
    )
    .unwrap();
    let chain = join(&[&w.open, &closing]);
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: "made-up",
        }),
        &call(),
        NOW,
    );
    assert_eq!(denied(&d), DenyReason::InvalidCredential);
}

#[test]
fn a_refused_call_does_not_use_up_the_mandate() {
    let w = world();
    let mut bad = call();
    bad.release = Release::Records;
    for _ in 0..5 {
        denied(&decide(&w, &bad));
    }
    assert!(matches!(decide(&w, &call()), Decision::Pass(_)));
    assert_eq!(
        w.uses.count(&a2a_gov_mandate::sdjwt::digest(
            w.open.split('~').next().unwrap()
        )),
        1
    );
}

// --- Delegation -------------------------------------------------------------------

fn delegate(w: &World, constraints: Value) -> (String, SigningKey) {
    let sub = SigningKey::generate();
    let hop = present(
        &w.open,
        &obj(json!({ "vct": "mandate.access.1", "cnf": { "jwk": sub.public_jwk().to_value() }, "constraints": constraints })),
        &Disclosable::none(),
        &w.agent,
        "https://sub.example.org",
        "n-sub",
        NOW,
    )
    .unwrap();
    (hop, sub)
}

#[test]
fn a_delegation_can_only_narrow() {
    let w = world();
    let (hop, sub) = delegate(
        &w,
        json!([{ "type": "access.authorization_details",
        "authorization_details": [reading(&["search"], &["published"])] }]),
    );
    // Allowed by the open mandate, but not by the delegation.
    let (chain, nonce) = presentation_with(&w, &[&w.open, &hop], &sub, closed_for(&call()));
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        &call(),
        NOW,
    );
    assert_eq!(denied(&d), DenyReason::InvalidMandate);

    let mut c = call();
    c.authorization_details = vec![reading(&["search"], &["published"])];
    let (chain, nonce) = presentation_with(&w, &[&w.open, &hop], &sub, closed_for(&c));
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        &c,
        NOW,
    );
    assert!(matches!(d, Decision::Pass(_)), "{d:?}");
}

#[test]
fn delegation_depth_is_enforced() {
    let w = world_with(json!([{ "type": "access.delegation", "max_depth": 0 }]));
    let (hop, sub) = delegate(&w, json!([]));
    let (chain, nonce) = presentation_with(&w, &[&w.open, &hop], &sub, closed_for(&call()));
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        &call(),
        NOW,
    );
    assert_eq!(denied(&d), DenyReason::InvalidMandate);
}

#[test]
fn use_limits_on_a_delegation_count_separately_and_atomically() {
    let w = world(); // open mandate: 3 uses
    let (hop, sub) = delegate(&w, json!([{ "type": "access.max_uses", "max_uses": 1 }]));
    let via_sub = || {
        let (chain, nonce) = presentation_with(&w, &[&w.open, &hop], &sub, closed_for(&call()));
        w.engine.decide(
            Some(Presentation {
                chain: &chain,
                aud: AUD,
                nonce: &nonce,
            }),
            &call(),
            NOW,
        )
    };
    assert!(matches!(via_sub(), Decision::Pass(_)));
    assert_eq!(denied(&via_sub()), DenyReason::InvalidMandate);
    // The refused second call must not have spent one of the open mandate's uses.
    let open_id = a2a_gov_mandate::sdjwt::digest(w.open.split('~').next().unwrap());
    assert_eq!(w.uses.count(&open_id), 1);
}

// --- Revocation, credentials, fail closed -------------------------------------------

#[test]
fn revoked_mandates_are_refused() {
    let w = world();
    let open_id = a2a_gov_mandate::sdjwt::digest(w.open.split('~').next().unwrap());
    w.revocations.revoke(&open_id);
    assert_eq!(denied(&decide(&w, &call())), DenyReason::InvalidMandate);
}

#[test]
fn a_revoked_delegation_is_refused_even_though_the_open_mandate_is_live() {
    let w = world();
    let (hop, sub) = delegate(&w, json!([]));
    w.revocations.revoke(&a2a_gov_mandate::sdjwt::digest(
        hop.split('~').next().unwrap(),
    ));
    let (chain, nonce) = presentation_with(&w, &[&w.open, &hop], &sub, closed_for(&call()));
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        &call(),
        NOW,
    );
    assert_eq!(denied(&d), DenyReason::InvalidMandate);
}

#[test]
fn an_unverifiable_chain_is_an_invalid_credential() {
    let w = world();
    let other = world();
    let (chain, nonce) = presentation_with(&w, &[&other.open], &other.agent, closed_for(&call()));
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        &call(),
        NOW,
    );
    assert_eq!(denied(&d), DenyReason::InvalidCredential);
    let _ = &w.surface;
}

struct Broken;
impl Nonces for Broken {
    fn consume(&self, _: &str) -> Result<bool, BackendError> {
        Err(BackendError("down".into()))
    }
}
impl Revocations for Broken {
    fn is_revoked(&self, _: &str) -> Result<bool, BackendError> {
        Err(BackendError("down".into()))
    }
}
impl UseCounter for Broken {
    fn try_consume(&self, _: &[(String, u64)]) -> Result<bool, BackendError> {
        Err(BackendError("down".into()))
    }
}

#[test]
fn any_backend_failure_fails_closed() {
    let w = world();
    let surfaces = Arc::new(StaticSurfaces::single(w.surface.public_jwk()));
    let engines = [
        Engine::new(
            surfaces.clone(),
            Arc::new(Broken),
            w.revocations.clone(),
            w.uses.clone(),
        ),
        Engine::new(
            surfaces.clone(),
            w.nonces.clone(),
            Arc::new(Broken),
            w.uses.clone(),
        ),
        Engine::new(
            surfaces,
            w.nonces.clone(),
            w.revocations.clone(),
            Arc::new(Broken),
        ),
    ];
    for engine in engines {
        let (chain, nonce) = presentation_with(&w, &[&w.open], &w.agent, closed_for(&call()));
        let d = engine.decide(
            Some(Presentation {
                chain: &chain,
                aud: AUD,
                nonce: &nonce,
            }),
            &call(),
            NOW,
        );
        assert_eq!(denied(&d), DenyReason::Denied);
    }
}

// --- Receipts -------------------------------------------------------------------------

#[test]
fn every_verified_decision_yields_a_receipt() {
    let w = world();
    let (chain, nonce) = presentation_with(&w, &[&w.open], &w.agent, closed_for(&call()));
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        &call(),
        NOW,
    );
    let r = d.receipt(AUD, NOW, Some(&chain)).unwrap();
    assert_eq!(r.outcome(), &Outcome::Success);
    assert!(r.matches(&chain));

    let mut bad = call();
    bad.release = Release::Records;
    let (chain, nonce) = presentation_with(&w, &[&w.open], &w.agent, closed_for(&bad));
    let d = w.engine.decide(
        Some(Presentation {
            chain: &chain,
            aud: AUD,
            nonce: &nonce,
        }),
        &bad,
        NOW,
    );
    let r = d.receipt(AUD, NOW, Some(&chain)).unwrap();
    assert!(matches!(r.outcome(), Outcome::Error { code, .. } if code == "invalid_mandate"));

    assert!(
        w.engine
            .decide(None, &call(), NOW)
            .receipt(AUD, NOW, None)
            .is_none()
    );
}

#[test]
fn a_request_must_state_every_dimension_the_mandate_restricts() {
    // An omitted `fields` could mean "all fields".
    let w = world();
    for requested in [
        json!({ "type": "reading", "actions": ["search"] }),
        json!({ "type": "reading", "fields": ["title"] }),
    ] {
        let mut c = call();
        c.authorization_details = vec![requested.clone()];
        assert_eq!(
            denied(&decide(&w, &c)),
            DenyReason::InvalidMandate,
            "{requested}"
        );
    }
}
