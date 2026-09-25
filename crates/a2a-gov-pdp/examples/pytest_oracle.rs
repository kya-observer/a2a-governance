//! A verifier for the Python package's end-to-end tests. Reads JSON on stdin:
//!
//! - `issue`: `{"agent_jwk"}` → an approved task status carrying an open mandate
//!   bound to that key, plus the surface key and the call to make.
//! - `decide`: `{"message", "surface_jwk", "call"}` → the engine's decision on the
//!   continuation message and, when a chain was presented, a result artifact with
//!   a receipt.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use a2a_gov_binding::{
    Approved, AuthState, ReceiptMeta, read_presentation, receipt_artifact, task_status,
};
use a2a_gov_mandate::{Disclosable, PublicJwk, SigningKey, issue_open};
use a2a_gov_pdp::memory::{MemoryNonces, MemoryRevocations, MemoryUses, StaticSurfaces};
use a2a_gov_pdp::{BackendError, Call, Decision, Engine, Nonces, Presentation, Release};
use serde_json::{Map, Value, json};

const AUD: &str = "https://vault.example.org/a2a";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let input: Value = serde_json::from_str(&input)?;
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let out = match std::env::args().nth(1).as_deref() {
        Some("issue") => issue(&input, now)?,
        Some("decide") => decide(&input, now)?,
        _ => return Err("usage: pytest_oracle issue|decide < input.json".into()),
    };
    println!("{out}");
    Ok(())
}

fn call() -> Value {
    json!({ "method": "SendMessage", "task_id": "t1",
            "authorization_details": [{ "type": "reading", "actions": ["search"], "fields": ["title"] }] })
}

fn issue(input: &Value, now: i64) -> Result<Value, Box<dyn std::error::Error>> {
    let surface = SigningKey::generate().with_kid("surface-1");
    let mandate: Map<String, Value> = serde_json::from_value(json!({
        "vct": "mandate.access.1", "cnf": { "jwk": input["agent_jwk"] }, "iat": now, "exp": now + 600,
        "constraints": [
            { "type": "access.authorization_details",
              "authorization_details": [{ "type": "reading", "actions": ["search"], "fields": ["title", "published"] }] },
            { "type": "access.max_uses", "max_uses": 1 },
        ],
    }))?;
    let open = issue_open(
        &mandate,
        &Disclosable::array_elements(["constraints"]),
        &surface,
    )?;
    let nonce = MemoryNonces::default().issue();
    let status = task_status(
        "m1",
        "t1",
        "c1",
        "Approved",
        &AuthState::Approved(Approved {
            mandate: open,
            aud: AUD.into(),
            nonce,
        }),
    );
    Ok(json!({ "status": status, "surface_jwk": surface.public_jwk().to_value(), "call": call() }))
}

fn decide(input: &Value, now: i64) -> Result<Value, Box<dyn std::error::Error>> {
    let p = read_presentation(&input["message"])?.ok_or("the message carries no presentation")?;
    let surface = PublicJwk::from_value(&input["surface_jwk"])?;
    let engine = Engine::new(
        Arc::new(StaticSurfaces::single(surface)),
        Arc::new(OneNonce(p.nonce.clone(), Mutex::new(false))),
        Arc::new(MemoryRevocations::default()),
        Arc::new(MemoryUses::default()),
    );
    let c = &input["call"];
    let call = Call {
        method: c["method"].as_str().unwrap_or_default().into(),
        task_id: c["task_id"].as_str().unwrap_or_default().into(),
        authorization_details: c["authorization_details"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
        purpose: None,
        release: Release::AnswerOnly,
    };
    let presentation = Presentation {
        chain: &p.presentation,
        aud: AUD,
        nonce: &p.nonce,
    };
    let decision = engine.decide(Some(presentation), &call, now);
    let verifier = SigningKey::generate().with_kid("verifier-1");
    let (outcome, reason) = match &decision {
        Decision::Pass(_) => ("pass", String::new()),
        Decision::Deny { reason, .. } => ("deny", reason.as_str().to_owned()),
        Decision::Challenge { reason, .. } => ("challenge", reason.as_str().to_owned()),
    };
    let artifact = decision.receipt(AUD, now, Some(&p.presentation)).map(|r| {
        receipt_artifact(
            "a1",
            vec![json!({ "text": "You read 3 articles about Rust." })],
            &ReceiptMeta {
                receipt: r.sign(&verifier),
                next_nonce: None,
            },
        )
    });
    Ok(
        json!({ "decision": outcome, "reason": reason, "artifact": artifact,
               "verifier_jwk": verifier.public_jwk().to_value(), "chain": p.presentation }),
    )
}

/// Accepts exactly the nonce presented, once: the oracle is stateless between
/// runs, so the issued nonce is trusted and single use is enforced per run.
struct OneNonce(String, Mutex<bool>);

impl Nonces for OneNonce {
    fn consume(&self, nonce: &str) -> Result<bool, BackendError> {
        let mut used = self.1.lock().map_err(|_| BackendError("poisoned".into()))?;
        let fresh = !*used && nonce == self.0;
        *used = true;
        Ok(fresh)
    }
}
