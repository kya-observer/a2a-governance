//! Writes `testdata/rust/receipts.json`: receipts signed by this crate, for
//! Google's AP2 SDK to verify (`interop/ap2/tests`).

use std::time::{SystemTime, UNIX_EPOCH};

use a2a_gov_mandate::{Disclosable, SigningKey, issue_open, join, present};
use a2a_gov_receipt::{Outcome, Receipt};
use serde_json::{Map, Value, json};

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!("literal objects only"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let mut vectors = Vec::new();
    for i in 0..12 {
        let surface = SigningKey::generate();
        let agent = SigningKey::generate();
        let verifier = SigningKey::generate().with_kid("verifier-1");
        let open = issue_open(
            &obj(
                json!({ "vct": "mandate.access.1", "cnf": { "jwk": agent.public_jwk().to_value() }, "exp": now + 3600 }),
            ),
            &Disclosable::none(),
            &surface,
        )?;
        let closing = present(
            &open,
            &obj(
                json!({ "vct": "mandate.access.1", "method": "SendMessage", "task_id": format!("task-{i}") }),
            ),
            &Disclosable::none(),
            &agent,
            "https://agent.example.org/a2a",
            "n",
            now,
        )?;
        let chain = join(&[&open, &closing]);
        let outcome = if i % 2 == 0 {
            Outcome::Success
        } else {
            Outcome::Error {
                code: "invalid_mandate".into(),
                description: "outside the mandate's scope".into(),
            }
        };
        let receipt = Receipt::for_chain("https://agent.example.org", now, outcome, &chain)?
            .with_method("SendMessage")
            .with_task_id(&format!("task-{i}"))
            .with_purpose("dpv:ServiceProvision")
            .with_released(["title", "published"])?;
        vectors.push(json!({
            "chain": chain,
            "receipt": receipt.sign(&verifier),
            "verifier_jwk": verifier.public_jwk().to_value(),
            "expected_status": if i % 2 == 0 { "Success" } else { "Error" },
        }));
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/rust/receipts.json"
    );
    let file = json!({
        "description": "Mandate Receipts signed by a2a-gov-receipt, for AP2 SDK cross-verification. Test keys only.",
        "vectors": vectors,
    });
    std::fs::write(path, serde_json::to_string_pretty(&file)? + "\n")?;
    eprintln!("wrote {path}");
    Ok(())
}
