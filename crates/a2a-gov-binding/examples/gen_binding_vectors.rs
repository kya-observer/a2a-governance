//! Writes `testdata/rust/binding.json`: the extension's A2A shapes, for the
//! official `a2a-sdk` to parse (`interop/a2a/tests`).

use a2a_gov_binding::{
    Approved, AuthState, Hello, MandateRequest, PresentationMeta, ReceiptMeta,
    continuation_message, hello_message, receipt_artifact, task_status,
};
use a2a_gov_extension::{Declaration, EXTENSION_URI};
use serde_json::{Map, Value, json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mandate: Map<String, Value> = serde_json::from_value(json!({
        "vct": "mandate.access.1", "exp": 1_790_003_600,
        "constraints": [
            { "type": "access.authorization_details",
              "authorization_details": [{ "type": "reading", "actions": ["search"], "fields": ["title"] }] },
            { "type": "access.max_uses", "max_uses": 3 },
        ],
    }))?;
    let pending = AuthState::Pending(MandateRequest {
        mandate,
        approval_url: "https://approve.example.org/c/ch_1".into(),
        challenge_id: "ch_1".into(),
        aud: "https://vault.example.org/a2a".into(),
        nonce: "n1".into(),
    });
    let approved = AuthState::Approved(Approved {
        mandate: "eyJhbGciOiJFUzI1NiJ9.e30.sig~".into(),
        aud: "https://vault.example.org/a2a".into(),
        nonce: "n2".into(),
    });
    let denied = AuthState::Denied {
        reason: "denied by the user".into(),
    };
    let receipt = ReceiptMeta {
        receipt: "eyJhbGciOiJFUzI1NiJ9.e30.sig".into(),
        next_nonce: Some("n3".into()),
    };
    let artifact = receipt_artifact(
        "a1",
        vec![json!({ "text": "You read 3 articles about Rust." })],
        &receipt,
    );

    let file = json!({
        "description": "The Delegation Governance extension's A2A v1.0 shapes, from a2a-gov-binding.",
        "extension_uri": EXTENSION_URI,
        "task_status": {
            "pending": task_status("m1", "t1", "c1", "Approval needed", &pending),
            "approved": task_status("m2", "t1", "c1", "Approved", &approved),
            "denied": task_status("m3", "t1", "c1", "Denied", &denied),
        },
        "message": {
            "hello": hello_message("m0", "c1", "What have I read about Rust?",
                &Hello { holder_jwk: json!({ "kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB" }) }),
            "continuation": continuation_message("m4", "t1", "c1", "Continuing with the mandate",
                &PresentationMeta { presentation: "open~~closing~".into(), nonce: "n2".into() }),
        },
        "artifact": artifact,
        "task": {
            "id": "t1", "contextId": "c1",
            "status": task_status("m1", "t1", "c1", "Approval needed", &pending),
            "artifacts": [artifact],
        },
        "agent_card": {
            "name": "Example vault agent",
            "description": "Answers questions about a reading history",
            "version": "0.1.0",
            "supportedInterfaces": [{ "url": "https://vault.example.org/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }],
            "capabilities": { "streaming": false, "extensions": [serde_json::to_value(
                Declaration::new(true).with_param("mandateFormats", json!(["dc+sd-jwt"])))?] },
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{ "id": "reading", "name": "Reading history", "description": "Answers from reading history", "tags": ["reading"] }],
        },
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/rust/binding.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&file)? + "\n")?;
    eprintln!("wrote {path}");
    Ok(())
}
