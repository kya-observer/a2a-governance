//! Writes `testdata/rust/cards.json`: Agent Cards signed by this crate, for the
//! official a2a-sdk's verifier (`interop/a2a/tests`).

use a2a_gov_card::sign;
use a2a_gov_mandate::SigningKey;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = json!({
        "name": "Example vault agent",
        "description": "Answers questions about a reading history",
        "version": "0.1.0",
        "supportedInterfaces": [{ "url": "https://vault.example.org/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }],
        "capabilities": { "streaming": false, "extensions": [{ "uri": "https://example.org/ext/v1", "required": true,
                          "params": { "mandateFormats": ["dc+sd-jwt"], "n": 3 } }] },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{ "id": "reading", "name": "Reading", "description": "Answers from reading history", "tags": ["reading"] }],
    });
    let mut vectors = Vec::new();
    for name in ["plain", "empty-description", "unicode"] {
        let mut card = base.clone();
        if name == "empty-description" {
            card["description"] = json!("");
        }
        if name == "unicode" {
            card["name"] = json!("Agent für Lesehistorie €");
        }
        let key = SigningKey::generate().with_kid(&format!("key-{name}"));
        vectors.push(json!({ "name": name, "card": sign(&card, &key)?, "kid": key.kid(), "jwk": key.public_jwk().to_value() }));
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/rust/cards.json"
    );
    let file = json!({ "description": "Agent Cards signed by a2a-gov-card (A2A §8.4.1 form). Test keys only.", "vectors": vectors });
    std::fs::write(path, serde_json::to_string_pretty(&file)? + "\n")?;
    eprintln!("wrote {path}");
    Ok(())
}
