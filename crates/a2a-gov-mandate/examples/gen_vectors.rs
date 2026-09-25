//! Writes `testdata/rust/access_chains.json`: chains minted by this crate, for
//! Google's AP2 SDK to verify (`interop/ap2/tests`).

use std::time::{SystemTime, UNIX_EPOCH};

use a2a_gov_mandate::{Disclosable, SigningKey, issue_open, join, present};
use serde_json::{Map, Value, json};

const AUD: &str = "https://agent.example.org/a2a";
const NONCE: &str = "n-rust-vectors";

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!("literal objects only"),
    }
}

fn vector(now: i64, sd: &Disclosable) -> Result<Value, a2a_gov_mandate::Error> {
    let surface = SigningKey::generate().with_kid("trusted-surface-1");
    let agent = SigningKey::generate();
    let sub_agent = SigningKey::generate();

    let open_mandate = obj(json!({
        "vct": "mandate.access.1",
        "cnf": { "jwk": agent.public_jwk().to_value() },
        "iat": now,
        "exp": now + 7200,
        "constraints": [
            { "type": "access.authorization_details", "authorization_details": [
                { "type": "calendar", "actions": ["read.freebusy"], "fields": ["start", "end"] } ] },
            { "type": "access.purpose", "purpose": "dpv:ServiceProvision" },
            { "type": "access.release", "release": "answer-only" },
            { "type": "access.max_uses", "max_uses": 3 },
        ],
    }));
    let delegated = obj(json!({
        "vct": "mandate.access.1",
        "cnf": { "jwk": sub_agent.public_jwk().to_value() },
        "constraints": [{ "type": "access.max_uses", "max_uses": 1 }],
    }));
    let closed = obj(json!({
        "vct": "mandate.access.1",
        "method": "SendMessage",
        "task_id": "task-7f3c",
        "action_hash": "3WiKMabE8NRYJgveUbyAZ3pBqRfPrWwGDbOyvbO1eYA",
    }));

    let open = issue_open(&open_mandate, sd, &surface)?;
    let closing = present(
        &open,
        &closed,
        &Disclosable::none(),
        &agent,
        AUD,
        NONCE,
        now,
    )?;
    let delegation = present(
        &open,
        &delegated,
        &Disclosable::none(),
        &agent,
        "https://sub-agent.example.org/a2a",
        "n-sub",
        now,
    )?;
    let closing_after_delegation = present(
        &delegation,
        &closed,
        &Disclosable::none(),
        &sub_agent,
        AUD,
        NONCE,
        now,
    )?;

    Ok(json!({
        "issued_at": now,
        "trusted_surface_jwk": surface.public_jwk().to_value(),
        "aud": AUD,
        "nonce": NONCE,
        "chain": join(&[&open, &closing]),
        "two_hop_chain": join(&[&open, &delegation, &closing_after_delegation]),
        "expected_open": open_mandate,
        "expected_delegated": delegated,
        "expected_closed": closed,
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let sd_modes = [
        Disclosable::array_elements(["constraints"]),
        Disclosable::fields(["exp", "iat"]),
        Disclosable::none(),
    ];
    let vectors = (0..24)
        .map(|i| vector(now, &sd_modes[i % sd_modes.len()]))
        .collect::<Result<Vec<_>, _>>()?;
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/rust/access_chains.json"
    );
    std::fs::create_dir_all(std::path::Path::new(path).parent().ok_or("no parent")?)?;
    let file = json!({
        "description": "Access mandate chains minted by a2a-gov-mandate, for AP2 SDK cross-verification. \
                        Fresh test keys per vector; never reuse them.",
        "vectors": vectors,
    });
    std::fs::write(path, serde_json::to_string_pretty(&file)? + "\n")?;
    eprintln!("wrote {path}");
    Ok(())
}
