//! Native half of the `a2a_governance` Python package. Values cross the
//! boundary as JSON strings; `python/a2a_governance` turns them into dicts and
//! a2a-sdk types.

use a2a_gov_binding as binding;
use a2a_gov_extension::errors::{ErrorProfile, GovernanceError};
use a2a_gov_mandate::{Disclosable, PublicJwk, SigningKey, join};
use a2a_gov_receipt::Receipt;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::{Map, Value, json};

fn err(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn parse(s: &str) -> PyResult<Value> {
    serde_json::from_str(s).map_err(err)
}

fn object(s: &str) -> PyResult<Map<String, Value>> {
    match parse(s)? {
        Value::Object(m) => Ok(m),
        _ => Err(PyValueError::new_err("expected a JSON object")),
    }
}

/// A new P-256 agent key, as a private JWK (JSON). Store it as a secret.
#[pyfunction]
#[pyo3(signature = (kid=None))]
fn generate_key(kid: Option<&str>) -> String {
    let key = SigningKey::generate();
    let key = match kid {
        Some(k) => key.with_kid(k),
        None => key,
    };
    key.to_private_jwk().to_string()
}

/// The public JWK (JSON) for a private JWK.
#[pyfunction]
fn public_jwk(private_jwk: &str) -> PyResult<String> {
    Ok(SigningKey::from_private_jwk(&parse(private_jwk)?)
        .map_err(err)?
        .public_jwk()
        .to_value()
        .to_string())
}

/// Builds the closing hop over `open_mandate` for one call and returns the
/// presentation chain.
#[pyfunction]
fn present(
    private_jwk: &str,
    open_mandate: &str,
    closed_mandate: &str,
    aud: &str,
    nonce: &str,
    iat: i64,
) -> PyResult<String> {
    let key = SigningKey::from_private_jwk(&parse(private_jwk)?).map_err(err)?;
    let closing = a2a_gov_mandate::present(
        open_mandate,
        &object(closed_mandate)?,
        &Disclosable::none(),
        &key,
        aud,
        nonce,
        iat,
    )
    .map_err(err)?;
    Ok(join(&[open_mandate, &closing]))
}

/// Recognizes a Deny or Challenge JSON-RPC error from `domain`; `None` otherwise.
#[pyfunction]
fn parse_error(error: &str, domain: &str) -> PyResult<Option<String>> {
    Ok(ErrorProfile::new(domain).parse(&parse(error)?).map(|e| {
        match e {
            GovernanceError::Deny { reason, message } => {
                json!({ "kind": "deny", "reason": reason.as_str(), "message": message })
            }
            GovernanceError::Challenge {
                reason,
                message,
                challenge_id,
                url,
            } => json!({
                "kind": "challenge", "reason": reason.as_str(), "message": message,
                "challengeId": challenge_id, "url": url,
            }),
        }
        .to_string()
    }))
}

/// Verifies a receipt with the verifier's public JWK and checks it refers to
/// `chain`. Returns the receipt's payload (JSON).
#[pyfunction]
fn verify_receipt(receipt: &str, verifier_jwk: &str, chain: &str) -> PyResult<String> {
    let key = PublicJwk::from_value(&parse(verifier_jwk)?).map_err(err)?;
    let verified = Receipt::verify(receipt, &key).map_err(err)?;
    if !verified.matches(chain) {
        return Err(PyValueError::new_err(
            "the receipt refers to a different presentation",
        ));
    }
    Ok(Value::Object(Receipt::decode_unverified(receipt).map_err(err)?).to_string())
}

/// The client's first message (ProtoJSON), offering its public key.
#[pyfunction]
fn hello_message(
    message_id: &str,
    context_id: &str,
    text: &str,
    holder_jwk: &str,
) -> PyResult<String> {
    let hello = binding::Hello {
        holder_jwk: parse(holder_jwk)?,
    };
    Ok(binding::hello_message(message_id, context_id, text, &hello).to_string())
}

/// A message (ProtoJSON) continuing `task_id` with a presentation.
#[pyfunction]
fn continuation_message(
    message_id: &str,
    task_id: &str,
    context_id: &str,
    text: &str,
    presentation: &str,
    nonce: &str,
) -> String {
    let p = binding::PresentationMeta {
        presentation: presentation.to_owned(),
        nonce: nonce.to_owned(),
    };
    binding::continuation_message(message_id, task_id, context_id, text, &p).to_string()
}

/// The extension's state in a task status (ProtoJSON), or `None`.
#[pyfunction]
fn read_status(status: &str) -> PyResult<Option<String>> {
    Ok(binding::read_status(&parse(status)?)
        .map_err(err)?
        .map(|s| serde_json::to_value(s).unwrap_or(Value::Null).to_string()))
}

/// The receipt carried by a result artifact (ProtoJSON), or `None`.
#[pyfunction]
fn read_receipt(artifact: &str) -> PyResult<Option<String>> {
    Ok(binding::read_receipt(&parse(artifact)?)
        .map_err(err)?
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null).to_string()))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("EXTENSION_URI", a2a_gov_extension::EXTENSION_URI)?;
    for f in [
        wrap_pyfunction!(generate_key, m)?,
        wrap_pyfunction!(public_jwk, m)?,
        wrap_pyfunction!(present, m)?,
        wrap_pyfunction!(parse_error, m)?,
        wrap_pyfunction!(verify_receipt, m)?,
        wrap_pyfunction!(hello_message, m)?,
        wrap_pyfunction!(continuation_message, m)?,
        wrap_pyfunction!(read_status, m)?,
        wrap_pyfunction!(read_receipt, m)?,
    ] {
        m.add_function(f)?;
    }
    Ok(())
}
