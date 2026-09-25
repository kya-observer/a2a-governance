//! A2A v1.0 message shapes for the Delegation Governance extension.
//!
//! Everything the extension adds travels in `metadata` keyed by the extension
//! URI, on objects that list the URI in `extensions` (A2A §4.6.2). Field names
//! follow ProtoJSON (ADR-001).
//!
//! The in-task flow:
//! 1. The client's first message offers its public key ([`Hello`]); the mandate
//!    will be bound to it.
//! 2. The agent answers with a task in `TASK_STATE_AUTH_REQUIRED` whose status
//!    carries the draft mandate, an approval link, and the audience and nonce
//!    for the closing hop ([`AuthState::Pending`]).
//! 3. After the user decides, the status carries the open mandate
//!    ([`AuthState::Approved`]), or the task is rejected ([`AuthState::Denied`]).
//! 4. The client continues the task with its presentation ([`PresentationMeta`]).
//! 5. The result artifact carries the receipt and a nonce for the next call
//!    ([`ReceiptMeta`]).

use a2a_gov_extension::EXTENSION_URI;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value, json};

/// Extension metadata that doesn't follow the shapes below.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The metadata under the extension URI is malformed.
    #[error("invalid extension metadata: {0}")]
    Invalid(String),
}

/// The client's opening offer: the key its mandates will be bound to (`cnf.jwk`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Hello {
    /// The client's public JWK.
    pub holder_jwk: Value,
}

/// What the agent asks the user to approve.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MandateRequest {
    /// Draft open-mandate content (`vct`, `constraints`, `exp`, ...), without `cnf`.
    #[serde(rename = "mandateRequest")]
    pub mandate: Map<String, Value>,
    /// Where the user approves, outside the client and its LLM.
    pub approval_url: String,
    /// Correlates the approval with this task.
    pub challenge_id: String,
    /// Audience for the closing hop.
    pub aud: String,
    /// Nonce for the closing hop.
    pub nonce: String,
}

/// The user approved: here is the open mandate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approved {
    /// The open mandate (SD-JWT), bound to the client's key.
    pub mandate: String,
    /// Audience for the closing hop.
    pub aud: String,
    /// Nonce for the closing hop.
    pub nonce: String,
}

/// Where the approval stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum AuthState {
    /// Waiting for the user.
    Pending(MandateRequest),
    /// Approved; continue with a presentation.
    Approved(Approved),
    /// Denied or expired.
    Denied {
        /// Why, for the caller.
        reason: String,
    },
}

/// The client's presentation for this call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresentationMeta {
    /// The `~~`-joined mandate chain.
    pub presentation: String,
    /// The nonce the closing hop was built for.
    pub nonce: String,
}

/// The verifier's receipt for a served call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptMeta {
    /// The signed Mandate Receipt (compact JWS).
    pub receipt: String,
    /// A nonce for the client's next call under the same mandate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_nonce: Option<String>,
}

/// A task status for `state`: `TASK_STATE_AUTH_REQUIRED` while pending or
/// approved, `TASK_STATE_REJECTED` when denied.
pub fn task_status(
    message_id: &str,
    task_id: &str,
    context_id: &str,
    text: &str,
    state: &AuthState,
) -> Value {
    let task_state = match state {
        AuthState::Denied { .. } => "TASK_STATE_REJECTED",
        _ => "TASK_STATE_AUTH_REQUIRED",
    };
    let mut message = message("ROLE_AGENT", message_id, context_id, text, to_value(state));
    message["taskId"] = json!(task_id);
    json!({ "state": task_state, "message": message })
}

/// Reads the extension's state from a task status, if it carries any.
pub fn read_status(status: &Value) -> Result<Option<AuthState>, Error> {
    let Some(meta) = status.get("message").and_then(extension_metadata) else {
        return Ok(None);
    };
    let state: AuthState = from_value(meta)?;
    if let AuthState::Pending(req) = &state {
        require_https(&req.approval_url)?;
        require_nonempty(&[&req.challenge_id, &req.aud, &req.nonce])?;
    }
    if let AuthState::Approved(a) = &state {
        require_nonempty(&[&a.mandate, &a.aud, &a.nonce])?;
    }
    Ok(Some(state))
}

/// The client's first message, offering its key.
pub fn hello_message(message_id: &str, context_id: &str, text: &str, hello: &Hello) -> Value {
    message("ROLE_USER", message_id, context_id, text, to_value(hello))
}

/// Reads the client's key offer from a message.
pub fn read_hello(message: &Value) -> Result<Option<Hello>, Error> {
    extension_metadata(message).map(from_value).transpose()
}

/// A message continuing `task_id` with a presentation.
pub fn continuation_message(
    message_id: &str,
    task_id: &str,
    context_id: &str,
    text: &str,
    p: &PresentationMeta,
) -> Value {
    let mut message = message("ROLE_USER", message_id, context_id, text, to_value(p));
    message["taskId"] = json!(task_id);
    message
}

/// Reads a presentation from a message that activates the extension.
pub fn read_presentation(message: &Value) -> Result<Option<PresentationMeta>, Error> {
    let Some(meta) = extension_metadata(message) else {
        return Ok(None);
    };
    let p: PresentationMeta = from_value(meta)?;
    require_nonempty(&[&p.presentation, &p.nonce])?;
    Ok(Some(p))
}

/// A result artifact carrying the receipt.
pub fn receipt_artifact(artifact_id: &str, parts: Vec<Value>, meta: &ReceiptMeta) -> Value {
    json!({
        "artifactId": artifact_id,
        "parts": parts,
        "extensions": [EXTENSION_URI],
        "metadata": { EXTENSION_URI: to_value(meta) },
    })
}

/// Reads the receipt from a result artifact.
pub fn read_receipt(artifact: &Value) -> Result<Option<ReceiptMeta>, Error> {
    extension_metadata(artifact).map(from_value).transpose()
}

fn message(role: &str, message_id: &str, context_id: &str, text: &str, meta: Value) -> Value {
    json!({
        "messageId": message_id,
        "contextId": context_id,
        "role": role,
        "parts": [{ "text": text }],
        "extensions": [EXTENSION_URI],
        "metadata": { EXTENSION_URI: meta },
    })
}

/// The object's metadata under the extension URI, only if the object lists the
/// extension. Numbers that protobuf `Struct` turned into integral doubles are
/// restored to integers.
fn extension_metadata(object: &Value) -> Option<Value> {
    let listed = object
        .get("extensions")
        .and_then(Value::as_array)
        .is_some_and(|exts| exts.iter().any(|e| e.as_str() == Some(EXTENSION_URI)));
    if !listed {
        return None;
    }
    let mut meta = object.get("metadata")?.get(EXTENSION_URI)?.clone();
    restore_integers(&mut meta);
    Some(meta)
}

fn restore_integers(v: &mut Value) {
    match v {
        Value::Number(n) => {
            if let Some(f) = n.as_f64()
                && n.as_i64().is_none()
                && n.as_u64().is_none()
                && f.fract() == 0.0
                && f.abs() < 9_007_199_254_740_992.0
            {
                #[allow(clippy::cast_possible_truncation)]
                let i = f as i64;
                *n = Number::from(i);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(restore_integers),
        Value::Object(m) => m.values_mut().for_each(restore_integers),
        _ => {}
    }
}

fn to_value<T: Serialize>(t: &T) -> Value {
    serde_json::to_value(t).unwrap_or(Value::Null)
}

fn from_value<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, Error> {
    serde_json::from_value(v).map_err(|e| Error::Invalid(e.to_string()))
}

fn require_https(url: &str) -> Result<(), Error> {
    let host = url
        .strip_prefix("https://")
        .map(|r| r.split(['/', '?', '#']).next().unwrap_or_default());
    match host {
        Some(h) if !h.is_empty() && !url.chars().any(char::is_whitespace) => Ok(()),
        _ => Err(Error::Invalid(format!(
            "approval URL must be https: {url:?}"
        ))),
    }
}

fn require_nonempty(values: &[&str]) -> Result<(), Error> {
    if values.iter().any(|v| v.is_empty()) {
        return Err(Error::Invalid("empty field".into()));
    }
    Ok(())
}
