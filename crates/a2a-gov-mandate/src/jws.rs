//! Compact JWS with ES256 only (RFC 7515, RFC 7518 §3.4). Public for other crates
//! in this workspace that sign JWTs (receipts); mandates use it internally.

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use serde_json::{Map, Value};

use crate::{Error, PublicJwk, SigningKey, b64};

/// A decoded compact JWS.
pub struct Decoded {
    /// Protected header.
    pub header: Map<String, Value>,
    /// Payload.
    pub payload: Map<String, Value>,
}

/// Signs `payload` with ES256 under `header` (which should carry `alg: ES256`).
pub fn sign(header: &Map<String, Value>, payload: &Map<String, Value>, key: &SigningKey) -> String {
    let signing_input = format!(
        "{}.{}",
        b64::encode(Value::Object(header.clone()).to_string()),
        b64::encode(Value::Object(payload.clone()).to_string())
    );
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64::encode(sig))
}

/// Signs `payload` bytes exactly as given (base64url-encoded, never
/// re-serialized). For payloads whose byte form is itself specified, such as
/// the RFC 8785 canonical form of a signed Agent Card.
pub fn sign_bytes(header: &Map<String, Value>, payload: &[u8], key: &SigningKey) -> String {
    let signing_input = format!(
        "{}.{}",
        b64::encode(Value::Object(header.clone()).to_string()),
        b64::encode(payload)
    );
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64::encode(sig))
}

/// Decodes without checking the signature. Callers must [`verify`] before
/// trusting anything in the result.
pub fn decode(compact: &str) -> Result<Decoded, Error> {
    let mut parts = compact.split('.');
    let (Some(h), Some(p), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed("JWS must have three parts".into()));
    };
    Ok(Decoded {
        header: json_object(h, "header")?,
        payload: json_object(p, "payload")?,
    })
}

/// Verifies an ES256 compact JWS with `key` and returns its contents.
pub fn verify(compact: &str, key: &PublicJwk) -> Result<Decoded, Error> {
    let decoded = decode(compact)?;
    match decoded.header.get("alg").and_then(Value::as_str) {
        Some("ES256") => {}
        other => return Err(Error::UnsupportedAlgorithm(format!("{other:?}"))),
    }
    if decoded.header.contains_key("crit") {
        return Err(Error::Malformed("unsupported crit header".into()));
    }
    let (signing_input, sig_b64) = compact
        .rsplit_once('.')
        .ok_or_else(|| Error::Malformed("JWS must have three parts".into()))?;
    let sig = Signature::from_slice(&b64::decode(sig_b64)?).map_err(|_| Error::BadSignature)?;
    key.verifying_key()?
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| Error::BadSignature)?;
    Ok(decoded)
}

fn json_object(segment: &str, what: &str) -> Result<Map<String, Value>, Error> {
    match crate::strict_json::from_slice(&b64::decode(segment)?) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(Error::Malformed(format!("JWS {what} is not a JSON object"))),
        Err(e) => Err(Error::Malformed(format!("JWS {what}: {e}"))),
    }
}
