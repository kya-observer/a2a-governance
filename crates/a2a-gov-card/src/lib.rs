//! Signed A2A Agent Cards (A2A v1.0 §8.4): canonical payloads, ES256 signing
//! and verification.
//!
//! Keys come only from the verifier's own configuration, looked up by `kid`.
//! The `jku` that §8.4.3 allows fetching is never used, because a header an
//! attacker controls can name any key set it likes.
//!
//! The official a2a-sdk (1.1.x) signs a slightly different payload from
//! §8.4.1: it also removes empty REQUIRED fields and empty values anywhere
//! (including extension `params`). Verification accepts that form by default,
//! and says so in [`Verified::form`], because most signed cards today come from
//! it. Signing always uses the §8.4.1 form.

mod canonical;
pub mod jcs;
#[rustfmt::skip]
mod schema;
mod schema_types;

use a2a_gov_mandate::{PublicJwk, SigningKey, jws};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::canonical::{Mode, payload};

/// Why a card couldn't be canonicalized, signed or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The card has no RFC 8785 canonical form.
    #[error("canonicalization: {0}")]
    Canonicalization(String),
    /// Signing needs a key with a `kid` (A2A §8.4.2).
    #[error("the signing key has no kid")]
    MissingKid,
    /// The card has no signatures.
    #[error("the card is not signed")]
    NoSignature,
    /// No signature verified with a key the verifier trusts.
    #[error("no valid signature from a trusted key")]
    InvalidSignature,
}

/// Which canonical form a verified signature covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// A2A v1.0 §8.4.1.
    Spec,
    /// The official a2a-sdk's variant (empty values not covered).
    A2aSdk,
}

/// Verification options.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Also accept signatures over the a2a-sdk's variant payload.
    pub accept_a2a_sdk_form: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            accept_a2a_sdk_form: true,
        }
    }
}

/// A verified card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The key that signed it.
    pub kid: String,
    /// Which payload form the signature covered.
    pub form: Form,
    /// SHA-256 of the §8.4.1 canonical payload, for pinning. It changes with
    /// any change to the card's content, including values the a2a-sdk form
    /// doesn't sign.
    pub fingerprint: String,
}

/// The §8.4.1 canonical payload: `signatures` removed, default values removed,
/// RFC 8785.
pub fn canonical_payload(card: &Value) -> Result<String, Error> {
    payload(card, Mode::Spec)
}

/// The card's fingerprint (see [`Verified::fingerprint`]).
pub fn fingerprint(card: &Value) -> Result<String, Error> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_payload(card)?.as_bytes())))
}

/// Signs `card` with `key` (which must have a `kid`) and returns it with the
/// signature appended to `signatures`.
pub fn sign(card: &Value, key: &SigningKey) -> Result<Value, Error> {
    sign_with(card, key, Mode::Spec)
}

/// Signs over the a2a-sdk's variant payload, for peers that verify with it.
pub fn sign_a2a_sdk_form(card: &Value, key: &SigningKey) -> Result<Value, Error> {
    sign_with(card, key, Mode::A2aSdk)
}

fn sign_with(card: &Value, key: &SigningKey, mode: Mode) -> Result<Value, Error> {
    let kid = key.kid().ok_or(Error::MissingKid)?;
    let mut header = Map::new();
    header.insert("alg".into(), json!("ES256"));
    header.insert("typ".into(), json!("JOSE"));
    header.insert("kid".into(), json!(kid));
    let compact = jws::sign_bytes(&header, payload(card, mode)?.as_bytes(), key);
    let mut parts = compact.split('.');
    let (Some(protected), Some(_), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Canonicalization("unexpected JWS shape".into()));
    };
    let mut signed = card.clone();
    let obj = signed
        .as_object_mut()
        .ok_or_else(|| Error::Canonicalization("a card is a JSON object".into()))?;
    let signatures = obj.entry("signatures").or_insert_with(|| json!([]));
    let Value::Array(list) = signatures else {
        return Err(Error::Canonicalization(
            "signatures must be an array".into(),
        ));
    };
    list.push(json!({ "protected": protected, "signature": signature }));
    Ok(signed)
}

/// Verifies that at least one of the card's signatures was made by a key the
/// verifier trusts. `keys` maps a `kid` to that key, from the verifier's own
/// configuration.
pub fn verify(
    card: &Value,
    keys: impl Fn(&str) -> Option<PublicJwk>,
    opts: &VerifyOptions,
) -> Result<Verified, Error> {
    let signatures = card
        .get("signatures")
        .and_then(Value::as_array)
        .filter(|s| !s.is_empty())
        .ok_or(Error::NoSignature)?;
    let mut forms = vec![(Form::Spec, URL_SAFE_NO_PAD.encode(canonical_payload(card)?))];
    if opts.accept_a2a_sdk_form {
        forms.push((
            Form::A2aSdk,
            URL_SAFE_NO_PAD.encode(payload(card, Mode::A2aSdk)?),
        ));
    }
    for sig in signatures {
        let (Some(protected), Some(signature)) = (
            sig.get("protected").and_then(Value::as_str),
            sig.get("signature").and_then(Value::as_str),
        ) else {
            continue;
        };
        for (form, encoded) in &forms {
            let compact = format!("{protected}.{encoded}.{signature}");
            let Ok(decoded) = jws::decode(&compact) else {
                continue;
            };
            let Some(kid) = decoded.header.get("kid").and_then(Value::as_str) else {
                continue;
            };
            let Some(key) = keys(kid) else { continue };
            if jws::verify(&compact, &key).is_ok() {
                return Ok(Verified {
                    kid: kid.to_owned(),
                    form: *form,
                    fingerprint: fingerprint(card)?,
                });
            }
        }
    }
    Err(Error::InvalidSignature)
}
