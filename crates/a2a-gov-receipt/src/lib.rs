//! Mandate Receipts: the verifier's signed record of each authorization
//! decision, success or failure, in AP2's receipt format. Plus a hash-chained
//! log that makes silent edits to a receipt history detectable.
//!
//! AP2 v0.2 names the outcome `result` in its prose and `status` in its schemas
//! and SDK. This crate emits the schema form (`status: "Success" | "Error"`) and
//! accepts both.
//!
//! AP2's `reference` hashes the closing hop *including* its ECDSA signature,
//! which is malleable (`s` → `n − s`), so two encodings of one presentation have
//! two references. It's kept for AP2 compatibility, but receipts also carry
//! `mandate_id` and `presentation_id`, computed without signatures; match and
//! key receipts on those.

pub mod log;

use a2a_gov_mandate::{PublicJwk, SigningKey, jws};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Why a receipt couldn't be built or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Signature or encoding failure from the underlying JWS.
    #[error(transparent)]
    Mandate(#[from] a2a_gov_mandate::Error),
    /// The receipt's content doesn't follow the format.
    #[error("malformed receipt: {0}")]
    Malformed(String),
}

/// The decision a receipt records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The action was authorized.
    Success,
    /// The action was refused. `code` is an AP2 action-authorization error
    /// (`invalid_credential`, `invalid_mandate`, ...).
    Error {
        /// Machine-readable code.
        code: String,
        /// Human-readable description.
        description: String,
    },
}

/// A Mandate Receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    iss: String,
    iat: i64,
    outcome: Outcome,
    reference: String,
    mandate_id: Option<String>,
    presentation_id: Option<String>,
    method: Option<String>,
    task_id: Option<String>,
    purpose: Option<String>,
    released: Vec<String>,
    prev: Option<String>,
}

impl Receipt {
    /// `iss` identifies the verifier; `reference` is [`reference_for`] the
    /// presented chain.
    pub fn new(iss: &str, iat: i64, outcome: Outcome, reference: String) -> Self {
        Self {
            iss: iss.to_owned(),
            iat,
            outcome,
            reference,
            mandate_id: None,
            presentation_id: None,
            method: None,
            task_id: None,
            purpose: None,
            released: Vec::new(),
            prev: None,
        }
    }

    /// A receipt for a presentation `chain`, carrying AP2's `reference` and the
    /// signature-independent `mandate_id` and `presentation_id`.
    pub fn for_chain(iss: &str, iat: i64, outcome: Outcome, chain: &str) -> Result<Self, Error> {
        let mut receipt = Self::new(iss, iat, outcome, reference_for(chain)?);
        let root_jwt = chain.split('~').next().unwrap_or_default();
        receipt.mandate_id = Some(a2a_gov_mandate::hop_id(root_jwt));
        receipt.presentation_id = Some(presentation_id(chain)?);
        Ok(receipt)
    }

    /// The A2A method the decision was about.
    pub fn with_method(mut self, method: &str) -> Self {
        self.method = Some(method.to_owned());
        self
    }

    /// The A2A task the decision was about.
    pub fn with_task_id(mut self, task_id: &str) -> Self {
        self.task_id = Some(task_id.to_owned());
        self
    }

    /// The purpose the data was released for (a W3C DPV term).
    pub fn with_purpose(mut self, purpose: &str) -> Self {
        self.purpose = Some(purpose.to_owned());
        self
    }

    /// The names of the fields released. Values never go in a receipt, so
    /// anything that doesn't look like a field path is refused.
    pub fn with_released<const N: usize>(mut self, fields: [&str; N]) -> Result<Self, Error> {
        for f in fields {
            if !is_field_path(f) {
                return Err(Error::Malformed(format!("{f:?} is not a field name")));
            }
            self.released.push(f.to_owned());
        }
        Ok(self)
    }

    /// The hash of the previous receipt in the verifier's log.
    pub fn with_prev(mut self, prev: &str) -> Self {
        self.prev = Some(prev.to_owned());
        self
    }

    /// The recorded decision.
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// The released field names.
    pub fn released(&self) -> &[String] {
        &self.released
    }

    /// The mandate reference.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Signs the receipt as the verifier (compact JWS, ES256).
    pub fn sign(&self, key: &SigningKey) -> String {
        let mut header = Map::new();
        header.insert("alg".into(), json!("ES256"));
        header.insert("typ".into(), json!("JWT"));
        if let Some(kid) = key.kid() {
            header.insert("kid".into(), json!(kid));
        }
        jws::sign(&header, &self.to_payload(), key)
    }

    /// Verifies a signed receipt with the verifier's public key.
    pub fn verify(compact: &str, key: &PublicJwk) -> Result<Self, Error> {
        Self::from_payload(&jws::verify(compact, key)?.payload)
    }

    /// The payload without checking the signature, for inspection only.
    pub fn decode_unverified(compact: &str) -> Result<Map<String, Value>, Error> {
        Ok(jws::decode(compact)?.payload)
    }

    /// Whether this receipt refers to `chain`. Uses `presentation_id` when the
    /// receipt has one, so a malleated encoding of the same presentation still
    /// matches; otherwise AP2's reference, in its spec or sample form.
    pub fn matches(&self, chain: &str) -> bool {
        if let Some(id) = &self.presentation_id {
            return presentation_id(chain).is_ok_and(|p| &p == id);
        }
        reference_for(chain).is_ok_and(|r| r == self.reference)
            || jwt_only_reference(chain).is_ok_and(|r| r == self.reference)
    }

    fn to_payload(&self) -> Map<String, Value> {
        let mut p = Map::new();
        match &self.outcome {
            Outcome::Success => {
                p.insert("status".into(), json!("Success"));
            }
            Outcome::Error { code, description } => {
                p.insert("status".into(), json!("Error"));
                p.insert("error".into(), json!(code));
                p.insert("error_description".into(), json!(description));
            }
        }
        p.insert("iss".into(), json!(self.iss));
        p.insert("iat".into(), json!(self.iat));
        p.insert("reference".into(), json!(self.reference));
        for (name, value) in [
            ("mandate_id", &self.mandate_id),
            ("presentation_id", &self.presentation_id),
            ("method", &self.method),
            ("task_id", &self.task_id),
            ("purpose", &self.purpose),
            ("prev", &self.prev),
        ] {
            if let Some(v) = value {
                p.insert(name.into(), json!(v));
            }
        }
        if !self.released.is_empty() {
            p.insert("released".into(), json!(self.released));
        }
        p
    }

    fn from_payload(p: &Map<String, Value>) -> Result<Self, Error> {
        let text = |name: &str| p.get(name).and_then(Value::as_str).map(str::to_owned);
        let required =
            |name: &str| text(name).ok_or_else(|| Error::Malformed(format!("missing {name}")));
        let status = match (p.get("status"), p.get("result")) {
            (Some(Value::String(s)), None) => s.to_ascii_lowercase(),
            (None, Some(Value::String(s))) => s.to_ascii_lowercase(),
            _ => {
                return Err(Error::Malformed(
                    "need exactly one of status, result".into(),
                ));
            }
        };
        let has_error_fields = p.contains_key("error") || p.contains_key("error_description");
        let outcome = match status.as_str() {
            "success" if !has_error_fields => Outcome::Success,
            "success" => return Err(Error::Malformed("error fields on a success receipt".into())),
            "error" => Outcome::Error {
                code: required("error")?,
                description: required("error_description")?,
            },
            other => return Err(Error::Malformed(format!("unknown status {other:?}"))),
        };
        let iat = p
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| Error::Malformed("missing iat".into()))?;
        let released = match p.get("released") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().filter(|s| is_field_path(s)).map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| Error::Malformed("released must list field names".into()))?,
            Some(_) => return Err(Error::Malformed("released must be an array".into())),
        };
        Ok(Self {
            iss: required("iss")?,
            iat,
            outcome,
            reference: required("reference")?,
            mandate_id: text("mandate_id"),
            presentation_id: text("presentation_id"),
            method: text("method"),
            task_id: text("task_id"),
            purpose: text("purpose"),
            released,
            prev: text("prev"),
        })
    }
}

/// The AP2 reference for a presentation chain: the `sd_hash`-style digest of
/// its closing hop (JWT and disclosures).
pub fn reference_for(chain: &str) -> Result<String, Error> {
    Ok(b64(&Sha256::digest(closing_segment(chain)?.as_bytes())))
}

/// A signature-independent ID for a presentation: the digest of its closing
/// hop's signing input and disclosures.
pub fn presentation_id(chain: &str) -> Result<String, Error> {
    let closing = closing_segment(chain)?;
    let (jwt, disclosures) = closing.split_once('~').unwrap_or((closing, ""));
    let signing_input = jwt.rsplit_once('.').map_or(jwt, |(input, _)| input);
    Ok(a2a_gov_mandate::sdjwt::digest(&format!(
        "{signing_input}~{disclosures}"
    )))
}

/// The reference AP2's sample code computes: the digest of the closing hop's
/// JWT alone.
pub fn jwt_only_reference(chain: &str) -> Result<String, Error> {
    let closing = closing_segment(chain)?;
    let jwt = closing.split('~').next().unwrap_or_default();
    Ok(b64(&Sha256::digest(jwt.as_bytes())))
}

fn closing_segment(chain: &str) -> Result<&str, Error> {
    let last = chain.rsplit("~~").next().unwrap_or_default();
    if chain.contains("~~") && last.ends_with('~') && !last.starts_with('~') {
        Ok(last)
    } else {
        Err(Error::Malformed("not a presentation chain".into()))
    }
}

fn is_field_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./[]".contains(c))
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
