//! Selective disclosure (RFC 9901): creating disclosures and resolving them
//! against an issuer-signed payload.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{Error, b64};

/// The only `_sd_alg` this crate accepts or emits.
pub const SD_ALG: &str = "sha-256";

const SD: &str = "_sd";
const ELLIPSIS: &str = "...";

/// The base64url SHA-256 digest of a disclosure, computed over its exact
/// encoded form (RFC 9901 §4.2.3).
pub fn digest(disclosure: &str) -> String {
    b64::encode(Sha256::digest(disclosure.as_bytes()))
}

/// A hop's stable identifier: the digest of its JWS signing input
/// (`header.payload`), leaving out the signature. ECDSA signatures are
/// malleable (`s` → `n − s` still verifies), so an ID that covered the
/// signature would let anyone mint a second ID for the same mandate and escape
/// use counting and revocation.
pub fn hop_id(jwt: &str) -> String {
    let signing_input = jwt.rsplit_once('.').map_or(jwt, |(input, _)| input);
    digest(signing_input)
}

/// A decoded disclosure: `[salt, name, value]` for an object property, or
/// `[salt, value]` for an array element.
#[derive(Debug, Clone, PartialEq)]
pub struct Disclosure {
    name: Option<String>,
    value: Value,
}

impl Disclosure {
    /// Decodes and validates one disclosure string.
    pub fn parse(encoded: &str) -> Result<Self, Error> {
        let bytes = b64::decode(encoded).map_err(|_| Error::Disclosure("not base64url".into()))?;
        let Ok(Value::Array(mut items)) = crate::strict_json::from_slice(&bytes) else {
            return Err(Error::Disclosure("not a JSON array".into()));
        };
        if !items.first().is_some_and(Value::is_string) {
            return Err(Error::Disclosure("salt must be a string".into()));
        }
        match items.len() {
            2 => Ok(Self {
                name: None,
                value: items.remove(1),
            }),
            3 => {
                let value = items.remove(2);
                let Value::String(name) = items.remove(1) else {
                    return Err(Error::Disclosure("claim name must be a string".into()));
                };
                if name == SD || name == ELLIPSIS {
                    return Err(Error::Disclosure(format!("reserved claim name {name:?}")));
                }
                Ok(Self {
                    name: Some(name),
                    value,
                })
            }
            n => Err(Error::Disclosure(format!("disclosure has {n} elements"))),
        }
    }

    /// The claim name, for object-property disclosures.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The disclosed value.
    pub fn value(&self) -> &Value {
        &self.value
    }
}

/// Which parts of a mandate the issuer makes selectively disclosable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Disclosable {
    fields: Vec<String>,
    array_elements: Vec<String>,
}

impl Disclosable {
    /// Nothing inside the mandate is individually disclosable. The mandate
    /// object itself is always one disclosure, as in AP2.
    pub fn none() -> Self {
        Self::default()
    }

    /// Top-level mandate fields that become individual disclosures.
    pub fn fields<const N: usize>(names: [&str; N]) -> Self {
        Self {
            fields: names.map(str::to_owned).to_vec(),
            ..Self::default()
        }
    }

    /// Array fields whose elements each become a disclosure (AP2's
    /// `x-selectively-disclosable-array`), e.g. `constraints`.
    pub fn array_elements<const N: usize>(names: [&str; N]) -> Self {
        Self {
            array_elements: names.map(str::to_owned).to_vec(),
            ..Self::default()
        }
    }
}

/// Collects disclosures while building an issuer payload.
pub(crate) struct Builder {
    disclosures: Vec<String>,
}

impl Builder {
    pub(crate) fn new() -> Self {
        Self {
            disclosures: Vec::new(),
        }
    }

    pub(crate) fn disclosures(&self) -> &[String] {
        &self.disclosures
    }

    /// `parts` is `[value]` for an array element or `[name, value]` for a claim.
    fn push(&mut self, parts: Vec<Value>) -> Result<String, Error> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| Error::Malformed(format!("no randomness: {e}")))?;
        let mut array = vec![Value::String(b64::encode(salt))];
        array.extend(parts);
        let encoded = b64::encode(Value::Array(array).to_string());
        let d = digest(&encoded);
        self.disclosures.push(encoded);
        Ok(d)
    }

    /// Applies `sd` to `mandate`, then wraps the result as one array-element
    /// disclosure, returning the `delegate_payload` value.
    pub(crate) fn delegate_payload(
        &mut self,
        mandate: &Map<String, Value>,
        sd: &Disclosable,
    ) -> Result<Value, Error> {
        let mut item = mandate.clone();
        for key in &sd.array_elements {
            let Some(Value::Array(elements)) = item.remove(key) else {
                return Err(Error::Malformed(format!("{key:?} is not an array")));
            };
            let mut hidden = Vec::with_capacity(elements.len());
            for element in elements {
                hidden.push(json!({ ELLIPSIS: self.push(vec![element])? }));
            }
            item.insert(key.clone(), Value::Array(hidden));
        }
        let mut digests = Vec::new();
        for key in &sd.fields {
            let value = item
                .remove(key)
                .ok_or_else(|| Error::Malformed(format!("no field {key:?}")))?;
            digests.push(Value::String(
                self.push(vec![Value::String(key.clone()), value])?,
            ));
        }
        if !digests.is_empty() {
            // Sorted so digest order leaks nothing about claim order (RFC 9901 §4.2.4.1).
            digests.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            item.insert(SD.into(), Value::Array(digests));
        }
        let wrapper = self.push(vec![Value::Object(item)])?;
        Ok(json!([{ ELLIPSIS: wrapper }]))
    }
}

/// Resolves every disclosure into `payload` per RFC 9901 §7.1 and removes the
/// SD-JWT bookkeeping claims.
pub(crate) fn resolve(
    mut payload: Map<String, Value>,
    disclosures: &[&str],
) -> Result<Map<String, Value>, Error> {
    match payload.remove("_sd_alg") {
        None => {}
        Some(Value::String(alg)) if alg == SD_ALG => {}
        Some(other) => return Err(Error::Disclosure(format!("unsupported _sd_alg {other}"))),
    }
    let mut by_digest = HashMap::with_capacity(disclosures.len());
    for encoded in disclosures {
        if by_digest
            .insert(digest(encoded), Disclosure::parse(encoded)?)
            .is_some()
        {
            return Err(Error::Disclosure("duplicate disclosure".into()));
        }
    }
    let mut resolver = Resolver {
        by_digest,
        seen: HashSet::new(),
        used: 0,
        withheld: 0,
    };
    resolver.object(&mut payload)?;
    if resolver.used != disclosures.len() {
        return Err(Error::Disclosure(
            "disclosure not referenced by the payload".into(),
        ));
    }
    // The holder chooses which disclosures to forward, and signs the next hop
    // over its choice, so sd_hash can't reveal a withheld constraint or `exp`.
    // This profile therefore requires every digest to be disclosed (no decoys).
    if resolver.withheld > 0 {
        return Err(Error::Disclosure(format!(
            "{} disclosure(s) withheld; every disclosure must be presented",
            resolver.withheld
        )));
    }
    Ok(payload)
}

struct Resolver {
    by_digest: HashMap<String, Disclosure>,
    seen: HashSet<String>,
    used: usize,
    withheld: usize,
}

impl Resolver {
    fn take(&mut self, digest: &str) -> Result<Option<Disclosure>, Error> {
        if !self.seen.insert(digest.to_owned()) {
            return Err(Error::Disclosure("digest referenced more than once".into()));
        }
        let found = self.by_digest.remove(digest);
        if found.is_some() {
            self.used += 1;
        } else {
            self.withheld += 1;
        }
        Ok(found)
    }

    fn value(&mut self, v: &mut Value) -> Result<(), Error> {
        match v {
            Value::Object(m) => self.object(m),
            Value::Array(a) => self.array(a),
            _ => Ok(()),
        }
    }

    fn object(&mut self, m: &mut Map<String, Value>) -> Result<(), Error> {
        let digests = match m.remove(SD) {
            None => Vec::new(),
            Some(Value::Array(ds)) => ds,
            Some(_) => return Err(Error::Disclosure("_sd must be an array".into())),
        };
        for v in m.values_mut() {
            self.value(v)?;
        }
        for d in digests {
            let Value::String(d) = d else {
                return Err(Error::Disclosure("_sd entries must be strings".into()));
            };
            let Some(disclosure) = self.take(&d)? else {
                continue;
            };
            let Some(name) = disclosure.name else {
                return Err(Error::Disclosure(
                    "array-element disclosure used for a claim".into(),
                ));
            };
            let mut value = disclosure.value;
            self.value(&mut value)?;
            if m.insert(name.clone(), value).is_some() {
                return Err(Error::Disclosure(format!("claim {name:?} disclosed twice")));
            }
        }
        Ok(())
    }

    fn array(&mut self, a: &mut Vec<Value>) -> Result<(), Error> {
        let mut out = Vec::with_capacity(a.len());
        for mut element in a.drain(..) {
            let placeholder = element
                .as_object()
                .filter(|o| o.len() == 1)
                .and_then(|o| o.get(ELLIPSIS))
                .map(|d| d.as_str().map(str::to_owned));
            match placeholder {
                Some(None) => {
                    return Err(Error::Disclosure("array digest must be a string".into()));
                }
                Some(Some(d)) => {
                    let Some(disclosure) = self.take(&d)? else {
                        continue;
                    };
                    if disclosure.name.is_some() {
                        return Err(Error::Disclosure(
                            "claim disclosure used for an array element".into(),
                        ));
                    }
                    let mut value = disclosure.value;
                    self.value(&mut value)?;
                    out.push(value);
                }
                None => {
                    self.value(&mut element)?;
                    out.push(element);
                }
            }
        }
        *a = out;
        Ok(())
    }
}
