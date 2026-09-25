//! Issuing open mandates and appending hops, in AP2's wire format.

use serde_json::{Map, Value, json};

use crate::chain::{TYP_CLOSING, TYP_DELEGATION};
use crate::sdjwt::{Builder, SD_ALG, digest};
use crate::{Disclosable, Error, SigningKey, jws};

/// Signs an open mandate as a trusted surface. The result is one segment
/// ending in `~`. `mandate` should carry `vct`, `cnf.jwk` (the agent's key),
/// `exp` and its constraints.
pub fn issue_open(
    mandate: &Map<String, Value>,
    sd: &Disclosable,
    key: &SigningKey,
) -> Result<String, Error> {
    let mut builder = Builder::new();
    let mut payload = Map::new();
    payload.insert(
        "delegate_payload".into(),
        builder.delegate_payload(mandate, sd)?,
    );
    payload.insert("_sd_alg".into(), json!(SD_ALG));
    Ok(segment(
        &header("dc+sd-jwt", key),
        &payload,
        key,
        builder.disclosures(),
    ))
}

/// Appends one hop to `prev`, the previous hop's segment. A mandate with
/// `cnf` makes a delegation; one without makes the closing hop.
pub fn present(
    prev: &str,
    mandate: &Map<String, Value>,
    sd: &Disclosable,
    key: &SigningKey,
    aud: &str,
    nonce: &str,
    iat: i64,
) -> Result<String, Error> {
    if prev.contains("~~") || !prev.ends_with('~') {
        return Err(Error::Malformed(
            "prev must be a single segment ending in '~'".into(),
        ));
    }
    if aud.is_empty() || nonce.is_empty() {
        return Err(Error::Malformed("aud and nonce are required".into()));
    }
    let typ = if mandate.contains_key("cnf") {
        TYP_DELEGATION
    } else {
        TYP_CLOSING
    };
    let mut builder = Builder::new();
    let mut payload = Map::new();
    payload.insert(
        "delegate_payload".into(),
        builder.delegate_payload(mandate, sd)?,
    );
    payload.insert("iat".into(), json!(iat));
    payload.insert("aud".into(), json!(aud));
    payload.insert("nonce".into(), json!(nonce));
    payload.insert("sd_hash".into(), json!(digest(prev)));
    payload.insert("_sd_alg".into(), json!(SD_ALG));
    Ok(segment(
        &header(typ, key),
        &payload,
        key,
        builder.disclosures(),
    ))
}

/// Joins segments into a chain, stripping each non-final segment's trailing `~`.
pub fn join(segments: &[&str]) -> String {
    let last = segments.len().saturating_sub(1);
    segments
        .iter()
        .enumerate()
        .map(|(i, s)| {
            if i < last {
                s.strip_suffix('~').unwrap_or(s)
            } else {
                s
            }
        })
        .collect::<Vec<_>>()
        .join("~~")
}

fn header(typ: &str, key: &SigningKey) -> Map<String, Value> {
    let mut h = Map::new();
    h.insert("alg".into(), json!("ES256"));
    h.insert("typ".into(), json!(typ));
    if let Some(kid) = key.kid() {
        h.insert("kid".into(), json!(kid));
    }
    h
}

fn segment(
    header: &Map<String, Value>,
    payload: &Map<String, Value>,
    key: &SigningKey,
    disclosures: &[String],
) -> String {
    let mut out = jws::sign(header, payload, key);
    out.push('~');
    for d in disclosures {
        out.push_str(d);
        out.push('~');
    }
    out
}
