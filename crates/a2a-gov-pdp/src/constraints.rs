//! The `access.*` constraint types. Every authorizing hop's constraints must
//! cover the call on their own, so a delegation can only narrow.

use a2a_gov_mandate::{HopKind, VerifiedChain};
use serde_json::{Map, Value};

use crate::{Call, Release};

pub(crate) enum Evaluation {
    Covered {
        purpose: Option<String>,
        limits: Vec<(String, u64)>,
    },
    Refused(String),
    Unresolved(String),
}

pub(crate) fn evaluate(chain: &VerifiedChain, call: &Call) -> Evaluation {
    let mut purpose = call.purpose.clone();
    let mut limits = Vec::new();
    let mut unknown = None;
    let hops = chain.hops();

    for (i, hop) in hops
        .iter()
        .enumerate()
        .filter(|(_, h)| h.kind() != HopKind::Closing)
    {
        let constraints = match hop.mandate().get("constraints") {
            None => continue,
            Some(Value::Array(items)) => items,
            Some(_) => return Evaluation::Refused("constraints must be an array".into()),
        };
        for c in constraints {
            let Some(kind) = c.get("type").and_then(Value::as_str) else {
                return Evaluation::Refused("constraint without a type".into());
            };
            let result = match kind {
                "access.authorization_details" => authorization_details(c, call),
                "access.purpose" => constrain_purpose(c, &mut purpose),
                "access.release" => release(c, call),
                "access.max_uses" => max_uses(c).map(|n| limits.push((hop.id().to_owned(), n))),
                "access.delegation" => delegation(c, hops.len() - 2 - i),
                other => {
                    unknown.get_or_insert_with(|| format!("unknown constraint {other:?}"));
                    Ok(())
                }
            };
            if let Err(detail) = result {
                return Evaluation::Refused(detail);
            }
        }
    }
    match unknown {
        Some(detail) => Evaluation::Unresolved(detail),
        None => Evaluation::Covered { purpose, limits },
    }
}

fn authorization_details(c: &Value, call: &Call) -> Result<(), String> {
    let Some(Value::Array(allowed)) = c.get("authorization_details") else {
        return Err("access.authorization_details needs an array".into());
    };
    for requested in &call.authorization_details {
        if !allowed.iter().any(|a| covers(a, requested)) {
            return Err(format!("not covered by the mandate: {requested}"));
        }
    }
    Ok(())
}

/// RFC 9396 matching: same `type`; where the allowance restricts `actions`,
/// `fields` or `locations`, the request must state them and stay within them
/// (an omitted dimension could mean "all"); any other key the allowance sets
/// must appear in the request with the same value.
fn covers(allowed: &Value, requested: &Value) -> bool {
    let (Some(a), Some(r)) = (allowed.as_object(), requested.as_object()) else {
        return false;
    };
    if a.get("type").and_then(Value::as_str).is_none() || a.get("type") != r.get("type") {
        return false;
    }
    a.iter()
        .filter(|(k, _)| k.as_str() != "type")
        .all(|(k, v)| match k.as_str() {
            "actions" | "fields" | "locations" => subset(r, k, v),
            _ => r.get(k) == Some(v),
        })
}

fn subset(requested: &Map<String, Value>, key: &str, allowed: &Value) -> bool {
    let Some(allowed) = allowed.as_array() else {
        return false;
    };
    match requested.get(key) {
        None => false,
        Some(Value::Array(items)) => items.iter().all(|i| allowed.contains(i)),
        Some(_) => false,
    }
}

fn constrain_purpose(c: &Value, purpose: &mut Option<String>) -> Result<(), String> {
    let Some(required) = c.get("purpose").and_then(Value::as_str) else {
        return Err("access.purpose needs a purpose".into());
    };
    match purpose {
        Some(p) if p != required => Err(format!("purpose {p:?} is not {required:?}")),
        _ => {
            *purpose = Some(required.to_owned());
            Ok(())
        }
    }
}

fn release(c: &Value, call: &Call) -> Result<(), String> {
    let cap = c
        .get("release")
        .and_then(Value::as_str)
        .and_then(Release::parse)
        .ok_or("access.release must be answer-only or records")?;
    if call.release > cap {
        return Err("the call releases more than the mandate allows".into());
    }
    Ok(())
}

fn max_uses(c: &Value) -> Result<u64, String> {
    match c.get("max_uses").and_then(Value::as_u64) {
        Some(n) if n >= 1 => Ok(n),
        _ => Err("access.max_uses must be a positive integer".into()),
    }
}

fn delegation(c: &Value, delegations_after: usize) -> Result<(), String> {
    let max = c
        .get("max_depth")
        .and_then(Value::as_u64)
        .ok_or("access.delegation needs max_depth")?;
    if delegations_after as u64 > max {
        return Err("delegated further than the mandate allows".into());
    }
    Ok(())
}
