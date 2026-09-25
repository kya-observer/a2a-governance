//! The payload an Agent Card signature covers.

use serde_json::{Map, Value};

use crate::schema_types::{Kind, Presence, Shape, field};
use crate::{Error, jcs};

/// How to prepare the card before RFC 8785.
#[derive(Clone, Copy)]
pub(crate) enum Mode {
    /// A2A v1.0 §8.4.1: remove default values, keep REQUIRED and present
    /// `optional` fields, keep fields this version doesn't know.
    Spec,
    /// What the official a2a-sdk (1.1.x) signs: the card parsed into protobuf
    /// (unknown fields dropped, no notion of REQUIRED), then every empty string,
    /// list and object removed.
    A2aSdk,
}

pub(crate) fn payload(card: &Value, mode: Mode) -> Result<String, Error> {
    let mut card = card.clone();
    if let Some(obj) = card.as_object_mut() {
        obj.remove("signatures");
    }
    let cleaned = strip(&card, "AgentCard", mode, 0)?;
    let prepared = match mode {
        Mode::Spec => cleaned,
        Mode::A2aSdk => clean_empty(&cleaned).unwrap_or(Value::Null),
    };
    jcs::canonicalize(&prepared)
}

fn strip(value: &Value, message: &str, mode: Mode, depth: usize) -> Result<Value, Error> {
    if depth > jcs::MAX_DEPTH {
        return Err(Error::Canonicalization("card nested too deeply".into()));
    }
    let Some(obj) = value.as_object() else {
        return Ok(value.clone());
    };
    let mut out = Map::new();
    for (key, v) in obj {
        let Some(f) = field(message, key) else {
            if matches!(mode, Mode::Spec) {
                out.insert(key.clone(), v.clone());
            }
            continue;
        };
        let v = match (f.shape, f.kind, v) {
            (Shape::Single, Kind::Message(m), v) => strip(v, m, mode, depth + 1)?,
            (Shape::Repeated, Kind::Message(m), Value::Array(items)) => Value::Array(
                items
                    .iter()
                    .map(|i| strip(i, m, mode, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            (Shape::Map, Kind::Message(m), Value::Object(entries)) => Value::Object(
                entries
                    .iter()
                    .map(|(k, e)| Ok((k.clone(), strip(e, m, mode, depth + 1)?)))
                    .collect::<Result<_, Error>>()?,
            ),
            (_, _, v) => v.clone(),
        };
        let presence = match (mode, f.presence) {
            (Mode::A2aSdk, Presence::Required) => Presence::Implicit,
            (_, p) => p,
        };
        if presence != Presence::Implicit || !is_default(&v, f.shape, f.kind) {
            out.insert(key.clone(), v);
        }
    }
    Ok(Value::Object(out))
}

/// Whether `v` is the proto3 default for a field with implicit presence.
fn is_default(v: &Value, shape: Shape, kind: Kind) -> bool {
    match (shape, kind, v) {
        (Shape::Repeated, _, Value::Array(a)) => a.is_empty(),
        (Shape::Map, _, Value::Object(m)) => m.is_empty(),
        (Shape::Single, Kind::Str, Value::String(s)) => s.is_empty(),
        (Shape::Single, Kind::Bool, Value::Bool(b)) => !b,
        (Shape::Single, Kind::Number, Value::Number(n)) => n.as_f64() == Some(0.0),
        (Shape::Single, Kind::Enum, Value::Number(n)) => n.as_i64() == Some(0),
        (Shape::Single, Kind::Enum, Value::String(s)) => s.ends_with("_UNSPECIFIED"),
        _ => false,
    }
}

/// The a2a-sdk's `_clean_empty`: drop empty strings, lists and objects,
/// recursively; `None` when nothing is left.
fn clean_empty(v: &Value) -> Option<Value> {
    match v {
        Value::Object(m) => {
            let kept: Map<String, Value> = m
                .iter()
                .filter_map(|(k, v)| clean_empty(v).map(|v| (k.clone(), v)))
                .collect();
            (!kept.is_empty()).then_some(Value::Object(kept))
        }
        Value::Array(a) => {
            let kept: Vec<Value> = a.iter().filter_map(clean_empty).collect();
            (!kept.is_empty()).then_some(Value::Array(kept))
        }
        Value::String(s) if s.is_empty() => None,
        other => Some(other.clone()),
    }
}
