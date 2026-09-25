//! Field metadata for A2A §8.4.1 default-value removal (see `schema.rs`).

/// How a field's presence is tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    /// `REQUIRED`: always kept, even at its default.
    Required,
    /// proto3 `optional`: kept whenever present.
    Optional,
    /// A oneof member: presence is tracked, kept whenever present.
    Oneof,
    /// Plain proto3 field: removed at its default value.
    Implicit,
}

/// Cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    Single,
    Repeated,
    Map,
}

/// Value type. `Number` and `Enum` aren't used by the current Agent Card schema;
/// the generator emits them if a2a.proto starts using such fields.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Str,
    Bool,
    Number,
    Enum,
    /// `google.protobuf.Struct`: arbitrary JSON, kept as is.
    Struct,
    Message(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Field {
    pub name: &'static str,
    pub presence: Presence,
    pub shape: Shape,
    pub kind: Kind,
}

pub(crate) fn field(message: &str, name: &str) -> Option<&'static Field> {
    crate::schema::MESSAGES
        .iter()
        .find(|(m, _)| *m == message)
        .and_then(|(_, fields)| fields.iter().find(|f| f.name == name))
}
