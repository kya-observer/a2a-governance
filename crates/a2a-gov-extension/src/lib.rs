//! The A2A Delegation Governance extension: how agents declare it, how clients
//! activate it, and the error profile used to refuse or pause a call.
//!
//! Normative references: A2A v1.0 §3.2.6 (service parameters), §4.4.4 and §4.6
//! (extensions), §3.3.2, §5.4 and §9.5 (errors).

pub mod errors;

use serde::Serialize;
use serde_json::{Map, Value};

/// The extension identifier. Agents list it in their Agent Card; clients send it
/// in the `A2A-Extensions` service parameter to activate the extension.
pub const EXTENSION_URI: &str = "https://kya.observer/ext/a2a-governance/v0.1";

const DESCRIPTION: &str = "Mandate-based in-task authorization: scoped, key-bound grants \
    approved by the user, verified per call, with signed receipts";

/// An `AgentExtension` entry for `AgentCard.capabilities.extensions`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Declaration {
    uri: &'static str,
    description: &'static str,
    required: bool,
    #[serde(skip_serializing_if = "Map::is_empty")]
    params: Map<String, Value>,
}

impl Declaration {
    /// With `required: true`, a client that doesn't activate the extension gets
    /// `ExtensionSupportRequiredError` (A2A §5.4, JSON-RPC `-32008`).
    pub fn new(required: bool) -> Self {
        Self {
            uri: EXTENSION_URI,
            description: DESCRIPTION,
            required,
            params: Map::new(),
        }
    }

    /// Adds an extension-specific parameter.
    pub fn with_param(mut self, key: &str, value: Value) -> Self {
        self.params.insert(key.to_owned(), value);
        self
    }
}

/// Whether an `A2A-Extensions` value activates this extension.
///
/// Matching is exact: A2A §4.6.3 forbids falling back to another version.
pub fn is_activated(a2a_extensions: &str) -> bool {
    a2a_extensions
        .split(',')
        .map(str::trim)
        .any(|uri| uri == EXTENSION_URI)
}
