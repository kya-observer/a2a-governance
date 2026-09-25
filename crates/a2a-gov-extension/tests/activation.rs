//! Extension declaration and activation, checked against A2A v1.0 §3.2.6 and §4.6.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_extension::{Declaration, EXTENSION_URI, is_activated};
use serde_json::json;

#[test]
fn declaration_is_a_valid_agent_extension() {
    // A2A §4.4.4 AgentExtension: uri, description, required, params.
    let decl = Declaration::new(true).with_param("mandateFormats", json!(["dc+sd-jwt"]));
    let value = serde_json::to_value(&decl).expect("serializes");
    assert_eq!(value["uri"], json!(EXTENSION_URI));
    assert_eq!(value["required"], json!(true));
    assert!(value["description"].as_str().is_some_and(|d| !d.is_empty()));
    assert_eq!(value["params"]["mandateFormats"], json!(["dc+sd-jwt"]));
}

#[test]
fn declaration_omits_empty_params() {
    let value = serde_json::to_value(Declaration::new(false)).expect("serializes");
    assert!(value.get("params").is_none());
}

#[test]
fn extension_uri_is_versioned() {
    // A2A §4.6.3: extensions SHOULD include version information in their URI.
    assert!(EXTENSION_URI.starts_with("https://"));
    assert!(
        EXTENSION_URI
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .is_some_and(|v| v.starts_with('v'))
    );
}

#[test]
fn activation_reads_the_comma_separated_service_parameter() {
    // A2A §3.2.6: A2A-Extensions is a comma-separated list of URIs.
    assert!(is_activated(EXTENSION_URI));
    assert!(is_activated(&format!(
        "https://example.com/ext/geo/v1, {EXTENSION_URI}"
    )));
    assert!(is_activated(&format!(
        "  {EXTENSION_URI}  ,https://example.com/x/v1"
    )));
}

#[test]
fn activation_requires_an_exact_uri_match() {
    // A2A §4.6.3: no automatic fallback to other versions.
    assert!(!is_activated(""));
    assert!(!is_activated("https://example.com/ext/geo/v1"));
    assert!(!is_activated(&format!("{EXTENSION_URI}x")));
    assert!(!is_activated(&EXTENSION_URI.replace("v0.1", "v0.2")));
    assert!(!is_activated(&EXTENSION_URI.to_uppercase()));
}
