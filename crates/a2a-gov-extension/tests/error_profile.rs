//! The pre-task Deny/Challenge error profile, checked against A2A v1.0.
//!
//! Sources: A2A specification §3.3.2 (error model), §5.4 (error code table),
//! §9.5 (JSON-RPC error handling); JSON-RPC 2.0 §5.1.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_extension::errors::{
    CHALLENGE_CODE, ChallengeReason, DENY_CODE, DenyReason, ErrorProfile, GovernanceError,
};
use serde_json::{Value, json};

const DOMAIN: &str = "example.org";

/// A2A v1.0 §5.4: every JSON-RPC code the core specification assigns.
const A2A_ASSIGNED: [i64; 9] = [
    -32001, -32002, -32003, -32004, -32005, -32006, -32007, -32008, -32009,
];

fn deny() -> GovernanceError {
    GovernanceError::deny(
        DenyReason::InvalidMandate,
        "mandate does not cover this action",
    )
}

fn challenge() -> GovernanceError {
    GovernanceError::challenge(
        ChallengeReason::ApprovalRequired,
        "approval required",
        "ch_123",
        "https://approve.example.org/c/ch_123",
    )
    .expect("valid challenge")
}

#[test]
fn codes_sit_outside_the_json_rpc_reserved_block() {
    // JSON-RPC 2.0 §5.1 reserves -32768..=-32000 for pre-defined errors.
    for code in [DENY_CODE, CHALLENGE_CODE] {
        assert!(!(-32768..=-32000).contains(&code), "{code} is reserved");
    }
}

#[test]
fn codes_never_collide_with_a2a_core_errors() {
    // A2A §9.5 reserves -32001..=-32099 for A2A-specific errors.
    for code in [DENY_CODE, CHALLENGE_CODE] {
        assert!(!(-32099..=-32001).contains(&code));
        assert!(!A2A_ASSIGNED.contains(&code));
    }
    assert_ne!(DENY_CODE, CHALLENGE_CODE);
}

#[test]
fn deny_maps_to_the_documented_json_rpc_error() {
    let err = deny().to_json_rpc_error(DOMAIN);
    assert_eq!(err["code"], json!(-31000));
    assert_eq!(err["message"], json!("mandate does not cover this action"));
    let data = err["data"].as_array().expect("data is an array (A2A §9.5)");
    assert_eq!(data.len(), 1);
    assert_eq!(
        data[0],
        json!({
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "INVALID_MANDATE",
            "domain": DOMAIN,
        })
    );
}

#[test]
fn challenge_carries_error_info_and_a_help_link() {
    let err = challenge().to_json_rpc_error(DOMAIN);
    assert_eq!(err["code"], json!(-31001));
    let data = err["data"].as_array().expect("array");
    assert_eq!(
        data[0],
        json!({
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "APPROVAL_REQUIRED",
            "domain": DOMAIN,
            "metadata": { "challengeId": "ch_123" },
        })
    );
    assert_eq!(
        data[1],
        json!({
            "@type": "type.googleapis.com/google.rpc.Help",
            "links": [{
                "description": "approval required",
                "url": "https://approve.example.org/c/ch_123",
            }],
        })
    );
}

#[test]
fn every_error_detail_has_a_type_key() {
    // A2A §9.5: each object in `data` MUST include `@type`.
    for err in [deny(), challenge()] {
        for detail in err.to_json_rpc_error(DOMAIN)["data"]
            .as_array()
            .expect("array")
        {
            assert!(detail["@type"].is_string(), "{detail}");
        }
    }
}

#[test]
fn both_outcomes_use_the_a2a_authorization_mappings_for_grpc_and_http() {
    // A2A §3.3.2, Authorization Errors: HTTP 403, gRPC PERMISSION_DENIED.
    for err in [deny(), challenge()] {
        assert_eq!(err.http_status(), 403);
        assert_eq!(err.grpc_status(), "PERMISSION_DENIED");
    }
}

#[test]
fn challenge_urls_must_be_https() {
    // The approval happens on a trusted surface outside the client; never plain HTTP.
    for url in [
        "http://approve.example.org/c/1",
        "javascript:alert(1)",
        "not a url",
        "",
    ] {
        assert!(
            GovernanceError::challenge(ChallengeReason::ApprovalRequired, "m", "id", url).is_err(),
            "{url} accepted"
        );
    }
}

#[test]
fn reasons_follow_ap2_action_authorization_errors() {
    let reasons: Vec<&str> = [
        DenyReason::Denied,
        DenyReason::InvalidCredential,
        DenyReason::InvalidMandate,
        DenyReason::MandatesNotSupported,
    ]
    .iter()
    .map(|r| r.as_str())
    .collect();
    assert_eq!(
        reasons,
        [
            "DENIED",
            "INVALID_CREDENTIAL",
            "INVALID_MANDATE",
            "MANDATES_NOT_SUPPORTED"
        ]
    );
    assert_eq!(
        ChallengeReason::UnresolvedConstraint.as_str(),
        "UNRESOLVED_CONSTRAINT"
    );
    assert_eq!(
        ChallengeReason::ApprovalRequired.as_str(),
        "APPROVAL_REQUIRED"
    );
}

#[test]
fn clients_recover_the_outcome_from_the_wire() {
    for original in [deny(), challenge()] {
        let wire = original.to_json_rpc_error(DOMAIN);
        let parsed = ErrorProfile::new(DOMAIN).parse(&wire).expect("recognized");
        assert_eq!(parsed, original);
    }
}

#[test]
fn clients_ignore_errors_from_other_domains_or_unknown_reasons() {
    let profile = ErrorProfile::new(DOMAIN);
    let foreign = deny().to_json_rpc_error("other.example");
    assert_eq!(profile.parse(&foreign), None);

    let mut unknown = deny().to_json_rpc_error(DOMAIN);
    unknown["data"][0]["reason"] = json!("SOMETHING_ELSE");
    assert_eq!(profile.parse(&unknown), None);

    // A2A's own TaskNotFoundError must never be mistaken for a governance error.
    let task_not_found: Value = json!({
        "code": -32001,
        "message": "Task not found",
        "data": [{
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "TASK_NOT_FOUND",
            "domain": "a2a-protocol.org",
        }],
    });
    assert_eq!(profile.parse(&task_not_found), None);
}

#[test]
fn clients_tolerate_extra_error_details() {
    let mut wire = challenge().to_json_rpc_error(DOMAIN);
    wire["data"].as_array_mut().expect("array").insert(
        0,
        json!({"@type": "type.googleapis.com/google.rpc.DebugInfo", "detail": "x"}),
    );
    assert_eq!(ErrorProfile::new(DOMAIN).parse(&wire), Some(challenge()));
}

#[test]
fn a_challenge_without_its_help_link_is_not_accepted() {
    let mut wire = challenge().to_json_rpc_error(DOMAIN);
    wire["data"].as_array_mut().expect("array").truncate(1);
    assert_eq!(ErrorProfile::new(DOMAIN).parse(&wire), None);
}
