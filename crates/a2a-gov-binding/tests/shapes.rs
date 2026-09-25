//! The extension's A2A v1.0 message shapes (ProtoJSON, ADR-001), all carried in
//! `metadata` keyed by the extension URI (A2A §4.6.2).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_binding::{
    Approved, AuthState, Error, Hello, MandateRequest, PresentationMeta, ReceiptMeta,
    continuation_message, hello_message, read_hello, read_presentation, read_receipt, read_status,
    receipt_artifact, task_status,
};
use a2a_gov_extension::EXTENSION_URI;
use serde_json::json;

fn request() -> MandateRequest {
    MandateRequest {
        mandate: json!({ "vct": "mandate.access.1", "exp": 1_790_003_600,
                         "constraints": [{ "type": "access.max_uses", "max_uses": 3 }] })
        .as_object()
        .unwrap()
        .clone(),
        approval_url: "https://approve.example.org/c/ch_1".into(),
        challenge_id: "ch_1".into(),
        aud: "https://vault.example.org/a2a".into(),
        nonce: "n1".into(),
    }
}

#[test]
fn task_status_is_an_a2a_task_status() {
    let status = task_status(
        "m1",
        "t1",
        "c1",
        "Approval needed",
        &AuthState::Pending(request()),
    );
    assert_eq!(status["state"], json!("TASK_STATE_AUTH_REQUIRED"));
    let message = &status["message"];
    assert_eq!(message["role"], json!("ROLE_AGENT"));
    assert_eq!(message["messageId"], json!("m1"));
    assert_eq!(message["taskId"], json!("t1"));
    assert_eq!(message["contextId"], json!("c1"));
    assert_eq!(message["parts"], json!([{ "text": "Approval needed" }]));
    assert_eq!(message["extensions"], json!([EXTENSION_URI]));
    let meta = &message["metadata"][EXTENSION_URI];
    assert_eq!(meta["state"], json!("pending"));
    assert_eq!(
        meta["approvalUrl"],
        json!("https://approve.example.org/c/ch_1")
    );
    assert_eq!(meta["mandateRequest"]["vct"], json!("mandate.access.1"));
}

#[test]
fn pending_and_approved_states_round_trip() {
    for state in [
        AuthState::Pending(request()),
        AuthState::Approved(Approved {
            mandate: "eyJ...~".into(),
            aud: "https://vault.example.org/a2a".into(),
            nonce: "n2".into(),
        }),
        AuthState::Denied {
            reason: "denied by the user".into(),
        },
    ] {
        let status = task_status("m", "t", "c", "text", &state);
        let expected = if matches!(state, AuthState::Denied { .. }) {
            "TASK_STATE_REJECTED"
        } else {
            "TASK_STATE_AUTH_REQUIRED"
        };
        assert_eq!(status["state"], json!(expected));
        assert_eq!(read_status(&status).unwrap(), Some(state));
    }
}

#[test]
fn statuses_without_the_extension_are_not_ours() {
    let status = json!({ "state": "TASK_STATE_WORKING", "message": {
        "messageId": "m", "role": "ROLE_AGENT", "parts": [{ "text": "hi" }] } });
    assert_eq!(read_status(&status).unwrap(), None);
    assert_eq!(
        read_status(&json!({ "state": "TASK_STATE_WORKING" })).unwrap(),
        None
    );
}

#[test]
fn approval_urls_must_be_https() {
    let mut status = task_status("m", "t", "c", "x", &AuthState::Pending(request()));
    status["message"]["metadata"][EXTENSION_URI]["approvalUrl"] =
        json!("http://approve.example.org/c/ch_1");
    assert!(matches!(read_status(&status), Err(Error::Invalid(_))));
}

#[test]
fn protobuf_struct_doubles_are_read_back_as_integers() {
    // google.protobuf.Struct stores numbers as doubles, so SDKs built on protobuf
    // hand back `1790003600.0` for `1790003600`.
    let mut status = task_status("m", "t", "c", "x", &AuthState::Pending(request()));
    let req = &mut status["message"]["metadata"][EXTENSION_URI]["mandateRequest"];
    req["exp"] = json!(1_790_003_600.0);
    req["constraints"][0]["max_uses"] = json!(3.0);
    let Some(AuthState::Pending(read)) = read_status(&status).unwrap() else {
        panic!()
    };
    assert_eq!(read.mandate["exp"], json!(1_790_003_600));
    assert_eq!(read.mandate["constraints"][0]["max_uses"], json!(3));
}

#[test]
fn fractional_numbers_stay_fractional() {
    let mut status = task_status("m", "t", "c", "x", &AuthState::Pending(request()));
    status["message"]["metadata"][EXTENSION_URI]["mandateRequest"]["ratio"] = json!(0.5);
    let Some(AuthState::Pending(read)) = read_status(&status).unwrap() else {
        panic!()
    };
    assert_eq!(read.mandate["ratio"], json!(0.5));
}

#[test]
fn a_continuation_carries_the_presentation_and_activates_the_extension() {
    let p = PresentationMeta {
        presentation: "a~~b~".into(),
        nonce: "n1".into(),
    };
    let message = continuation_message("m2", "t1", "c1", "go on", &p);
    assert_eq!(message["role"], json!("ROLE_USER"));
    assert_eq!(message["taskId"], json!("t1"));
    assert_eq!(message["extensions"], json!([EXTENSION_URI]));
    assert_eq!(read_presentation(&message).unwrap(), Some(p));
}

#[test]
fn a_presentation_is_ignored_unless_the_message_activates_the_extension() {
    // A2A §4.6.2: extension data travels with the extension listed on the object.
    let mut message = continuation_message(
        "m",
        "t",
        "c",
        "x",
        &PresentationMeta {
            presentation: "a~~b~".into(),
            nonce: "n".into(),
        },
    );
    message.as_object_mut().unwrap().remove("extensions");
    assert_eq!(read_presentation(&message).unwrap(), None);
}

#[test]
fn malformed_presentations_are_invalid() {
    for meta in [
        json!({ "presentation": "", "nonce": "n" }),
        json!({ "presentation": "x" }),
        json!("str"),
    ] {
        let mut message = continuation_message(
            "m",
            "t",
            "c",
            "x",
            &PresentationMeta {
                presentation: "a".into(),
                nonce: "n".into(),
            },
        );
        message["metadata"][EXTENSION_URI] = meta.clone();
        assert!(
            matches!(read_presentation(&message), Err(Error::Invalid(_))),
            "{meta}"
        );
    }
}

#[test]
fn the_first_message_offers_the_holder_key() {
    let hello = Hello {
        holder_jwk: json!({ "kty": "EC", "crv": "P-256", "x": "x", "y": "y" }),
    };
    let message = hello_message("m0", "c1", "what have I read about rust?", &hello);
    assert!(message.get("taskId").is_none());
    assert_eq!(read_hello(&message).unwrap(), Some(hello));
}

#[test]
fn a_result_artifact_carries_the_receipt_and_the_next_nonce() {
    let meta = ReceiptMeta {
        receipt: "eyJ.r.s".into(),
        next_nonce: Some("n3".into()),
    };
    let artifact = receipt_artifact(
        "a1",
        vec![json!({ "text": "You read 3 articles about Rust." })],
        &meta,
    );
    assert_eq!(artifact["artifactId"], json!("a1"));
    assert_eq!(artifact["extensions"], json!([EXTENSION_URI]));
    assert_eq!(read_receipt(&artifact).unwrap(), Some(meta));
}

#[test]
fn metadata_from_other_extensions_is_left_alone() {
    let mut message = continuation_message(
        "m",
        "t",
        "c",
        "x",
        &PresentationMeta {
            presentation: "a~~b~".into(),
            nonce: "n".into(),
        },
    );
    message["metadata"]["https://example.com/ext/geo/v1"] = json!({ "lat": 1.5 });
    message["extensions"]
        .as_array_mut()
        .unwrap()
        .push(json!("https://example.com/ext/geo/v1"));
    assert!(read_presentation(&message).unwrap().is_some());
}

#[test]
fn message_shapes_use_protojson_field_names() {
    // ADR-001: lowerCamelCase field names, enum values as their full names.
    let texts = [
        task_status("m", "t", "c", "x", &AuthState::Pending(request())).to_string(),
        continuation_message(
            "m",
            "t",
            "c",
            "x",
            &PresentationMeta {
                presentation: "a".into(),
                nonce: "n".into(),
            },
        )
        .to_string(),
    ];
    for t in texts {
        for snake in [
            "message_id",
            "task_id",
            "context_id",
            "approval_url",
            "challenge_id",
            "holder_jwk",
            "next_nonce",
        ] {
            assert!(!t.contains(&format!("\"{snake}\"")), "{snake} in {t}");
        }
    }
}

#[test]
fn pending_requests_need_every_field() {
    for field in ["challengeId", "aud", "nonce"] {
        let mut status = task_status("m", "t", "c", "x", &AuthState::Pending(request()));
        status["message"]["metadata"][EXTENSION_URI][field] = json!("");
        assert!(
            matches!(read_status(&status), Err(Error::Invalid(_))),
            "{field}"
        );
    }
}

#[test]
fn unknown_fields_in_our_metadata_are_refused() {
    let mut message = continuation_message(
        "m",
        "t",
        "c",
        "x",
        &PresentationMeta {
            presentation: "a~~b~".into(),
            nonce: "n".into(),
        },
    );
    message["metadata"][EXTENSION_URI]["presentationOverride"] = json!("x");
    assert!(matches!(
        read_presentation(&message),
        Err(Error::Invalid(_))
    ));
}
