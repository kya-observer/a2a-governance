//! Deny and Challenge: how a gateway or agent refuses or pauses a call before a
//! task exists.
//!
//! A2A v1.0 has no JSON-RPC code for authorization errors (§3.3.2) and reserves
//! `-32001..=-32099` for its own errors (§9.5). These codes sit outside the whole
//! JSON-RPC reserved block, so they can't collide with either. Clients should
//! switch on `ErrorInfo.domain` + `reason`; the number is a hint.

use serde_json::{Map, Value, json};

/// JSON-RPC code for a refused call.
pub const DENY_CODE: i64 = -31000;
/// JSON-RPC code for a call that may proceed after an out-of-band approval.
pub const CHALLENGE_CODE: i64 = -31001;

const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";
const HELP_TYPE: &str = "type.googleapis.com/google.rpc.Help";

/// Why a call was refused. Mirrors AP2's action-authorization errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Refused by policy; no mandate was involved.
    Denied,
    /// The mandate failed verification (signature, chain, key binding, expiry).
    InvalidCredential,
    /// The mandate is valid but doesn't approve this action.
    InvalidMandate,
    /// The verifier doesn't accept mandates for this action.
    MandatesNotSupported,
}

impl DenyReason {
    const ALL: [Self; 4] = [
        Self::Denied,
        Self::InvalidCredential,
        Self::InvalidMandate,
        Self::MandatesNotSupported,
    ];

    /// The `ErrorInfo.reason` value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Denied => "DENIED",
            Self::InvalidCredential => "INVALID_CREDENTIAL",
            Self::InvalidMandate => "INVALID_MANDATE",
            Self::MandatesNotSupported => "MANDATES_NOT_SUPPORTED",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Why a call is paused for approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeReason {
    /// A mandate was presented, but the verifier can't confirm its constraints
    /// cover the call, so the user is brought back into the loop (AP2
    /// `unresolved_constraint`).
    UnresolvedConstraint,
    /// No mandate was presented yet.
    ApprovalRequired,
}

impl ChallengeReason {
    const ALL: [Self; 2] = [Self::UnresolvedConstraint, Self::ApprovalRequired];

    /// The `ErrorInfo.reason` value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnresolvedConstraint => "UNRESOLVED_CONSTRAINT",
            Self::ApprovalRequired => "APPROVAL_REQUIRED",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// A challenge URL was not an absolute `https` URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("challenge URL must be an absolute https URL: {0:?}")]
pub struct InvalidUrl(String);

/// A governance refusal or pause, independent of the protocol binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    /// The call is refused.
    Deny {
        /// Machine-readable reason.
        reason: DenyReason,
        /// Human-readable message.
        message: String,
    },
    /// The call may proceed after approval at `url`.
    Challenge {
        /// Machine-readable reason.
        reason: ChallengeReason,
        /// Human-readable message.
        message: String,
        /// Correlates the approval with the retry.
        challenge_id: String,
        /// Where the approval happens, outside the client and its LLM.
        url: String,
    },
}

impl GovernanceError {
    /// A refusal.
    pub fn deny(reason: DenyReason, message: &str) -> Self {
        Self::Deny {
            reason,
            message: message.to_owned(),
        }
    }

    /// A pause for approval. `url` must be an absolute `https` URL.
    pub fn challenge(
        reason: ChallengeReason,
        message: &str,
        challenge_id: &str,
        url: &str,
    ) -> Result<Self, InvalidUrl> {
        if !is_https_url(url) {
            return Err(InvalidUrl(url.to_owned()));
        }
        Ok(Self::Challenge {
            reason,
            message: message.to_owned(),
            challenge_id: challenge_id.to_owned(),
            url: url.to_owned(),
        })
    }

    /// The JSON-RPC `error` object (A2A §9.5). `domain` identifies the issuer,
    /// such as the gateway or agent.
    pub fn to_json_rpc_error(&self, domain: &str) -> Value {
        match self {
            Self::Deny { reason, message } => json!({
                "code": DENY_CODE,
                "message": message,
                "data": [error_info(reason.as_str(), domain, None)],
            }),
            Self::Challenge {
                reason,
                message,
                challenge_id,
                url,
            } => json!({
                "code": CHALLENGE_CODE,
                "message": message,
                "data": [
                    error_info(reason.as_str(), domain, Some(challenge_id)),
                    { "@type": HELP_TYPE, "links": [{ "description": message, "url": url }] },
                ],
            }),
        }
    }

    /// HTTP+JSON binding status (A2A §3.3.2, authorization errors).
    pub fn http_status(&self) -> u16 {
        403
    }

    /// gRPC binding status (A2A §3.3.2, authorization errors).
    pub fn grpc_status(&self) -> &'static str {
        "PERMISSION_DENIED"
    }
}

fn error_info(reason: &str, domain: &str, challenge_id: Option<&str>) -> Value {
    let mut info = json!({ "@type": ERROR_INFO_TYPE, "reason": reason, "domain": domain });
    if let Some(id) = challenge_id {
        info["metadata"] = json!({ "challengeId": id });
    }
    info
}

fn is_https_url(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        !host.is_empty() && !url.chars().any(char::is_whitespace)
    })
}

/// Recognizes governance errors from one issuer domain on the client side.
#[derive(Debug, Clone)]
pub struct ErrorProfile {
    domain: String,
}

impl ErrorProfile {
    /// Accept errors whose `ErrorInfo.domain` equals `domain`.
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_owned(),
        }
    }

    /// Parses a JSON-RPC `error` object. Returns `None` for anything that isn't a
    /// well-formed governance error from this profile's domain.
    pub fn parse(&self, error: &Value) -> Option<GovernanceError> {
        let code = error.get("code")?.as_i64()?;
        let message = error.get("message")?.as_str()?;
        let details = error.get("data")?.as_array()?;
        let info = details.iter().find(|d| {
            d.get("@type").and_then(Value::as_str) == Some(ERROR_INFO_TYPE)
                && d.get("domain").and_then(Value::as_str) == Some(self.domain.as_str())
        })?;
        let reason = info.get("reason")?.as_str()?;

        match code {
            DENY_CODE => Some(GovernanceError::deny(DenyReason::parse(reason)?, message)),
            CHALLENGE_CODE => {
                let reason = ChallengeReason::parse(reason)?;
                let challenge_id = info
                    .get("metadata")
                    .and_then(Value::as_object)
                    .and_then(|m: &Map<String, Value>| m.get("challengeId"))?
                    .as_str()?;
                let url = details
                    .iter()
                    .filter(|d| d.get("@type").and_then(Value::as_str) == Some(HELP_TYPE))
                    .filter_map(|d| d.get("links")?.as_array()?.first()?.get("url")?.as_str())
                    .next()?;
                GovernanceError::challenge(reason, message, challenge_id, url).ok()
            }
            _ => None,
        }
    }
}
