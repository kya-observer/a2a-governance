//! The decision engine for the A2A Delegation Governance extension.
//!
//! Given a presentation (a mandate chain the agent built for this verifier's
//! nonce) and the concrete A2A call the verifier is about to serve, it decides:
//!
//! - **Pass**: the chain verifies, its closed mandate describes exactly this
//!   call, every hop's constraints cover it, nothing is revoked, and the use
//!   limits allow one more;
//! - **Deny**, with AP2's action-authorization reason;
//! - **Challenge**: no mandate yet, or a constraint this verifier doesn't know,
//!   so the user is asked directly.
//!
//! Storage is behind traits, so the engine is the same in memory, in SQLite or
//! behind a gateway. Any storage error means Deny.

mod constraints;
pub mod memory;

use std::sync::Arc;

pub use a2a_gov_extension::errors::{ChallengeReason, DenyReason};
use a2a_gov_mandate::{HopKind, PublicJwk, VerifiedChain, VerifyOptions, verify_chain};
use a2a_gov_receipt::{Outcome, Receipt};
use serde_json::{Map, Value};

use crate::constraints::{Evaluation, evaluate};

/// How much of the underlying data may be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Release {
    /// A derived answer, not the records it came from.
    AnswerOnly,
    /// The records themselves.
    Records,
}

impl Release {
    /// Parses the `access.release` value.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "answer-only" => Some(Self::AnswerOnly),
            "records" => Some(Self::Records),
            _ => None,
        }
    }
}

/// The concrete call the verifier is about to serve, as the verifier sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    /// A2A method, e.g. `SendMessage`.
    pub method: String,
    /// The task the call belongs to.
    pub task_id: String,
    /// What the call will access, as RFC 9396 authorization details.
    pub authorization_details: Vec<Value>,
    /// The purpose declared for the call, if any (W3C DPV term).
    pub purpose: Option<String>,
    /// What the call will release.
    pub release: Release,
}

/// The agent's presentation for this call.
#[derive(Debug, Clone, Copy)]
pub struct Presentation<'a> {
    /// The `~~`-joined mandate chain.
    pub chain: &'a str,
    /// This verifier's audience identifier.
    pub aud: &'a str,
    /// The nonce this verifier issued for the call.
    pub nonce: &'a str,
}

/// What a passing decision authorizes.
#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    /// ID of the open mandate the user approved.
    pub mandate_id: String,
    /// The purpose the data is released for.
    pub purpose: Option<String>,
    /// What may be released.
    pub release: Release,
}

/// The engine's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Serve the call.
    Pass(Grant),
    /// Refuse the call.
    Deny {
        /// Machine-readable reason.
        reason: DenyReason,
        /// Human-readable detail, safe to return to the caller.
        detail: String,
    },
    /// Ask the user.
    Challenge {
        /// Why.
        reason: ChallengeReason,
        /// Human-readable detail.
        detail: String,
    },
}

impl Decision {
    fn deny(reason: DenyReason, detail: impl Into<String>) -> Self {
        Self::Deny {
            reason,
            detail: detail.into(),
        }
    }

    /// The Mandate Receipt for this decision, or `None` when no chain was
    /// presented (there is nothing to refer to).
    pub fn receipt(&self, iss: &str, now: i64, chain: Option<&str>) -> Option<Receipt> {
        let chain = chain?;
        let (outcome, purpose) = match self {
            Self::Pass(grant) => (Outcome::Success, grant.purpose.as_deref()),
            Self::Deny { reason, detail } => (
                Outcome::Error {
                    code: reason.as_str().to_ascii_lowercase(),
                    description: detail.clone(),
                },
                None,
            ),
            Self::Challenge { reason, detail } => (
                Outcome::Error {
                    code: reason.as_str().to_ascii_lowercase(),
                    description: detail.clone(),
                },
                None,
            ),
        };
        let receipt = Receipt::for_chain(iss, now, outcome, chain).ok()?;
        Some(match purpose {
            Some(p) => receipt.with_purpose(p),
            None => receipt,
        })
    }
}

/// A storage failure. The engine turns it into a denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError(pub String);

/// Keys of the trusted surfaces whose open mandates this verifier accepts.
pub trait TrustedSurfaces: Send + Sync {
    /// The key for an open mandate with this JWS header, or `None` if untrusted.
    fn key_for(&self, header: &Map<String, Value>) -> Option<PublicJwk>;
}

/// Single-use nonces this verifier issued.
pub trait Nonces: Send + Sync {
    /// Consumes `nonce`. `Ok(false)` if it was never issued or already used.
    fn consume(&self, nonce: &str) -> Result<bool, BackendError>;
}

/// Revoked mandates, by hop ID.
pub trait Revocations: Send + Sync {
    /// Whether the mandate with this ID is revoked.
    fn is_revoked(&self, mandate_id: &str) -> Result<bool, BackendError>;
}

/// Use counts per mandate.
pub trait UseCounter: Send + Sync {
    /// If every `(mandate_id, limit)` has a use left, records one use of each and
    /// returns `true`; otherwise records nothing and returns `false`.
    fn try_consume(&self, limits: &[(String, u64)]) -> Result<bool, BackendError>;
}

/// The decision engine.
pub struct Engine {
    surfaces: Arc<dyn TrustedSurfaces>,
    nonces: Arc<dyn Nonces>,
    revocations: Arc<dyn Revocations>,
    uses: Arc<dyn UseCounter>,
    clock_skew: u32,
    max_closing_age: u32,
}

impl Engine {
    /// An engine over the given stores, with 60 s clock skew and closing hops at
    /// most 300 s old.
    pub fn new(
        surfaces: Arc<dyn TrustedSurfaces>,
        nonces: Arc<dyn Nonces>,
        revocations: Arc<dyn Revocations>,
        uses: Arc<dyn UseCounter>,
    ) -> Self {
        Self {
            surfaces,
            nonces,
            revocations,
            uses,
            clock_skew: 60,
            max_closing_age: 300,
        }
    }

    /// Decides whether to serve `call` given the agent's `presentation`.
    pub fn decide(
        &self,
        presentation: Option<Presentation<'_>>,
        call: &Call,
        now: i64,
    ) -> Decision {
        let Some(p) = presentation else {
            return Decision::Challenge {
                reason: ChallengeReason::ApprovalRequired,
                detail: "this call needs a mandate the user approves".into(),
            };
        };
        match self.decide_presented(p, call, now) {
            Ok(decision) => decision,
            Err(BackendError(_)) => Decision::deny(
                DenyReason::Denied,
                "the verifier could not complete the check",
            ),
        }
    }

    fn decide_presented(
        &self,
        p: Presentation<'_>,
        call: &Call,
        now: i64,
    ) -> Result<Decision, BackendError> {
        let opts = VerifyOptions::new(p.aud, p.nonce, now)
            .clock_skew(self.clock_skew)
            .max_closing_age(self.max_closing_age);
        let chain = match verify_chain(p.chain, |h| self.surfaces.key_for(h), &opts) {
            Ok(chain) => chain,
            Err(e) => return Ok(Decision::deny(DenyReason::InvalidCredential, e.to_string())),
        };

        for hop in authorizing_hops(&chain) {
            if self.revocations.is_revoked(hop.id())? {
                return Ok(Decision::deny(
                    DenyReason::InvalidMandate,
                    "the mandate was revoked",
                ));
            }
        }

        if let Some(mismatch) = describes_call(chain.closed(), call) {
            return Ok(Decision::deny(
                DenyReason::InvalidMandate,
                format!("the closed mandate does not describe this call: {mismatch}"),
            ));
        }

        let (purpose, limits) = match evaluate(&chain, call) {
            Evaluation::Covered { purpose, limits } => (purpose, limits),
            Evaluation::Refused(detail) => {
                return Ok(Decision::deny(DenyReason::InvalidMandate, detail));
            }
            Evaluation::Unresolved(detail) => {
                return Ok(Decision::Challenge {
                    reason: ChallengeReason::UnresolvedConstraint,
                    detail,
                });
            }
        };

        if !self.nonces.consume(p.nonce)? {
            return Ok(Decision::deny(
                DenyReason::InvalidCredential,
                "nonce unknown or already used",
            ));
        }
        if !self.uses.try_consume(&limits)? {
            return Ok(Decision::deny(
                DenyReason::InvalidMandate,
                "the mandate's uses are spent",
            ));
        }

        Ok(Decision::Pass(Grant {
            mandate_id: chain.hops()[0].id().to_owned(),
            purpose,
            release: call.release,
        }))
    }
}

/// The hops whose authority the call relies on: the open mandate and every delegation.
fn authorizing_hops(chain: &VerifiedChain) -> impl Iterator<Item = &a2a_gov_mandate::VerifiedHop> {
    chain.hops().iter().filter(|h| h.kind() != HopKind::Closing)
}

fn describes_call(closed: &Map<String, Value>, call: &Call) -> Option<&'static str> {
    if closed.get("method").and_then(Value::as_str) != Some(call.method.as_str()) {
        return Some("method");
    }
    if closed.get("task_id").and_then(Value::as_str) != Some(call.task_id.as_str()) {
        return Some("task_id");
    }
    match closed.get("authorization_details") {
        Some(Value::Array(details)) if *details == call.authorization_details => None,
        _ => Some("authorization_details"),
    }
}
