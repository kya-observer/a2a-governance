//! Mandates and receipts for the A2A Delegation Governance extension,
//! wire-compatible with the Agent Authorization model of AP2 v0.2.
//!
//! A mandate chain starts with an **open mandate**, an SD-JWT signed by a
//! trusted surface after the user approves it, whose `cnf` names the agent's
//! key. Each following hop is a KB-SD-JWT signed by the key the previous hop
//! named: a **delegation** (it names the next key) or the final **closing**
//! hop that binds the chain to one concrete call for one verifier.
//!
//! References: RFC 9901 (SD-JWT), RFC 7515 (JWS), RFC 7517 and RFC 7800 (JWK,
//! `cnf`), draft-gco-oauth-delegate-sd-jwt, AP2 v0.2 `agent_authorization.md`.
//! `docs/wire-format.md` lists where this crate is stricter than AP2.

mod b64;
mod chain;
mod error;
mod issue;
mod jwk;
mod jws;
mod keys;
pub mod sdjwt;

#[cfg(test)]
mod forged_tests;

pub use chain::{
    HopKind, MAX_CHAIN_BYTES, MAX_HOPS, VerifiedChain, VerifiedHop, VerifyOptions, verify_chain,
};
pub use error::Error;
pub use issue::{issue_open, join, present};
pub use jwk::PublicJwk;
pub use keys::SigningKey;
pub use sdjwt::Disclosable;
