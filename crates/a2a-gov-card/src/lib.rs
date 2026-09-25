//! Signed A2A Agent Cards (A2A v1.0 §8.4).

pub mod jcs;

/// Why a card couldn't be canonicalized, signed or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The card has no RFC 8785 canonical form.
    #[error("canonicalization: {0}")]
    Canonicalization(String),
}
