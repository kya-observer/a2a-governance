/// Why a mandate chain was rejected.
///
/// Every variant is a verification failure in AP2's terms
/// (`invalid_credential`): the chain can't be trusted, whatever it says.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input isn't a well-formed token or chain.
    #[error("malformed: {0}")]
    Malformed(String),
    /// A JWS header named an algorithm other than ES256.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// A key was missing, malformed or not a P-256 public key.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// The key resolver doesn't know the root's issuer.
    #[error("unknown issuer")]
    UnknownIssuer,
    /// A signature didn't verify.
    #[error("bad signature")]
    BadSignature,
    /// A disclosure was malformed, unreferenced, or referenced twice.
    #[error("disclosure: {0}")]
    Disclosure(String),
    /// A hop's `sd_hash` or `issuer_jwt_hash` doesn't match the previous hop.
    #[error("binding: {0}")]
    Binding(String),
    /// The chain's shape is wrong (hop types, `cnf` placement, mandate type, length).
    #[error("chain: {0}")]
    Chain(String),
    /// A mandate has expired.
    #[error("expired")]
    Expired,
    /// A token's `iat` or `nbf` is in the future.
    #[error("not yet valid")]
    NotYetValid,
    /// The closing hop is older than the verifier accepts.
    #[error("closing hop too old")]
    Stale,
    /// The closing hop names another audience.
    #[error("audience mismatch")]
    Audience,
    /// The closing hop carries another nonce.
    #[error("nonce mismatch")]
    Nonce,
}

impl Error {
    /// The AP2 action-authorization error code for this failure.
    pub fn ap2_code(&self) -> &'static str {
        "invalid_credential"
    }
}
