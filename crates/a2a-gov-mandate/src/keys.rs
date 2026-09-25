use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey as P256SigningKey};

use crate::PublicJwk;

/// A P-256 key that signs mandates (ES256).
#[derive(Clone)]
pub struct SigningKey {
    inner: P256SigningKey,
    kid: Option<String>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// A fresh key from the operating system's CSPRNG.
    pub fn generate() -> Self {
        loop {
            let mut scalar = [0u8; 32];
            if getrandom::fill(&mut scalar).is_err() {
                continue;
            }
            // Out-of-range scalars (probability ~2^-32) are simply redrawn.
            if let Ok(inner) = P256SigningKey::from_slice(&scalar) {
                return Self { inner, kid: None };
            }
        }
    }

    /// Sets the `kid` placed in headers this key signs.
    pub fn with_kid(mut self, kid: &str) -> Self {
        self.kid = Some(kid.to_owned());
        self
    }

    /// The key ID, if any.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The public half as a JWK.
    pub fn public_jwk(&self) -> PublicJwk {
        PublicJwk::from_verifying_key(self.inner.verifying_key())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig: Signature = self.inner.sign(message);
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
}
