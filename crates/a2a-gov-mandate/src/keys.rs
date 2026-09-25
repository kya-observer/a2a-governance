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

    /// Restores a key from a private P-256 JWK (`kty`, `crv`, `d`, `x`, `y`,
    /// optional `kid`). The public coordinates must match `d`.
    pub fn from_private_jwk(jwk: &serde_json::Value) -> Result<Self, crate::Error> {
        let bad = |why: &str| crate::Error::InvalidKey(why.to_owned());
        let d = jwk
            .get("d")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| bad("missing d"))?;
        let scalar = crate::b64::decode(d)?;
        let inner =
            P256SigningKey::from_slice(&scalar).map_err(|_| bad("d is not a P-256 scalar"))?;
        let mut public = jwk.clone();
        if let Some(obj) = public.as_object_mut() {
            obj.remove("d");
        }
        let key = Self {
            inner,
            kid: jwk
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        };
        if PublicJwk::from_value(&public)? != key.public_jwk() {
            return Err(bad("x and y don't match d"));
        }
        Ok(key)
    }

    /// The key as a private JWK, for storage. Treat the result as a secret.
    pub fn to_private_jwk(&self) -> serde_json::Value {
        let mut jwk = self.public_jwk().to_value();
        jwk["d"] = serde_json::Value::String(crate::b64::encode(self.inner.to_bytes()));
        if let Some(kid) = &self.kid {
            jwk["kid"] = serde_json::Value::String(kid.clone());
        }
        jwk
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
