use p256::ecdsa::VerifyingKey;
use serde_json::{Value, json};

use crate::{Error, b64};

/// A P-256 public key in JWK form (RFC 7517 §6.2), as carried in `cnf.jwk`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicJwk {
    x: [u8; 32],
    y: [u8; 32],
}

impl PublicJwk {
    /// Parses and validates a public JWK. Rejects other curves and any JWK that
    /// carries private key material (`d`).
    pub fn from_value(v: &Value) -> Result<Self, Error> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::InvalidKey("JWK is not an object".into()))?;
        if obj.get("kty").and_then(Value::as_str) != Some("EC") {
            return Err(Error::InvalidKey("kty must be EC".into()));
        }
        if obj.get("crv").and_then(Value::as_str) != Some("P-256") {
            return Err(Error::InvalidKey("crv must be P-256".into()));
        }
        if obj.contains_key("d") {
            return Err(Error::InvalidKey("JWK contains a private key".into()));
        }
        let coord = |name: &str| -> Result<[u8; 32], Error> {
            let s = obj
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| Error::InvalidKey(format!("missing {name}")))?;
            b64::decode(s)?
                .try_into()
                .map_err(|_| Error::InvalidKey(format!("{name} must be 32 bytes")))
        };
        let jwk = Self {
            x: coord("x")?,
            y: coord("y")?,
        };
        jwk.verifying_key()?;
        Ok(jwk)
    }

    /// The JWK as JSON.
    pub fn to_value(&self) -> Value {
        json!({ "kty": "EC", "crv": "P-256", "x": b64::encode(self.x), "y": b64::encode(self.y) })
    }

    pub(crate) fn from_verifying_key(key: &VerifyingKey) -> Self {
        let point = key.to_sec1_point(false);
        let bytes = point.as_bytes();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        Self { x, y }
    }

    /// Fails if the coordinates aren't a point on the curve.
    pub(crate) fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&self.x);
        sec1[33..].copy_from_slice(&self.y);
        VerifyingKey::from_sec1_bytes(&sec1)
            .map_err(|_| Error::InvalidKey("not a point on P-256".into()))
    }
}
