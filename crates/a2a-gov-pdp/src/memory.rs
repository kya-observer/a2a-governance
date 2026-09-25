//! In-memory stores, for tests, examples and single-process verifiers.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use a2a_gov_mandate::PublicJwk;
use base64::Engine as _;
use serde_json::{Map, Value};

use crate::{BackendError, Nonces, Revocations, TrustedSurfaces, UseCounter};

fn poisoned() -> BackendError {
    BackendError("lock poisoned".into())
}

/// Trusted-surface keys, either one key or keyed by `kid`.
#[derive(Debug, Clone)]
pub struct StaticSurfaces {
    single: Option<PublicJwk>,
    by_kid: HashMap<String, PublicJwk>,
}

impl StaticSurfaces {
    /// Trust exactly one key, whatever the header says.
    pub fn single(key: PublicJwk) -> Self {
        Self {
            single: Some(key),
            by_kid: HashMap::new(),
        }
    }

    /// Trust keys by the open mandate's `kid`.
    pub fn by_kid(keys: HashMap<String, PublicJwk>) -> Self {
        Self {
            single: None,
            by_kid: keys,
        }
    }
}

impl TrustedSurfaces for StaticSurfaces {
    fn key_for(&self, header: &Map<String, Value>) -> Option<PublicJwk> {
        if let Some(key) = &self.single {
            return Some(key.clone());
        }
        let kid = header.get("kid").and_then(Value::as_str)?;
        self.by_kid.get(kid).cloned()
    }
}

/// Issued, unused nonces.
#[derive(Debug, Default)]
pub struct MemoryNonces {
    issued: Mutex<HashSet<String>>,
}

impl MemoryNonces {
    /// Issues a fresh 128-bit nonce.
    ///
    /// # Panics
    /// If the OS random source fails; a verifier can't operate without one.
    #[allow(clippy::expect_used)]
    pub fn issue(&self) -> String {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS randomness");
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        if let Ok(mut issued) = self.issued.lock() {
            issued.insert(nonce.clone());
        }
        nonce
    }
}

impl Nonces for MemoryNonces {
    fn consume(&self, nonce: &str) -> Result<bool, BackendError> {
        Ok(self.issued.lock().map_err(|_| poisoned())?.remove(nonce))
    }
}

/// Revoked mandate IDs.
#[derive(Debug, Default)]
pub struct MemoryRevocations {
    revoked: Mutex<HashSet<String>>,
}

impl MemoryRevocations {
    /// Revokes a mandate by ID.
    pub fn revoke(&self, mandate_id: &str) {
        if let Ok(mut revoked) = self.revoked.lock() {
            revoked.insert(mandate_id.to_owned());
        }
    }
}

impl Revocations for MemoryRevocations {
    fn is_revoked(&self, mandate_id: &str) -> Result<bool, BackendError> {
        Ok(self
            .revoked
            .lock()
            .map_err(|_| poisoned())?
            .contains(mandate_id))
    }
}

/// Use counts per mandate ID.
#[derive(Debug, Default)]
pub struct MemoryUses {
    counts: Mutex<HashMap<String, u64>>,
}

impl MemoryUses {
    /// Uses recorded so far.
    pub fn count(&self, mandate_id: &str) -> u64 {
        self.counts
            .lock()
            .map(|c| c.get(mandate_id).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

impl UseCounter for MemoryUses {
    fn try_consume(&self, limits: &[(String, u64)]) -> Result<bool, BackendError> {
        let mut counts = self.counts.lock().map_err(|_| poisoned())?;
        if limits
            .iter()
            .any(|(id, limit)| counts.get(id).copied().unwrap_or(0) >= *limit)
        {
            return Ok(false);
        }
        for (id, _) in limits {
            *counts.entry(id.clone()).or_insert(0) += 1;
        }
        Ok(true)
    }
}
