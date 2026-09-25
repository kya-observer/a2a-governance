//! A hash-chained, append-only receipt log. Each entry's hash covers its
//! sequence number, the previous entry's hash and the receipt, so editing,
//! deleting or reordering any entry breaks verification from that point on.
//! Dropping entries from the end is only detectable against a head someone
//! kept, which is why receipts can carry `prev`.

use sha2::{Digest, Sha256};

use crate::b64;

/// One log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Position, from 0.
    pub seq: u64,
    /// Hash of the previous entry; empty for the first.
    pub prev: String,
    /// This entry's hash.
    pub hash: String,
    /// The signed receipt (compact JWS).
    pub receipt: String,
}

/// Where verification failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// An entry is out of sequence (deleted, inserted or reordered).
    #[error("entry {seq}: out of sequence")]
    Sequence {
        /// Expected position.
        seq: u64,
    },
    /// An entry doesn't point at the previous entry's hash.
    #[error("entry {seq}: prev does not match the previous hash")]
    PrevMismatch {
        /// Position of the entry.
        seq: u64,
    },
    /// An entry's content doesn't match its hash.
    #[error("entry {seq}: content does not match its hash")]
    HashMismatch {
        /// Position of the entry.
        seq: u64,
    },
}

/// The hash of one entry.
pub fn entry_hash(seq: u64, prev: &str, receipt: &str) -> String {
    b64(&Sha256::digest(
        format!("{seq}:{prev}:{receipt}").as_bytes(),
    ))
}

/// An in-memory log. Stores persist [`Entry`] rows and check them with [`verify`].
#[derive(Debug, Default, Clone)]
pub struct Log {
    entries: Vec<Entry>,
}

impl Log {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a receipt and returns its entry.
    pub fn append(&mut self, receipt: String) -> &Entry {
        let seq = self.entries.len() as u64;
        let prev = self.head().to_owned();
        let hash = entry_hash(seq, &prev, &receipt);
        self.entries.push(Entry {
            seq,
            prev,
            hash,
            receipt,
        });
        &self.entries[self.entries.len() - 1]
    }

    /// All entries, oldest first.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The latest hash; empty for an empty log.
    pub fn head(&self) -> &str {
        self.entries.last().map_or("", |e| e.hash.as_str())
    }
}

/// Verifies a full log from its first entry and returns its head.
pub fn verify(entries: &[Entry]) -> Result<String, LogError> {
    let mut prev = String::new();
    for (i, e) in entries.iter().enumerate() {
        let seq = i as u64;
        if e.seq != seq {
            return Err(LogError::Sequence { seq });
        }
        if e.prev != prev {
            return Err(LogError::PrevMismatch { seq });
        }
        if e.hash != entry_hash(e.seq, &e.prev, &e.receipt) {
            return Err(LogError::HashMismatch { seq });
        }
        prev.clone_from(&e.hash);
    }
    Ok(prev)
}
