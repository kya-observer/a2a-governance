//! A tamper-evident receipt log: each entry commits to the previous one.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_receipt::log::{Log, LogError, verify};

fn log_of(n: usize) -> Log {
    let mut log = Log::new();
    for i in 0..n {
        log.append(format!("receipt-{i}"));
    }
    log
}

#[test]
fn an_intact_log_verifies() {
    let log = log_of(5);
    assert_eq!(verify(log.entries()), Ok(log.head().to_owned()));
}

#[test]
fn an_empty_log_verifies() {
    assert!(verify(Log::new().entries()).is_ok());
}

#[test]
fn an_edited_entry_is_detected_at_its_position() {
    let mut entries = log_of(5).entries().to_vec();
    entries[2].receipt = "forged".into();
    assert_eq!(verify(&entries), Err(LogError::HashMismatch { seq: 2 }));
}

#[test]
fn a_deleted_entry_is_detected() {
    let mut entries = log_of(5).entries().to_vec();
    entries.remove(2);
    assert!(matches!(
        verify(&entries),
        Err(LogError::Sequence { seq: 2 } | LogError::PrevMismatch { seq: 2 })
    ));
}

#[test]
fn reordered_entries_are_detected() {
    let mut entries = log_of(5).entries().to_vec();
    entries.swap(1, 3);
    assert!(verify(&entries).is_err());
}

#[test]
fn truncating_the_end_is_detected_against_a_known_head() {
    // A suffix can always be dropped silently; holders of a later head (e.g. from a
    // receipt) catch it.
    let full = log_of(5);
    let truncated = &full.entries()[..3];
    let head = verify(truncated).unwrap();
    assert_ne!(head, full.head());
}

#[test]
fn a_rehashed_forgery_still_breaks_the_next_link() {
    let mut entries = log_of(5).entries().to_vec();
    entries[2].receipt = "forged".into();
    entries[2].hash = a2a_gov_receipt::log::entry_hash(2, &entries[2].prev, "forged");
    assert_eq!(verify(&entries), Err(LogError::PrevMismatch { seq: 3 }));
}

#[test]
fn a_renumbered_last_entry_is_detected() {
    // Rehashing makes prev and hash consistent; only the sequence check catches it.
    let mut entries = log_of(4).entries().to_vec();
    let last = entries.last_mut().unwrap();
    last.seq = 9;
    last.hash = a2a_gov_receipt::log::entry_hash(9, &last.prev, &last.receipt);
    assert_eq!(verify(&entries), Err(LogError::Sequence { seq: 3 }));
}

#[test]
fn an_entry_hash_commits_to_its_position() {
    // So a head also commits to how long the log is.
    use a2a_gov_receipt::log::entry_hash;
    assert_ne!(entry_hash(0, "", "r"), entry_hash(1, "", "r"));
}
