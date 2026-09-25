//! The Rust canonicalizer must produce byte-identical output to the official
//! a2a-sdk's RFC 8785 implementation on seeded random input: 20,000 random
//! doubles (every magnitude, subnormals, ties) and 2,000 random documents.
//! Vectors: `testdata/a2a/jcs.json`, from `interop/a2a/gen_jcs_vectors.py`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_card::jcs::{canonicalize, number};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/a2a/jcs.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_double_serializes_like_the_a2a_sdk() {
    let v = vectors();
    let numbers = v["numbers"].as_array().unwrap();
    assert!(numbers.len() >= 20_000);
    let mismatches: Vec<String> = numbers
        .iter()
        .filter_map(|n| {
            let bits = n["bits"].as_u64().unwrap();
            let ours = number(f64::from_bits(bits)).unwrap();
            let theirs = n["jcs"].as_str().unwrap();
            (ours != theirs).then(|| format!("{bits:016x}: ours {ours}, a2a-sdk {theirs}"))
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{} mismatches, e.g. {:?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(5)]
    );
}

#[test]
fn every_document_canonicalizes_like_the_a2a_sdk() {
    let v = vectors();
    let documents = v["documents"].as_array().unwrap();
    assert!(documents.len() >= 2_000);
    for d in documents {
        let input: Value = serde_json::from_str(d["json"].as_str().unwrap()).unwrap();
        assert_eq!(
            canonicalize(&input).unwrap(),
            d["jcs"].as_str().unwrap(),
            "{}",
            d["json"]
        );
    }
}
