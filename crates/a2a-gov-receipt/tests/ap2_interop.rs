//! Receipts signed by Google's AP2 SDK verify here.
//! Vectors: `testdata/ap2/receipts.json`, from `interop/ap2/gen_ap2_receipts.py`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_mandate::PublicJwk;
use a2a_gov_receipt::{Outcome, Receipt};
use serde_json::Value;

#[test]
fn ap2_checkout_receipts_verify() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/ap2/receipts.json"
    );
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let key = PublicJwk::from_value(&v["verifier_jwk"]).unwrap();
        let receipt = Receipt::verify(v["receipt"].as_str().unwrap(), &key).unwrap();
        assert_eq!(receipt.outcome(), &Outcome::Success);
        assert_eq!(
            receipt.reference(),
            v["expected"]["reference"].as_str().unwrap()
        );
    }
}
