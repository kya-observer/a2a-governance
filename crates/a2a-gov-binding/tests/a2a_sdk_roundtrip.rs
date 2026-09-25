//! Shapes re-serialized by the official a2a-sdk (protobuf `Struct` turns every
//! number into a double) must read back to exactly what we wrote.
//! Vectors: `testdata/a2a/binding_roundtrip.json`, from `interop/a2a/roundtrip.py`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_binding::{read_hello, read_presentation, read_receipt, read_status};
use serde_json::Value;

fn load(dir: &str, file: &str) -> Value {
    let path = format!("{}/../../testdata/{dir}/{file}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn sdk_roundtripped_shapes_read_back_unchanged() {
    let original = load("rust", "binding.json");
    let tripped = load("a2a", "binding_roundtrip.json");
    for name in ["pending", "approved", "denied"] {
        let a = read_status(&original["task_status"][name])
            .unwrap()
            .unwrap();
        let b = read_status(&tripped["task_status"][name]).unwrap().unwrap();
        assert_eq!(a, b, "{name}");
    }
    assert_eq!(
        read_hello(&original["message"]["hello"]).unwrap(),
        read_hello(&tripped["message"]["hello"]).unwrap()
    );
    assert_eq!(
        read_presentation(&original["message"]["continuation"]).unwrap(),
        read_presentation(&tripped["message"]["continuation"]).unwrap()
    );
    assert_eq!(
        read_receipt(&original["artifact"]).unwrap(),
        read_receipt(&tripped["artifact"]).unwrap()
    );
}

#[test]
fn the_roundtrip_really_turned_integers_into_doubles() {
    // Guards the test above: if the SDK ever stops doing this, we want to know.
    let tripped = load("a2a", "binding_roundtrip.json");
    let exp = &tripped["task_status"]["pending"]["message"]["metadata"]
        [a2a_gov_extension::EXTENSION_URI]["mandateRequest"]["exp"];
    assert!(exp.is_f64(), "{exp}");
}
