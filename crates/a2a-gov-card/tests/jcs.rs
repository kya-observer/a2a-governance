//! RFC 8785 (JSON Canonicalization Scheme), using the RFC's own test data.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use a2a_gov_card::jcs::{canonicalize, number};
use serde_json::{Value, json};

/// RFC 8785's examples, stored verbatim (with their `\u` escapes) in testdata.
fn rfc_example(name: &str) -> Value {
    let path = format!(
        "{}/../../testdata/rfc8785/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn numbers_match_rfc_8785_appendix_b() {
    for (bits, expected) in [
        (0x0000000000000000u64, "0"),
        (0x8000000000000000, "0"),
        (0x0000000000000001, "5e-324"),
        (0x8000000000000001, "-5e-324"),
        (0x7fefffffffffffff, "1.7976931348623157e+308"),
        (0xffefffffffffffff, "-1.7976931348623157e+308"),
        (0x4340000000000000, "9007199254740992"),
        (0xc340000000000000, "-9007199254740992"),
        (0x4430000000000000, "295147905179352830000"),
        (0x44b52d02c7e14af5, "9.999999999999997e+22"),
        (0x44b52d02c7e14af6, "1e+23"),
        (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
        (0x444b1ae4d6e2ef4e, "999999999999999700000"),
        (0x444b1ae4d6e2ef4f, "999999999999999900000"),
        (0x444b1ae4d6e2ef50, "1e+21"),
        (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
        (0x3eb0c6f7a0b5ed8d, "0.000001"),
        (0x41b3de4355555553, "333333333.3333332"),
        (0x41b3de4355555554, "333333333.33333325"),
        (0x41b3de4355555555, "333333333.3333333"),
        (0x41b3de4355555556, "333333333.3333334"),
        (0x41b3de4355555557, "333333333.33333343"),
        (0xbecbf647612f3696, "-0.0000033333333333333333"),
        (0x43143ff3c1cb0959, "1424953923781206.2"),
    ] {
        assert_eq!(
            number(f64::from_bits(bits)).unwrap(),
            expected,
            "{bits:016x}"
        );
    }
}

#[test]
fn non_finite_numbers_are_refused() {
    // RFC 8785 §3.2.2.3.
    assert!(number(f64::NAN).is_err());
    assert!(number(f64::INFINITY).is_err());
}

#[test]
fn the_section_3_2_2_example_serializes_exactly() {
    let input = rfc_example("section-3.2.2.json");
    // §3.2.4 gives the exact UTF-8 bytes.
    let expected: Vec<u8> = "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72 \
         75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a \
         5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31 \
         65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37 \
         5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30 \
         30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d"
        .split_whitespace()
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();
    assert_eq!(canonicalize(&input).unwrap().into_bytes(), expected);
}

#[test]
fn properties_sort_by_utf16_code_units() {
    // RFC 8785 §3.2.3: sorting by UTF-8 bytes would put the emoji after U+FB33.
    let input = rfc_example("section-3.2.3.json");
    let out: Value = serde_json::from_str(&canonicalize(&input).unwrap()).unwrap();
    let order: Vec<&str> = out
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        order,
        [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ]
    );
}

#[test]
fn nesting_whitespace_and_array_order() {
    let input = json!({ "b": [3, { "z": 1, "a": [true, null] }], "a": "x" });
    assert_eq!(
        canonicalize(&input).unwrap(),
        r#"{"a":"x","b":[3,{"a":[true,null],"z":1}]}"#
    );
}

#[test]
fn control_characters_use_short_or_lowercase_unicode_escapes() {
    let input = json!("\u{8}\t\n\u{c}\r\u{1}\u{1f}\u{7f}");
    assert_eq!(
        canonicalize(&input).unwrap(),
        "\"\\b\\t\\n\\f\\r\\u0001\\u001f\u{7f}\""
    );
}

#[test]
fn deep_nesting_is_refused() {
    let mut v = json!(1);
    for _ in 0..200 {
        v = json!([v]);
    }
    assert!(canonicalize(&v).is_err());
}

#[test]
fn integers_outside_the_exact_range_are_refused() {
    // Otherwise 9007199254740993 and 9007199254740992 would canonicalize alike.
    assert_eq!(
        canonicalize(&json!(9_007_199_254_740_991_i64)).unwrap(),
        "9007199254740991"
    );
    assert_eq!(
        canonicalize(&json!(-9_007_199_254_740_991_i64)).unwrap(),
        "-9007199254740991"
    );
    for big in [
        json!(9_007_199_254_740_992_i64),
        json!(-9_007_199_254_740_992_i64),
        json!(u64::MAX),
    ] {
        assert!(canonicalize(&big).is_err(), "{big}");
    }
}
