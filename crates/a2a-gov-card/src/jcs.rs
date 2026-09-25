//! RFC 8785, the JSON Canonicalization Scheme: sorted properties (by UTF-16
//! code units), no whitespace, ECMAScript number and string serialization.

use std::fmt::Write as _;

use serde_json::Value;

use crate::Error;

/// Nesting limit, matching the official a2a-sdk's canonicalizer.
pub const MAX_DEPTH: usize = 128;

/// Largest integer a JSON number (an IEEE 754 double) represents exactly.
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// The canonical form of `value`.
pub fn canonicalize(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_value(&mut out, value, 0)?;
    Ok(out)
}

fn write_value(out: &mut String, value: &Value, depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Canonicalization(format!(
            "nesting deeper than {MAX_DEPTH}"
        )));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // Integers outside ±(2^53 - 1) would be rounded, so two different
            // integers could share one canonical form (and one signature).
            // Refused, as the official a2a-sdk does.
            #[allow(clippy::cast_precision_loss)]
            let f = if let Some(i) = n.as_i64() {
                if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
                    return Err(Error::Canonicalization(format!(
                        "integer {i} is not exactly representable"
                    )));
                }
                i as f64
            } else if n.is_u64() {
                return Err(Error::Canonicalization(format!(
                    "integer {n} is not exactly representable"
                )));
            } else {
                n.as_f64()
                    .ok_or_else(|| Error::Canonicalization("unrepresentable number".into()))?
            };
            out.push_str(&number(f)?);
        }
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, v, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number.prototype.toString` for a finite double (ECMA-262
/// §7.1.12.1), as RFC 8785 §3.2.2.3 requires.
pub fn number(x: f64) -> Result<String, Error> {
    if !x.is_finite() {
        return Err(Error::Canonicalization(
            "NaN and infinities have no JSON form".into(),
        ));
    }
    if x == 0.0 {
        return Ok("0".into());
    }
    // Rust's `{:e}` gives the shortest digit string that round-trips, which is
    // what ECMAScript requires; only the layout differs.
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exp: i32 = exp
        .parse()
        .map_err(|_| Error::Canonicalization("bad exponent".into()))?;
    let (digits, exp) = even_on_tie(x.abs(), digits, exp);
    let k = i32::try_from(digits.len())
        .map_err(|_| Error::Canonicalization("too many digits".into()))?;
    let n = exp + 1;

    let mut out = String::new();
    if x < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n(
            '0',
            usize::try_from(n - k).unwrap_or(0),
        ));
    } else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at(usize::try_from(n).unwrap_or(0));
        out.push_str(int);
        out.push('.');
        out.push_str(frac);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', usize::try_from(-n).unwrap_or(0)));
        out.push_str(&digits);
    } else {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let e = n - 1;
        let _ = write!(out, "e{}{}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    Ok(out)
}

/// ECMAScript breaks ties between two equally close shortest candidates toward
/// the even one (RFC 8785 Appendix B, note 4); Rust's shortest formatting may
/// pick the odd one. A tie means the double's exact decimal expansion
/// continues with exactly `5` after the candidate's last digit.
fn even_on_tie(x: f64, digits: String, exp: i32) -> (String, i32) {
    let exact = format!("{x:.1100e}");
    let Some((mantissa, exact_exp)) = exact.split_once('e') else {
        return (digits, exp);
    };
    if exact_exp.parse::<i32>().ok() != Some(exp) {
        return (digits, exp);
    }
    let exact_digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len();
    let Some(tail) = exact_digits.get(k..) else {
        return (digits, exp);
    };
    let is_tie = tail.starts_with('5') && tail[1..].bytes().all(|b| b == b'0');
    if !is_tie {
        return (digits, exp);
    }
    let truncated = &exact_digits[..k];
    let last_even = truncated
        .bytes()
        .last()
        .is_some_and(|b| (b - b'0').is_multiple_of(2));
    let (candidate, candidate_exp) = if last_even {
        (truncated.to_owned(), exp)
    } else {
        increment(truncated, exp)
    };
    let round_trips = format!("{}.{}e{candidate_exp}", &candidate[..1], &candidate[1..])
        .parse::<f64>()
        .is_ok_and(|v| v == x);
    if round_trips {
        (candidate, candidate_exp)
    } else {
        (digits, exp)
    }
}

/// Adds one unit in the last place to a decimal digit string.
fn increment(digits: &str, exp: i32) -> (String, i32) {
    let mut bytes = digits.as_bytes().to_vec();
    for b in bytes.iter_mut().rev() {
        if *b == b'9' {
            *b = b'0';
        } else {
            *b += 1;
            return (String::from_utf8(bytes).unwrap_or_default(), exp);
        }
    }
    let mut carried = String::from("1");
    carried.push_str(&"0".repeat(digits.len()));
    carried.truncate(digits.len());
    (carried, exp + 1)
}
