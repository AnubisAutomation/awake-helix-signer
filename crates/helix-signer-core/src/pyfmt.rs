//! Python-compatible formatting, so messages and amounts read exactly as the
//! Python signer printed them: ``repr()`` of JSON values in messages and the
//! ``decimal`` module's 28-digit arithmetic behind every amount.

use serde_json::Value;

/// Python truthiness of a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|n| n != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// ``str(value)`` of a parsed JSON value.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => py_repr(other),
    }
}

/// ``repr(value)`` of a parsed JSON value.
pub fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                int.to_string()
            } else if let Some(int) = number.as_u64() {
                int.to_string()
            } else {
                float_repr(number.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(text) => str_repr(text),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Object(map) => {
            let inner: Vec<String> = map.iter().map(|(key, item)| format!("{}: {}", str_repr(key), py_repr(item))).collect();
            format!("{{{}}}", inner.join(", "))
        }
    }
}

/// ``repr(text)`` of a Python string.
pub fn str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (0x7f..0xa0).contains(&(c as u32)) => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// ``repr(float)``: shortest round-trip digits, scientific below 1e-4 or from 1e16.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let scientific = format!("{:e}", value);
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(|ch| ch.is_ascii_digit()).collect();
    let sign = if negative { "-" } else { "" };
    if !(-4..16).contains(&exponent) {
        let mut text = String::from(sign);
        text.push_str(&digits[..1]);
        if digits.len() > 1 {
            text.push('.');
            text.push_str(&digits[1..]);
        }
        text.push_str(&format!("e{}{:02}", if exponent < 0 { '-' } else { '+' }, exponent.abs()));
        return text;
    }
    let point = exponent + 1; // digits before the decimal point
    let mut text = String::from(sign);
    if point <= 0 {
        text.push_str("0.");
        text.push_str(&"0".repeat((-point) as usize));
        text.push_str(&digits);
    } else if point as usize >= digits.len() {
        text.push_str(&digits);
        text.push_str(&"0".repeat(point as usize - digits.len()));
        text.push_str(".0");
    } else {
        text.push_str(&digits[..point as usize]);
        text.push('.');
        text.push_str(&digits[point as usize..]);
    }
    text
}

/// Default ``decimal`` context precision.
pub const PRECISION: usize = 28;

/// A finite Python ``Decimal``: ``(-1)**negative * coefficient * 10**exponent``.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decimal {
    /// Sign.
    pub negative: bool,
    /// Decimal digits without leading zeros ("0" for zero).
    pub coefficient: String,
    /// Power of ten.
    pub exponent: i64,
}

/// A parsed ``Decimal(text)``.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// A finite number.
    Finite(Decimal),
    /// ``Infinity``, ``NaN`` or ``sNaN`` (not finite).
    Special,
}

fn strip_zeros(digits: &str) -> String {
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    }
}

/// ``Decimal(text)`` as CPython's ``_decimal`` parses it: surrounding
/// whitespace is ignored and underscores are dropped anywhere.
pub fn parse_decimal(text: &str) -> Option<Parsed> {
    let cleaned: String = text.trim().chars().filter(|ch| *ch != '_').collect();
    let mut rest = cleaned.as_str();
    let mut negative = false;
    if let Some(stripped) = rest.strip_prefix('-') {
        negative = true;
        rest = stripped;
    } else if let Some(stripped) = rest.strip_prefix('+') {
        rest = stripped;
    }
    let lower = rest.to_ascii_lowercase();
    if lower == "inf" || lower == "infinity" {
        return Some(Parsed::Special);
    }
    let nan = lower.strip_prefix('s').unwrap_or(&lower);
    if let Some(diagnostic) = nan.strip_prefix("nan") {
        return diagnostic.chars().all(|ch| ch.is_ascii_digit()).then_some(Parsed::Special);
    }
    let (mantissa, exponent) = match lower.find('e') {
        Some(index) => (&lower[..index], Some(&lower[index + 1..])),
        None => (lower.as_str(), None),
    };
    let (int_part, frac_part) = match mantissa.find('.') {
        Some(index) => (&mantissa[..index], &mantissa[index + 1..]),
        None => (mantissa, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.chars().all(|ch| ch.is_ascii_digit()) || !frac_part.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let mut exp: i64 = 0;
    if let Some(text) = exponent {
        let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
        if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        // Exponents beyond any context limit are treated as unparsable here.
        let value: i64 = digits.parse().ok()?;
        exp = if text.starts_with('-') { -value } else { value };
    }
    let coefficient = strip_zeros(&format!("{int_part}{frac_part}"));
    Some(Parsed::Finite(Decimal { negative, coefficient, exponent: exp.checked_sub(frac_part.len() as i64)? }))
}

/// Round a digit string to ``precision`` significant digits (ROUND_HALF_EVEN).
///
/// Returns the rounded digits and how much the exponent grows.
pub fn round_half_even(digits: &str, precision: usize) -> (String, i64) {
    if digits.len() <= precision {
        return (digits.to_string(), 0);
    }
    let dropped = digits.len() - precision;
    let (keep, rest) = digits.split_at(precision);
    let first = rest.as_bytes()[0];
    let tail_nonzero = rest.as_bytes()[1..].iter().any(|byte| *byte != b'0');
    let last_odd = (keep.as_bytes()[precision - 1] - b'0') % 2 == 1;
    let round_up = first > b'5' || (first == b'5' && (tail_nonzero || last_odd));
    let mut kept: Vec<u8> = keep.as_bytes().to_vec();
    let mut grow = dropped as i64;
    if round_up {
        let mut index = kept.len();
        loop {
            if index == 0 {
                kept.insert(0, b'1');
                break;
            }
            index -= 1;
            if kept[index] == b'9' {
                kept[index] = b'0';
            } else {
                kept[index] += 1;
                break;
            }
        }
        if kept.len() > precision {
            kept.pop();
            grow += 1;
        }
    }
    (String::from_utf8(kept).unwrap_or_default(), grow)
}

impl Decimal {
    /// Round to the context precision (what every arithmetic result goes through).
    pub fn fix(&self) -> Decimal {
        let (coefficient, grow) = round_half_even(&self.coefficient, PRECISION);
        Decimal { negative: self.negative, coefficient: strip_zeros(&coefficient), exponent: self.exponent + grow }
    }

    /// Whether the value is zero.
    pub fn is_zero(&self) -> bool {
        self.coefficient == "0"
    }

    /// ``self.scaleb(places)`` in the default context.
    pub fn scaleb(&self, places: i64) -> Decimal {
        Decimal { negative: self.negative, coefficient: self.coefficient.clone(), exponent: self.exponent + places }.fix()
    }

    /// Whether ``self == self.to_integral_value()``.
    pub fn is_integral(&self) -> bool {
        if self.exponent >= 0 || self.is_zero() {
            return true;
        }
        let drop = (-self.exponent) as usize;
        if drop >= self.coefficient.len() {
            return false;
        }
        self.coefficient.as_bytes()[self.coefficient.len() - drop..].iter().all(|byte| *byte == b'0')
    }

    /// ``int(self)`` (truncation) as a digit string without sign.
    pub fn integer_digits(&self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        if self.exponent >= 0 {
            return strip_zeros(&format!("{}{}", self.coefficient, "0".repeat(self.exponent as usize)));
        }
        let drop = (-self.exponent) as usize;
        if drop >= self.coefficient.len() {
            return "0".into();
        }
        strip_zeros(&self.coefficient[..self.coefficient.len() - drop])
    }

    /// ``format(self.normalize(), "f")``.
    pub fn normalized_plain(&self) -> String {
        let fixed = self.fix();
        if fixed.is_zero() {
            return "0".into();
        }
        let trimmed = fixed.coefficient.trim_end_matches('0');
        let exponent = fixed.exponent + (fixed.coefficient.len() - trimmed.len()) as i64;
        let sign = if fixed.negative { "-" } else { "" };
        if exponent >= 0 {
            return format!("{sign}{trimmed}{}", "0".repeat(exponent as usize));
        }
        let point = trimmed.len() as i64 + exponent;
        if point > 0 {
            let (int_part, frac) = trimmed.split_at(point as usize);
            format!("{sign}{int_part}.{frac}")
        } else {
            format!("{sign}0.{}{trimmed}", "0".repeat((-point) as usize))
        }
    }
}

/// ``format((Decimal(digits) / Decimal(10) ** shift).normalize(), "f")`` for a
/// non-negative integer given as decimal digits (``shift`` may be negative).
pub fn shifted_plain(digits: &str, shift: i64) -> String {
    Decimal { negative: false, coefficient: strip_zeros(digits), exponent: -shift }.normalized_plain()
}

/// Compare two non-negative integers given as digit strings.
pub fn cmp_digits(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr(&json!("revoke")), "'revoke'");
        assert_eq!(py_repr(&json!(null)), "None");
        assert_eq!(py_repr(&json!(true)), "True");
        assert_eq!(py_repr(&json!(1)), "1");
        assert_eq!(py_repr(&json!("it's")), "\"it's\"");
        assert_eq!(py_repr(&json!({"a": [1, "b"]})), "{'a': [1, 'b']}");
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1e15), "1000000000000000.0");
        assert_eq!(float_repr(1.5e-5), "1.5e-05");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(-0.0), "-0.0");
        assert_eq!(float_repr(6714.0), "6714.0");
        assert_eq!(float_repr(123456789012345678901234567890.0), "1.2345678901234568e+29");
    }

    #[test]
    fn decimal_parsing_matches_cpython() {
        let finite = |text: &str| match parse_decimal(text) {
            Some(Parsed::Finite(value)) => Some(value.normalized_plain()),
            _ => None,
        };
        assert_eq!(finite("1_000").as_deref(), Some("1000"));
        assert_eq!(finite("_1").as_deref(), Some("1"));
        assert_eq!(finite("1._5").as_deref(), Some("1.5"));
        assert_eq!(finite("1e1_0").as_deref(), Some("10000000000"));
        assert_eq!(finite("  1.5 ").as_deref(), Some("1.5"));
        assert_eq!(finite("+.5").as_deref(), Some("0.5"));
        assert_eq!(finite("5.").as_deref(), Some("5"));
        for bad in [".", "1e", "0x10", "1 0", "", "e5", "--1"] {
            assert_eq!(parse_decimal(bad), None, "{bad}");
        }
        for special in ["inf", "Infinity", "-nan", "sNaN", "NaN12"] {
            assert_eq!(parse_decimal(special), Some(Parsed::Special), "{special}");
        }
    }

    #[test]
    fn amounts_round_like_python() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(shifted_plain(max, 18), "115792089237316195423570985000000000000000000000000000000000");
        assert_eq!(shifted_plain("10000000000000000000", 18), "10");
        assert_eq!(shifted_plain("900000000000000000", 18), "0.9");
        assert_eq!(shifted_plain("100000000", 18 - 9), "0.1");
        assert_eq!(shifted_plain("0", 18), "0");
        assert_eq!(shifted_plain("1500000000", 9), "1.5");
        let rounded = match parse_decimal("1.0000000000000000000000000001").unwrap() {
            Parsed::Finite(value) => value.scaleb(18),
            Parsed::Special => unreachable!(),
        };
        assert!(rounded.is_integral());
        assert_eq!(rounded.integer_digits(), "1000000000000000000");
    }
}
