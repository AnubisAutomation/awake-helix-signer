//! ``json.dumps`` with Python's defaults (``", "``/``": "`` separators,
//! ``ensure_ascii=True``), optionally with ``sort_keys=True``. Used where the
//! bytes matter: the companion's constants hash and files the signer writes.

use serde_json::Value;

fn string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7f => {
                let mut buffer = [0u16; 2];
                for unit in c.encode_utf16(&mut buffer) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(out: &mut String, value: &Value, sort_keys: bool) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => {
            if number.is_f64() {
                out.push_str(&crate::pyfmt::float_repr(number.as_f64().unwrap_or(0.0)));
            } else {
                out.push_str(&number.to_string());
            }
        }
        Value::String(text) => string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write(out, item, sort_keys);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if sort_keys {
                entries.sort_by(|left, right| left.0.cmp(right.0));
            }
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                string(out, key);
                out.push_str(": ");
                write(out, item, sort_keys);
            }
            out.push('}');
        }
    }
}

/// ``json.dumps(value, sort_keys=sort_keys)``.
pub fn dumps(value: &Value, sort_keys: bool) -> String {
    let mut out = String::new();
    write(&mut out, value, sort_keys);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python() {
        assert_eq!(dumps(&json!({"b": 1, "a": [true, null, "x"]}), true), r#"{"a": [true, null, "x"], "b": 1}"#);
        assert_eq!(dumps(&json!({"b": 1, "a": 2}), false), r#"{"b": 1, "a": 2}"#);
        assert_eq!(dumps(&json!("\u{e9}\u{1F600}"), false), "\"\\u00e9\\ud83d\\ude00\"");
    }
}
