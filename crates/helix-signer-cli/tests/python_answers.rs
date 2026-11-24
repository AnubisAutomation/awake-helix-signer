//! Replay the Python signer's recorded answers through the Rust core.
//!
//! `tests/fixtures/python_answers.jsonl.gz` was recorded from the former
//! Python signer before it was removed (it is kept as a frozen reference): plan
//! verification (valid and tampered grant/revoke plans, with their text
//! summaries), revocation calls, customize parsing and answer checks, login
//! challenges, links, URLs, amounts, keystores, mnemonics in every language,
//! personal_sign, EIP-712 attestations, type-2/type-4 transactions and the
//! companion's constants hash. Every case must give the same value or the
//! same refusal text (the version line of summaries aside).
//!
//! Signer 0.6.0 (version 2 Diamond, Origin rule kinds 10-26) rewrote the 11
//! expectations whose answer changed on purpose: the three constants hashes
//! (both Diamonds and the larger allow-list are hashed), the two production
//! revocation calls (they now name the version 2 Diamond), the production
//! grant plan naming the version 1 Diamond (now refused as such before its
//! attestation is checked), and the five grants with a rule of kind 10 or 11
//! (no longer an unknown kind: refused as not on the Origin allow-list).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::Value;

fn normalize(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(start) = text.find("Awake Helix Signer ") {
                let end = text[start + 19..].find('\n').map(|index| start + 19 + index).unwrap_or(text.len());
                text.replace_range(start..end, "Awake Helix Signer <version>");
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize),
        Value::Object(map) => map.values_mut().for_each(normalize),
        _ => {}
    }
}

#[test]
fn rust_answers_like_the_python_signer() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/python_answers.jsonl.gz");
    let reader = BufReader::new(flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap()));
    let cases: Vec<Value> = reader.lines().map(|line| serde_json::from_str(&line.unwrap()).unwrap()).collect();
    assert!(cases.len() > 1000, "{} cases", cases.len());
    let mut child = Command::new(env!("CARGO_BIN_EXE_helix-signer-devtool"))
        .arg("batch")
        .env("TZ", "UTC")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input: String = cases.iter().map(|case| format!("{}\n", case["op"])).collect();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    let answers: Vec<Value> = String::from_utf8(output.stdout).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(answers.len(), cases.len());
    let mut differences = Vec::new();
    for (case, answer) in cases.iter().zip(answers) {
        let mut answer = answer;
        if let Value::Object(map) = &mut answer {
            map.remove("kind");
        }
        let mut expected = case["expect"].clone();
        normalize(&mut expected);
        normalize(&mut answer);
        if expected != answer {
            differences.push(format!("{}\n  python: {expected}\n  rust:   {answer}", case["op"]));
        }
    }
    assert!(differences.is_empty(), "{} of {} differ:\n{}", differences.len(), cases.len(), differences[..differences.len().min(5)].join("\n"));
}
