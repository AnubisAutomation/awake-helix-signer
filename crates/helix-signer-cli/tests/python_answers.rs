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
//!
//! Signer 0.7.0 (renamed Anubis Automation Script Signer) migrated the
//! recording to the new names, mechanically: the texts the signer writes (its
//! name, `anubisauto-signer revoke`, the link refusals); grant plans name
//! `anubisauto-signer-plan/2`; every session key attestation is signed again
//! under the new EIP-712 domain name with the same test key and fields (the
//! one signed by a key the recorder made up, by a fixed foreign test key that
//! its refusal now names), and the attestation known answers were recomputed;
//! the revocation calls the signer builds name `anubisauto-signer-plan/1`. The
//! revoke plans and links are kept as recorded, with the legacy
//! `awake-helix-signer-plan/1`, `/2` and `awakehelix://` names the signer still
//! accepts, and each is repeated with the new names (2223 cases from 1831).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::Value;

/// The first line of every summary: the signer's name and version.
const NAME: &str = "Anubis Automation Script Signer ";

fn normalize(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(start) = text.find(NAME) {
                let end = text[start + NAME.len()..].find('\n').map(|index| start + NAME.len() + index).unwrap_or(text.len());
                text.replace_range(start..end, &format!("{NAME}<version>"));
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
