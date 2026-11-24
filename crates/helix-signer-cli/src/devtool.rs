//! ``helix-signer-devtool``: test-only entry points into the core (never
//! shipped to users).
//!
//! * ``verify-revoke-call --owner ADDR --grant ID --call JSON``: the check
//!   ``grants revoke`` applies to a website-built revocation call (exit 0 when
//!   accepted, 1 with the refusal on stdout). Used by the Awake Helix
//!   website's fork tests.
//! * ``batch``: one JSON operation per stdin line, one JSON result per stdout
//!   line: the replay of the Python signer's recorded answers
//!   (``tests/python_answers.rs``) and the Awake Helix website's tests
//!   (through ``tests/py/rust_signer.py``).

use std::io::{BufRead, Write};

use helix_signer_core::address::Address;
use helix_signer_core::chain::{AccountKind, AccountState};
use helix_signer_core::custom::{self, CustomizeRequest};
use helix_signer_core::keys::Kdf;
use helix_signer_core::tx::{Authorization, Transaction};
use helix_signer_core::{
    companion, flow, plan, summary, website, Constants, Error, GrantPlan, KeyMaterial, Result, Zeroizing, U256,
};
use serde_json::{json, Value};

fn constants_of(value: Option<&Value>) -> Result<Constants> {
    match value {
        None | Some(Value::Null) => Ok(helix_signer_core::production()),
        Some(Value::String(text)) if text == "production" => Ok(helix_signer_core::production()),
        Some(Value::Object(map)) => {
            let mut overrides = map.clone();
            let placeholder = overrides.remove("_placeholder").is_some();
            let mut constants = helix_signer_core::production().with_overrides(&Value::Object(overrides))?;
            if placeholder {
                constants.attestation_address = Address::constant(helix_signer_core::constants::ATTESTATION_PLACEHOLDER);
            }
            Ok(constants)
        }
        Some(other) => Err(Error::plan(format!("bad constants {other}"))),
    }
}

fn text<'a>(op: &'a Value, key: &str) -> &'a str {
    op.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn u256(value: &Value) -> U256 {
    match value {
        Value::String(text) => text.parse().unwrap_or_default(),
        Value::Number(number) => U256::from(number.as_u64().unwrap_or(0)),
        _ => U256::ZERO,
    }
}

fn state_of(op: &Value) -> AccountState {
    // "pinned" (recorded by the former Python signer) is the version 2 Diamond.
    let kind = match text(op, "state") {
        "pinned" | "v2" => AccountKind::V2,
        "v1" => AccountKind::V1,
        _ => AccountKind::Plain,
    };
    AccountState {
        kind,
        target: text(op, "target").to_string(),
        nonce: 0,
        balance: op.get("balance").map(u256).unwrap_or_default(),
    }
}

fn grant_of(op: &Value, key: &str, constants: &Constants) -> Result<GrantPlan> {
    plan::verify_grant_plan(op.get(key).unwrap_or(&Value::Null), constants, op.get("now").and_then(Value::as_u64))
}

fn request_of(value: &Value) -> CustomizeRequest {
    serde_json::from_value(value.clone()).unwrap_or_default()
}

fn caps_of(value: Option<&Value>) -> Vec<custom::Cap> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let part = |index: usize| item.get(index).and_then(Value::as_str).map(str::to_string);
                    (item.get(0).and_then(Value::as_u64).unwrap_or(0) as usize, part(1), part(2))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn hex32(value: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let _ = hex::decode_to_slice(value.trim_start_matches("0x"), out.as_mut());
    out
}

fn operate(op: &Value) -> Result<Value> {
    let constants = constants_of(op.get("constants"))?;
    match text(op, "op") {
        "verify_grant" => {
            let verified = grant_of(op, "plan", &constants)?;
            let summary = summary::grant_summary(&verified, &state_of(op), op.get("api").and_then(Value::as_str), text(op, "rpc"), &constants);
            Ok(json!({"plan": verified, "summary": summary.text()}))
        }
        "verify_revoke" => {
            let mut verified = plan::verify_revoke_plan(op.get("plan").unwrap_or(&Value::Null), &constants)?;
            // The former Python signer only revoked on an account delegated to the
            // pinned implementation, so a recorded revoke without "state" is that
            // one; "plain" (re-delegate and revoke) or "v1" must be asked for
            // explicitly, and then the plan's delegate must be the wallet's.
            let mut state = state_of(op);
            if op.get("state").is_none() {
                state.kind = AccountKind::V2;
            } else {
                plan::bind_revoke_delegate(&mut verified, state.delegate(&constants, false))?;
            }
            let summary = summary::revoke_summary(&verified, &state, op.get("api").and_then(Value::as_str), text(op, "rpc"), &constants);
            Ok(json!({"plan": verified, "summary": summary.text()}))
        }
        "offline_revoke" => Ok(json!(plan::offline_revoke(text(op, "owner"), text(op, "grant"), text(op, "kind"), &constants)?)),
        "revoke_call" => {
            let owner = Address::parse(text(op, "owner")).ok_or_else(|| Error::plan("bad owner"))?;
            Ok(json!(flow::revoke_call_plan(op.get("call").unwrap_or(&Value::Null), &owner, text(op, "grant"), &constants)?))
        }
        "parse_expiry" => Ok(json!(custom::parse_expiry(text(op, "text"), op.get("now").and_then(Value::as_i64))?)),
        "combine_expiry" => Ok(json!(custom::combine_expiry(text(op, "date"), text(op, "clock"), text(op, "zone"))?)),
        "expiry_parts" => {
            let (date, clock) = custom::expiry_parts(op.get("seconds").and_then(Value::as_i64).unwrap_or(0), text(op, "zone"))?;
            Ok(json!([date, clock]))
        }
        "parse_calls" => Ok(json!(custom::parse_calls(text(op, "text"))?)),
        "base_units" => Ok(json!(custom::base_units(text(op, "text"), op.get("decimals").and_then(Value::as_u64).unwrap_or(18) as u32, text(op, "label"))?)),
        "amount" => Ok(json!(plan::amount_digits(text(op, "value"), op.get("decimals").and_then(Value::as_u64).unwrap_or(18) as u32))),
        "parse_cap" => {
            let verified = grant_of(op, "plan", &constants)?;
            let (index, per_call, per_day) = custom::parse_cap(text(op, "text"), &verified.rules)?;
            Ok(json!([index, per_call, per_day]))
        }
        "request_of" => Ok(json!(custom::request_of(&grant_of(op, "plan", &constants)?))),
        "with_changes" => {
            let verified = grant_of(op, "plan", &constants)?;
            let caps = caps_of(op.get("caps"));
            Ok(json!(custom::with_changes(
                &verified,
                op.get("expires").and_then(Value::as_i64),
                op.get("calls").and_then(Value::as_u64),
                &caps
            )?))
        }
        "check_answer" => {
            let before = grant_of(op, "before", &constants)?;
            let after = grant_of(op, "after", &constants)?;
            custom::check_answer(&before, &after, &request_of(op.get("request").unwrap_or(&Value::Null)))?;
            Ok(json!(null))
        }
        "check_challenge" => {
            let owner = Address::parse(text(op, "owner")).ok_or_else(|| Error::plan("bad owner"))?;
            Ok(json!(website::check_challenge(op.get("message").and_then(Value::as_str), &owner, text(op, "api"), 6714)?))
        }
        "parse_link" => {
            let allowed: Vec<String> = op.get("allowed").and_then(Value::as_array).map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
            Ok(json!(helix_signer_core::parse_link(text(op, "url"), &allowed, op.get("development").and_then(Value::as_bool).unwrap_or(false))?))
        }
        "validate_url" => Ok(json!(helix_signer_core::net::validate_url(text(op, "url"), "API")?)),
        "is_loopback" => Ok(json!(helix_signer_core::net::is_loopback(text(op, "url")))),
        "parse_listing" => Ok(json!(website::parse_listing(op.get("raw").and_then(Value::as_object).ok_or_else(|| Error::plan("bad raw"))?, text(op, "owner"))?
            .rows
            .iter()
            .map(|row| row.describe())
            .collect::<Vec<_>>())),
        "keystore" => {
            let material = KeyMaterial::from_keystore_json(&op["document"].to_string(), "keystore.json", text(op, "password"))?;
            Ok(json!(material.address()))
        }
        "keystore_create" => {
            let material = KeyMaterial::from_private_key(text(op, "key"))?;
            let kdf = if text(op, "kdf") == "pbkdf2" { Kdf::Pbkdf2 } else { Kdf::Scrypt };
            let document = helix_signer_core::keys::keystore::encrypt(
                &hex32(text(op, "key")),
                &material.address().to_checksum(),
                text(op, "password"),
                kdf,
                op.get("work").and_then(Value::as_u64).map(|work| work as u32),
            )
            .ok_or_else(|| Error::key("cannot encrypt"))?;
            Ok(document)
        }
        "private_key" => Ok(json!(KeyMaterial::from_private_key(text(op, "text"))?.address())),
        "mnemonic" => {
            let material = KeyMaterial::from_mnemonic(text(op, "phrase"), op.get("index").and_then(Value::as_i64).unwrap_or(0), text(op, "passphrase"))?;
            Ok(json!([material.address(), material.path()]))
        }
        "sign_message" => Ok(json!(KeyMaterial::from_private_key(text(op, "key"))?.sign_message(text(op, "message"))?)),
        "attestation" => {
            let owner = Address::parse(text(op, "owner")).ok_or_else(|| Error::plan("bad owner"))?;
            let session = Address::parse(text(op, "session")).ok_or_else(|| Error::plan("bad session"))?;
            let mut bot = [0u8; 16];
            let _ = hex::decode_to_slice(text(op, "bot"), &mut bot);
            let digest = plan::attestation_digest(op.get("chainId").and_then(Value::as_u64).unwrap_or(6714), &owner, &bot, &session);
            let signature = KeyMaterial::from_private_key(text(op, "key"))?.sign_digest(&digest)?;
            Ok(json!({"digest": hex::encode(digest), "signature": format!("0x{}", hex::encode(signature.to_bytes_65()))}))
        }
        "transaction" => {
            let key = hex32(text(op, "key"));
            let authorization = match op.get("authorization") {
                Some(Value::Object(auth)) => Some(
                    Authorization::sign(
                        &key,
                        auth.get("chainId").and_then(Value::as_u64).unwrap_or(6714),
                        Address::parse(auth.get("address").and_then(Value::as_str).unwrap_or_default()).unwrap_or_default(),
                        auth.get("nonce").and_then(Value::as_u64).unwrap_or(0),
                    )
                    .ok_or_else(|| Error::key("bad key"))?,
                ),
                _ => None,
            };
            let transaction = Transaction {
                chain_id: op.get("chainId").and_then(Value::as_u64).unwrap_or(6714),
                nonce: op.get("nonce").and_then(Value::as_u64).unwrap_or(0),
                max_priority_fee_per_gas: u256(&op["tip"]),
                max_fee_per_gas: u256(&op["maxFee"]),
                gas: u256(&op["gas"]),
                to: Address::parse(text(op, "to")).unwrap_or_default(),
                data: hex::decode(text(op, "data").trim_start_matches("0x")).unwrap_or_default(),
                authorization_list: authorization.map(|item| vec![item]),
            };
            let (raw, hash) = transaction.sign(&key).ok_or_else(|| Error::key("bad key"))?;
            Ok(json!({"raw": format!("0x{}", hex::encode(raw)), "hash": format!("0x{}", hex::encode(hash))}))
        }
        "constants_hash" => Ok(json!(companion::constants_hash(&constants))),
        "dev_constants" => {
            let mut document = json!(constants);
            let allowlist: serde_json::Map<String, Value> = helix_signer_core::constants::RULE_ALLOWLIST
                .iter()
                .map(|(kind, entries)| (kind.to_string(), json!(entries.iter().map(|(a, b, c)| [a, b, c]).collect::<Vec<_>>())))
                .collect();
            document["ruleAllowlist"] = Value::Object(allowlist);
            document["maxValiditySeconds"] = json!(helix_signer_core::constants::MAX_VALIDITY_SECONDS);
            document["maxCalls"] = json!(helix_signer_core::constants::MAX_CALLS);
            document["maxRules"] = json!(helix_signer_core::constants::MAX_RULES);
            Ok(document)
        }
        "when" => Ok(json!(summary::when(op.get("seconds").and_then(Value::as_u64).unwrap_or(0)))),
        other => Err(Error::plan(format!("unknown op {other}"))),
    }
}

fn batch() -> i32 {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let result = match serde_json::from_str::<Value>(&line) {
            Ok(op) => match operate(&op) {
                Ok(value) => json!({"ok": value}),
                Err(error) => json!({"error": error.message(), "kind": error.kind()}),
            },
            Err(error) => json!({"error": format!("bad json: {error}")}),
        };
        let _ = writeln!(stdout, "{result}");
        let _ = stdout.flush();
    }
    0
}

fn verify_revoke_call(args: &[String]) -> i32 {
    let value = |name: &str| args.iter().position(|arg| arg == name).and_then(|index| args.get(index + 1)).cloned().unwrap_or_default();
    let call: Value = match serde_json::from_str(&value("--call")) {
        Ok(call) => call,
        Err(error) => {
            println!("Refused: the call is not JSON ({error}).");
            return 2;
        }
    };
    let Some(owner) = Address::parse(&value("--owner")) else {
        println!("Refused: --owner is not an address.");
        return 2;
    };
    match flow::revoke_call_plan(&call, &owner, &value("--grant"), &helix_signer_core::production()) {
        Ok(plan) => {
            println!("{}", json!(plan));
            0
        }
        Err(error) => {
            println!("Refused: {error}");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let status = match args.first().map(String::as_str) {
        Some("batch") => batch(),
        Some("verify-revoke-call") => verify_revoke_call(&args[1..]),
        _ => {
            eprintln!("usage: helix-signer-devtool batch | verify-revoke-call --owner ADDR --grant ID --call JSON");
            2
        }
    };
    std::process::exit(status);
}
