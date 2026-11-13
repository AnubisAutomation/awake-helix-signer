//! Verify website grant and revoke plans against the pinned constants.
//!
//! Nothing in a plan is trusted: the calldata is decoded here, every field is
//! checked against the constants, the decoded values (not the website's
//! preview) are what the summary shows, and the calldata must re-encode byte
//! for byte. A grant's session key differs per bot, so the plan carries the
//! platform's EIP-712 attestation of it, recomputed here from the decoded
//! calldata and checked against the pinned attestation address.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use ruint::aliases::U256;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::abi::{decode_install, encode_install, RawRule};
use crate::address::{hex0x, keccak, same, Address};
use crate::constants::{self as c, Constants, GrantKind};
use crate::error::{Error, Result};
use crate::pyfmt::{py_repr, py_str, shifted_plain};

/// One decoded Helix7702Account policy rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    /// RuleKind.
    pub kind: u8,
    /// Called contract.
    pub target: Address,
    /// Input token (swaps) or zero.
    pub token_in: Address,
    /// Spender (approve), output token (swaps) or zero.
    pub counterparty: Address,
    /// Per-call cap in base units.
    #[serde(serialize_with = "u256_string")]
    pub max_amount: U256,
    /// Secondary cap (activation DAI) in base units.
    #[serde(serialize_with = "u256_string")]
    pub max_secondary: U256,
    /// Per-UTC-day cap in base units.
    #[serde(serialize_with = "u256_string")]
    pub max_daily: U256,
    /// Swap price floor scaled by 1e18.
    #[serde(serialize_with = "u256_string")]
    pub min_out_per_in_wad: U256,
    /// Seconds.
    pub max_deadline_delay: u64,
}

fn u256_string<S: serde::Serializer>(value: &U256, serializer: S) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

impl Rule {
    /// The method name this rule permits.
    pub fn method(&self) -> &'static str {
        let signature = c::RULE_METHODS[self.kind as usize];
        &signature[..signature.find('(').unwrap_or(signature.len())]
    }

    /// The primary amount's unit and decimals (as the planner shows).
    pub fn unit(&self) -> (&'static str, u32) {
        let token = if self.kind == 0 {
            self.target
        } else if c::SWAP_KINDS.contains(&self.kind) {
            self.token_in
        } else {
            Address::ZERO
        };
        if self.kind == 2 || token == Address::constant(c::LGNS) {
            return ("LGNS", 9);
        }
        if self.kind == 9 {
            return ("lock IDs", 0);
        }
        if [5, 6, 7, 8].contains(&self.kind) || token == Address::constant(c::AILGNS) {
            return ("aiLGNS", 18);
        }
        ("DAI", 18)
    }
}

/// A verified ``installPolicyGrant`` plan.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantPlan {
    /// Owner EOA (also the call target).
    pub owner: Address,
    /// Lowercase bytes32.
    pub grant_id: String,
    /// Session key.
    pub session_key: Address,
    /// The grant's bot UUID.
    pub bot_id: String,
    /// Unix seconds.
    pub valid_after: u64,
    /// Unix seconds.
    pub valid_until: u64,
    /// Total UserOperations allowed.
    pub remaining_calls: u64,
    /// Decoded rules.
    pub rules: Vec<Rule>,
    /// Exact lowercase calldata to send.
    pub data: String,
    /// Pinned delegate.
    pub implementation: Address,
    /// Raw plan (script name, bounds, customization).
    pub plan: Value,
}

/// A verified ``revokePolicyGrant`` / ``revokeGrant`` self-call.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokePlan {
    /// Owner EOA (also the call target).
    pub owner: Address,
    /// Lowercase bytes32.
    pub grant_id: String,
    /// ``policy`` or ``session``.
    pub grant_kind: GrantKind,
    /// Exact calldata.
    pub data: String,
    /// Pinned delegate the account must use.
    pub implementation: Address,
    /// Raw plan, or ``{}`` for an offline revoke.
    pub plan: Value,
}

/// Python ``value == number`` for a JSON value (``True == 1``, ``6714.0 == 6714``).
pub fn py_int_eq(value: &Value, number: u64) -> bool {
    match value {
        Value::Bool(flag) => (*flag as u64) == number,
        Value::Number(n) => {
            if let Some(int) = n.as_u64() {
                int == number
            } else if n.as_i64().is_some() {
                false
            } else {
                n.as_f64().map(|float| float == number as f64 && float.fract() == 0.0).unwrap_or(false)
            }
        }
        _ => false,
    }
}

fn is_hex_data(text: &str) -> bool {
    text.strip_prefix("0x").map(|rest| rest.len() % 2 == 0 && rest.bytes().all(|byte| byte.is_ascii_hexdigit())).unwrap_or(false)
}

fn is_bytes32(text: &str) -> bool {
    text.len() == 66 && text.starts_with("0x") && text[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// ``^[A-Za-z0-9_-]{22,128}$``.
pub fn is_token(text: &str) -> bool {
    (22..=128).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn is_signature(text: &str) -> bool {
    text.len() == 132 && text.starts_with("0x") && text[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn field_address(value: Option<&Value>, field: &str) -> Result<Address> {
    match value {
        Some(Value::String(text)) => Address::parse(text),
        _ => None,
    }
    .ok_or_else(|| Error::plan(format!("Plan field {field} is not an address.")))
}

fn get<'a>(plan: &'a Map<String, Value>, key: &str) -> &'a Value {
    plan.get(key).unwrap_or(&Value::Null)
}

/// Canonical UUID text of 16 bytes.
pub fn uuid_text(bytes: &[u8; 16]) -> String {
    let hex = hex::encode(bytes);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

fn common<'a>(plan: &'a Value, kind: &str, constants: &Constants) -> Result<(&'a Map<String, Value>, Address)> {
    let map = plan.as_object().ok_or_else(|| Error::plan("Plan is not a JSON object."))?;
    let shown = get(map, "kind");
    if shown.as_str() != Some(kind) {
        return Err(Error::plan(format!("This is a {} plan, not a '{kind}' plan.", py_repr(shown))));
    }
    let schema = get(map, "schema");
    let accepted: &[&str] = if kind == "grant" { &[c::PLAN_SCHEMA] } else { &c::REVOKE_PLAN_SCHEMAS };
    if !schema.as_str().map(|text| accepted.contains(&text)).unwrap_or(false) {
        return Err(Error::plan(format!(
            "Unsupported plan schema {}; update the signer from the website and create a new plan on the dashboard.",
            py_repr(schema)
        )));
    }
    let chain = get(map, "chainId");
    if !py_int_eq(chain, constants.chain_id) || chain.is_boolean() {
        return Err(Error::plan(format!(
            "Wrong chain {}: only Anubis Chain {} is supported.",
            py_repr(chain),
            constants.chain_id
        )));
    }
    let owner = field_address(map.get("owner"), "owner")?;
    if field_address(map.get("to"), "to")? != owner {
        return Err(Error::plan("The call target is not the owner's own address."));
    }
    let value_ok = match map.get("value") {
        None => true,
        Some(Value::String(text)) => ["0x0", "0x", "0"].contains(&text.as_str()),
        Some(Value::Bool(flag)) => !flag,
        Some(Value::Number(n)) => n.as_f64() == Some(0.0),
        Some(_) => false,
    };
    if !value_ok {
        return Err(Error::plan("The plan moves native value; Anubis transactions must have value 0."));
    }
    let implementation = get(map, "implementation");
    if !implementation.is_null() && field_address(Some(implementation), "implementation")? != constants.implementation {
        return Err(Error::plan(format!(
            "Wrong delegate {}: only Helix7702 implementation {} is accepted.",
            py_str(implementation),
            constants.implementation
        )));
    }
    match map.get("data") {
        Some(Value::String(data)) if is_hex_data(data) && data.len() >= 10 => {}
        _ => return Err(Error::plan("Plan calldata is not hex.")),
    }
    Ok((map, owner))
}

fn check_rule(raw: &RawRule) -> Result<Rule> {
    let kind = raw.kind;
    let allowed = c::allowed_for(kind).ok_or_else(|| Error::plan(format!("Unknown rule kind {kind}.")))?;
    let rule = Rule {
        kind,
        target: raw.target,
        token_in: raw.token_in,
        counterparty: raw.counterparty,
        max_amount: raw.max_amount,
        max_secondary: raw.max_secondary,
        max_daily: raw.max_daily,
        min_out_per_in_wad: raw.min_out_per_in_wad,
        max_deadline_delay: raw.max_deadline_delay,
    };
    let listed = allowed.iter().any(|(target, token_in, counterparty)| {
        Address::constant(target) == rule.target
            && Address::constant(token_in) == rule.token_in
            && Address::constant(counterparty) == rule.counterparty
    });
    let method = rule.method();
    if !listed {
        let target = rule.target.to_checksum();
        let name = match c::contract_name(&target) {
            "" => target,
            name => name.to_string(),
        };
        return Err(Error::plan(format!(
            "Rule {method} on {name} (tokenIn {}, counterparty {}) is not on the HELIX allow-list.",
            rule.token_in, rule.counterparty
        )));
    }
    if raw.usage_day != 0 || !raw.used_today.is_zero() {
        return Err(Error::plan("A rule arrives with non-zero usage counters."));
    }
    if rule.max_amount.is_zero() || rule.max_daily < rule.max_amount {
        return Err(Error::plan(format!("Rule {method} has an invalid per-call or daily cap.")));
    }
    let swap = c::SWAP_KINDS.contains(&kind);
    if swap && rule.min_out_per_in_wad.is_zero() {
        return Err(Error::plan(format!("Swap rule {method} has no price floor.")));
    }
    if !swap && !rule.min_out_per_in_wad.is_zero() {
        return Err(Error::plan(format!("Rule {method} carries an unexpected price field.")));
    }
    if c::DEADLINE_KINDS.contains(&kind) {
        if !(0 < rule.max_deadline_delay && rule.max_deadline_delay <= c::MAX_DEADLINE_DELAY_SECONDS) {
            return Err(Error::plan(format!("Rule {method} has an unbounded deadline.")));
        }
    } else if rule.max_deadline_delay != 0 {
        return Err(Error::plan(format!("Rule {method} carries an unexpected deadline field.")));
    }
    if kind != 5 && !rule.max_secondary.is_zero() {
        return Err(Error::plan(format!("Rule {method} carries an unexpected secondary cap.")));
    }
    if kind == 5 && rule.max_secondary.is_zero() {
        return Err(Error::plan("Activation rule has no DAI cap."));
    }
    Ok(rule)
}

fn word_u64(value: u64) -> [u8; 32] {
    U256::from(value).to_be_bytes::<32>()
}

/// The EIP-712 digest a session key attestation signs:
/// domain ``{name: "Awake Helix Session Key Attestation", version: "1", chainId}``,
/// ``SessionKeyAttestation(uint256 version,uint256 chainId,address owner,bytes16 botId,address sessionKey)``.
pub fn attestation_digest(chain_id: u64, owner: &Address, bot: &[u8; 16], session_key: &Address) -> [u8; 32] {
    let domain_type = keccak(b"EIP712Domain(string name,string version,uint256 chainId)");
    let mut domain = Vec::with_capacity(128);
    domain.extend_from_slice(&domain_type);
    domain.extend_from_slice(&keccak(c::ATTESTATION_NAME.as_bytes()));
    domain.extend_from_slice(&keccak(c::ATTESTATION_DOMAIN_VERSION.as_bytes()));
    domain.extend_from_slice(&word_u64(chain_id));
    let domain = keccak(&domain);
    let struct_type =
        keccak(b"SessionKeyAttestation(uint256 version,uint256 chainId,address owner,bytes16 botId,address sessionKey)");
    let mut message = Vec::with_capacity(192);
    message.extend_from_slice(&struct_type);
    message.extend_from_slice(&word_u64(c::ATTESTATION_VERSION));
    message.extend_from_slice(&word_u64(chain_id));
    message.extend_from_slice(&owner.word());
    let mut bot_word = [0u8; 32];
    bot_word[..16].copy_from_slice(bot);
    message.extend_from_slice(&bot_word);
    message.extend_from_slice(&session_key.word());
    let message = keccak(&message);
    let mut digest = Vec::with_capacity(66);
    digest.extend_from_slice(b"\x19\x01");
    digest.extend_from_slice(&domain);
    digest.extend_from_slice(&message);
    keccak(&digest)
}

const ATTESTATION_FIELDS: [&str; 6] = ["version", "chainId", "owner", "botId", "sessionKey", "signature"];

/// Prove that the platform attested this exact session key.
///
/// The signature is checked over the values decoded from the calldata, so a
/// document naming anything else cannot verify; the explicit field checks only
/// make the refusal readable.
pub fn verify_attestation(
    attestation: Option<&Value>,
    owner: &Address,
    bot: &[u8; 16],
    session_key: &Address,
    constants: &Constants,
) -> Result<()> {
    let document = match attestation {
        Some(Value::Object(map)) => map,
        _ => return Err(Error::plan("Plan has no platform attestation for its session key.")),
    };
    let keys: HashSet<&str> = document.keys().map(String::as_str).collect();
    if keys != ATTESTATION_FIELDS.iter().copied().collect() {
        return Err(Error::plan("The session key attestation has the wrong fields."));
    }
    let version = &document["version"];
    if version.is_boolean() || !py_int_eq(version, c::ATTESTATION_VERSION) {
        return Err(Error::plan(format!("Unsupported session key attestation version {}.", py_repr(version))));
    }
    let chain = &document["chainId"];
    if chain.is_boolean() || !py_int_eq(chain, constants.chain_id) {
        return Err(Error::plan(format!(
            "The session key attestation is for chain {}, not {}.",
            py_repr(chain),
            constants.chain_id
        )));
    }
    if field_address(document.get("owner"), "attestation owner")? != *owner {
        return Err(Error::plan("The session key attestation is for another owner."));
    }
    if document["botId"].as_str() != Some(uuid_text(bot).as_str()) {
        return Err(Error::plan("The session key attestation is for another bot."));
    }
    if field_address(document.get("sessionKey"), "attestation sessionKey")? != *session_key {
        return Err(Error::plan("The session key attestation names another session key."));
    }
    let signature = match &document["signature"] {
        Value::String(text) if is_signature(text) => text,
        _ => return Err(Error::plan("The session key attestation signature is malformed.")),
    };
    if constants.attestation_address == Address::constant(c::ATTESTATION_PLACEHOLDER) {
        return Err(Error::plan(
            "This signer build has no platform attestation address and cannot sign grants; update the signer from the website.",
        ));
    }
    let mut bytes = [0u8; 65];
    hex::decode_to_slice(&signature[2..], &mut bytes).map_err(|_| Error::plan("The session key attestation signature is malformed."))?;
    let digest = attestation_digest(constants.chain_id, owner, bot, session_key);
    let signer = crate::secp::recover_65(&digest, &bytes)
        .ok_or_else(|| Error::plan("The session key attestation signature is invalid."))?;
    if signer != constants.attestation_address {
        return Err(Error::plan(format!(
            "The session key attestation was signed by {signer}, not by the platform key {}.",
            constants.attestation_address
        )));
    }
    Ok(())
}

/// Seconds since the Unix epoch on this computer.
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0)
}

/// Verify an ``installPolicyGrant`` plan completely.
///
/// ``now``: Unix time for the expiry bounds (chain time when known,
/// otherwise this computer's clock).
pub fn verify_grant_plan(plan: &Value, constants: &Constants, now: Option<u64>) -> Result<GrantPlan> {
    let (map, owner) = common(plan, "grant", constants)?;
    if get(map, "implementation").is_null() {
        return Err(Error::plan("Plan names no delegate implementation."));
    }
    let data = map["data"].as_str().unwrap_or_default().to_lowercase();
    let selector = c::install_selector();
    if !data.starts_with(&selector) {
        return Err(Error::plan(format!(
            "Wrong method selector {}: only installPolicyGrant ({selector}) is signed.",
            &data[..10.min(data.len())]
        )));
    }
    let body = hex::decode(&data[10..]).map_err(|_| Error::plan("Plan calldata is not hex."))?;
    let call = decode_install(&body).map_err(|_| Error::plan("installPolicyGrant calldata does not decode."))?;
    if encode_install(&call) != body {
        return Err(Error::plan("installPolicyGrant calldata is not canonically encoded."));
    }
    let grant_hex = hex0x(&call.grant_id);
    if call.grant_id == [0u8; 32] {
        return Err(Error::plan("Grant ID is zero."));
    }
    let shown_grant = map.get("grantId").map(py_str).unwrap_or_default();
    if shown_grant.to_lowercase() != grant_hex {
        return Err(Error::plan("Plan grantId does not match the calldata."));
    }
    let session_key = call.key;
    let shown_key = map.get("sessionKey").map(py_str).unwrap_or_default();
    if !same(&shown_key, &session_key.to_checksum()) {
        return Err(Error::plan("Plan sessionKey does not match the calldata."));
    }
    if session_key.is_zero() {
        return Err(Error::plan("Grant has no session key."));
    }
    if session_key == constants.legacy_session_key {
        return Err(Error::plan(format!(
            "Wrong session key {session_key}: the former shared hosted key is no longer accepted for new grants; every bot has its own key."
        )));
    }
    if call.bot == [0u8; 16] {
        return Err(Error::plan("Grant has no bot ID."));
    }
    verify_attestation(map.get("sessionKeyAttestation"), &owner, &call.bot, &session_key, constants)?;
    let current = now.unwrap_or_else(unix_now) as i128;
    let (valid_after, valid_until, calls) = (call.valid_after, call.valid_until, call.remaining_calls);
    if valid_until <= valid_after {
        return Err(Error::plan("Grant ends before it starts."));
    }
    let left = valid_until as i128 - current;
    if left > c::MAX_VALIDITY_SECONDS as i128 {
        return Err(Error::plan(format!(
            "Grant lasts too long: it ends {left} s from now; the maximum is {} s ({} days).",
            c::MAX_VALIDITY_SECONDS,
            c::MAX_GRANT_DAYS
        )));
    }
    if left < c::MIN_REMAINING_SECONDS as i128 {
        return Err(Error::plan("Grant is expired or about to expire."));
    }
    if valid_after as i128 - current > c::MAX_START_DELAY_SECONDS as i128 {
        return Err(Error::plan("Grant starts in the future."));
    }
    if !py_int_eq(get(map, "validUntil"), valid_until) {
        return Err(Error::plan("Plan validUntil does not match the calldata."));
    }
    if !(0 < calls && calls <= c::MAX_CALLS) {
        return Err(Error::plan(format!("Grant allows {calls} calls; the maximum is {}.", c::MAX_CALLS)));
    }
    if let Some(shown) = map.get("remainingCalls") {
        if !py_int_eq(shown, calls) {
            return Err(Error::plan("Plan remainingCalls does not match the calldata."));
        }
    }
    if call.rules.is_empty() || call.rules.len() > c::MAX_RULES {
        return Err(Error::plan(format!("Grant has {} rules; 1 to {} are allowed.", call.rules.len(), c::MAX_RULES)));
    }
    let rules = call.rules.iter().map(check_rule).collect::<Result<Vec<Rule>>>()?;
    let mut keys = HashSet::new();
    for rule in &rules {
        let spender = if rule.kind == 0 { rule.counterparty.to_lower() } else { String::new() };
        if !keys.insert((rule.target, rule.kind, spender)) {
            return Err(Error::plan("Grant repeats a rule."));
        }
    }
    let preview_error = || Error::plan("The website's rule preview does not match the calldata.");
    let preview = match map.get("rules") {
        Some(Value::Array(items)) if items.len() == rules.len() => items,
        _ => return Err(preview_error()),
    };
    for (shown, rule) in preview.iter().zip(&rules) {
        let shown = shown.as_object().ok_or_else(preview_error)?;
        let target = shown.get("target").map(py_str).unwrap_or_default();
        let counterparty = shown.get("counterparty").map(py_str).unwrap_or_default();
        if shown.get("method").and_then(Value::as_str) != Some(rule.method())
            || !same(&target, &rule.target.to_checksum())
            || !same(&counterparty, &rule.counterparty.to_checksum())
        {
            return Err(preview_error());
        }
    }
    Ok(GrantPlan {
        owner,
        grant_id: grant_hex,
        session_key,
        bot_id: uuid_text(&call.bot),
        valid_after,
        valid_until,
        remaining_calls: calls,
        rules,
        data,
        implementation: constants.implementation,
        plan: plan.clone(),
    })
}

/// Encode the owner's revocation call.
pub fn revoke_calldata(grant_id: &str, grant_kind: &str) -> Result<String> {
    let kind = GrantKind::parse(grant_kind)
        .ok_or_else(|| Error::plan(format!("Unknown grant kind {}.", crate::pyfmt::str_repr(grant_kind))))?;
    if !is_bytes32(grant_id) {
        return Err(Error::plan("Grant ID must be a 0x-prefixed 32-byte hex value."));
    }
    Ok(format!("{}{}", c::revoke_selector(kind), grant_id[2..].to_lowercase()))
}

/// Verify a website revocation plan.
pub fn verify_revoke_plan(plan: &Value, constants: &Constants) -> Result<RevokePlan> {
    let (map, owner) = common(plan, "revoke", constants)?;
    let kind_value = get(map, "grantKind");
    let kind_text = py_str(kind_value);
    let grant_text = map.get("grantId").map(py_str).unwrap_or_default();
    let expected = revoke_calldata(&grant_text, &kind_text)?;
    let kind = GrantKind::parse(&kind_text).expect("checked by revoke_calldata");
    let data = map["data"].as_str().unwrap_or_default().to_lowercase();
    if data.get(..10) != expected.get(..10) {
        return Err(Error::plan(format!(
            "Wrong method selector {}: a {kind_text} revoke must call {}.",
            &data[..10.min(data.len())],
            kind.revoke_signature()
        )));
    }
    if data != expected {
        return Err(Error::plan("Revoke calldata does not name the plan's grant ID exactly."));
    }
    Ok(RevokePlan {
        owner,
        grant_id: grant_text.to_lowercase(),
        grant_kind: kind,
        data,
        implementation: constants.implementation,
        plan: plan.clone(),
    })
}

/// Build a revocation without the website.
pub fn offline_revoke(owner: &str, grant_id: &str, grant_kind: &str, constants: &Constants) -> Result<RevokePlan> {
    let checked = field_address(Some(&Value::String(owner.to_string())), "owner")?;
    let data = revoke_calldata(grant_id, grant_kind)?;
    Ok(RevokePlan {
        owner: checked,
        grant_id: grant_id.to_lowercase(),
        grant_kind: GrantKind::parse(grant_kind).expect("checked by revoke_calldata"),
        data,
        implementation: constants.implementation,
        plan: Value::Object(Map::new()),
    })
}

/// Format base units as a plain decimal string (Python ``Decimal`` rules).
pub fn amount(value: &U256, decimals: u32) -> String {
    amount_digits(&value.to_string(), decimals)
}

/// ``amount`` of a non-negative integer given as decimal digits (may exceed 256 bits).
pub fn amount_digits(digits: &str, decimals: u32) -> String {
    if decimals == 0 {
        let trimmed = digits.trim_start_matches('0');
        return if trimmed.is_empty() { "0".into() } else { trimmed.into() };
    }
    shifted_plain(digits, decimals as i64)
}

/// Validate a one-time plan token's shape.
pub fn check_token(token: &str) -> Result<()> {
    if is_token(token) {
        Ok(())
    } else {
        Err(Error::plan("The plan token is malformed; copy the whole command again."))
    }
}
