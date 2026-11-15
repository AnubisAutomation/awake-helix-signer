//! Read the owner's account state, build, sign and broadcast the transaction.
//!
//! The owner sends the transaction itself, to its own address, with value 0:
//!
//! * plain EOA: one EIP-7702 type-4 transaction whose authorizationList holds
//!   the owner's authorization for the pinned delegate. The sender is the
//!   authority and the transaction's own nonce is consumed before the
//!   authorization list is processed, so the authorization nonce is the
//!   account nonce **plus one**. This holds for installs and for revoking a
//!   dormant grant of an account whose delegation was cleared: its storage
//!   persists, so the grant would act again after any later re-delegation;
//!   the same transaction re-delegates and revokes;
//! * already delegated to the pinned delegate: an ordinary EIP-1559 self-call;
//! * delegated to anything else, or a contract: refused.
//!
//! Gas is paid in DAI (Anubis's native gas token).

use std::time::{Duration, Instant};

use ruint::aliases::U256;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::address::{hex0x, keccak, Address};
use crate::constants::{self as c, Constants, GrantKind};
use crate::error::{Error, Result};
use crate::keys::KeyMaterial;
use crate::net::Rpc;
use crate::pyfmt::{py_repr, py_str, truthy};
use crate::tx::{Authorization, Transaction};

/// Code prefix of an EIP-7702 delegation.
pub const DELEGATION_PREFIX: &str = "0xef0100";
/// Used only when the RPC cannot estimate a type-4 transaction.
pub const FALLBACK_GAS_BASE: u64 = 400_000;
/// Per rule on top of the base.
pub const FALLBACK_GAS_PER_RULE: u64 = 220_000;
/// Revocation fallback.
pub const REVOKE_FALLBACK_GAS: u64 = 120_000;
/// EIP-7702 PER_EMPTY_ACCOUNT_COST.
pub const AUTHORIZATION_GAS: u64 = 25_000;

/// How the owner account looks on chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountKind {
    /// No code: needs the type-4 delegation.
    Plain,
    /// Delegated to the pinned implementation.
    Pinned,
    /// Delegated elsewhere (refused).
    Other,
    /// A contract (refused).
    Contract,
}

/// The owner's delegation and nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountState {
    /// Delegation state.
    pub kind: AccountKind,
    /// Lowercase delegation target for ``pinned``/``other``, else "".
    pub target: String,
    /// Next (pending) nonce.
    pub nonce: u64,
    /// DAI wei available for gas.
    #[serde(serialize_with = "u256_string")]
    pub balance: U256,
}

fn u256_string<S: serde::Serializer>(value: &U256, serializer: S) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

/// Parse a JSON-RPC quantity.
pub fn quantity(value: &Value) -> Result<U256> {
    let malformed = || Error::network(format!("Malformed RPC quantity {}.", py_repr(value)));
    let text = value.as_str().ok_or_else(malformed)?;
    let digits = text.strip_prefix("0x").ok_or_else(malformed)?;
    let digits: String = digits.chars().filter(|ch| *ch != '_').collect();
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    U256::from_str_radix(&digits, 16).map_err(|_| malformed())
}

fn quantity_u64(value: &Value) -> Result<u64> {
    let number = quantity(value)?;
    u64::try_from(number).map_err(|_| Error::network(format!("Malformed RPC quantity {}.", py_repr(value))))
}

/// ``hex(int)`` of Python.
pub fn py_hex(value: U256) -> String {
    format!("{value:#x}")
}

fn code_bytes(code: &str) -> Result<Vec<u8>> {
    hex::decode(code.get(2..).unwrap_or_default()).map_err(|_| Error::network("Malformed eth_getCode answer."))
}

/// Require the RPC's chain ID and the pinned delegate's code; returns the
/// latest block timestamp.
pub fn check_chain(rpc: &Rpc, constants: &Constants) -> Result<u64> {
    let chain = quantity(&rpc.call("eth_chainId", json!([]))?)?;
    if chain != U256::from(constants.chain_id) {
        return Err(Error::chain(format!("The RPC is chain {chain}, not Anubis Chain {}.", constants.chain_id)));
    }
    let implementation = constants.implementation.to_checksum();
    let code = py_str(&rpc.call("eth_getCode", json!([implementation, "latest"]))?);
    if ["0x", "0x0", ""].contains(&code.as_str()) {
        return Err(Error::chain(format!("The delegate {implementation} has no code on this chain.")));
    }
    if let Some(expected) = &constants.implementation_code_hash {
        let digest = hex0x(&keccak(&code_bytes(&code)?));
        if digest != expected.to_lowercase() {
            return Err(Error::chain(format!(
                "The delegate's code hash {digest} differs from the reviewed {expected}; refusing to sign."
            )));
        }
    }
    let block = rpc.call("eth_getBlockByNumber", json!(["latest", false]))?;
    let timestamp = block
        .as_object()
        .and_then(|block| block.get("timestamp"))
        .ok_or_else(|| Error::network("Cannot read the latest block."))?;
    quantity_u64(timestamp)
}

/// Classify the owner's code and read its nonce and gas balance.
pub fn account_state(rpc: &Rpc, owner: &Address, constants: &Constants) -> Result<AccountState> {
    let owner_text = owner.to_checksum();
    let code = py_str(&rpc.call("eth_getCode", json!([owner_text, "latest"]))?).to_lowercase();
    let (kind, target) = if ["0x", "0x0", ""].contains(&code.as_str()) {
        (AccountKind::Plain, String::new())
    } else if code.starts_with(DELEGATION_PREFIX) && code.chars().count() == 48 {
        let target = format!("0x{}", &code[8..]);
        let kind = if target == constants.implementation.to_lower() { AccountKind::Pinned } else { AccountKind::Other };
        (kind, target)
    } else {
        (AccountKind::Contract, String::new())
    };
    let nonce = quantity_u64(&rpc.call("eth_getTransactionCount", json!([owner_text, "pending"]))?)?;
    let balance = quantity(&rpc.call("eth_getBalance", json!([owner_text, "latest"]))?)?;
    Ok(AccountState { kind, target, nonce, balance })
}

/// Why the account state forbids signing, or None. Installs and revocations
/// follow the same rule (``_install`` is kept for callers): a plain account is
/// delegated by the transaction itself, a foreign delegation or a contract is
/// refused.
pub fn refuse_state(state: &AccountState, _install: bool) -> Option<String> {
    match state.kind {
        AccountKind::Other => Some(format!(
            "This account is already delegated (EIP-7702) to another contract, {}. The signer never overwrites someone else's delegation: that contract may hold your wallet's settings or funds logic. Remove that delegation with the wallet that set it, or use a different (dedicated) account.",
            state.target
        )),
        AccountKind::Contract => Some("This address is a contract, not an externally owned account.".into()),
        // A plain account may still store a dormant grant (its storage outlives the
        // delegation): a revocation re-delegates it in the same type-4 transaction.
        AccountKind::Plain | AccountKind::Pinned => None,
    }
}

/// EIP-1559 fees: (maxFeePerGas, maxPriorityFeePerGas).
pub fn fees(rpc: &Rpc) -> Result<(U256, U256)> {
    let gas_price = quantity(&rpc.call("eth_gasPrice", json!([]))?)?;
    let block = rpc.call("eth_getBlockByNumber", json!(["latest", false]))?;
    let base = match block.as_object() {
        Some(block) => quantity(block.get("baseFeePerGas").unwrap_or(&json!("0x0")))?,
        None => U256::ZERO,
    };
    let tip = if gas_price > base { (gas_price - base).max(U256::from(1)) } else { U256::from(1) };
    Ok((base.saturating_mul(U256::from(2)).saturating_add(tip), tip))
}

/// Sign the owner's EIP-7702 authorization for the pinned delegate with
/// ``nonce + 1`` (``nonce`` is the transaction nonce).
pub fn sign_authorization(material: &KeyMaterial, constants: &Constants, nonce: u64) -> Result<Authorization> {
    let raw = material.raw()?;
    Authorization::sign(raw, constants.chain_id, constants.implementation, nonce + 1)
        .ok_or_else(|| Error::key("The key was already wiped."))
}

fn rpc_authorization(authorization: &Authorization) -> Value {
    json!({
        "chainId": py_hex(U256::from(authorization.chain_id)),
        "address": authorization.address.to_lower(),
        "nonce": py_hex(U256::from(authorization.nonce)),
        "yParity": py_hex(U256::from(authorization.signature.y_parity)),
        "r": py_hex(U256::from_be_bytes(authorization.signature.r)),
        "s": py_hex(U256::from_be_bytes(authorization.signature.s)),
    })
}

fn margin(estimate: U256, extra: u64) -> U256 {
    estimate.saturating_mul(U256::from(6)) / U256::from(5) + U256::from(extra)
}

/// Estimate the transaction's gas with a safety margin; returns the limit
/// and how it was obtained.
pub fn estimate_gas(rpc: &Rpc, owner: &Address, data: &str, authorization: Option<&Authorization>, fallback: u64) -> Result<(U256, String)> {
    let owner_text = owner.to_checksum();
    let call = json!({"from": owner_text, "to": owner_text, "data": data, "value": "0x0"});
    if let Some(authorization) = authorization {
        let mut with_list = call.clone();
        with_list["authorizationList"] = json!([rpc_authorization(authorization)]);
        match rpc.call("eth_estimateGas", json!([with_list])).and_then(|value| quantity(&value)) {
            Ok(estimate) => {
                return Ok((margin(estimate, AUTHORIZATION_GAS), "eth_estimateGas with authorizationList".into()))
            }
            Err(error) if error.is_network() => {}
            Err(error) => return Err(error),
        }
        let mut override_map = Map::new();
        override_map.insert(owner_text.clone(), json!({"code": format!("{DELEGATION_PREFIX}{}", &authorization.address.to_lower()[2..])}));
        return match rpc.call("eth_estimateGas", json!([call, "latest", Value::Object(override_map)])).and_then(|value| quantity(&value)) {
            Ok(estimate) => Ok((margin(estimate, 2 * AUTHORIZATION_GAS), "eth_estimateGas with a delegation override".into())),
            Err(error) if error.is_network() => Ok((
                U256::from(fallback),
                "fixed fallback limit (the RPC could not estimate a type-4 transaction)".into(),
            )),
            Err(error) => Err(error),
        };
    }
    let estimate = match rpc.call("eth_estimateGas", json!([call])).and_then(|value| quantity(&value)) {
        Ok(estimate) => estimate,
        Err(error) if error.is_network() => {
            return Err(Error::chain(format!("The transaction would fail on chain: {error}")))
        }
        Err(error) => return Err(error),
    };
    Ok((margin(estimate, 10_000), "eth_estimateGas".into()))
}

/// The signed raw transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransaction {
    /// ``0x`` raw transaction.
    pub raw: String,
    /// ``0x`` hash.
    pub hash: String,
    /// 2 or 4.
    pub tx_type: u8,
}

/// Sign the value-0 self-call (type 4 with an authorization, else type 2).
#[allow(clippy::too_many_arguments)]
pub fn sign_transaction(
    material: &KeyMaterial,
    constants: &Constants,
    owner: &Address,
    data: &str,
    nonce: u64,
    gas: U256,
    max_fee: U256,
    tip: U256,
    authorization: Option<Authorization>,
) -> Result<SignedTransaction> {
    let raw_key = material.raw()?;
    let calldata = hex::decode(data.strip_prefix("0x").unwrap_or(data)).map_err(|_| Error::plan("Plan calldata is not hex."))?;
    let transaction = Transaction {
        chain_id: constants.chain_id,
        nonce,
        max_priority_fee_per_gas: tip,
        max_fee_per_gas: max_fee,
        gas,
        to: *owner,
        data: calldata,
        authorization_list: authorization.map(|item| vec![item]),
    };
    let (raw, hash) = transaction.sign(raw_key).ok_or_else(|| Error::key("The key was already wiped."))?;
    Ok(SignedTransaction { raw: hex0x(&raw), hash: hex0x(&hash), tx_type: transaction.tx_type() })
}

/// Send the signed transaction; the node must return the same hash.
pub fn broadcast(rpc: &Rpc, raw: &str, expected_hash: &str) -> Result<String> {
    let sent = py_str(&rpc.call("eth_sendRawTransaction", json!([raw]))?).to_lowercase();
    if sent != expected_hash.to_lowercase() {
        return Err(Error::chain(format!("The RPC returned hash {sent}, expected {expected_hash}.")));
    }
    Ok(sent)
}

/// Receipt polling (``wait_receipt``): timeout and interval.
#[derive(Clone, Copy, Debug)]
pub struct Polling {
    /// Give up after this long.
    pub timeout: Duration,
    /// Poll interval.
    pub interval: Duration,
}

impl Default for Polling {
    fn default() -> Self {
        Polling { timeout: Duration::from_secs(300), interval: Duration::from_secs(2) }
    }
}

/// Wait until the transaction is mined; refuses a reverted one.
pub fn wait_receipt(rpc: &Rpc, tx_hash: &str, polling: Polling) -> Result<Map<String, Value>> {
    let deadline = Instant::now() + polling.timeout;
    loop {
        let receipt = rpc.call("eth_getTransactionReceipt", json!([tx_hash])).ok();
        if let Some(Value::Object(receipt)) = receipt {
            if receipt.get("blockNumber").map(truthy).unwrap_or(false) {
                if receipt.get("status").and_then(Value::as_str) != Some("0x1") {
                    return Err(Error::chain(format!("Transaction {tx_hash} reverted on chain.")));
                }
                return Ok(receipt);
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::chain(format!(
                "Transaction {tx_hash} is not mined after {} s. Check it on https://browser.anubispace.org before trying again.",
                polling.timeout.as_secs()
            )));
        }
        std::thread::sleep(polling.interval);
    }
}

/// Read the session key stored for a grant (zero address when absent).
pub fn read_grant_key(rpc: &Rpc, owner: &Address, grant_id: &str, kind: GrantKind) -> Result<Address> {
    let (getter, _) = kind.getter();
    let data = format!("{}{}", c::selector(getter), grant_id.get(2..).unwrap_or_default().to_lowercase());
    let raw = py_str(&rpc.call("eth_call", json!([{"to": owner.to_checksum(), "data": data}, "latest"]))?);
    let bytes = hex::decode(raw.get(2..).unwrap_or_default()).map_err(|_| Error::network(format!("Cannot decode {getter}.")))?;
    crate::abi::decode_getter_key(&bytes, kind == GrantKind::Session).map_err(|_| Error::network(format!("Cannot decode {getter}.")))
}

/// Helix7702Account storage layout (``forge inspect Helix7702Account
/// storageLayout``): base slot of ``grants`` and ``policyGrants``. The
/// session key is the low 20 bytes of the first word of each struct.
pub fn grant_mapping_slot(kind: GrantKind) -> u64 {
    match kind {
        GrantKind::Session => 0,
        GrantKind::Policy => 2,
    }
}

/// Storage slot of ``mapping(bytes32 => ...)[grant_id]`` at a base slot.
pub fn mapping_slot(grant_id: &str, base: u64) -> Result<[u8; 32]> {
    let mut preimage = hex::decode(grant_id.get(2..).unwrap_or_default())
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| Error::plan(format!("Grant ID {grant_id} is not 32 bytes of hex.")))?;
    preimage.extend_from_slice(&U256::from(base).to_be_bytes::<32>());
    Ok(keccak(&preimage))
}

/// Read a grant's session key straight from the account's storage, for an
/// account that is not delegated to the pinned implementation (an
/// ``eth_call`` would not run the Helix getters there).
pub fn read_stored_grant_key(rpc: &Rpc, owner: &Address, grant_id: &str, kind: GrantKind) -> Result<Address> {
    let slot = mapping_slot(grant_id, grant_mapping_slot(kind))?;
    let raw = py_str(&rpc.call("eth_getStorageAt", json!([owner.to_checksum(), hex0x(&slot), "latest"]))?);
    let word = quantity(&json!(if raw == "0x" { "0x0".to_string() } else { raw }))?.to_be_bytes::<32>();
    Ok(Address(word[12..].try_into().expect("20 bytes")))
}

/// The stored session key of a grant, however the account is delegated now.
pub fn grant_key(rpc: &Rpc, state: &AccountState, owner: &Address, grant_id: &str, kind: GrantKind) -> Result<Address> {
    match state.kind {
        AccountKind::Pinned => read_grant_key(rpc, owner, grant_id, kind),
        _ => read_stored_grant_key(rpc, owner, grant_id, kind),
    }
}

/// Whether a grant ID is stored as a policy or session grant, read the way
/// ``grant_key`` reads (storage for an account not delegated to Helix).
pub fn detect_stored_grant_kind(rpc: &Rpc, state: &AccountState, owner: &Address, grant_id: &str) -> Result<Option<GrantKind>> {
    for kind in [GrantKind::Policy, GrantKind::Session] {
        if !grant_key(rpc, state, owner, grant_id, kind)?.is_zero() {
            return Ok(Some(kind));
        }
    }
    Ok(None)
}

/// After a revocation: the account is delegated to the pinned implementation
/// (a revocation of a dormant grant re-delegated it) and the key is cleared.
pub fn verify_revoke(rpc: &Rpc, owner: &Address, grant_id: &str, kind: GrantKind, constants: &Constants) -> Result<()> {
    let code = py_str(&rpc.call("eth_getCode", json!([owner.to_checksum(), "latest"]))?).to_lowercase();
    if code != format!("{DELEGATION_PREFIX}{}", &constants.implementation.to_lower()[2..]) {
        let shown: String = code.chars().take(60).collect();
        return Err(Error::chain(format!("After the transaction the account code is {shown}, not the Helix delegation.")));
    }
    if !read_grant_key(rpc, owner, grant_id, kind)?.is_zero() {
        return Err(Error::chain("The grant still has a session key after the transaction."));
    }
    Ok(())
}

/// Check the delegation, the install event and the stored grant.
pub fn verify_install(rpc: &Rpc, owner: &Address, grant_id: &str, session_key: &Address, receipt: &Map<String, Value>, constants: &Constants) -> Result<()> {
    let code = py_str(&rpc.call("eth_getCode", json!([owner.to_checksum(), "latest"]))?).to_lowercase();
    if code != format!("{DELEGATION_PREFIX}{}", &constants.implementation.to_lower()[2..]) {
        let shown: String = code.chars().take(60).collect();
        return Err(Error::chain(format!("After the transaction the account code is {shown}, not the Helix delegation.")));
    }
    let topic_key = format!("0x{:0>64}", &session_key.to_lower()[2..]);
    let wanted = [c::policy_installed_topic(), grant_id.to_lowercase(), topic_key];
    let logs = receipt.get("logs").and_then(Value::as_array).cloned().unwrap_or_default();
    let found = logs.iter().filter_map(Value::as_object).any(|log| {
        let address = log.get("address").map(py_str).unwrap_or_default().to_lowercase();
        let topics: Vec<String> = log
            .get("topics")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(|topic| py_str(topic).to_lowercase()).collect())
            .unwrap_or_default();
        address == owner.to_lower() && topics.iter().take(3).cloned().collect::<Vec<_>>() == wanted
    });
    if !found {
        return Err(Error::chain("The receipt has no PolicyGrantInstalled event for this grant."));
    }
    if read_grant_key(rpc, owner, grant_id, GrantKind::Policy)? != *session_key {
        return Err(Error::chain("policyGrants does not hold the hosted session key for this grant."));
    }
    Ok(())
}

/// Whether a grant ID is a live policy or session grant.
pub fn detect_grant_kind(rpc: &Rpc, owner: &Address, grant_id: &str) -> Result<Option<GrantKind>> {
    for kind in [GrantKind::Policy, GrantKind::Session] {
        if !read_grant_key(rpc, owner, grant_id, kind)?.is_zero() {
            return Ok(Some(kind));
        }
    }
    Ok(None)
}
