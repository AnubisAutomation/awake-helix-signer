//! An in-memory Anubis chain and website behind the `HttpClient` trait (the
//! Rust counterpart of the Python signer's `tests/fakes.py`), so the flows
//! run in-process without any network.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use helix_signer_core::abi::{encode_install, InstallCall, RawRule};
use helix_signer_core::address::{hex0x, keccak, Address};
use helix_signer_core::constants::{self as c, GrantKind};
use helix_signer_core::net::{HttpClient, HttpRequest, HttpResponse, TransportError};
use helix_signer_core::secp;
use helix_signer_core::tx::Rlp;
use helix_signer_core::{attestation_digest, Constants, KeyMaterial, Transport, U256};
use serde_json::{json, Map, Value};

pub const API: &str = "http://127.0.0.1:18000";
pub const RPC: &str = "http://127.0.0.1:18545/rpc";
pub const TOKEN: &str = "tok_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
pub const IMPLEMENTATION_CODE: &[u8] = b"\x60\x80\x60\x40\x52helix-test-implementation";

pub fn key(label: &str) -> KeyMaterial {
    KeyMaterial::from_private_key(&hex::encode(keccak(label.as_bytes()))).unwrap()
}

pub fn attestor() -> KeyMaterial {
    key("awake-helix signer tests: attestation key")
}

pub fn session_key() -> Address {
    key("awake-helix signer tests: session key").address()
}

pub fn constants() -> Constants {
    helix_signer_core::production()
        .with_overrides(&json!({
            "implementation": c::IMPLEMENTATION,
            "implementationCodeHash": hex0x(&keccak(IMPLEMENTATION_CODE)),
            "attestationAddress": attestor().address().to_checksum(),
        }))
        .unwrap()
}

pub fn now() -> u64 {
    helix_signer_core::plan::unix_now()
}

pub fn rule(kind: u8, target: &str, maximum: u128) -> RawRule {
    RawRule {
        kind,
        target: Address::constant(target),
        token_in: Address::ZERO,
        counterparty: Address::ZERO,
        max_amount: U256::from(maximum),
        max_secondary: U256::ZERO,
        max_daily: U256::from(maximum),
        min_out_per_in_wad: U256::ZERO,
        max_deadline_delay: 0,
        usage_day: 0,
        used_today: U256::ZERO,
    }
}

pub fn dai_power() -> Vec<RawRule> {
    let wad = 1_000_000_000_000_000_000u128;
    let mut approve = rule(0, c::DAI, 10 * wad);
    approve.counterparty = Address::constant(c::LEDGER);
    vec![approve, rule(1, c::LEDGER, 10 * wad)]
}

pub fn attestation(owner: &Address, bot: &[u8; 16], session: &Address, signer: &KeyMaterial) -> Value {
    let digest = attestation_digest(6714, owner, bot, session);
    let signature = signer.sign_digest(&digest).unwrap();
    json!({
        "version": 1, "chainId": 6714, "owner": owner.to_checksum(),
        "botId": helix_signer_core::plan::uuid_text(bot), "sessionKey": session.to_checksum(),
        "signature": hex0x(&signature.to_bytes_65()),
    })
}

/// A grant plan as the website serves it.
pub fn grant_plan(owner: &Address, rules: Vec<RawRule>, valid_seconds: u64, calls: u64) -> Value {
    let current = now();
    let mut grant_id = [0u8; 32];
    getrandom::getrandom(&mut grant_id).unwrap();
    let mut bot = [0u8; 16];
    getrandom::getrandom(&mut bot).unwrap();
    let session = session_key();
    let call = InstallCall { grant_id, key: session, bot, valid_after: current - 60, valid_until: current + valid_seconds, remaining_calls: calls, rules: rules.clone() };
    let preview: Vec<Value> = rules
        .iter()
        .map(|rule| {
            let signature = c::RULE_METHODS[rule.kind as usize];
            json!({"kind": rule.kind, "method": &signature[..signature.find('(').unwrap()], "target": rule.target.to_checksum(), "counterparty": rule.counterparty.to_checksum()})
        })
        .collect();
    json!({
        "schema": c::PLAN_SCHEMA, "kind": "grant", "chainId": 6714, "owner": owner.to_checksum(),
        "implementation": c::IMPLEMENTATION, "to": owner.to_checksum(), "value": "0x0",
        "data": format!("{}{}", c::install_selector(), hex::encode(encode_install(&call))),
        "grantId": hex0x(&grant_id), "sessionKey": session.to_checksum(),
        "sessionKeyAttestation": attestation(owner, &bot, &session, &attestor()),
        "validUntil": current + valid_seconds, "rules": preview, "bot": {"id": 7, "script": "dai-power"},
        "reportUrl": format!("{API}/api/signer/plans/{TOKEN}/report"),
    })
}

pub fn revoke_plan(owner: &Address, grant_id: &str, kind: GrantKind) -> Value {
    json!({
        "schema": "awake-helix-signer-plan/1", "kind": "revoke", "chainId": 6714, "owner": owner.to_checksum(),
        "implementation": c::IMPLEMENTATION, "to": owner.to_checksum(), "value": "0x0", "grantId": grant_id,
        "grantKind": kind.as_str(), "data": format!("{}{}", c::revoke_selector(kind), &grant_id[2..]),
    })
}

// -- RLP decoding of the signed transactions ----------------------------------

#[derive(Debug, Clone)]
pub enum Item {
    Bytes(Vec<u8>),
    List(Vec<Item>),
}

impl Item {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Item::Bytes(bytes) => bytes,
            Item::List(_) => panic!("not bytes"),
        }
    }

    pub fn list(&self) -> &[Item] {
        match self {
            Item::List(items) => items,
            Item::Bytes(_) => panic!("not a list"),
        }
    }

    pub fn uint(&self) -> U256 {
        U256::from_be_slice(self.bytes())
    }

    fn encode(&self) -> Rlp {
        match self {
            Item::Bytes(bytes) => Rlp::Bytes(bytes.clone()),
            Item::List(items) => Rlp::List(items.iter().map(Item::encode).collect()),
        }
    }
}

fn length(data: &[u8], size: usize) -> usize {
    data[..size].iter().fold(0usize, |acc, byte| (acc << 8) | *byte as usize)
}

pub fn decode(data: &[u8]) -> (Item, usize) {
    let prefix = data[0];
    match prefix {
        0x00..=0x7f => (Item::Bytes(vec![prefix]), 1),
        0x80..=0xb7 => {
            let size = (prefix - 0x80) as usize;
            (Item::Bytes(data[1..1 + size].to_vec()), 1 + size)
        }
        0xb8..=0xbf => {
            let size_of = (prefix - 0xb7) as usize;
            let size = length(&data[1..], size_of);
            (Item::Bytes(data[1 + size_of..1 + size_of + size].to_vec()), 1 + size_of + size)
        }
        _ => {
            let (start, size) = if prefix <= 0xf7 {
                (1, (prefix - 0xc0) as usize)
            } else {
                let size_of = (prefix - 0xf7) as usize;
                (1 + size_of, length(&data[1..], size_of))
            };
            let mut items = Vec::new();
            let mut cursor = start;
            while cursor < start + size {
                let (item, used) = decode(&data[cursor..]);
                items.push(item);
                cursor += used;
            }
            (Item::List(items), start + size)
        }
    }
}

fn word(item: &Item) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = item.bytes();
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

/// One transaction the fake chain executed.
#[derive(Debug, Clone)]
pub struct Sent {
    pub tx_type: u8,
    pub raw: Vec<u8>,
    pub sender: Address,
    pub nonce: u64,
    pub to: Address,
    pub data: Vec<u8>,
    pub gas: U256,
    pub authorities: Vec<(Address, u64, Address)>,
}

/// How the fake website answers ``POST .../customize``: (status, body) of (plan, request).
pub type CustomizeAnswer = Box<dyn Fn(&Value, &Value) -> (u16, Value) + Send>;

/// Chain and website state.
#[derive(Default)]
pub struct State {
    pub chain_id: u64,
    pub code: HashMap<Address, Vec<u8>>,
    pub nonces: HashMap<Address, u64>,
    pub balances: HashMap<Address, U256>,
    pub policy: HashMap<Address, HashMap<String, Address>>,
    pub session: HashMap<Address, HashMap<String, Address>>,
    pub receipts: HashMap<String, Value>,
    pub sent: Vec<Sent>,
    pub estimate_with_authorization: bool,
    pub estimate_with_override: bool,
    pub block: u64,
    pub plans: HashMap<String, Value>,
    pub fetched: HashSet<String>,
    pub reports: Vec<(String, String)>,
    pub report_status: u16,
    pub customize: Option<CustomizeAnswer>,
    pub customized: Vec<Value>,
    pub challenges: HashMap<String, String>,
    pub sessions: HashMap<String, String>,
    pub grants: HashMap<String, Vec<Value>>,
    pub confirmations: Vec<(String, String)>,
    pub logged_out: usize,
    pub requests: Vec<(String, String)>,
    pub login_domain: String,
    /// The chain drops every EIP-7702 authorization (to test the checks after a revocation).
    pub ignore_authorizations: bool,
}

#[derive(Clone)]
pub struct Fake {
    pub state: Arc<Mutex<State>>,
}

fn ok(body: Value) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse { status: 200, headers: vec![], body: serde_json::to_vec(&body).unwrap() })
}

fn status(code: u16, body: Value) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse { status: code, headers: vec![], body: serde_json::to_vec(&body).unwrap() })
}

fn quantity(value: u64) -> String {
    format!("{value:#x}")
}

/// ``extraData`` of Anubis mainnet block 19,222,581: 280 bytes of
/// proof-of-authority data (vanity, validator signature, vote attestation).
/// Clients that require Ethereum's 32-byte limit fail on every real block;
/// forks mine empty extraData and never showed it.
pub const MAINNET_EXTRA_DATA: &str = concat!(
    "0xda8301000188343861393536636288676f312e32362e31836c696e00effaa169f8b5831e",
    "ffffb86090b4e56ef878e649ec700cc20537cc8649581cfad20e86103d340e79c166bed548",
    "82725b7b5cacaaabb57fd12f9881b7087f712dd9a6b1bfaeab8ff88e7fea293ce23af16e86",
    "0db3437a978137dad660d5e1c9fdf1c593133d71f75633f86f4ef84c8401255033a05e284e",
    "d937bfa3b55f6549bf8fc7eb00a1fbba23b9aeee5f0ddc4cf34ebc1a578401255034a06a8b",
    "912eef12d0519746007514ff25aa3fe502357513efe933094e6b0ff05c758094d9afbd373d",
    "990d551149553febd73c47684fc8aa460ed3fa1376d2377675055e4782f0fbdeaa4e8bbb11",
    "a45963df14248235dc8b21c2f51edf476091e21daa00",
);

/// An ``eth_getBlockByNumber`` result shaped like a real Anubis header.
pub fn anubis_block(number: u64, timestamp: u64) -> Value {
    json!({
        "baseFeePerGas": "0x0", "blobGasUsed": "0x0", "difficulty": "0x2", "excessBlobGas": "0x0",
        "extraData": MAINNET_EXTRA_DATA, "gasLimit": "0x5f5e100", "gasUsed": "0x577a9e",
        "hash": format!("0x{:064x}", number), "logsBloom": format!("0x{}", "00".repeat(256)),
        "milliTimestamp": quantity(timestamp * 1000), "miner": "0x01654850a9c457e3cb8d2d9672ab3abea00bb16b",
        "mixHash": format!("0x{:064x}", 0x2bc), "nonce": "0x0000000000000000", "number": quantity(number),
        "parentBeaconBlockRoot": format!("0x{}", "00".repeat(32)), "parentHash": format!("0x{:064x}", number.saturating_sub(1)),
        "receiptsRoot": "0x131dd446b8dd3b80aea9d4e481a7002b651145ef44ee60fe462963fcb2deeaf7",
        "requestsHash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "size": "0xbef",
        "stateRoot": "0xcf8a87b5f10492f1588ae9ff71d854b090411fb31f5a7ad4473cf64faf986ef0",
        "timestamp": quantity(timestamp), "totalDifficulty": "0x24a9fde", "transactions": [],
        "transactionsRoot": "0x67d36cdee0efa779dc599cb202ad2336df2c94aea04770708648a9a73b2f1407",
        "uncles": [], "withdrawals": [],
        "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    })
}

impl Fake {
    pub fn new() -> Fake {
        let mut state = State { chain_id: 6714, estimate_with_authorization: true, estimate_with_override: true, block: 100, report_status: 200, login_domain: "127.0.0.1:18000".into(), ..State::default() };
        state.code.insert(Address::constant(c::IMPLEMENTATION), IMPLEMENTATION_CODE.to_vec());
        Fake { state: Arc::new(Mutex::new(state)) }
    }

    pub fn transport(&self) -> Transport {
        Transport::single(Arc::new(self.clone()))
    }

    pub fn delegate(&self, owner: &Address, target: &str) {
        let mut code = hex::decode("ef0100").unwrap();
        code.extend_from_slice(&Address::constant(target).0);
        self.state.lock().unwrap().code.insert(*owner, code);
    }

    fn rpc(&self, body: &Value) -> Result<HttpResponse, TransportError> {
        let method = body["method"].as_str().unwrap_or_default();
        let params = body["params"].as_array().cloned().unwrap_or_default();
        let id = body["id"].clone();
        match self.answer(method, &params) {
            Ok(result) => ok(json!({"jsonrpc": "2.0", "id": id, "result": result})),
            Err(message) => ok(json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": message}})),
        }
    }

    fn answer(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        let mut state = self.state.lock().unwrap();
        let address = |index: usize| Address::parse(params[index].as_str().unwrap_or_default()).unwrap_or_default();
        match method {
            "eth_chainId" => Ok(json!(quantity(state.chain_id))),
            "eth_getCode" => Ok(json!(hex0x(state.code.get(&address(0)).map(Vec::as_slice).unwrap_or(&[])))),
            "eth_getBlockByNumber" => Ok(anubis_block(state.block, now())),
            "eth_getTransactionCount" => Ok(json!(quantity(*state.nonces.get(&address(0)).unwrap_or(&0)))),
            "eth_getBalance" => Ok(json!(format!("{:#x}", state.balances.get(&address(0)).copied().unwrap_or_default()))),
            "eth_gasPrice" => Ok(json!(quantity(12_000_000_000))),
            "eth_estimateGas" => {
                if params[0].get("authorizationList").is_some() && !state.estimate_with_authorization {
                    return Err("authorizationList not supported".into());
                }
                if params.len() == 3 && !state.estimate_with_override {
                    return Err("state override not supported".into());
                }
                Ok(json!(quantity(300_000)))
            }
            "eth_getTransactionReceipt" => Ok(state.receipts.get(&params[0].as_str().unwrap_or_default().to_lowercase()).cloned().unwrap_or(Value::Null)),
            "eth_getStorageAt" => {
                // Helix7702Account layout: grants at slot 0, policyGrants at slot 2.
                let owner = address(0);
                let slot = params[1].as_str().unwrap_or_default().to_lowercase();
                for (table, base) in [(&state.policy, GrantKind::Policy), (&state.session, GrantKind::Session)] {
                    for (grant, key) in table.get(&owner).into_iter().flatten() {
                        let expected = helix_signer_core::chain::mapping_slot(grant, helix_signer_core::chain::grant_mapping_slot(base)).unwrap();
                        if hex0x(&expected) == slot {
                            return Ok(json!(hex0x(&key.word())));
                        }
                    }
                }
                Ok(json!(format!("0x{}", "0".repeat(64))))
            }
            "eth_call" => {
                let owner = Address::parse(params[0]["to"].as_str().unwrap_or_default()).unwrap_or_default();
                let mut pinned = hex::decode("ef0100").unwrap();
                pinned.extend_from_slice(&Address::constant(c::IMPLEMENTATION).0);
                if state.code.get(&owner) != Some(&pinned) {
                    // No Helix code runs at an account that is not delegated to it.
                    return Ok(json!("0x"));
                }
                let data = params[0]["data"].as_str().unwrap_or_default().to_lowercase();
                let grant = format!("0x{}", &data[10..]);
                let (table, words) = if data.starts_with(&c::selector(c::POLICY_GETTER)) { (&state.policy, 5) } else { (&state.session, 6) };
                let found = table.get(&owner).and_then(|grants| grants.get(&grant)).copied().unwrap_or_default();
                Ok(json!(format!("0x{}{}", hex::encode(found.word()), "0".repeat(64 * (words - 1)))))
            }
            "eth_sendRawTransaction" => {
                let raw = hex::decode(params[0].as_str().unwrap_or_default().trim_start_matches("0x")).map_err(|e| e.to_string())?;
                execute(&mut state, raw)
            }
            other => Err(format!("unsupported {other}")),
        }
    }
}

fn execute(state: &mut State, raw: Vec<u8>) -> Result<Value, String> {
    let tx_type = raw[0];
    let (fields, _) = decode(&raw[1..]);
    let fields = fields.list().to_vec();
    let signed = fields.len() - 3;
    let unsigned = Rlp::List(fields[..signed].iter().map(Item::encode).collect());
    let mut message = vec![tx_type];
    message.extend(unsigned.encode());
    let digest = keccak(&message);
    let parity = fields[signed].uint().to::<u8>();
    let sender = secp::recover(&digest, &word(&fields[signed + 1]), &word(&fields[signed + 2]), parity).ok_or("bad signature")?;
    let chain_id = fields[0].uint().to::<u64>();
    let nonce = fields[1].uint().to::<u64>();
    let max_fee = fields[3].uint();
    let gas = fields[4].uint();
    let to = Address(fields[5].bytes().try_into().map_err(|_| "bad to")?);
    let value = fields[6].uint();
    let data = fields[7].bytes().to_vec();
    if chain_id != state.chain_id || !value.is_zero() {
        return Err("bad chain or value".into());
    }
    if nonce != *state.nonces.get(&sender).unwrap_or(&0) {
        return Err("bad nonce".into());
    }
    let cost = gas * max_fee;
    if state.balances.get(&sender).copied().unwrap_or_default() < cost {
        return Err("insufficient balance".into());
    }
    state.nonces.insert(sender, nonce + 1);
    let mut authorities = Vec::new();
    if tx_type == 4 {
        for entry in fields[9].list() {
            let entry = entry.list();
            let auth_chain = entry[0].uint().to::<u64>();
            let target = Address(entry[1].bytes().try_into().unwrap());
            let auth_nonce = entry[2].uint().to::<u64>();
            let digest = helix_signer_core::tx::Authorization::digest(auth_chain, &target, auth_nonce);
            let authority = secp::recover(&digest, &word(&entry[4]), &word(&entry[5]), entry[3].uint().to::<u8>()).unwrap();
            authorities.push((authority, auth_nonce, target));
            // EIP-7702: valid only at the authority's current nonce (the sender's is already bumped).
            if !state.ignore_authorizations && (auth_chain == 0 || auth_chain == state.chain_id) && auth_nonce == *state.nonces.get(&authority).unwrap_or(&0) {
                let mut code = hex::decode("ef0100").unwrap();
                code.extend_from_slice(&target.0);
                state.code.insert(authority, code);
                *state.nonces.entry(authority).or_default() += 1;
            }
        }
    }
    let pinned = {
        let mut code = hex::decode("ef0100").unwrap();
        code.extend_from_slice(&Address::constant(c::IMPLEMENTATION).0);
        code
    };
    let delegated = state.code.get(&to) == Some(&pinned);
    let data_hex = hex0x(&data);
    let mut logs = Vec::new();
    if to == sender && delegated && data_hex.starts_with(&c::install_selector()) {
        let call = helix_signer_core::abi::decode_install(&data[4..]).map_err(|_| "bad calldata")?;
        let grant = hex0x(&call.grant_id);
        state.policy.entry(to).or_default().insert(grant.clone(), call.key);
        logs.push(json!({"address": to.to_lower(), "topics": [c::policy_installed_topic(), grant, hex0x(&call.key.word())]}));
    } else if to == sender && delegated && (data_hex.starts_with(&c::revoke_selector(GrantKind::Policy)) || data_hex.starts_with(&c::revoke_selector(GrantKind::Session))) {
        let grant = format!("0x{}", &data_hex[10..]);
        let table = if data_hex.starts_with(&c::revoke_selector(GrantKind::Policy)) { &mut state.policy } else { &mut state.session };
        table.entry(to).or_default().remove(&grant);
    }
    let balance = state.balances.get(&sender).copied().unwrap_or_default();
    state.balances.insert(sender, balance - gas * U256::from(6_000_000_000u64));
    state.block += 1;
    let hash = hex0x(&keccak(&raw));
    let block = state.block;
    state.receipts.insert(hash.clone(), json!({"transactionHash": hash, "status": "0x1", "blockNumber": quantity(block), "gasUsed": format!("{:#x}", gas / U256::from(2)), "logs": logs}));
    state.sent.push(Sent { tx_type, raw, sender, nonce, to, data, gas, authorities });
    Ok(json!(hash))
}

impl Fake {
    fn website(&self, request: &HttpRequest, path: &str) -> Result<HttpResponse, TransportError> {
        let body: Value = request.body.as_ref().map(|body| serde_json::from_slice(body).unwrap_or(Value::Null)).unwrap_or(Value::Null);
        let mut state = self.state.lock().unwrap();
        state.requests.push((request.method.clone(), path.to_string()));
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        if parts.len() >= 4 && parts[..3] == ["api", "signer", "plans"] {
            let token = parts[3].to_string();
            if parts.len() == 4 && request.method == "GET" {
                let Some(plan) = state.plans.get(&token).cloned() else { return status(404, json!({"error": "unknown"})) };
                if !state.fetched.insert(token) {
                    return status(410, json!({"error": "used"}));
                }
                return ok(plan);
            }
            if parts.get(4) == Some(&"report") {
                state.reports.push((token, body["txHash"].as_str().unwrap_or_default().to_string()));
                let code = state.report_status;
                return if code == 200 { ok(json!({"ok": true, "status": "done"})) } else { status(code, json!({"error": "rejected"})) };
            }
            if parts.get(4) == Some(&"customize") {
                state.customized.push(body["grant"].clone());
                let plan = state.plans.get(&token).cloned().unwrap_or(Value::Null);
                let (code, answer) = (state.customize.as_ref().expect("customize answer"))(&plan, &body["grant"]);
                return status(code, answer);
            }
        }
        let cookies: HashMap<String, String> = request
            .header("Cookie")
            .unwrap_or_default()
            .split("; ")
            .filter_map(|pair| pair.split_once('=').map(|(name, value)| (name.to_string(), value.to_string())))
            .collect();
        let csrf_ok = cookies.get("csrftoken").map(|token| Some(token.as_str()) == request.header("X-CSRFToken")).unwrap_or(false) && request.header("Origin").is_some();
        let cookie = |text: &str| ("Set-Cookie".to_string(), text.to_string());
        match path {
            "/api/csrf" => {
                let origin = format!("http://{}", state.login_domain);
                return Ok(HttpResponse { status: 200, headers: vec![cookie("csrftoken=csrf-1; Path=/")], body: serde_json::to_vec(&json!({"csrfToken": "csrf-1", "origin": origin})).unwrap() });
            }
            "/api/auth/challenge" => {
                if !csrf_ok {
                    return status(403, json!({"error": "CSRF verification failed."}));
                }
                let wallet = body["wallet"].as_str().unwrap_or_default().to_string();
                let domain = state.login_domain.clone();
                let message = format!("{domain} wants you to sign in with your Ethereum account:\n{wallet}\n\nx\n\nURI: http://{domain}\nVersion: 1\nChain ID: 6714\nNonce: 1\nIssued At: now");
                state.challenges.insert(wallet, message.clone());
                return ok(json!({"message": message}));
            }
            "/api/auth/verify" => {
                let wallet = body["wallet"].as_str().unwrap_or_default().to_string();
                let message = body["message"].as_str().unwrap_or_default();
                if !csrf_ok || state.challenges.get(&wallet).map(String::as_str) != Some(message) {
                    return status(400, json!({"error": "expired"}));
                }
                let mut signature = [0u8; 65];
                hex::decode_to_slice(&body["signature"].as_str().unwrap_or_default()[2..], &mut signature).unwrap();
                let signer = secp::recover_65(&secp::personal_digest(message.as_bytes()), &signature).unwrap();
                if signer.to_lower() != wallet {
                    return status(400, json!({"error": "mismatch"}));
                }
                state.sessions.insert("session-1".into(), wallet.clone());
                return Ok(HttpResponse {
                    status: 200,
                    headers: vec![cookie("sessionid=session-1; HttpOnly; Path=/"), cookie("csrftoken=csrf-2; Path=/")],
                    body: serde_json::to_vec(&json!({"wallet": wallet})).unwrap(),
                });
            }
            "/api/auth/logout" => {
                state.logged_out += 1;
                return Ok(HttpResponse { status: 200, headers: vec![cookie("sessionid=\"\"; Max-Age=0; Path=/")], body: b"{\"ok\": true}".to_vec() });
            }
            _ => {}
        }
        let Some(owner) = cookies.get("sessionid").and_then(|session| state.sessions.get(session)).cloned() else {
            return status(401, json!({"error": "login"}));
        };
        if path == "/api/grants" {
            let grants = state.grants.get(&owner).cloned().unwrap_or_default();
            return ok(json!({"owner": owner, "grants": grants, "scan": {"complete": true, "percent": 100}, "truncated": false, "delegation": {}}));
        }
        if parts.len() == 4 && parts[..2] == ["api", "grants"] {
            if !csrf_ok {
                return status(403, json!({"error": "CSRF verification failed."}));
            }
            let grant = parts[2].to_string();
            let owner_address = Address::parse(&owner).unwrap();
            if parts[3] == "revoke-call" {
                if !state.policy.get(&owner_address).map(|grants| grants.contains_key(&grant)).unwrap_or(false) {
                    return status(409, json!({"error": "revoked"}));
                }
                let mut pinned = hex::decode("ef0100").unwrap();
                pinned.extend_from_slice(&Address::constant(c::IMPLEMENTATION).0);
                if state.code.get(&owner_address).map(|code| !code.is_empty() && *code != pinned).unwrap_or(false) {
                    // Like the website: a grant under a foreign delegation is not revocable.
                    return status(409, json!({"error": "foreign delegation", "status": "inactive", "reason": "otherDelegation"}));
                }
                return ok(json!({"to": owner, "data": format!("{}{}", c::revoke_selector(GrantKind::Policy), &grant[2..]), "value": "0x0", "chainId": 6714, "grantId": grant, "kind": "policy"}));
            }
            if parts[3] == "revoke-confirm" {
                state.confirmations.push((grant, body["txHash"].as_str().unwrap_or_default().to_string()));
                return ok(json!({"ok": true, "status": "revoked", "stoppedBots": [7]}));
            }
        }
        status(404, json!({"error": "not found"}))
    }
}

impl HttpClient for Fake {
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        let path = helix_signer_core::net::urlsplit(&request.url).unwrap().path;
        if path == "/rpc" {
            let body: Value = serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}")).unwrap();
            return self.rpc(&body);
        }
        self.website(request, &path)
    }
}

pub fn map(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}
