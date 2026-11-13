//! The sign, customize and revoke flows against the in-memory chain and
//! website (`common`), through the public API the CLI and the app use.

mod common;

use std::time::Duration;

use common::*;
use helix_signer_core::chain::Polling;
use helix_signer_core::constants::{self as c, GrantKind};
use helix_signer_core::custom::{self, CustomizeRequest};
use helix_signer_core::{flow, Address, ErrorKind, KeyMaterial, RevokeSource, Session, Website, U256};
use serde_json::{json, Value};

const WAD: u128 = 1_000_000_000_000_000_000;

struct World {
    fake: Fake,
    key: KeyMaterial,
    owner: Address,
}

fn world() -> World {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let key = KeyMaterial::from_private_key(&hex::encode(seed)).unwrap();
    let owner = key.address();
    let fake = Fake::new();
    {
        let mut state = fake.state.lock().unwrap();
        state.balances.insert(owner, U256::from(WAD));
        state.nonces.insert(owner, 3);
    }
    World { fake, key, owner }
}

fn quiet(_: &str) {}

impl World {
    fn serve(&self, plan: Value) {
        self.fake.state.lock().unwrap().plans.insert(TOKEN.into(), plan);
    }

    fn prepare(&self) -> helix_signer_core::Result<Session> {
        flow::prepare_sign(TOKEN, API, RPC, &constants(), Some(&self.key), &self.fake.transport(), &quiet).map(fast)
    }

    fn sent(&self) -> Vec<Sent> {
        self.fake.state.lock().unwrap().sent.clone()
    }
}

fn fast(mut session: Session) -> Session {
    session.polling = Polling { timeout: Duration::from_secs(5), interval: Duration::from_millis(10) };
    session.report_delay = Duration::from_millis(1);
    session
}

#[test]
fn plain_eoa_signs_one_type4_with_nonce_plus_one() {
    let world = world();
    let plan = grant_plan(&world.owner, dai_power(), 7 * 86400, 256);
    world.serve(plan.clone());
    let lines = std::sync::Mutex::new(Vec::new());
    let log = |line: &str| lines.lock().unwrap().push(line.to_string());
    let session = fast(flow::prepare_sign(TOKEN, API, RPC, &constants(), Some(&world.key), &world.fake.transport(), &log).unwrap());
    assert_eq!(session.confirm_word(), "AUTHORIZE");
    let text = session.summary_text();
    for fragment in ["ONE EIP-7702 type-4", "approve on DAI", "spender: PowerLedger", "10 DAI per call", "participate on PowerLedger", "code hash verified"] {
        assert!(text.contains(fragment), "{fragment}\n{text}");
    }
    assert!(session.summary.grant.as_ref().unwrap().delegates);
    let outcome = flow::execute_sign(&session, world.key.clone(), &log).unwrap();
    assert_eq!(outcome.tx_type, 4);
    assert!(outcome.reported);
    let sent = world.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!((sent[0].tx_type, sent[0].nonce, sent[0].sender, sent[0].to), (4, 3, world.owner, world.owner));
    assert_eq!(sent[0].authorities, vec![(world.owner, 4, Address::constant(c::IMPLEMENTATION))]);
    assert_eq!(hex::encode(&sent[0].data), plan["data"].as_str().unwrap()[2..]);
    let state = world.fake.state.lock().unwrap();
    assert_eq!(state.policy[&world.owner][plan["grantId"].as_str().unwrap()], session_key());
    assert_eq!(state.reports, vec![(TOKEN.to_string(), outcome.tx_hash.clone())]);
    let lines = lines.lock().unwrap();
    assert!(lines.iter().any(|line| line.starts_with("Gas limit 385000 (eth_estimateGas with authorizationList)")), "{lines:?}");
    assert!(lines.iter().any(|line| line.starts_with("Confirmed in block 101")));
}

#[test]
fn delegated_account_uses_a_type2_self_call() {
    let world = world();
    world.fake.delegate(&world.owner, c::IMPLEMENTATION);
    world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
    let session = world.prepare().unwrap();
    assert!(session.summary_text().contains("ordinary self-call installing the grant"));
    let outcome = flow::execute_sign(&session, world.key.clone(), &quiet).unwrap();
    assert_eq!(outcome.tx_type, 2);
    assert!(world.sent()[0].authorities.is_empty());
}

#[test]
fn account_states_and_chains_that_are_refused() {
    type Setup = Box<dyn Fn(&World)>;
    let cases: Vec<(Setup, &str)> = vec![
        (Box::new(|w: &World| w.fake.delegate(&w.owner, "0x9999999999999999999999999999999999999999")), "already delegated"),
        (Box::new(|w: &World| {
            w.fake.state.lock().unwrap().code.insert(w.owner, vec![0x60, 0x80]);
        }), "is a contract"),
        (Box::new(|w: &World| w.fake.state.lock().unwrap().chain_id = 1), "not Anubis Chain 6714"),
        (Box::new(|w: &World| {
            w.fake.state.lock().unwrap().code.insert(Address::constant(c::IMPLEMENTATION), b"\x00malicious".to_vec());
        }), "code hash"),
    ];
    for (prepare, fragment) in cases {
        let world = world();
        prepare(&world);
        world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
        let error = world.prepare().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Flow);
        assert!(error.message().contains(fragment), "{fragment}: {error}");
        assert!(world.sent().is_empty());
    }
}

#[test]
fn wrong_key_and_missing_gas_sign_nothing() {
    let world = world();
    world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
    let other = key("another owner");
    let error = flow::prepare_sign(TOKEN, API, RPC, &constants(), Some(&other), &world.fake.transport(), &quiet).unwrap_err();
    assert!(error.message().contains(&format!("controls {}", other.address())), "{error}");
    let world = world_with_balance(1000);
    world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
    let session = world.prepare().unwrap();
    let error = flow::execute_sign(&session, world.key.clone(), &quiet).unwrap_err();
    assert!(error.message().starts_with("Not enough DAI for gas: the owner has 0.000000000000001 DAI"), "{error}");
    assert!(world.sent().is_empty());
}

fn world_with_balance(balance: u64) -> World {
    let world = world();
    world.fake.state.lock().unwrap().balances.insert(world.owner, U256::from(balance));
    world
}

#[test]
fn estimate_fallbacks() {
    for (with_list, with_override, how, gas) in [
        (false, true, "eth_estimateGas with a delegation override", 410_000u64),
        (false, false, "fixed fallback limit (the RPC could not estimate a type-4 transaction)", 840_000),
    ] {
        let world = world();
        {
            let mut state = world.fake.state.lock().unwrap();
            state.estimate_with_authorization = with_list;
            state.estimate_with_override = with_override;
        }
        world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
        let session = world.prepare().unwrap();
        let lines = std::sync::Mutex::new(Vec::new());
        flow::execute_sign(&session, world.key.clone(), &|line| lines.lock().unwrap().push(line.to_string())).unwrap();
        assert!(lines.lock().unwrap().iter().any(|line| line.starts_with(&format!("Gas limit {gas} ({how})"))), "{:?}", lines.lock().unwrap());
        assert_eq!(world.sent()[0].gas, U256::from(gas));
    }
}

#[test]
fn report_refused_still_succeeds_and_server_errors_are_retried() {
    for (status, attempts) in [(409u16, 1usize), (503, 3)] {
        let world = world();
        world.fake.state.lock().unwrap().report_status = status;
        world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
        let session = world.prepare().unwrap();
        let outcome = flow::execute_sign(&session, world.key.clone(), &quiet).unwrap();
        assert!(!outcome.reported);
        assert_eq!(world.fake.state.lock().unwrap().reports.len(), attempts);
    }
}

#[test]
fn used_and_unknown_tokens() {
    let world = world();
    world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
    world.prepare().unwrap();
    assert!(world.prepare().unwrap_err().message().contains("expired (15 minutes) or was already fetched"));
    let error = flow::prepare_sign("tok_UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU", API, RPC, &constants(), None, &world.fake.transport(), &quiet).unwrap_err();
    assert!(error.message().contains("does not know this plan token"));
    let error = flow::prepare_sign("short", API, RPC, &constants(), None, &world.fake.transport(), &quiet).unwrap_err();
    assert_eq!(error.message(), "The plan token is malformed; copy the whole command again.");
    let error = flow::prepare_sign(TOKEN, "http://example.com", RPC, &constants(), None, &world.fake.transport(), &quiet).unwrap_err();
    assert!(error.message().contains("must use HTTPS"));
}

fn rebuild(plan: &Value, request: &Value) -> Value {
    // The website's customize: re-encode the planner's calldata with the requested values.
    let body = hex::decode(&plan["data"].as_str().unwrap()[10..]).unwrap();
    let mut call = helix_signer_core::abi::decode_install(&body).unwrap();
    if let Some(until) = request["validUntil"].as_u64() {
        call.valid_until = until;
    }
    if let Some(calls) = request["remainingCalls"].as_u64() {
        call.remaining_calls = calls;
    }
    for change in request["rules"].as_array().cloned().unwrap_or_default() {
        let rule = &mut call.rules[change["index"].as_u64().unwrap() as usize];
        let wei = |text: &Value| U256::from_str_radix(&custom::base_units(text.as_str().unwrap(), 18, "cap").unwrap(), 10).unwrap();
        rule.max_amount = wei(&change["maxPerCall"]);
        rule.max_daily = wei(&change["maxPerDay"]);
    }
    let mut answer = plan.clone();
    answer["data"] = json!(format!("{}{}", c::install_selector(), hex::encode(helix_signer_core::abi::encode_install(&call))));
    answer["validUntil"] = json!(call.valid_until);
    answer["remainingCalls"] = json!(call.remaining_calls);
    answer["customization"] = json!({"customized": ["edited"]});
    answer
}

#[test]
fn customize_verifies_the_new_plan_and_the_signed_transaction_carries_it() {
    let world = world();
    world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
    world.fake.state.lock().unwrap().customize = Some(Box::new(|plan, request| (200, rebuild(plan, request))));
    let session = world.prepare().unwrap();
    let until = (now() + 30 * 86400) as i64;
    let request = custom::with_changes(session.grant().unwrap(), Some(until), Some(200), &[(0, Some("15".into()), Some("30".into()))]).unwrap();
    let updated = flow::customize(&session, &request, &quiet).unwrap();
    let grant = updated.grant().unwrap();
    assert_eq!((grant.valid_until as i64, grant.remaining_calls), (until, 200));
    assert_eq!((grant.rules[0].max_amount, grant.rules[0].max_daily), (U256::from(15 * WAD), U256::from(30 * WAD)));
    assert!(updated.summary_text().contains("15 DAI per call, 30 DAI per UTC day"));
    assert!(updated.summary_text().contains("You customized: edited"));
    flow::execute_sign(&updated, world.key.clone(), &quiet).unwrap();
    assert_eq!(hex::encode(&world.sent()[0].data), grant.data[2..]);
    assert_eq!(world.fake.state.lock().unwrap().customized[0], serde_json::to_value(&request).unwrap());
}

#[test]
fn customize_refusals() {
    let world = world();
    world.serve(grant_plan(&world.owner, dai_power(), 7 * 86400, 256));
    let session = world.prepare().unwrap();
    let request = CustomizeRequest { remaining_calls: Some(100), ..custom::request_of(session.grant().unwrap()) };
    let answers: Vec<(u16, Value, ErrorKind, &str)> = vec![
        (400, json!({"error": "超出範圍", "errorEn": "Rule 1: the per-call cap is out of range."}), ErrorKind::CustomizeRefused, "Rule 1: the per-call cap is out of range."),
        (400, json!({"error": "zh only"}), ErrorKind::CustomizeRefused, "zh only"),
        (429, json!({}), ErrorKind::CustomizeRefused, "Too many changes in a short time"),
        (410, json!({"error": "stopped"}), ErrorKind::Flow, "This plan can no longer be edited (stopped)."),
        (500, json!({}), ErrorKind::Flow, "The website refused the change: HTTP 500"),
    ];
    for (code, body, kind, fragment) in answers {
        world.fake.state.lock().unwrap().customize = Some(Box::new(move |_, _| (code, body.clone())));
        let error = flow::customize(&session, &request, &quiet).unwrap_err();
        assert_eq!(error.kind(), kind, "{error}");
        assert!(error.message().contains(fragment), "{fragment}: {error}");
    }
    // Answers that do anything but the request are refused (and are not CustomizeRefused).
    let other = grant_plan(&world.owner, dai_power(), 7 * 86400, 256);
    type Tamper = Box<dyn Fn(&Value, &Value) -> Value + Send>;
    let tampers: Vec<(Tamper, &str)> = vec![
        (Box::new(move |_, _| other.clone()), "may never change"),
        (Box::new(|plan, request| {
            let mut answer = rebuild(plan, request);
            answer["value"] = json!("0x1");
            answer
        }), "native value"),
        (Box::new(|plan, request| {
            let mut answer = rebuild(plan, request);
            answer["sessionKeyAttestation"] = Value::Null;
            answer
        }), "attestation"),
        (Box::new(|plan, _| rebuild(plan, &json!({"remainingCalls": 90}))), "number of calls you asked for"),
    ];
    for (tamper, fragment) in tampers {
        world.fake.state.lock().unwrap().customize = Some(Box::new(move |plan, request| (200, tamper(plan, request))));
        let error = flow::customize(&session, &request, &quiet).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Flow);
        assert!(error.message().starts_with("The website's new plan was refused: "), "{error}");
        assert!(error.message().contains(fragment), "{fragment}: {error}");
    }
    assert!(world.sent().is_empty());
}

#[test]
fn revoke_with_a_plan_and_offline() {
    let world = world();
    world.fake.delegate(&world.owner, c::IMPLEMENTATION);
    let grant = format!("0x{}", "cd".repeat(32));
    world.fake.state.lock().unwrap().policy.entry(world.owner).or_default().insert(grant.clone(), session_key());
    world.serve(revoke_plan(&world.owner, &grant, GrantKind::Policy));
    let transport = world.fake.transport();
    let source = RevokeSource::Plan { token: TOKEN.into(), api: API.into() };
    let session = fast(flow::prepare_revoke(RPC, &constants(), source, Some(&world.key), &transport, &quiet).unwrap());
    assert_eq!(session.confirm_word(), "REVOKE");
    assert!(session.summary_text().contains("Transaction: ordinary self-call revokePolicyGrant(bytes32)"));
    let outcome = flow::execute_revoke(&session, world.key.clone(), &quiet).unwrap();
    assert_eq!(outcome.tx_type, 2);
    assert!(outcome.reported);
    assert!(!world.fake.state.lock().unwrap().policy[&world.owner].contains_key(&grant));
    // Offline: the kind is detected on chain.
    let session_grant = format!("0x{}", "ef".repeat(32));
    world.fake.state.lock().unwrap().session.entry(world.owner).or_default().insert(session_grant.clone(), Address([0x77; 20]));
    let offline = RevokeSource::Offline { owner: world.owner.to_checksum(), grant_id: session_grant.clone(), kind: None };
    let session = fast(flow::prepare_revoke(RPC, &constants(), offline.clone(), Some(&world.key), &transport, &quiet).unwrap());
    let outcome = flow::execute_revoke(&session, world.key.clone(), &quiet).unwrap();
    assert_eq!(outcome.report_message, "offline revoke: nothing to report");
    assert_eq!(hex::encode(&world.sent()[1].data), format!("{}{}", &c::revoke_selector(GrantKind::Session)[2..], "ef".repeat(32)));
    let error = flow::prepare_revoke(RPC, &constants(), offline, Some(&world.key), &transport, &quiet).unwrap_err();
    assert!(error.message().contains("is not active on chain"), "{error}");
    // Not delegated: nothing to revoke.
    let plain = self::world();
    plain.serve(revoke_plan(&plain.owner, &grant, GrantKind::Policy));
    let source = RevokeSource::Plan { token: TOKEN.into(), api: API.into() };
    let error = flow::prepare_revoke(RPC, &constants(), source, Some(&plain.key), &plain.fake.transport(), &quiet).unwrap_err();
    assert!(error.message().contains("not delegated"), "{error}");
}

#[test]
fn grants_view_login_list_and_revoke() {
    let world = world();
    let owner = world.owner.to_lower();
    world.fake.delegate(&world.owner, c::IMPLEMENTATION);
    let grants = [format!("0x{}", "a1".repeat(32)), format!("0x{}", "b2".repeat(32))];
    {
        let mut state = world.fake.state.lock().unwrap();
        for grant in &grants {
            state.policy.entry(world.owner).or_default().insert(grant.clone(), session_key());
        }
        state.grants.insert(owner.clone(), grants.iter().map(|grant| json!({"grantId": grant, "kind": "policy", "status": "active", "revocable": true, "key": session_key().to_checksum(), "keyOrigin": "hosted", "bot": {"id": 7, "script": "dai-power", "status": "active"}, "validUntilUnix": 1798705800, "remainingCalls": 256})).collect());
    }
    let transport = world.fake.transport();
    let site = Website::new(API, transport.website.clone()).unwrap();
    let lines = std::sync::Mutex::new(Vec::new());
    assert_eq!(site.login(&world.key, &|line| lines.lock().unwrap().push(line.to_string())).unwrap(), world.owner);
    assert!(lines.lock().unwrap()[0].contains("(a signature only; no transaction)"));
    let listing = site.grants().unwrap();
    assert_eq!(listing.active().len(), 2);
    assert_eq!(listing.rows[0].bot, "dai-power #7 (running)");
    assert!(!format!("{site:?}").contains("session-1"));
    let session = fast(flow::prepare_grant_revoke(&site, &grants[0], RPC, &constants(), &world.key, &transport, &quiet).unwrap().unwrap());
    let outcome = flow::execute_grant_revoke(&session, &world.key, &site, &quiet).unwrap();
    assert!(outcome.reported);
    assert_eq!(outcome.stopped_bots, vec![json!(7)]);
    assert!(!world.key.is_wiped(), "the key survives for the next grant");
    assert_eq!(world.fake.state.lock().unwrap().confirmations, vec![(grants[0].clone(), outcome.tx_hash.clone())]);
    // Already revoked: not an error, nothing to sign.
    assert!(flow::prepare_grant_revoke(&site, &grants[0], RPC, &constants(), &world.key, &transport, &quiet).unwrap().is_none());
    site.logout();
    assert!(!site.has_session());
    assert_eq!(world.fake.state.lock().unwrap().logged_out, 1);
    // A website message for another site is never signed.
    let hostile = self::world();
    hostile.fake.state.lock().unwrap().login_domain = "bank.example".into();
    let site = Website::new(API, hostile.fake.transport().website).unwrap();
    let error = site.login(&hostile.key, &quiet).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Login);
    assert!(!hostile.fake.state.lock().unwrap().requests.iter().any(|(_, path)| path == "/api/auth/verify"));
}

#[test]
fn dev_constants_only_on_loopback() {
    let folder = std::env::temp_dir().join(format!("helix-dev-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let path = folder.join("dev.json");
    std::fs::write(&path, json!({"implementation": format!("0x{}", "12".repeat(20)), "attestationAddress": format!("0x{}", "34".repeat(20))}).to_string()).unwrap();
    let error = flow::load_constants(Some(&path), "https://rpc.anubispace.org").unwrap_err();
    assert!(error.message().contains("refused"));
    let loaded = flow::load_constants(Some(&path), "http://127.0.0.1:8545").unwrap();
    assert!(loaded.development);
    assert_eq!(loaded.implementation_code_hash, None);
    assert_eq!(flow::load_constants(None, "https://rpc.anubispace.org").unwrap(), helix_signer_core::production());
    std::fs::write(&path, "[1]").unwrap();
    assert_eq!(flow::load_constants(Some(&path), "http://127.0.0.1:8545").unwrap_err().message(), "--dev-constants must be a JSON object.");
    let missing = folder.join("missing.json");
    let error = flow::load_constants(Some(&missing), "http://localhost:8545").unwrap_err();
    assert!(error.message().starts_with(&format!("Cannot read {}: [Errno 2] No such file or directory", missing.display())), "{error}");
    let _ = std::fs::remove_dir_all(&folder);
}
