//! Sign and revoke flows shared by the command line, the companion and the app.
//!
//! ``prepare_*`` fetches (or builds) the plan, verifies it against the pinned
//! constants and the live chain, and produces the summary; nothing is
//! signed. ``execute_*`` signs with the loaded key, broadcasts to the RPC,
//! waits for the receipt, verifies the result on chain and reports the hash
//! to the website. ``customize`` asks the website to re-plan a prepared grant
//! and verifies the answer again; ``prepare_grant_revoke`` /
//! ``execute_grant_revoke`` revoke through the owner's own website login.

use std::path::Path;
use std::time::Duration;

use ruint::aliases::U256;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::address::Address;
use crate::chain::{self, AccountKind, AccountState, Polling};
use crate::constants::{self as c, Constants, GrantKind};
use crate::custom::{check_answer, CustomizeRequest};
use crate::error::{Error, ErrorKind, Result};
use crate::keys::KeyMaterial;
use crate::message::Message;
use crate::msg;
use crate::net::{http_json, is_loopback, validate_url, Rpc, Transport};
use crate::plan::{check_token, offline_revoke, unix_now, verify_grant_plan, verify_revoke_plan, GrantPlan, RevokePlan};
use crate::pyfmt::py_str;
use crate::summary::{dai, grant_summary, revoke_summary, PlanKind, Summary};
use crate::website::Website;

/// A progress callback receiving one line at a time (its English text is
/// ``line.text``; the app translates its code).
pub type Log<'a> = &'a dyn Fn(&Message);

/// Word the owner types to sign a grant.
pub const AUTHORIZE: &str = "AUTHORIZE";
/// Word the owner types to sign a revocation.
pub const REVOKE: &str = "REVOKE";
/// Why a grant under a foreign EIP-7702 delegation is not revoked here.
pub const FOREIGN_DELEGATION: &str = "this account is delegated (EIP-7702) to another contract, and the signer never overwrites someone else's delegation. The grant is inactive while that delegation stays; remove that delegation with the wallet that set it, then revoke the grant here.";

/// A verified plan.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum VerifiedPlan {
    /// installPolicyGrant.
    Grant(GrantPlan),
    /// revokePolicyGrant / revokeGrant.
    Revoke(RevokePlan),
}

impl VerifiedPlan {
    /// The owner.
    pub fn owner(&self) -> Address {
        match self {
            VerifiedPlan::Grant(plan) => plan.owner,
            VerifiedPlan::Revoke(plan) => plan.owner,
        }
    }

    /// The grant ID.
    pub fn grant_id(&self) -> &str {
        match self {
            VerifiedPlan::Grant(plan) => &plan.grant_id,
            VerifiedPlan::Revoke(plan) => &plan.grant_id,
        }
    }

    /// The exact calldata.
    pub fn data(&self) -> &str {
        match self {
            VerifiedPlan::Grant(plan) => &plan.data,
            VerifiedPlan::Revoke(plan) => &plan.data,
        }
    }
}

/// A verified plan ready to be signed.
#[derive(Clone, Debug)]
pub struct Session {
    /// Grant or revoke.
    pub kind: PlanKind,
    /// Verified plan.
    pub plan: VerifiedPlan,
    /// Chain endpoint.
    pub rpc: Rpc,
    /// Pinned values used.
    pub constants: Constants,
    /// Owner state when prepared.
    pub state: AccountState,
    /// What the owner confirms.
    pub summary: Summary,
    /// Website API base, None for an offline revoke.
    pub api: Option<String>,
    /// One-time plan token.
    pub token: Option<String>,
    /// HTTP clients.
    pub transport: Transport,
    /// Receipt polling.
    pub polling: Polling,
    /// Wait between report attempts.
    pub report_delay: Duration,
}

impl Session {
    /// Word the owner types to sign.
    pub fn confirm_word(&self) -> &'static str {
        match self.kind {
            PlanKind::Grant => AUTHORIZE,
            PlanKind::Revoke => REVOKE,
        }
    }

    /// Owner of the plan.
    pub fn owner(&self) -> Address {
        self.plan.owner()
    }

    /// The grant plan, for a grant session.
    pub fn grant(&self) -> Option<&GrantPlan> {
        match &self.plan {
            VerifiedPlan::Grant(plan) => Some(plan),
            VerifiedPlan::Revoke(_) => None,
        }
    }

    /// The summary text.
    pub fn summary_text(&self) -> String {
        self.summary.text()
    }
}

/// Outcome of a broadcast.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    /// Mined transaction hash.
    pub tx_hash: String,
    /// 2 or 4.
    pub tx_type: u8,
    /// Block number.
    pub block: u64,
    /// Whether the website accepted the report.
    pub reported: bool,
    /// Website answer or error.
    pub report_message: String,
    /// Gas used.
    pub gas_used: u64,
    /// Bots the website stopped after a grants-view revocation.
    pub stopped_bots: Vec<Value>,
}

/// Asks the owner to confirm a prepared session: the CLI reads the typed
/// word in the terminal, the app shows a dialog.
pub trait Confirmer: Send + Sync {
    /// Return Ok(true) to sign; ``word`` is AUTHORIZE or REVOKE.
    /// ``Err(Cancelled)`` when the input is closed.
    fn confirm(&self, session: &Session, word: &str) -> Result<bool>;
}

fn os_error_text(error: &std::io::Error, path: &Path) -> String {
    let text = error.to_string();
    let text = match text.rfind(" (os error ") {
        Some(index) => text[..index].to_string(),
        None => text,
    };
    match error.raw_os_error() {
        Some(code) => format!("[Errno {code}] {text}: '{}'", path.display()),
        None => text,
    }
}

/// The pinned constants, or development overrides on a loopback RPC only.
pub fn load_constants(dev_file: Option<&Path>, rpc_url: &str) -> Result<Constants> {
    let Some(dev_file) = dev_file else { return Ok(c::production()) };
    if !is_loopback(rpc_url) {
        return Err(Error::flow(
            "--dev-constants is refused: it only works with a loopback RPC (a local test fork), never with a real network.",
        ));
    }
    let text = std::fs::read_to_string(dev_file)
        .map_err(|error| Error::flow(format!("Cannot read {}: {}", dev_file.display(), os_error_text(&error, dev_file))))?;
    let values: Value =
        serde_json::from_str(&text).map_err(|error| Error::flow(format!("Cannot read {}: {error}", dev_file.display())))?;
    if !values.is_object() {
        return Err(Error::flow("--dev-constants must be a JSON object."));
    }
    c::production().with_overrides(&values).map_err(|error| error.into_kind(ErrorKind::Flow))
}

/// URL of one plan.
pub fn plan_url(api: &str, token: &str) -> String {
    format!("{api}/api/signer/plans/{token}")
}

const WEBSITE_TIMEOUT: Duration = Duration::from_secs(20);

/// Fetch a one-time plan from the website.
pub fn fetch_plan(api: &str, token: &str, transport: &Transport) -> Result<Value> {
    match http_json(transport.website.as_ref(), &plan_url(api, token), "GET", None, WEBSITE_TIMEOUT) {
        Ok(plan) => Ok(Value::Object(plan)),
        Err(error) if error.kind() == ErrorKind::HttpStatus => Err(Error::coded(ErrorKind::Flow, match error.status() {
            Some(404) => msg!("flow.planUnknown", "The website does not know this plan token. Copy the command again."),
            Some(410) => msg!(
                "flow.planGone",
                "This plan expired (15 minutes) or was already fetched once. Click the button on the dashboard again to get a new command."
            ),
            Some(429) => msg!("flow.tooManyRequests", "Too many requests; wait a minute and try again."),
            _ => msg!("flow.planRefused", "The website refused the plan: {error}", error = &error),
        })),
        Err(error) => Err(error.into_kind(ErrorKind::Flow)),
    }
}

fn check_report_url(plan: &Value, api: &str, token: &str, log: Log) {
    let expected = format!("{}/report", plan_url(api, token));
    match plan.get("reportUrl") {
        None | Some(Value::Null) => {}
        Some(Value::String(url)) if *url == expected => {}
        Some(other) => log(&msg!(
            "log.reportUrl",
            "Note: the plan names report URL {named}; the signer reports to {expected}.",
            named = py_str(other),
            expected = &expected
        )),
    }
}

fn require_owner(material: Option<&KeyMaterial>, owner: &Address) -> Result<()> {
    match material {
        Some(material) if material.address() != *owner => Err(Error::coded(
            ErrorKind::Flow,
            msg!(
                "flow.wrongKey",
                "Wrong key: it controls {key}, but this plan is for {owner}. Use the key of the wallet you are signed in with on the website (for a mnemonic, check --account-index).",
                key = material.address(),
                owner = owner
            ),
        )),
        _ => Ok(()),
    }
}

fn checked_state(rpc: &Rpc, owner: &Address, constants: &Constants, install: bool) -> Result<AccountState> {
    let state = chain::account_state(rpc, owner, constants)?;
    match chain::refuse_state(&state, install) {
        Some(reason) => Err(Error::coded(ErrorKind::Flow, reason)),
        None => Ok(state),
    }
}

/// Plan, chain and network failures become FlowError with the same text;
/// a FlowError passes unchanged.
fn as_flow(error: Error) -> Error {
    match error.kind() {
        ErrorKind::Plan | ErrorKind::Chain | ErrorKind::Network | ErrorKind::HttpStatus => error.into_kind(ErrorKind::Flow),
        _ => error,
    }
}

/// Plan, chain and network failures become a FlowError whose message wraps
/// the cause (``wrap(cause)``); other errors pass unchanged.
fn wrapped(error: Error, wrap: impl FnOnce(&Error) -> Message) -> Error {
    match error.kind() {
        ErrorKind::Plan | ErrorKind::Chain | ErrorKind::Network | ErrorKind::HttpStatus => Error::coded(ErrorKind::Flow, wrap(&error)),
        _ => error,
    }
}

fn with_transaction(tx: &str) -> impl FnOnce(&Error) -> Message + '_ {
    move |cause| msg!("flow.withTransaction", "{cause} (transaction {tx})", cause = cause, tx = tx)
}

#[allow(clippy::too_many_arguments)]
fn session(kind: PlanKind, plan: VerifiedPlan, rpc: Rpc, constants: &Constants, state: AccountState, summary: Summary, api: Option<String>, token: Option<String>, transport: &Transport) -> Session {
    Session {
        kind,
        plan,
        rpc,
        constants: constants.clone(),
        state,
        summary,
        api,
        token,
        transport: transport.clone(),
        polling: Polling::default(),
        report_delay: Duration::from_secs(2),
    }
}

/// Fetch and verify a grant plan; nothing is signed.
pub fn prepare_sign(
    token: &str,
    api: &str,
    rpc_url: &str,
    constants: &Constants,
    material: Option<&KeyMaterial>,
    transport: &Transport,
    log: Log,
) -> Result<Session> {
    check_token(token).map_err(as_flow)?;
    let api = validate_url(api, "Website API").map_err(as_flow)?;
    let rpc = Rpc::new(rpc_url, transport.rpc.clone()).map_err(as_flow)?;
    log(&msg!("log.fetchingPlan", "Fetching plan from {api} ...", api = &api));
    let raw = fetch_plan(&api, token, transport)?;
    let (plan, state) = (|| -> Result<(GrantPlan, AccountState)> {
        verify_grant_plan(&raw, constants, None)?;
        log(&msg!("log.planVerified", "Plan verified against the pinned constants. Checking the chain ..."));
        let chain_time = chain::check_chain(&rpc, constants)?;
        let plan = verify_grant_plan(&raw, constants, Some(chain_time.max(unix_now())))?;
        require_owner(material, &plan.owner)?;
        let state = checked_state(&rpc, &plan.owner, constants, true)?;
        Ok((plan, state))
    })()
    .map_err(as_flow)?;
    check_report_url(&raw, &api, token, log);
    let summary = grant_summary(&plan, &state, Some(&api), &rpc.url, constants);
    Ok(session(PlanKind::Grant, VerifiedPlan::Grant(plan), rpc, constants, state, summary, Some(api), Some(token.to_string()), transport))
}

/// Ask the website to re-plan a prepared grant, then verify the new plan.
///
/// ``Err`` of kind ``CustomizeRefused``: a value is out of bounds or too many
/// edits; the given session can still be signed. Kind ``Flow``: the plan is
/// gone, or the answer fails verification.
pub fn customize(current: &Session, request: &CustomizeRequest, log: Log) -> Result<Session> {
    let (Some(plan), Some(api), Some(token)) = (current.grant(), current.api.as_deref(), current.token.as_deref()) else {
        return Err(Error::flow("Only a website grant plan can be edited."));
    };
    log(&msg!("log.askingReplan", "Asking the website to re-plan the grant with these values ..."));
    let body = json!({"grant": request});
    let url = format!("{}/customize", plan_url(api, token));
    let raw = match http_json(current.transport.website.as_ref(), &url, "POST", Some(&body), WEBSITE_TIMEOUT) {
        Ok(raw) => Value::Object(raw),
        Err(error) if error.kind() == ErrorKind::HttpStatus => {
            return Err(match error.status().unwrap_or(0) {
                400 => {
                    // The website's own message (its code, Chinese and English
                    // texts); the command line prints the English one.
                    let english = error.body().get("errorEn").filter(|value| crate::pyfmt::truthy(value)).map(py_str);
                    let mut refused = error.msg().clone();
                    if let Some(english) = english {
                        refused.text = english;
                    }
                    Error::coded(ErrorKind::CustomizeRefused, refused)
                }
                429 => Error::coded(
                    ErrorKind::CustomizeRefused,
                    msg!("customize.tooMany", "Too many changes in a short time; wait a minute and try again."),
                ),
                404 | 409 | 410 => Error::coded(
                    ErrorKind::Flow,
                    msg!(
                        "flow.editGone",
                        "This plan can no longer be edited ({error}). Nothing was signed. Press the button on the website's bot card again to get a new one.",
                        error = &error
                    ),
                ),
                _ => Error::coded(ErrorKind::Flow, msg!("flow.editRefused", "The website refused the change: {error}", error = &error)),
            })
        }
        Err(error) => return Err(error.into_kind(ErrorKind::CustomizeRefused)),
    };
    let (verified, state) = (|| -> Result<(GrantPlan, AccountState)> {
        let chain_time = chain::check_chain(&current.rpc, &current.constants)?;
        let verified = verify_grant_plan(&raw, &current.constants, Some(chain_time.max(unix_now())))?;
        check_answer(plan, &verified, request)?;
        let state = checked_state(&current.rpc, &verified.owner, &current.constants, true)?;
        Ok((verified, state))
    })()
    .map_err(|error| wrapped(error, |cause| msg!("flow.newPlanRefused", "The website's new plan was refused: {cause}", cause = cause)))?;
    log(&msg!("log.newPlanVerified", "New plan verified against the pinned constants."));
    let summary = grant_summary(&verified, &state, Some(api), &current.rpc.url, &current.constants);
    let mut next = current.clone();
    next.plan = VerifiedPlan::Grant(verified);
    next.state = state;
    next.summary = summary;
    Ok(next)
}

/// Where a revocation comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevokeSource {
    /// A website revoke plan token.
    Plan {
        /// One-time token.
        token: String,
        /// Website API base.
        api: String,
    },
    /// Offline: owner and grant ID typed by the owner.
    Offline {
        /// Owner address.
        owner: String,
        /// Grant ID.
        grant_id: String,
        /// Grant kind; detected on chain when None.
        kind: Option<GrantKind>,
    },
}

/// Fetch (or build offline) and verify a revocation; nothing is signed.
pub fn prepare_revoke(rpc_url: &str, constants: &Constants, source: RevokeSource, material: Option<&KeyMaterial>, transport: &Transport, log: Log) -> Result<Session> {
    let rpc = Rpc::new(rpc_url, transport.rpc.clone()).map_err(as_flow)?;
    let (token, api) = match &source {
        RevokeSource::Plan { token, api } => {
            check_token(token).map_err(as_flow)?;
            let api = if api.is_empty() { c::DEFAULT_API.to_string() } else { api.clone() };
            (Some(token.clone()), Some(validate_url(&api, "Website API").map_err(as_flow)?))
        }
        RevokeSource::Offline { .. } => (None, None),
    };
    let (plan, state) = (|| -> Result<(RevokePlan, AccountState)> {
        let mut plan = match (&source, &token, &api) {
            (RevokeSource::Plan { .. }, Some(token), Some(api)) => {
                log(&msg!("log.fetchingRevokePlan", "Fetching revoke plan from {api} ...", api = api));
                let raw = fetch_plan(api, token, transport)?;
                let plan = verify_revoke_plan(&raw, constants)?;
                check_report_url(&raw, api, token, log);
                plan
            }
            (RevokeSource::Offline { owner, grant_id, kind }, _, _) => {
                if owner.is_empty() || grant_id.is_empty() {
                    return Err(Error::flow("Pass --plan TOKEN, or --grant ID and --owner ADDRESS."));
                }
                offline_revoke(owner, grant_id, kind.map(|kind| kind.as_str()).unwrap_or("policy"), constants)?
            }
            _ => unreachable!("token and api come with a plan source"),
        };
        chain::check_chain(&rpc, constants)?;
        require_owner(material, &plan.owner)?;
        let state = checked_state(&rpc, &plan.owner, constants, false)?;
        let live = chain::detect_stored_grant_kind(&rpc, &state, &plan.owner, &plan.grant_id)?;
        let Some(live) = live else {
            return Err(Error::coded(
                ErrorKind::Flow,
                msg!(
                    "flow.grantNotActive",
                    "Grant {grant} is not active on chain (already revoked or never installed); nothing to sign. The dashboard detects a revocation on chain by itself.",
                    grant = plan.grant_id.as_str()
                ),
            ));
        };
        let detect = matches!(source, RevokeSource::Offline { kind: None, .. });
        if detect && live != plan.grant_kind {
            plan = offline_revoke(&plan.owner.to_checksum(), &plan.grant_id, live.as_str(), constants)?;
        } else if live != plan.grant_kind {
            return Err(Error::coded(
                ErrorKind::Flow,
                msg!(
                    "flow.kindMismatch",
                    "On chain this is a {live} grant, but the plan revokes a {planned} grant.",
                    live = live.as_str(),
                    planned = plan.grant_kind.as_str()
                ),
            ));
        }
        Ok((plan, state))
    })()
    .map_err(as_flow)?;
    let summary = revoke_summary(&plan, &state, api.as_deref(), &rpc.url, constants);
    Ok(session(PlanKind::Revoke, VerifiedPlan::Revoke(plan), rpc, constants, state, summary, api, token, transport))
}

struct Sent {
    tx_hash: String,
    tx_type: u8,
    receipt: Map<String, Value>,
}

/// Estimate, check gas, sign, broadcast and wait; the key is wiped (dropped).
fn send(current: &Session, material: KeyMaterial, log: Log, install: bool) -> Result<Sent> {
    let mut material = material;
    let rpc = &current.rpc;
    let constants = &current.constants;
    let owner = current.owner();
    let signed = (|| -> Result<(chain::SignedTransaction, bool)> {
        require_owner(Some(&material), &owner)?;
        let state = checked_state(rpc, &owner, constants, install)?;
        let (max_fee, tip) = chain::fees(rpc)?;
        // A plain account is delegated by this transaction: for an install, and
        // for revoking a dormant grant left in its storage (re-delegation).
        let authorization = if state.kind == AccountKind::Plain {
            Some(chain::sign_authorization(&material, constants, state.nonce)?)
        } else {
            None
        };
        let fallback = match &current.plan {
            VerifiedPlan::Grant(plan) if install => {
                chain::FALLBACK_GAS_BASE + chain::FALLBACK_GAS_PER_RULE * plan.rules.len() as u64
            }
            _ if authorization.is_some() => chain::REVOKE_FALLBACK_GAS + chain::AUTHORIZATION_GAS,
            _ => chain::REVOKE_FALLBACK_GAS,
        };
        let (gas, how) = chain::estimate_gas(rpc, &owner, current.plan.data(), authorization.as_ref(), fallback)?;
        let cost = gas.saturating_mul(max_fee);
        log(&msg!("log.gas", "Gas limit {gas} ({how}); maximum fee {fee}.", gas = gas, how = how, fee = dai(&cost)));
        if state.balance < cost {
            return Err(Error::coded(
                ErrorKind::Flow,
                msg!(
                    "flow.notEnoughGas",
                    "Not enough {symbol} for gas: the owner has {balance}, the transaction may cost up to {cost}. Send some DAI to {owner} and run the command again (get a new command if the plan expired).",
                    symbol = c::GAS_SYMBOL,
                    balance = dai(&state.balance),
                    cost = dai(&cost),
                    owner = owner
                ),
            ));
        }
        let has_authorization = authorization.is_some();
        let signed = chain::sign_transaction(&material, constants, &owner, current.plan.data(), state.nonce, gas, max_fee, tip, authorization)?;
        Ok((signed, has_authorization))
    })();
    material.wipe();
    drop(material);
    let (signed, _) = signed.map_err(as_flow)?;
    let tx_hash = signed.hash.clone();
    let tx_type = signed.tx_type;
    let receipt = (|| -> Result<Map<String, Value>> {
        log(&msg!("log.broadcasting", "Broadcasting type-{kind} transaction {tx} to {rpc} ...", kind = tx_type, tx = &tx_hash, rpc = rpc.url.as_str()));
        chain::broadcast(rpc, &signed.raw, &tx_hash)?;
        log(&msg!("log.waitingReceipt", "Waiting for the receipt ..."));
        chain::wait_receipt(rpc, &tx_hash, current.polling)
    })()
    .map_err(|error| wrapped(error, with_transaction(&tx_hash)))?;
    Ok(Sent { tx_hash, tx_type, receipt })
}

/// Tell the website the transaction hash (it verifies it on chain itself).
pub fn report(current: &Session, tx_hash: &str, log: Log) -> (bool, String) {
    let (Some(api), Some(token)) = (current.api.as_deref(), current.token.as_deref()) else {
        return (false, "offline revoke: nothing to report".into());
    };
    let url = format!("{}/report", plan_url(api, token));
    let attempts = 3;
    let mut failure: Option<Error> = None;
    for attempt in 0..attempts {
        match http_json(current.transport.website.as_ref(), &url, "POST", Some(&json!({"txHash": tx_hash})), WEBSITE_TIMEOUT) {
            Ok(answer) => return (true, answer.get("status").map(py_str).unwrap_or_else(|| "ok".into())),
            Err(error) => {
                let stop = error.status().map(|status| status < 500 && status != 429).unwrap_or(false);
                failure = Some(error);
                if stop {
                    break;
                }
            }
        }
        if attempt + 1 < attempts {
            std::thread::sleep(current.report_delay);
        }
    }
    let failure = failure.unwrap_or_else(|| Error::network(""));
    log(&msg!(
        "log.reportFailed",
        "The website did not accept the report ({error}); the dashboard also detects the transaction on chain.",
        error = &failure
    ));
    (false, failure.message().to_string())
}

fn receipt_number(receipt: &Map<String, Value>, key: &str) -> u64 {
    receipt
        .get(key)
        .and_then(Value::as_str)
        .and_then(|text| u64::from_str_radix(text.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0)
}

/// Sign, broadcast and verify a grant install, then report it. The key is consumed and wiped.
pub fn execute_sign(current: &Session, material: KeyMaterial, log: Log) -> Result<Outcome> {
    let Some(plan) = current.grant() else { return Err(Error::flow("This session is not a grant.")) };
    let sent = send(current, material, log, true)?;
    chain::verify_install(&current.rpc, &plan.owner, &plan.grant_id, &plan.session_key, &sent.receipt, &current.constants)
        .map_err(|error| wrapped(error, with_transaction(&sent.tx_hash)))?;
    let block = receipt_number(&sent.receipt, "blockNumber");
    log(&msg!("log.confirmedGrant", "Confirmed in block {block}: delegation and grant verified on chain.", block = block));
    let (reported, report_message) = report(current, &sent.tx_hash, log);
    Ok(Outcome {
        tx_hash: sent.tx_hash,
        tx_type: sent.tx_type,
        block,
        reported,
        report_message,
        gas_used: receipt_number(&sent.receipt, "gasUsed"),
        stopped_bots: Vec::new(),
    })
}

/// Sign, broadcast and verify a revocation, then report it. The key is consumed and wiped.
pub fn execute_revoke(current: &Session, material: KeyMaterial, log: Log) -> Result<Outcome> {
    let VerifiedPlan::Revoke(plan) = &current.plan else { return Err(Error::flow("This session is not a revocation.")) };
    let sent = send(current, material, log, false)?;
    chain::verify_revoke(&current.rpc, &plan.owner, &plan.grant_id, plan.grant_kind, &current.constants)
        .map_err(|error| wrapped(error, with_transaction(&sent.tx_hash)))?;
    let block = receipt_number(&sent.receipt, "blockNumber");
    if sent.tx_type == 4 {
        log(&msg!(
            "log.confirmedRedelegated",
            "Confirmed in block {block}: the account is delegated to Helix again and the grant is revoked on chain.",
            block = block
        ));
    } else {
        log(&msg!("log.confirmedRevoke", "Confirmed in block {block}: the grant is revoked on chain.", block = block));
    }
    let (reported, report_message) = report(current, &sent.tx_hash, log);
    Ok(Outcome {
        tx_hash: sent.tx_hash,
        tx_type: sent.tx_type,
        block,
        reported,
        report_message,
        gas_used: receipt_number(&sent.receipt, "gasUsed"),
        stopped_bots: Vec::new(),
    })
}

/// Check a website-built revocation call exactly like a revoke plan
/// (``to`` is the owner, the selector and grant ID are exact, value and chain
/// are checked).
pub fn revoke_call_plan(call: &Value, owner: &Address, grant_id: &str, constants: &Constants) -> Result<RevokePlan> {
    let field = |key: &str| call.get(key).cloned().unwrap_or(Value::Null);
    let plan = json!({
        "schema": c::PLAN_SCHEMA,
        "kind": "revoke",
        "chainId": field("chainId"),
        "owner": owner.to_checksum(),
        "to": field("to"),
        "value": field("value"),
        "data": field("data"),
        "grantId": field("grantId"),
        "grantKind": field("kind"),
    });
    let verified = verify_revoke_plan(&plan, constants)?;
    if verified.grant_id != grant_id.to_lowercase() {
        return Err(Error::plan(format!("The website's revocation is for grant {}, not {grant_id}.", verified.grant_id)));
    }
    Ok(verified)
}

/// Get and verify one grant's revocation through the owner's website login;
/// None when the grant is already revoked or no longer on chain.
pub fn prepare_grant_revoke(site: &Website, grant_id: &str, rpc_url: &str, constants: &Constants, material: &KeyMaterial, transport: &Transport, log: Log) -> Result<Option<Session>> {
    let rpc = Rpc::new(rpc_url, transport.rpc.clone()).map_err(as_flow)?;
    let call = match site.revoke_call(grant_id) {
        Ok(call) => call,
        Err(error) if error.status() == Some(409) && error.body().get("reason").and_then(Value::as_str) == Some("otherDelegation") => {
            return Err(Error::coded(
                ErrorKind::Flow,
                msg!(
                    "flow.foreignDelegation",
                    "Grant {grant} cannot be revoked here: {reason}",
                    grant = grant_id,
                    reason = FOREIGN_DELEGATION
                ),
            ))
        }
        Err(error) if error.status() == Some(409) => {
            log(&msg!("log.alreadyRevoked", "Grant {grant} is already revoked or not on chain.", grant = grant_id));
            return Ok(None);
        }
        Err(error) if error.kind() == ErrorKind::HttpStatus => {
            return Err(Error::coded(
                ErrorKind::Flow,
                msg!(
                    "flow.revokeRefused",
                    "The website refused to prepare the revocation of {grant}: {error}",
                    grant = grant_id,
                    error = &error
                ),
            ))
        }
        Err(error) => return Err(as_flow(error)),
    };
    let prepared = (|| -> Result<Option<(RevokePlan, AccountState)>> {
        let plan = revoke_call_plan(&Value::Object(call), &material.address(), grant_id, constants)?;
        chain::check_chain(&rpc, constants)?;
        let state = checked_state(&rpc, &plan.owner, constants, false)?;
        let Some(live) = chain::detect_stored_grant_kind(&rpc, &state, &plan.owner, &plan.grant_id)? else {
            log(&msg!("log.notActive", "Grant {grant} is not active on chain; nothing to sign.", grant = grant_id));
            return Ok(None);
        };
        if live != plan.grant_kind {
            return Err(Error::coded(
                ErrorKind::Flow,
                msg!(
                    "flow.kindMismatchWebsite",
                    "On chain this is a {live} grant, but the website revokes a {planned} grant.",
                    live = live.as_str(),
                    planned = plan.grant_kind.as_str()
                ),
            ));
        }
        Ok(Some((plan, state)))
    })()
    .map_err(|error| wrapped(error, |cause| msg!("flow.grantFailed", "Grant {grant}: {cause}", grant = grant_id, cause = cause)))?;
    let Some((plan, state)) = prepared else { return Ok(None) };
    let summary = revoke_summary(&plan, &state, Some(site.api()), &rpc.url, constants);
    Ok(Some(session(PlanKind::Revoke, VerifiedPlan::Revoke(plan), rpc, constants, state, summary, None, None, transport)))
}

/// Sign and broadcast a verified revocation, then tell the website. The key
/// is kept: a copy signs and is wiped.
pub fn execute_grant_revoke(current: &Session, material: &KeyMaterial, site: &Website, log: Log) -> Result<Outcome> {
    let mut outcome = execute_revoke(current, material.clone(), log)?;
    match site.revoke_confirm(current.plan.grant_id(), &outcome.tx_hash) {
        Ok(answer) => {
            outcome.reported = true;
            outcome.report_message = answer.get("status").map(py_str).unwrap_or_else(|| "ok".into());
            outcome.stopped_bots = match answer.get("stoppedBots") {
                Some(Value::Array(items)) => items.clone(),
                _ => Vec::new(),
            };
        }
        Err(error) if error.is_network() => {
            log(&msg!(
                "log.confirmFailed",
                "The website did not accept the confirmation ({error}); it also detects the revocation on chain.",
                error = &error
            ));
            outcome.report_message = error.message().to_string();
        }
        Err(error) => return Err(error),
    }
    Ok(outcome)
}

/// Gas cost helper for callers that show an estimate.
pub fn max_cost(gas: U256, max_fee: U256) -> U256 {
    gas.saturating_mul(max_fee)
}
