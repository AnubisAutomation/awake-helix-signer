//! Human-readable summaries of exactly what will be signed.
//!
//! [`Summary`] is structured data (serializable for the app's UI) and
//! [`Summary::text`] renders the same lines as the Python signer's
//! ``summary.py``.

use jiff::tz::TimeZone;
use jiff::Timestamp;
use ruint::aliases::U256;
use serde::Serialize;
use serde_json::Value;

use crate::address::Address;
use crate::chain::{AccountKind, AccountState};
use crate::constants::{self as c, Constants, GrantKind};
use crate::plan::{amount, GrantPlan, RevokePlan, Rule};
use crate::pyfmt::{py_str, shifted_plain, truthy};

/// Whether a session installs a grant or revokes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanKind {
    /// installPolicyGrant (AUTHORIZE).
    Grant,
    /// revokePolicyGrant / revokeGrant (REVOKE).
    Revoke,
}

impl PlanKind {
    /// ``grant`` or ``revoke``.
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanKind::Grant => "grant",
            PlanKind::Revoke => "revoke",
        }
    }
}

/// Render a Unix time in UTC and in this computer's local time zone.
pub fn when(seconds: u64) -> String {
    match Timestamp::from_second(seconds as i64) {
        Ok(moment) => {
            let utc = moment.to_zoned(TimeZone::UTC);
            let local = moment.to_zoned(TimeZone::system());
            format!(
                "{} UTC (local {})",
                utc.strftime("%Y-%m-%d %H:%M:%S"),
                local.strftime("%Y-%m-%d %H:%M:%S %Z")
            )
        }
        Err(_) => format!("{seconds} (Unix time)"),
    }
}

/// Format DAI wei for the gas lines.
pub fn dai(wei: &U256) -> String {
    let text = if wei.is_zero() { "0".to_string() } else { amount(wei, 18) };
    format!("{text} {}", c::GAS_SYMBOL)
}

/// Render an address with its pinned contract name.
pub fn named(address: &Address) -> String {
    let text = address.to_checksum();
    match c::contract_name(&text) {
        "" => text,
        name => format!("{name} ({text})"),
    }
}

fn token_decimals(address: &Address) -> i64 {
    if *address == Address::constant(c::LGNS) {
        9
    } else {
        18
    }
}

/// A swap rule's tokens and price floor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapSummary {
    /// Input token.
    pub token_in: Address,
    /// Its pinned name, or "".
    pub token_in_name: String,
    /// Output token.
    pub token_out: Address,
    /// Its pinned name, or "".
    pub token_out_name: String,
    /// Minimum output per 1 input token, as a decimal.
    pub price_floor: String,
}

/// One decoded rule, ready to show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSummary {
    /// 1-based number (used by ``--cap``).
    pub index: usize,
    /// RuleKind.
    pub kind: u8,
    /// Method name.
    pub method: String,
    /// Called contract.
    pub target: Address,
    /// Its pinned name, or "".
    pub target_name: String,
    /// The only spender of an approval.
    pub spender: Option<Address>,
    /// Swap details.
    pub swap: Option<SwapSummary>,
    /// Unit of the caps (DAI, LGNS, aiLGNS, lock IDs).
    pub unit: String,
    /// Decimals of the unit.
    pub decimals: u32,
    /// Per-call cap as a decimal.
    pub max_per_call: String,
    /// Per-UTC-day cap as a decimal.
    pub max_per_day: String,
    /// Activation DAI cap (Turbine activate).
    pub activation_dai: Option<String>,
    /// Deadline bound in seconds.
    pub deadline_seconds: Option<u64>,
}

impl RuleSummary {
    /// Build from a verified rule.
    pub fn of(index: usize, rule: &Rule) -> RuleSummary {
        let (unit, decimals) = rule.unit();
        let swap = c::SWAP_KINDS.contains(&rule.kind).then(|| {
            let shift = 18 - (token_decimals(&rule.token_in) - token_decimals(&rule.counterparty));
            SwapSummary {
                token_in: rule.token_in,
                token_in_name: c::contract_name(&rule.token_in.to_checksum()).to_string(),
                token_out: rule.counterparty,
                token_out_name: c::contract_name(&rule.counterparty.to_checksum()).to_string(),
                price_floor: shifted_plain(&rule.min_out_per_in_wad.to_string(), shift),
            }
        });
        RuleSummary {
            index,
            kind: rule.kind,
            method: rule.method().to_string(),
            target: rule.target,
            target_name: c::contract_name(&rule.target.to_checksum()).to_string(),
            spender: (rule.kind == 0).then_some(rule.counterparty),
            swap,
            unit: unit.to_string(),
            decimals,
            max_per_call: amount(&rule.max_amount, decimals),
            max_per_day: amount(&rule.max_daily, decimals),
            activation_dai: (rule.kind == 5).then(|| amount(&rule.max_secondary, 18)),
            deadline_seconds: (rule.max_deadline_delay != 0).then_some(rule.max_deadline_delay),
        }
    }

    /// The rule's lines of the text summary.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![format!("  {}. {} on {}", self.index, self.method, named(&self.target))];
        if let Some(spender) = &self.spender {
            lines.push(format!("     spender: {} (the only address the allowance may go to)", named(spender)));
        }
        if let Some(swap) = &self.swap {
            lines.push(format!(
                "     swap: {} -> {}, recipient: your own account",
                named(&swap.token_in),
                named(&swap.token_out)
            ));
            let out_name = if swap.token_out_name.is_empty() { "output" } else { &swap.token_out_name };
            let in_name = if swap.token_in_name.is_empty() { "input" } else { &swap.token_in_name };
            lines.push(format!("     price floor: at least {} {out_name} per 1 {in_name}", swap.price_floor));
        }
        lines.push(format!(
            "     limit: {} {} per call, {} {} per UTC day",
            self.max_per_call, self.unit, self.max_per_day, self.unit
        ));
        if let Some(activation) = &self.activation_dai {
            lines.push(format!("     activation DAI: at most {activation} DAI per call"));
        }
        if let Some(deadline) = self.deadline_seconds {
            lines.push(format!("     deadline: at most {deadline} s ahead"));
        }
        lines
    }
}

/// What a grant installs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantSummary {
    /// True: one type-4 transaction that also delegates the account.
    pub delegates: bool,
    /// Pinned delegate.
    pub delegate: Address,
    /// Whether the delegate's code hash was checked against the pinned one.
    pub code_hash_verified: bool,
    /// This bot's attested session key.
    pub session_key: Address,
    /// Bot script name from the website (display only), if any.
    pub bot_script: Option<String>,
    /// Bot UUID from the calldata.
    pub bot_id: String,
    /// Grant ID.
    pub grant_id: String,
    /// validAfter (Unix seconds) and its text.
    pub valid_after: u64,
    /// ``when(valid_after)``.
    pub valid_after_text: String,
    /// validUntil (Unix seconds).
    pub valid_until: u64,
    /// ``when(valid_until)``.
    pub valid_until_text: String,
    /// Total bot operations.
    pub remaining_calls: u64,
    /// Decoded rules.
    pub rules: Vec<RuleSummary>,
    /// What the owner customized (website's list, display only).
    pub customized: Vec<String>,
}

/// What a revocation removes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSummary {
    /// ``revokePolicyGrant(bytes32)`` or ``revokeGrant(bytes32)``.
    pub method: String,
    /// Grant ID.
    pub grant_id: String,
    /// ``policy`` or ``session``.
    pub grant_kind: GrantKind,
    /// Current delegation target (stays in place), "" for a plain account.
    pub delegation: String,
    /// True when the account has no code: the same type-4 transaction
    /// re-delegates it to the pinned implementation, then revokes.
    pub redelegates: bool,
    /// The pinned implementation it is delegated to.
    pub delegate: Address,
}

/// Everything the owner confirms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    /// Grant or revoke.
    pub kind: PlanKind,
    /// Signer version.
    pub signer_version: String,
    /// Website the plan came from (None: offline revoke).
    pub website: Option<String>,
    /// Whether ``website`` is the official site.
    pub official_website: bool,
    /// Chain checked.
    pub chain_id: u64,
    /// RPC used.
    pub rpc_url: String,
    /// Development constants in use (local fork only).
    pub development: bool,
    /// Owner.
    pub owner: Address,
    /// The transaction, in words.
    pub transaction: String,
    /// Owner's gas balance, e.g. "1 DAI".
    pub balance: String,
    /// Grant details.
    pub grant: Option<GrantSummary>,
    /// Revocation details.
    pub revoke: Option<RevokeSummary>,
}

fn is_official(api: &str) -> bool {
    api.trim_end_matches('/') == c::DEFAULT_API
}

impl Summary {
    fn header(&self) -> Vec<String> {
        let mut lines = vec![format!("Awake Helix Signer {}", self.signer_version)];
        if let Some(api) = &self.website {
            let warn = if self.official_website { "" } else { "   <-- NOT the official site; continue only if you trust it" };
            lines.push(format!("Website (plan source): {api}{warn}"));
        }
        lines.push(format!("Chain:       Anubis Chain {} (checked via {})", self.chain_id, self.rpc_url));
        if self.development {
            lines.push("!!! DEVELOPMENT CONSTANTS (local fork only) - not the production contracts !!!".into());
        }
        lines
    }

    /// The text summary, line for line as the Python signer printed it.
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }

    /// The text summary as lines.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = self.header();
        lines.push(format!("Owner:       {}", self.owner));
        lines.push(format!("Transaction: {}", self.transaction));
        if let Some(grant) = &self.grant {
            lines.push(format!(
                "Delegate:    {} (Helix7702 implementation, pinned{}",
                grant.delegate,
                if grant.code_hash_verified { ", code hash verified)" } else { ")" }
            ));
            lines.push(format!("Session key: {} (this bot's own key, attested by the platform)", grant.session_key));
            match &grant.bot_script {
                Some(script) => lines.push(format!("Bot:         {script} (bot ID {})", grant.bot_id)),
                None => lines.push(format!("Bot ID:      {}", grant.bot_id)),
            }
            lines.push(format!("Grant ID:    {}", grant.grant_id));
            lines.push(format!("Valid from:  {}", grant.valid_after_text));
            lines.push(format!("Expires:     {}", grant.valid_until_text));
            lines.push(format!("Calls:       at most {} bot operations in total", grant.remaining_calls));
            lines.push("Rules (decoded from the calldata; every target is on the pinned HELIX allow-list):".into());
            for rule in &grant.rules {
                lines.extend(rule.lines());
            }
            if !grant.customized.is_empty() {
                lines.push(format!(
                    "You customized: {} (the values above are decoded from the calldata)",
                    grant.customized.join(", ")
                ));
            }
            lines.push("Value:       0 (no native value is sent)".into());
            lines.push(format!("Gas:         paid in {} by the owner; balance {}", c::GAS_SYMBOL, self.balance));
            lines.push("The bot can only make these calls, within these limits, until the expiry.".into());
            lines.push("You can revoke the grant at any time (awake-helix-signer revoke).".into());
        }
        if let Some(revoke) = &self.revoke {
            lines.push(format!("Grant ID:    {} ({} grant)", revoke.grant_id, revoke.grant_kind.as_str()));
            if revoke.redelegates {
                lines.push(format!(
                    "Delegation:  none now. The grant is inactive but still stored, and would act again after any re-delegation; this transaction re-delegates the account to {} and revokes it (the delegation stays afterwards)",
                    named(&revoke.delegate)
                ));
            } else {
                lines.push(format!("Delegation:  {} (stays in place; only the grant is revoked)", revoke.delegation));
            }
            lines.push("Value:       0 (no native value is sent)".into());
            lines.push(format!("Gas:         paid in {} by the owner; balance {}", c::GAS_SYMBOL, self.balance));
            lines.push("After this the session key can no longer act for this grant.".into());
        }
        lines
    }
}

fn base(kind: PlanKind, owner: Address, state: &AccountState, api: Option<&str>, rpc_url: &str, constants: &Constants) -> Summary {
    let api = api.filter(|api| !api.is_empty());
    Summary {
        kind,
        signer_version: crate::VERSION.to_string(),
        website: api.map(str::to_string),
        official_website: api.map(is_official).unwrap_or(false),
        chain_id: constants.chain_id,
        rpc_url: rpc_url.to_string(),
        development: constants.development,
        owner,
        transaction: String::new(),
        balance: dai(&state.balance),
        grant: None,
        revoke: None,
    }
}

/// Summarize a verified grant install.
pub fn grant_summary(plan: &GrantPlan, state: &AccountState, api: Option<&str>, rpc_url: &str, constants: &Constants) -> Summary {
    let mut summary = base(PlanKind::Grant, plan.owner, state, api, rpc_url, constants);
    let delegates = state.kind == AccountKind::Plain;
    summary.transaction = if delegates {
        "ONE EIP-7702 type-4 transaction from the owner to itself: delegate the account and install the grant".into()
    } else {
        "ordinary self-call installing the grant (already delegated to Helix)".into()
    };
    let bot_script = plan
        .plan
        .get("bot")
        .and_then(Value::as_object)
        .and_then(|bot| bot.get("script"))
        .filter(|script| truthy(script))
        .map(py_str);
    let customized = plan
        .plan
        .get("customization")
        .and_then(Value::as_object)
        .and_then(|custom| custom.get("customized"))
        .and_then(Value::as_array)
        .map(|items| items.iter().take(20).map(py_str).collect())
        .unwrap_or_default();
    summary.grant = Some(GrantSummary {
        delegates,
        delegate: plan.implementation,
        code_hash_verified: constants.implementation_code_hash.as_deref().map(|hash| !hash.is_empty()).unwrap_or(false),
        session_key: plan.session_key,
        bot_script,
        bot_id: plan.bot_id.clone(),
        grant_id: plan.grant_id.clone(),
        valid_after: plan.valid_after,
        valid_after_text: when(plan.valid_after),
        valid_until: plan.valid_until,
        valid_until_text: when(plan.valid_until),
        remaining_calls: plan.remaining_calls,
        rules: plan.rules.iter().enumerate().map(|(index, rule)| RuleSummary::of(index + 1, rule)).collect(),
        customized,
    });
    summary
}

/// Summarize a verified revocation.
pub fn revoke_summary(plan: &RevokePlan, state: &AccountState, api: Option<&str>, rpc_url: &str, constants: &Constants) -> Summary {
    let mut summary = base(PlanKind::Revoke, plan.owner, state, api, rpc_url, constants);
    let method = plan.grant_kind.revoke_signature();
    let redelegates = state.kind == AccountKind::Plain;
    summary.transaction = if redelegates {
        format!("ONE EIP-7702 type-4 transaction from the owner to itself: re-delegate the account to Helix and {method}")
    } else {
        format!("ordinary self-call {method}")
    };
    summary.revoke = Some(RevokeSummary {
        method: method.to_string(),
        grant_id: plan.grant_id.clone(),
        grant_kind: plan.grant_kind,
        delegation: state.target.clone(),
        redelegates,
        delegate: constants.implementation,
    });
    summary
}
