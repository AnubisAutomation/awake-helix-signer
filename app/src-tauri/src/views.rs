//! What the backend sends to the page (camelCase JSON; mirrored in src/api.ts)
//! and the one error shape every command returns.

use helix_signer_core::{msg, Message, Summary};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A command's refusal or error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandError {
    /// `refused`, `error`, `customize` (edit out of bounds, the plan stays),
    /// `busy`, `cancelled` or `nokey`.
    pub kind: &'static str,
    /// English text (logs, tests).
    pub message: String,
    /// The same with its code and params: what the page translates.
    pub msg: Message,
}

impl CommandError {
    pub fn new(kind: &'static str, msg: Message) -> Self {
        Self { kind, message: msg.text.clone(), msg }
    }
    pub fn refused(msg: Message) -> Self {
        Self::new("refused", msg)
    }
    pub fn error(msg: Message) -> Self {
        Self::new("error", msg)
    }
    /// A local failure without a code of its own (an OS error text).
    pub fn io(text: impl Into<String>) -> Self {
        Self::error(Message::plain("io", text))
    }
    pub fn busy() -> Self {
        Self::new("busy", msg!("app.busy", "Wait for the current request to finish."))
    }
    pub fn no_key() -> Self {
        Self::new("nokey", msg!("app.noKey", "Unlock your key first."))
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type CommandResult<T> = Result<T, CommandError>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub os: &'static str,
    pub arch: &'static str,
    pub mobile: bool,
    pub chain_id: u64,
    pub rpc: String,
    pub default_api: String,
    pub development: bool,
    pub selftest: bool,
    pub launched_for_ping: bool,
}

/// A validated anubisauto:// (or legacy awakehelix://) link (the token stays in the backend).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkView {
    pub action: String,
    pub api: String,
    pub official: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    pub address: String,
    /// `keystore`, `privateKey` or `mnemonic`.
    pub source: String,
    pub derivation_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Range {
    pub min: Value,
    pub max: Value,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleBounds {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_per_call: Option<Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_per_day: Option<Range>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorRule {
    pub index: usize,
    /// RuleKind: method names repeat across kinds (participate 1/10, claim 14/18).
    pub kind: u8,
    pub method: String,
    /// The target's pinned name, or "".
    pub target_name: String,
    /// The caps count calls (Origin claims): the per-call cap is always 1.
    pub counted: bool,
    pub unit: String,
    pub decimals: u32,
    pub max_per_call: String,
    pub max_per_day: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounds: Option<RuleBounds>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorBounds {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_calls: Option<Range>,
}

/// The editable values of a verified grant plan, with the website's ranges.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorPlan {
    pub valid_until: u64,
    pub remaining_calls: u64,
    pub bounds: EditorBounds,
    pub rules: Vec<EditorRule>,
}

/// A verified plan awaiting the typed confirmation.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    /// `grant` or `revoke`.
    pub kind: String,
    pub confirm_word: String,
    /// The summary as the command line prints it (English).
    pub summary: String,
    /// The same summary as data: the page renders it in its language.
    pub summary_data: Summary,
    pub editor: Option<EditorPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResult {
    pub tx_hash: String,
    pub block: u64,
    pub reported: bool,
    pub report_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRowView {
    pub grant_id: String,
    pub kind: String,
    pub status: String,
    pub key: String,
    pub key_origin: String,
    pub bot: String,
    /// `none`, `unknown`, `deleted`, `running` or `stopped`.
    pub bot_state: String,
    pub bot_script: String,
    pub bot_id: String,
    pub valid_until: Option<i64>,
    pub remaining_calls: Option<i64>,
    pub revocable: bool,
    pub active: bool,
    pub delegation: String,
    pub not_revocable_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListingView {
    pub owner: String,
    pub rows: Vec<GrantRowView>,
    pub scan_complete: bool,
    pub scan_percent: i64,
    pub truncated: bool,
    /// The website's cached copy while it re-reads the chain (statuses may be
    /// a few seconds old); the page reads the list again shortly.
    pub refreshing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingView {
    pub count: usize,
    pub summaries: Vec<String>,
    pub summary_data: Vec<Summary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeOutcome {
    pub done: usize,
    pub total: usize,
    pub cancelled: bool,
    pub listing: ListingView,
    pub lines: Vec<Message>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupView {
    pub os: &'static str,
    pub mobile: bool,
    pub handler: Option<String>,
    pub command: Option<String>,
    pub can_register: bool,
    pub can_install_cli: bool,
    pub cli_places: Vec<String>,
    pub first_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingView {
    pub version: String,
    pub os: String,
    pub arch: String,
    pub api: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    pub scope: &'static str,
    /// English text.
    pub line: String,
    /// The line with its code and params.
    pub msg: Message,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProgressEvent {
    pub done: usize,
    pub total: usize,
}
