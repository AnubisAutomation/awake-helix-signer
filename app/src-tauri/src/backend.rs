//! The app's view of the core library. `Core` is everything the controller
//! needs from `helix-signer-core`; `RealCore` implements it with the library
//! (and is what the app ships), the unit tests implement it with a mock.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::views::{
    CommandError, EditorBounds, EditorPlan, EditorRule, GrantRowView, KeyView, ListingView, PingView, Range, RuleBounds,
    SessionView, SignResult,
};

/// A secret string from the page, wiped when dropped.
#[derive(Default)]
pub struct Secret(pub Zeroizing<String>);

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut text = String::deserialize(deserializer)?;
        let secret = Secret(Zeroizing::new(text.clone()));
        text.zeroize();
        Ok(secret)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Where the key comes from (the page's key box).
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum KeyInput {
    /// A keystore file: a path on desktop, the file's text on mobile.
    #[serde(rename_all = "camelCase")]
    Keystore { path: Option<PathBuf>, json: Option<String>, password: Secret },
    #[serde(rename_all = "camelCase")]
    PrivateKey { secret: Secret },
    #[serde(rename_all = "camelCase")]
    Mnemonic { phrase: Secret, index: u32 },
}

/// A parsed link, as the controller needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    pub action: String,
    pub token: String,
    pub api: String,
}

/// One revocation done in a sequence.
#[derive(Debug, Clone)]
pub struct RevokeDone {
    pub tx_hash: String,
    pub block: u64,
    pub stopped_bots: Vec<String>,
}

/// A core error as the page shows it.
pub fn refusal(error: &helix_signer_core::Error) -> CommandError {
    use helix_signer_core::ErrorKind;
    let kind = match error.kind() {
        ErrorKind::CustomizeRefused => "customize",
        ErrorKind::Cancelled => "cancelled",
        ErrorKind::Io => "error",
        _ => "refused",
    };
    CommandError::new(kind, error.msg().clone())
}

pub type Log<'a> = &'a (dyn Fn(&helix_signer_core::Message) + Sync);

/// Everything the controller needs from the core library.
pub trait Core: Send + Sync + 'static {
    type Key: Send + Sync + Clone + 'static;
    type Session: Send + Sync + Clone + 'static;
    type Site: Send + Sync + 'static;

    fn development(&self) -> bool;
    fn rpc_url(&self) -> String;
    fn default_api(&self) -> String;
    fn chain_id(&self) -> u64;
    fn official(&self, api: &str) -> bool;

    fn parse_link(&self, url: &str) -> Result<LinkInfo, CommandError>;
    fn load_key(&self, input: KeyInput) -> Result<Self::Key, CommandError>;
    fn key_view(&self, key: &Self::Key) -> KeyView;
    fn wipe(&self, key: &mut Self::Key);
    fn export_keystore(&self, key: &Self::Key, password: &str) -> Result<String, CommandError>;

    fn prepare(&self, link: &LinkInfo, key: &Self::Key, log: Log) -> Result<Self::Session, CommandError>;
    fn customize(&self, session: &Self::Session, request: &Value, log: Log) -> Result<Self::Session, CommandError>;
    fn session_view(&self, session: &Self::Session) -> SessionView;
    /// Sign and broadcast; consumes (and wipes) the key.
    fn execute(&self, session: &Self::Session, key: Self::Key, log: Log) -> Result<SignResult, CommandError>;

    fn website(&self, api: &str) -> Result<Self::Site, CommandError>;
    fn signed_in(&self, site: &Self::Site) -> bool;
    fn login(&self, site: &Self::Site, key: &Self::Key, log: Log) -> Result<(), CommandError>;
    fn logout(&self, site: &Self::Site);
    fn grants(&self, site: &Self::Site) -> Result<ListingView, CommandError>;
    fn prepare_grant_revoke(&self, site: &Self::Site, grant_id: &str, key: &Self::Key, log: Log)
        -> Result<Option<Self::Session>, CommandError>;
    fn grant_of(&self, session: &Self::Session) -> String;
    fn execute_grant_revoke(&self, session: &Self::Session, key: &Self::Key, site: &Self::Site, log: Log)
        -> Result<RevokeDone, CommandError>;

    fn ping(&self, link: &LinkInfo) -> Result<PingView, CommandError>;
}

// ------------------------------------------------------------------ real core

use helix_signer_core as core;

/// The core library with the system transport and the pinned (or, in a
/// `dev-constants` build, development) constants.
pub struct RealCore {
    pub constants: core::Constants,
    pub rpc_url: String,
    pub default_api: String,
    pub allowed_apis: Vec<String>,
    pub transport: core::Transport,
}

impl RealCore {
    /// Production: pinned constants, official website and RPC.
    pub fn production() -> Self {
        Self {
            constants: core::production(),
            rpc_url: core::DEFAULT_RPC.to_string(),
            default_api: core::DEFAULT_API.to_string(),
            allowed_apis: Vec::new(),
            transport: core::Transport::system(),
        }
    }

    /// Development constants on a loopback RPC (end-to-end tests only).
    pub fn development(dev_file: &std::path::Path, rpc_url: &str, api: Option<&str>) -> Result<Self, CommandError> {
        let constants = core::load_constants(Some(dev_file), rpc_url).map_err(|error| refusal(&error))?;
        Ok(Self {
            constants,
            rpc_url: rpc_url.to_string(),
            default_api: api.unwrap_or(core::DEFAULT_API).trim_end_matches('/').to_string(),
            allowed_apis: Vec::new(),
            transport: core::Transport::system(),
        })
    }
}

/// A Python-style label for the key source.
fn source_name(source: &str) -> &'static str {
    match source {
        "keystore" => "keystore",
        "mnemonic" => "mnemonic",
        _ => "privateKey",
    }
}

fn range(value: Option<&Value>) -> Option<Range> {
    let value = value?.as_object()?;
    Some(Range { min: value.get("min")?.clone(), max: value.get("max")?.clone() })
}

/// The editor's values of a verified grant plan.
pub fn editor_of(plan: &core::GrantPlan) -> EditorPlan {
    let request = core::custom::request_of(plan);
    let bounds = plan.plan.get("bounds");
    let rule_bounds = bounds.and_then(|value| value.get("rules")).and_then(Value::as_array);
    let rules = plan
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let (unit, decimals) = rule.unit();
            let change = request.rules.iter().find(|item| item.index == index);
            let bound = rule_bounds.and_then(|list| {
                list.iter().find(|item| item.get("index").and_then(Value::as_u64) == Some(index as u64)).or_else(|| list.get(index))
            });
            EditorRule {
                index,
                method: rule.method().to_string(),
                unit: unit.to_string(),
                decimals,
                max_per_call: change
                    .and_then(|item| item.max_per_call.clone())
                    .unwrap_or_else(|| core::amount(&rule.max_amount, decimals)),
                max_per_day: change
                    .and_then(|item| item.max_per_day.clone())
                    .unwrap_or_else(|| core::amount(&rule.max_daily, decimals)),
                bounds: bound.map(|item| RuleBounds { max_per_call: range(item.get("maxPerCall")), max_per_day: range(item.get("maxPerDay")) }),
            }
        })
        .collect();
    EditorPlan {
        valid_until: plan.valid_until,
        remaining_calls: plan.remaining_calls,
        bounds: EditorBounds {
            valid_until: range(bounds.and_then(|value| value.get("validUntil"))),
            remaining_calls: range(bounds.and_then(|value| value.get("remainingCalls"))),
        },
        rules,
    }
}

fn listing_view(listing: &core::Listing) -> ListingView {
    ListingView {
        owner: listing.owner.clone(),
        rows: listing
            .rows
            .iter()
            .map(|row| GrantRowView {
                grant_id: row.grant_id.clone(),
                kind: row.kind.clone(),
                status: row.status.clone(),
                key: row.key.clone(),
                key_origin: row.key_origin.clone(),
                bot: row.bot.clone(),
                bot_state: row.bot_state.clone(),
                bot_script: row.bot_script.clone(),
                bot_id: row.bot_id.clone(),
                valid_until: row.valid_until,
                remaining_calls: row.remaining_calls,
                revocable: row.revocable,
                active: row.active(),
                delegation: row.delegation.clone(),
                not_revocable_reason: row.not_revocable_reason.clone(),
            })
            .collect(),
        scan_complete: listing.scan_complete,
        scan_percent: listing.scan_percent,
        truncated: listing.truncated,
    }
}

fn origin(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let host = rest.split('/').next().unwrap_or(rest);
    let scheme = url.split("://").next().unwrap_or("https");
    format!("{}://{}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase())
}

impl Core for RealCore {
    type Key = core::KeyMaterial;
    type Session = core::Session;
    type Site = core::Website;

    fn development(&self) -> bool {
        self.constants.development
    }
    fn rpc_url(&self) -> String {
        self.rpc_url.clone()
    }
    fn default_api(&self) -> String {
        self.default_api.clone()
    }
    fn chain_id(&self) -> u64 {
        self.constants.chain_id
    }
    fn official(&self, api: &str) -> bool {
        origin(api) == origin(core::DEFAULT_API)
    }

    fn parse_link(&self, url: &str) -> Result<LinkInfo, CommandError> {
        let link = core::parse_link(url, &self.allowed_apis, self.constants.development).map_err(|error| refusal(&error))?;
        Ok(LinkInfo { action: link.action.as_str().to_string(), token: link.token, api: link.api })
    }

    fn load_key(&self, input: KeyInput) -> Result<Self::Key, CommandError> {
        let result = match input {
            KeyInput::Keystore { path: Some(path), password, .. } => core::KeyMaterial::from_keystore(&path, &password.0),
            KeyInput::Keystore { json: Some(json), password, .. } => core::KeyMaterial::from_keystore_json(&json, "keystore", &password.0),
            KeyInput::Keystore { .. } => return Err(CommandError::refused(core::msg!("app.chooseKeystore", "Choose the keystore file."))),
            KeyInput::PrivateKey { secret } => core::KeyMaterial::from_private_key(&secret.0),
            KeyInput::Mnemonic { phrase, index } => core::KeyMaterial::from_mnemonic(&phrase.0, i64::from(index), ""),
        };
        result.map_err(|error| refusal(&error))
    }

    fn key_view(&self, key: &Self::Key) -> KeyView {
        let path = key.path();
        KeyView {
            address: key.address().to_checksum(),
            source: source_name(key.source()).to_string(),
            derivation_path: (!path.is_empty()).then(|| path.to_string()),
        }
    }

    fn wipe(&self, key: &mut Self::Key) {
        key.wipe();
    }

    fn export_keystore(&self, key: &Self::Key, password: &str) -> Result<String, CommandError> {
        // The document goes straight to the save dialog; nothing is written here.
        core::keystore_json(key, password).map_err(|error| refusal(&error))
    }

    fn prepare(&self, link: &LinkInfo, key: &Self::Key, log: Log) -> Result<Self::Session, CommandError> {
        let result = if link.action == "sign" {
            core::prepare_sign(&link.token, &link.api, &self.rpc_url, &self.constants, Some(key), &self.transport, log)
        } else {
            let source = core::RevokeSource::Plan { token: link.token.clone(), api: link.api.clone() };
            core::prepare_revoke(&self.rpc_url, &self.constants, source, Some(key), &self.transport, log)
        };
        result.map_err(|error| refusal(&error))
    }

    fn customize(&self, session: &Self::Session, request: &Value, log: Log) -> Result<Self::Session, CommandError> {
        let request: core::CustomizeRequest =
            serde_json::from_value(request.clone())
                .map_err(|error| CommandError::refused(core::msg!("app.malformedEdit", "Malformed edit: {detail}", detail = error.to_string())))?;
        core::customize(session, &request, log).map_err(|error| refusal(&error))
    }

    fn session_view(&self, session: &Self::Session) -> SessionView {
        SessionView {
            kind: if session.grant().is_some() { "grant" } else { "revoke" }.to_string(),
            confirm_word: session.confirm_word().to_string(),
            summary: session.summary.text(),
            summary_data: session.summary.clone(),
            editor: session.grant().map(editor_of),
        }
    }

    fn execute(&self, session: &Self::Session, key: Self::Key, log: Log) -> Result<SignResult, CommandError> {
        let outcome = if session.grant().is_some() {
            core::execute_sign(session, key, log)
        } else {
            core::execute_revoke(session, key, log)
        }
        .map_err(|error| refusal(&error))?;
        Ok(SignResult { tx_hash: outcome.tx_hash, block: outcome.block, reported: outcome.reported, report_message: outcome.report_message })
    }

    fn website(&self, api: &str) -> Result<Self::Site, CommandError> {
        core::Website::new(api, Arc::clone(&self.transport.website)).map_err(|error| refusal(&error))
    }
    fn signed_in(&self, site: &Self::Site) -> bool {
        site.owner().is_some()
    }
    fn login(&self, site: &Self::Site, key: &Self::Key, log: Log) -> Result<(), CommandError> {
        site.login(key, log).map(|_| ()).map_err(|error| refusal(&error))
    }
    fn logout(&self, site: &Self::Site) {
        site.logout();
    }
    fn grants(&self, site: &Self::Site) -> Result<ListingView, CommandError> {
        site.grants().map(|listing| listing_view(&listing)).map_err(|error| refusal(&error))
    }
    fn prepare_grant_revoke(&self, site: &Self::Site, grant_id: &str, key: &Self::Key, log: Log)
        -> Result<Option<Self::Session>, CommandError> {
        core::prepare_grant_revoke(site, grant_id, &self.rpc_url, &self.constants, key, &self.transport, log)
            .map_err(|error| refusal(&error))
    }
    fn grant_of(&self, session: &Self::Session) -> String {
        match &session.plan {
            core::VerifiedPlan::Grant(plan) => plan.grant_id.clone(),
            core::VerifiedPlan::Revoke(plan) => plan.grant_id.clone(),
        }
    }
    fn execute_grant_revoke(&self, session: &Self::Session, key: &Self::Key, site: &Self::Site, log: Log)
        -> Result<RevokeDone, CommandError> {
        let outcome = core::execute_grant_revoke(session, key, site, log).map_err(|error| refusal(&error))?;
        Ok(RevokeDone {
            tx_hash: outcome.tx_hash,
            block: outcome.block,
            stopped_bots: outcome.stopped_bots.iter().map(|bot| bot.as_str().map(str::to_string).unwrap_or_else(|| bot.to_string())).collect(),
        })
    }

    fn ping(&self, link: &LinkInfo) -> Result<PingView, CommandError> {
        let result = core::send_ping(&link.api, &link.token, self.transport.website.as_ref()).map_err(|error| refusal(&error))?;
        Ok(PingView { version: result.version, os: result.os, arch: result.arch, api: result.api })
    }
}
