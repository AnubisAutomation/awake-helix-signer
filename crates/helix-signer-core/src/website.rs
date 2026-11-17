//! The signer's own login on the website, and the owner's grant list.
//!
//! The signer signs in exactly like the browser: ``GET /api/csrf``, ``POST
//! /api/auth/challenge``, a local ``personal_sign`` (EIP-191) of the returned
//! message, ``POST /api/auth/verify``. The session and CSRF cookies are kept in
//! memory only, sent only to this API origin, never written or printed, and
//! dropped on ``logout``. Redirects are not followed, so no cookie can leave.
//!
//! Before signing, the challenge must be a sign-in message for this owner on
//! this chain and for the website being talked to: otherwise a hostile
//! ``--api`` could relay another site's challenge and obtain that site's
//! session with the owner's signature.
//!
//! Timeouts: connecting waits at most [`CONNECT_TIMEOUT`], the answer at
//! most [`LIST_TIMEOUT`] (logout: [`LOGOUT_TIMEOUT`]). A busy website (no
//! answer in time, HTTP 502/503/504, or its ``server.busy`` answer) gives
//! [`BUSY`]; no connection gives [`UNREACHABLE`]. GET requests are sent once
//! more after [`RETRY_PAUSE`] when the website was busy or a timeout hit;
//! POST requests (sign-in, revocation) are never repeated.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::address::Address;
use crate::error::{Error, ErrorKind, Result};
use crate::keys::KeyMaterial;
use crate::message::Message;
use crate::net::{
    error_body, is_loopback, json_object, origin, urlsplit, user_agent, validate_url, Failure, HttpClient, HttpRequest, TransportError, CONNECT_TIMEOUT,
};
use crate::pyfmt::py_str;
use crate::summary::when;

const COOKIES: [&str; 2] = ["sessionid", "csrftoken"];
/// Read timeout of the sign-in steps, the grant list and the revocation calls.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// Read timeout of the (best effort) logout.
pub const LOGOUT_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause before a GET is sent again.
pub const RETRY_PAUSE: Duration = Duration::from_millis(1500);
/// Message code: the website is busy (no answer in time, 502/503/504, ``server.busy``).
pub const BUSY: &str = "website.busy";
/// Message code: the website cannot be reached (DNS, refused, connect timeout, TLS).
pub const UNREACHABLE: &str = "website.unreachable";
/// Statuses "revoke all" includes (when revocable): usable now or later, or
/// dormant (``inactive``: it acts again if the account re-delegates).
const ACTIVE_STATUSES: [&str; 3] = ["active", "not_yet_valid", "inactive"];

/// What a grant status means, for ``grants list``; an unknown (newer)
/// status is shown as it is.
pub fn status_text(status: &str, not_revocable_reason: &str) -> String {
    let text = match status {
        "active" => "active",
        "not_yet_valid" => "not yet valid",
        "inactive" => "inactive: this account is not delegated to Helix7702Account; it becomes active again if the account re-delegates",
        "expired" => "expired",
        "exhausted" => "calls used up",
        "revoked" => "revoked",
        "missing" => "not installed (never on chain)",
        "unavailable" => "temporarily unreadable: the chain could not be read just now; run `grants list` again in a moment",
        other => return other.replace('_', " "),
    };
    if not_revocable_reason == "otherDelegation" {
        format!("{text} (delegated to another contract, so it cannot be revoked here)")
    } else {
        text.to_string()
    }
}
const COOKIE_ATTRIBUTES: [&str; 9] = ["expires", "path", "comment", "domain", "max-age", "secure", "httponly", "version", "samesite"];

fn hosts_match(left: &str, right: &str) -> bool {
    left == right || left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

fn hostname(url: &str) -> String {
    urlsplit(url).ok().and_then(|parts| parts.hostname()).unwrap_or_default().to_lowercase()
}

/// Refuse anything but a sign-in message for this owner, chain and website;
/// returns the site's domain as named in the message.
pub fn check_challenge(message: Option<&str>, owner: &Address, api: &str, chain_id: u64) -> Result<String> {
    let message = message.ok_or_else(|| Error::login("The website sent no sign-in message."))?;
    let lines: Vec<&str> = message.split('\n').collect();
    let not_ours = || Error::coded(ErrorKind::Login, crate::msg!("login.notOurs", "The website's sign-in message is not for this account; nothing was signed."));
    let domain = lines[0]
        .strip_suffix(" wants you to sign in with your Ethereum account:")
        .filter(|domain| !domain.is_empty() && !domain.chars().any(char::is_whitespace))
        .ok_or_else(not_ours)?;
    if lines.len() < 2 || lines[1].trim().to_lowercase() != owner.to_lower() {
        return Err(not_ours());
    }
    let host = hostname(&format!("//{domain}"));
    let same_site = if is_loopback(api) { is_loopback(&format!("http://{domain}")) } else { hosts_match(&host, &hostname(api)) };
    if !same_site {
        return Err(Error::login(format!("The sign-in message is for {domain}, but this is {}; nothing was signed.", origin(api))));
    }
    let uri = lines.iter().find_map(|line| line.strip_prefix("URI: ")).map(str::trim).unwrap_or("");
    if urlsplit(uri).map(|parts| parts.netloc).unwrap_or_default() != domain {
        return Err(Error::login("The website's sign-in message names another site; nothing was signed."));
    }
    if !message.contains(&format!("\nChain ID: {chain_id}\n")) {
        return Err(Error::login("The website's sign-in message is for another chain; nothing was signed."));
    }
    Ok(domain.to_string())
}

/// One grant of ``GET /api/grants``.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRow {
    /// Lowercase bytes32 ID.
    pub grant_id: String,
    /// ``policy`` or ``session``.
    pub kind: String,
    /// Live status (``active``, ``revoked``, ...).
    pub status: String,
    /// Session key address, or "".
    pub key: String,
    /// ``hosted`` or ``unknown``.
    pub key_origin: String,
    /// Linked bot, as text (English, for ``grants list``).
    pub bot: String,
    /// The linked bot for the app: ``none`` (no linked bot), ``unknown``
    /// (hosted key, bot unknown), ``deleted``, ``running`` or ``stopped``.
    pub bot_state: String,
    /// The bot's script name ("" when the website names none).
    pub bot_script: String,
    /// The bot's ID ("" when none).
    pub bot_id: String,
    /// Unix seconds.
    pub valid_until: Option<i64>,
    /// Calls left.
    pub remaining_calls: Option<i64>,
    /// Whether this signer can revoke it (stored on chain, and the account is
    /// not delegated to another contract).
    pub revocable: bool,
    /// ``helix``, ``none`` or ``other``: the account's code when it was read.
    pub delegation: String,
    /// ``otherDelegation`` when a stored grant cannot be revoked here, else "".
    pub not_revocable_reason: String,
}

impl GrantRow {
    /// Whether "revoke all active" includes this grant.
    pub fn active(&self) -> bool {
        self.revocable && ACTIVE_STATUSES.contains(&self.status.as_str())
    }

    /// Expiry in UTC and local time.
    pub fn until_text(&self) -> String {
        match self.valid_until {
            Some(seconds) if seconds != 0 => when(seconds.max(0) as u64),
            _ => "-".into(),
        }
    }

    /// Remaining calls.
    pub fn calls_text(&self) -> String {
        self.remaining_calls.map(|calls| calls.to_string()).unwrap_or_else(|| "-".into())
    }

    /// The lines ``grants list`` prints for this grant.
    pub fn describe(&self) -> String {
        // The statuses whose name says it all keep their former two-word lines;
        // the others (and a refusal) get a line explaining them.
        let plain = ["active", "not_yet_valid", "expired", "exhausted", "revoked"].contains(&self.status.as_str());
        let note = if plain && self.not_revocable_reason.is_empty() {
            String::new()
        } else {
            format!("\n  status: {}", status_text(&self.status, &self.not_revocable_reason))
        };
        let refused = if self.not_revocable_reason.is_empty() { "" } else { "\n  revocable here: no" };
        format!(
            "{}  {}{note}\n  key: {} ({})\n  bot: {}\n  valid until: {}\n  remaining calls: {}{refused}",
            self.grant_id,
            self.status,
            if self.key.is_empty() { "-" } else { &self.key },
            self.key_origin,
            self.bot,
            self.until_text(),
            self.calls_text()
        )
    }
}

/// The linked bot: (state, script, id); see [`GrantRow::bot_state`].
fn bot_parts(row: &Map<String, Value>) -> (&'static str, String, String) {
    let Some(Value::Object(bot)) = row.get("bot") else {
        let hosted = row.get("keyOrigin").and_then(Value::as_str) == Some("hosted");
        let policy = row.get("kind").and_then(Value::as_str) == Some("policy");
        return (if hosted && policy { "unknown" } else { "none" }, String::new(), String::new());
    };
    let script = match bot.get("script") {
        Some(script) if crate::pyfmt::truthy(script) => py_str(script),
        _ => String::new(),
    };
    let id = match bot.get("id") {
        Some(Value::Null) | None => String::new(),
        Some(id) => py_str(id),
    };
    let state = if bot.get("deleted").map(crate::pyfmt::truthy).unwrap_or(false) {
        "deleted"
    } else if bot.get("status").and_then(Value::as_str) == Some("active") {
        "running"
    } else {
        "stopped"
    };
    (state, script, id)
}

fn bot_text(row: &Map<String, Value>) -> String {
    let Some(Value::Object(bot)) = row.get("bot") else {
        let hosted = row.get("keyOrigin").and_then(Value::as_str) == Some("hosted");
        let policy = row.get("kind").and_then(Value::as_str) == Some("policy");
        return if hosted && policy { "hosted key, bot unknown".into() } else { "no linked bot".into() };
    };
    let name = match bot.get("script") {
        Some(script) if crate::pyfmt::truthy(script) => py_str(script),
        _ => "bot".into(),
    };
    if bot.get("deleted").map(crate::pyfmt::truthy).unwrap_or(false) {
        return format!("{name} (deleted)");
    }
    let id = bot.get("id").map(py_str).unwrap_or_else(|| "None".into());
    let running = bot.get("status").and_then(Value::as_str) == Some("active");
    format!("{name} #{id} ({})", if running { "running" } else { "stopped" })
}

fn optional_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) if number.is_i64() || number.is_u64() => number.as_i64(),
        _ => None,
    }
}

/// Answer of ``GET /api/grants``.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listing {
    /// Lowercase owner.
    pub owner: String,
    /// Every grant, in the server's order.
    pub rows: Vec<GrantRow>,
    /// Whether the install history scan finished.
    pub scan_complete: bool,
    /// Its progress.
    pub scan_percent: i64,
    /// Only the newest grants are listed.
    pub truncated: bool,
    /// Account delegation state.
    pub delegation: Value,
    /// The website answered from its cached copy while it re-reads the chain
    /// (statuses may be a few seconds old); asking again soon gives the fresh
    /// list. Revocation never relies on it: the revocation call is read fresh.
    pub refreshing: bool,
    /// When the website made the list (ISO time), "" when it does not say.
    pub generated_at: String,
}

impl Listing {
    /// Grants "revoke all active" handles.
    pub fn active(&self) -> Vec<&GrantRow> {
        self.rows.iter().filter(|row| row.active()).collect()
    }
}

fn int_of(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Number(number)) => number.as_i64().or_else(|| number.as_f64().map(|f| f.trunc() as i64)).unwrap_or(0),
        Some(Value::String(text)) => text.trim().parse().unwrap_or(0),
        Some(Value::Bool(flag)) => *flag as i64,
        _ => 0,
    }
}

/// Parse ``GET /api/grants`` and require it to be this owner's.
pub fn parse_listing(raw: &Map<String, Value>, owner: &str) -> Result<Listing> {
    if raw.get("owner").map(py_str).unwrap_or_default().to_lowercase() != owner.to_lowercase() {
        return Err(Error::coded(ErrorKind::Login, crate::msg!("login.otherListing", "The website listed the grants of another account.")));
    }
    let malformed = || Error::login("The website's grant list is malformed.");
    let rows = raw.get("grants").and_then(Value::as_array).ok_or_else(malformed)?;
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row.as_object().ok_or_else(malformed)?;
        let grant_id = row.get("grantId").and_then(Value::as_str).ok_or_else(malformed)?;
        let text = |key: &str, default: &str| match row.get(key) {
            Some(value) if crate::pyfmt::truthy(value) => py_str(value),
            _ => default.to_string(),
        };
        parsed.push(GrantRow {
            grant_id: grant_id.to_lowercase(),
            kind: row.get("kind").map(py_str).unwrap_or_default(),
            status: row.get("status").map(py_str).unwrap_or_default(),
            key: text("key", ""),
            key_origin: text("keyOrigin", "unknown"),
            bot: bot_text(row),
            bot_state: bot_parts(row).0.to_string(),
            bot_script: bot_parts(row).1,
            bot_id: bot_parts(row).2,
            valid_until: optional_int(row.get("validUntilUnix")),
            remaining_calls: optional_int(row.get("remainingCalls")),
            revocable: row.get("revocable") == Some(&Value::Bool(true)),
            delegation: text("delegation", ""),
            not_revocable_reason: text("notRevocableReason", ""),
        });
    }
    let scan = raw.get("scan").and_then(Value::as_object).cloned().unwrap_or_default();
    let delegation = raw.get("delegation").filter(|value| value.is_object()).cloned().unwrap_or_else(|| json!({}));
    Ok(Listing {
        owner: owner.to_lowercase(),
        rows: parsed,
        scan_complete: scan.get("complete") != Some(&Value::Bool(false)),
        scan_percent: match scan.get("percent") {
            Some(value) if crate::pyfmt::truthy(value) => int_of(Some(value)),
            _ => 0,
        },
        truncated: raw.get("truncated") == Some(&Value::Bool(true)),
        delegation,
        refreshing: raw.get("refreshing") == Some(&Value::Bool(true)),
        generated_at: raw.get("generatedAt").and_then(Value::as_str).unwrap_or_default().to_string(),
    })
}

/// A failed request, and whether a GET may be sent again.
struct Failed {
    error: Error,
    retry: bool,
}

impl Failed {
    fn fatal(error: Error) -> Failed {
        Failed { error, retry: false }
    }
}

/// The website is busy: the answer did not come in time, or it said so.
fn busy(site: &str, detail: &str) -> Error {
    Error::coded(
        ErrorKind::Network,
        crate::msg!(
            "website.busy",
            "The website {site} is busy and did not answer in time ({detail}); try again in a moment.",
            site = site,
            detail = detail
        ),
    )
}

/// The website gave no HTTP answer: busy when it did not answer in time
/// once connected, else unreachable.
fn unanswered(error: &TransportError, site: &str) -> Error {
    match error.failure {
        Failure::NoAnswer => busy(site, &error.detail),
        Failure::Unreachable | Failure::ConnectTimeout => Error::coded(
            ErrorKind::Network,
            crate::msg!(
                "website.unreachable",
                "Cannot reach the website {site} ({detail}); check the internet connection and try again.",
                site = site,
                detail = error.detail.as_str()
            ),
        ),
    }
}

/// HTTP 502/503/504 (a proxy or the website out of time) or the website's
/// own ``server.busy`` answer.
fn busy_answer(status: u16, body: &Map<String, Value>) -> bool {
    matches!(status, 502..=504) || body.get("code").and_then(Value::as_str) == Some("server.busy")
}

struct State {
    owner: Option<Address>,
    cookies: Vec<(String, String)>,
    origin: String,
}

/// A logged-in conversation with one website API.
pub struct Website {
    api: String,
    client: Arc<dyn HttpClient>,
    state: Mutex<State>,
    retry_pause: Duration,
}

impl std::fmt::Debug for Website {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let owner = self.owner().map(|owner| owner.to_checksum()).unwrap_or_default();
        write!(f, "Website(api='{}', owner='{owner}')", self.api)
    }
}

/// Parse one Set-Cookie header the way ``http.cookies.SimpleCookie`` does
/// for the cookies the signer keeps.
fn parse_set_cookie(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, raw) = part.split_once('=').map(|(name, raw)| (name.trim(), raw.trim())).unwrap_or((part, ""));
        if COOKIE_ATTRIBUTES.contains(&name.to_lowercase().as_str()) || !part.contains('=') {
            continue;
        }
        let unquoted = raw.strip_prefix('"').and_then(|inner| inner.strip_suffix('"')).unwrap_or(raw);
        out.push((name.to_string(), unquoted.to_string()));
    }
    out
}

impl Website {
    /// Validate the API base.
    pub fn new(api: &str, client: Arc<dyn HttpClient>) -> Result<Website> {
        let api = validate_url(api, "Website API")?;
        let origin = origin(&api);
        Ok(Website { api, client, state: Mutex::new(State { owner: None, cookies: Vec::new(), origin }), retry_pause: RETRY_PAUSE })
    }

    /// Another pause before a GET is sent again (tests use zero).
    pub fn with_retry_pause(mut self, pause: Duration) -> Website {
        self.retry_pause = pause;
        self
    }

    /// Validated API base.
    pub fn api(&self) -> &str {
        &self.api
    }

    /// Signed-in address, None before ``login``.
    pub fn owner(&self) -> Option<Address> {
        self.state.lock().map(|state| state.owner).unwrap_or(None)
    }

    fn remember(&self, headers: &[(String, String)]) {
        let Ok(mut state) = self.state.lock() else { return };
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            for (cookie, content) in parse_set_cookie(value) {
                if !COOKIES.contains(&cookie.as_str()) {
                    continue;
                }
                let position = state.cookies.iter().position(|(key, _)| *key == cookie);
                match (content.is_empty(), position) {
                    (false, Some(index)) => state.cookies[index].1 = content,
                    (false, None) => state.cookies.push((cookie, content)),
                    (true, Some(index)) => {
                        state.cookies.remove(index);
                    }
                    (true, None) => {}
                }
            }
        }
    }

    /// Send one API request with the session; `timeout` is the read
    /// timeout. A GET is sent once more (after a short pause) when the
    /// website was busy or timed out; other methods are sent once.
    pub fn call(&self, path: &str, method: &str, body: Option<&Value>, timeout: Duration) -> Result<Map<String, Value>> {
        let attempts = if method == "GET" { 2 } else { 1 };
        let mut attempt = 1;
        loop {
            match self.call_once(path, method, body, timeout) {
                Err(failed) if attempt < attempts && failed.retry => {
                    attempt += 1;
                    if !self.retry_pause.is_zero() {
                        std::thread::sleep(self.retry_pause);
                    }
                }
                Err(failed) => return Err(failed.error),
                Ok(answer) => return Ok(answer),
            }
        }
    }

    fn call_once(&self, path: &str, method: &str, body: Option<&Value>, timeout: Duration) -> std::result::Result<Map<String, Value>, Failed> {
        let data = if body.is_none() && method == "GET" {
            None
        } else {
            Some(serde_json::to_vec(body.unwrap_or(&json!({}))).unwrap_or_default())
        };
        let (site, cookies) = {
            let state = self.state.lock().map_err(|_| Failed::fatal(Error::network("The website session is unavailable.")))?;
            (state.origin.clone(), state.cookies.clone())
        };
        let mut headers = vec![("Accept".to_string(), "application/json".to_string()), ("User-Agent".to_string(), user_agent())];
        if data.is_some() {
            headers.push(("Content-Type".into(), "application/json".into()));
            headers.push(("Origin".into(), site.clone()));
            if let Some((_, token)) = cookies.iter().find(|(name, _)| name == "csrftoken") {
                headers.push(("X-CSRFToken".into(), token.clone()));
            }
        }
        if !cookies.is_empty() {
            let joined: Vec<String> = cookies.iter().map(|(name, value)| format!("{name}={value}")).collect();
            headers.push(("Cookie".into(), joined.join("; ")));
        }
        let request = HttpRequest {
            method: method.to_string(),
            url: format!("{}{path}", self.api),
            headers,
            body: data,
            connect_timeout: CONNECT_TIMEOUT,
            timeout,
        };
        let response = self.client.send(&request).map_err(|error| Failed { retry: error.timed_out(), error: unanswered(&error, &site) })?;
        self.remember(&response.headers);
        if !(200..300).contains(&response.status) {
            let body = error_body(&response.body);
            if busy_answer(response.status, &body) {
                return Err(Failed { retry: true, error: busy(&site, &format!("HTTP {}", response.status)) });
            }
            return Err(Failed::fatal(Error::http_status(response.status, body)));
        }
        json_object(&response.body, &site).map_err(Failed::fatal)
    }

    /// Sign in with the loaded key (a signature only, never a transaction).
    pub fn login(&self, material: &KeyMaterial, log: &dyn Fn(&Message)) -> Result<Address> {
        let owner = material.address();
        let timeout = LIST_TIMEOUT;
        let answer = (|| -> Result<Map<String, Value>> {
            let token = self.call("/api/csrf", "GET", None, timeout)?;
            if let Some(Value::String(trusted)) = token.get("origin") {
                if is_loopback(&self.api) || hosts_match(&hostname(trusted), &hostname(&self.api)) {
                    if let Ok(mut state) = self.state.lock() {
                        state.origin = origin(trusted);
                    }
                }
            }
            let challenge = self.call("/api/auth/challenge", "POST", Some(&json!({"wallet": owner.to_lower()})), timeout)?;
            let message = challenge.get("message").and_then(Value::as_str).map(str::to_string);
            let domain = check_challenge(message.as_deref(), &owner, &self.api, crate::constants::CHAIN_ID)?;
            log(&crate::msg!(
                "log.signingIn",
                "Signing in to {domain} as {owner} (a signature only; no transaction) ...",
                domain = &domain,
                owner = owner
            ));
            let message = message.unwrap_or_default();
            let signature = material.sign_message(&message)?;
            self.call(
                "/api/auth/verify",
                "POST",
                Some(&json!({"wallet": owner.to_lower(), "message": message, "signature": signature})),
                timeout,
            )
        })()
        .map_err(|error| match error.kind() {
            ErrorKind::HttpStatus => {
                Error::coded(ErrorKind::Login, crate::msg!("login.refused", "The website refused the sign-in: {error}", error = &error))
            }
            ErrorKind::Network => Error::coded(
                ErrorKind::Login,
                crate::msg!("login.failed", "Signing in to the website failed. {cause}", cause = &error),
            ),
            _ => error,
        })?;
        if answer.get("wallet").map(py_str).unwrap_or_default().to_lowercase() != owner.to_lower() {
            return Err(Error::coded(ErrorKind::Login, crate::msg!("login.otherAccount", "The website signed in another account.")));
        }
        if let Ok(mut state) = self.state.lock() {
            state.owner = Some(owner);
        }
        Ok(owner)
    }

    /// End the session on the website (best effort) and forget the cookies.
    pub fn logout(&self) {
        if self.owner().is_some() {
            let _ = self.call("/api/auth/logout", "POST", None, LOGOUT_TIMEOUT);
        }
        if let Ok(mut state) = self.state.lock() {
            state.owner = None;
            state.cookies.clear();
        }
    }

    /// Whether session cookies are held (never their values).
    pub fn has_session(&self) -> bool {
        self.state.lock().map(|state| !state.cookies.is_empty()).unwrap_or(false)
    }

    /// Every grant of the signed-in owner. With ``refreshing`` the website
    /// sent its cached copy; ask again in a few seconds for fresh statuses.
    pub fn grants(&self) -> Result<Listing> {
        let owner = self.owner().map(|owner| owner.to_checksum()).unwrap_or_default();
        parse_listing(&self.call("/api/grants", "GET", None, LIST_TIMEOUT)?, &owner)
    }

    /// The website's exact revocation call of one grant (409: already revoked).
    pub fn revoke_call(&self, grant_id: &str) -> Result<Map<String, Value>> {
        self.call(&format!("/api/grants/{grant_id}/revoke-call"), "POST", None, LIST_TIMEOUT)
    }

    /// Tell the website the mined revocation (it verifies it on chain).
    pub fn revoke_confirm(&self, grant_id: &str, tx_hash: &str) -> Result<Map<String, Value>> {
        self.call(&format!("/api/grants/{grant_id}/revoke-confirm"), "POST", Some(&json!({"txHash": tx_hash})), LIST_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::HttpResponse;

    #[test]
    fn challenge_rules() {
        let owner = Address::parse("0x1111111111111111111111111111111111111111").unwrap();
        let api = "https://anubis.sivilization.com";
        let good = format!(
            "anubis.sivilization.com wants you to sign in with your Ethereum account:\n{}\n\nx\n\nURI: https://anubis.sivilization.com\nVersion: 1\nChain ID: 6714\nNonce: 1",
            owner.to_lower()
        );
        assert_eq!(check_challenge(Some(&good), &owner, api, 6714).unwrap(), "anubis.sivilization.com");
        let www = good.replace("anubis.sivilization.com", "www.anubis.sivilization.com");
        assert_eq!(check_challenge(Some(&www), &owner, api, 6714).unwrap(), "www.anubis.sivilization.com");
        for (message, fragment) in [
            (good.replace("anubis.sivilization.com", "evil.example"), "for evil.example"),
            (good.replace("anubis.sivilization.com", "anubis.sivilization.com.evil.example"), "but this is"),
            (good.replace(&owner.to_lower(), &format!("0x{}", "22".repeat(20))), "not for this account"),
            (good.replace("Chain ID: 6714", "Chain ID: 1"), "another chain"),
            (good.replace("URI: https://anubis.sivilization.com", "URI: https://evil.example"), "names another site"),
            ("0xdeadbeef".to_string(), "not for this account"),
        ] {
            let error = check_challenge(Some(&message), &owner, api, 6714).unwrap_err();
            assert!(error.message().contains(fragment), "{fragment}: {error}");
        }
        assert!(check_challenge(None, &owner, api, 6714).is_err());
        let local = format!(
            "localhost:3000 wants you to sign in with your Ethereum account:\n{}\n\nx\n\nURI: http://localhost:3000\nVersion: 1\nChain ID: 6714\nNonce: 1",
            owner.to_lower()
        );
        assert_eq!(check_challenge(Some(&local), &owner, "http://127.0.0.1:8000", 6714).unwrap(), "localhost:3000");
        assert!(check_challenge(Some(&local.replace("localhost:3000", "evil.example")), &owner, "http://127.0.0.1:8000", 6714).is_err());
    }

    #[test]
    fn cookies() {
        assert_eq!(parse_set_cookie("csrftoken=csrf-1; Path=/; Secure; SameSite=Lax"), vec![("csrftoken".into(), "csrf-1".into())]);
        assert_eq!(parse_set_cookie("sessionid=\"\"; Max-Age=0; Path=/"), vec![("sessionid".into(), String::new())]);
        assert_eq!(
            parse_set_cookie("sessionid=abc; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Path=/"),
            vec![("sessionid".into(), "abc".into())]
        );
    }

    #[test]
    fn listing_must_be_this_owners() {
        let owner = "0x1111111111111111111111111111111111111111";
        assert!(parse_listing(json!({"owner": format!("0x{}", "33".repeat(20)), "grants": []}).as_object().unwrap(), owner).is_err());
        assert!(parse_listing(json!({"owner": owner, "grants": "x"}).as_object().unwrap(), owner).is_err());
        assert!(parse_listing(json!({"owner": owner, "grants": [{"grantId": 1}]}).as_object().unwrap(), owner).is_err());
        let listing = parse_listing(
            json!({"owner": owner, "grants": [{"grantId": "0xAB", "kind": "policy", "status": "active", "keyOrigin": "hosted", "revocable": true}], "scan": {"complete": false, "percent": 50}}).as_object().unwrap(),
            owner,
        )
        .unwrap();
        assert_eq!(listing.rows[0].bot, "hosted key, bot unknown");
        assert!(!listing.scan_complete);
        assert_eq!(listing.scan_percent, 50);
        assert_eq!(listing.active().len(), 1);
    }

    #[test]
    fn listing_refreshing_and_generated_at() {
        let owner = "0x1111111111111111111111111111111111111111";
        let grants = json!([{"grantId": "0x01", "kind": "policy", "status": "active", "revocable": true}]);
        let plain = parse_listing(json!({"owner": owner, "grants": grants}).as_object().unwrap(), owner).unwrap();
        assert!(!plain.refreshing);
        assert_eq!(plain.generated_at, "");
        let cached = parse_listing(
            json!({"owner": owner, "grants": grants, "refreshing": true, "generatedAt": "2026-11-17T08:00:00+00:00", "somethingNew": [1]}).as_object().unwrap(),
            owner,
        )
        .unwrap();
        assert!(cached.refreshing);
        assert_eq!(cached.generated_at, "2026-11-17T08:00:00+00:00");
        // Revoke all does not depend on it.
        assert_eq!(cached.active().len(), 1);
        assert_eq!(serde_json::to_value(&cached).unwrap()["refreshing"], true);
        // Anything but true is false; a non-text time is ignored.
        for odd in [json!("true"), json!(1), Value::Null] {
            let listing = parse_listing(json!({"owner": owner, "grants": [], "refreshing": odd, "generatedAt": 5}).as_object().unwrap(), owner).unwrap();
            assert!(!listing.refreshing);
            assert_eq!(listing.generated_at, "");
        }
    }

    /// Answers in order (the last one repeats) and records each request.
    struct Script {
        answers: Mutex<Vec<std::result::Result<HttpResponse, TransportError>>>,
        sent: Mutex<Vec<HttpRequest>>,
    }

    impl Script {
        fn new(answers: Vec<std::result::Result<HttpResponse, TransportError>>) -> Arc<Script> {
            Arc::new(Script { answers: Mutex::new(answers), sent: Mutex::new(Vec::new()) })
        }

        fn sent(&self) -> Vec<String> {
            self.sent.lock().unwrap().iter().map(|request| format!("{} {}", request.method, request.url)).collect()
        }
    }

    impl HttpClient for Script {
        fn send(&self, request: &HttpRequest) -> std::result::Result<HttpResponse, TransportError> {
            self.sent.lock().unwrap().push(request.clone());
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone()
            }
        }
    }

    fn answer(status: u16, body: Value) -> std::result::Result<HttpResponse, TransportError> {
        Ok(HttpResponse { status, headers: Vec::new(), body: serde_json::to_vec(&body).unwrap() })
    }

    fn no_answer() -> std::result::Result<HttpResponse, TransportError> {
        Err(TransportError::new(Failure::NoAnswer, "timed out"))
    }

    const OWNER: &str = "0x1111111111111111111111111111111111111111";

    fn site(script: &Arc<Script>) -> Website {
        let site = Website::new("https://anubis.sivilization.com", script.clone()).unwrap().with_retry_pause(Duration::ZERO);
        site.state.lock().unwrap().owner = Some(Address::parse(OWNER).unwrap());
        site
    }

    fn server_busy() -> Value {
        json!({"error": "網站忙碌中，請稍後再試。", "errorEn": "The website is busy; try again in a moment.", "code": "server.busy", "params": {}})
    }

    #[test]
    fn timeouts_of_website_calls() {
        let script = Script::new(vec![answer(200, json!({"owner": OWNER, "grants": []}))]);
        site(&script).grants().unwrap();
        let sent = script.sent.lock().unwrap()[0].clone();
        assert_eq!((sent.connect_timeout, sent.timeout), (Duration::from_secs(10), Duration::from_secs(30)));
        assert!(Website::new("https://a.example", script.clone()).unwrap().retry_pause > Duration::ZERO);
    }

    #[test]
    fn get_is_sent_once_more_when_busy_or_timed_out() {
        let listed = answer(200, json!({"owner": OWNER, "grants": []}));
        let cases = [
            ("read timeout", no_answer()),
            ("connect timeout", Err(TransportError::new(Failure::ConnectTimeout, "timed out"))),
            ("503", answer(503, json!({}))),
            ("502", answer(502, json!({}))),
            ("504", answer(504, json!({}))),
            ("server.busy", answer(503, server_busy())),
        ];
        for (what, first) in cases {
            let script = Script::new(vec![first, listed.clone()]);
            assert!(site(&script).grants().is_ok(), "{what}");
            assert_eq!(script.sent(), ["GET https://anubis.sivilization.com/api/grants"; 2], "{what}");
        }
        // Busy twice: exactly one retry, then the busy message.
        let script = Script::new(vec![no_answer()]);
        let error = site(&script).grants().unwrap_err();
        assert_eq!(script.sent().len(), 2);
        assert_eq!(error.msg().code, BUSY);
        assert_eq!(error.kind(), ErrorKind::Network);
        // Not repeated: unreachable, a refusal, a plain server error.
        for (what, first) in [
            ("refused", Err(TransportError::new(Failure::Unreachable, "Connection refused (os error 111)"))),
            ("403", answer(403, json!({"error": "請先登入", "code": "auth.required"}))),
            ("500", answer(500, json!({}))),
        ] {
            let script = Script::new(vec![first, listed.clone()]);
            assert!(site(&script).grants().is_err(), "{what}");
            assert_eq!(script.sent().len(), 1, "{what}");
        }
    }

    #[test]
    fn post_is_never_sent_again() {
        for first in [no_answer(), answer(503, server_busy()), answer(502, json!({})), Err(TransportError::new(Failure::ConnectTimeout, "timed out"))] {
            // The failure repeats: a second send of the same POST would show up.
            let script = Script::new(vec![first]);
            let site = site(&script);
            assert!(site.revoke_call(&format!("0x{}", "ab".repeat(32))).is_err());
            assert!(site.revoke_confirm("0x01", "0x02").is_err());
            assert_eq!(script.sent().len(), 2, "one request each");
            assert!(script.sent().iter().all(|line| line.starts_with("POST ")));
        }
    }

    #[test]
    fn busy_and_unreachable_messages() {
        let busy_code = |first| {
            let script = Script::new(vec![first]);
            let error = site(&script).grants().unwrap_err();
            (error.msg().code, error.msg().param("site").map(str::to_string), error.msg().param("detail").map(str::to_string), error.message().to_string())
        };
        let (code, place, detail, text) = busy_code(no_answer());
        assert_eq!((code, place.as_deref(), detail.as_deref()), (BUSY, Some("https://anubis.sivilization.com"), Some("timed out")));
        assert_eq!(text, "The website https://anubis.sivilization.com is busy and did not answer in time (timed out); try again in a moment.");
        assert_eq!(busy_code(answer(503, server_busy())).0, BUSY);
        assert_eq!(busy_code(answer(503, server_busy())).2.as_deref(), Some("HTTP 503"));
        // The website's busy code on another status, and a bare 504 of a proxy.
        assert_eq!(busy_code(answer(500, server_busy())).0, BUSY);
        assert_eq!(busy_code(answer(504, json!({}))).2.as_deref(), Some("HTTP 504"));
        let (code, _, detail, text) = busy_code(Err(TransportError::new(Failure::Unreachable, "Connection refused (os error 111)")));
        assert_eq!((code, detail.as_deref()), (UNREACHABLE, Some("Connection refused (os error 111)")));
        assert!(text.starts_with("Cannot reach the website https://anubis.sivilization.com"), "{text}");
        assert_eq!(busy_code(Err(TransportError::new(Failure::ConnectTimeout, "timed out"))).0, UNREACHABLE);
        // Other errors keep their own message and status.
        let script = Script::new(vec![answer(409, json!({"error": "已撤銷", "code": "grant.revoked"}))]);
        let error = site(&script).revoke_call("0x01").unwrap_err();
        assert_eq!((error.kind(), error.status()), (ErrorKind::HttpStatus, Some(409)));
    }

    #[test]
    fn sign_in_names_the_step_and_the_cause() {
        let material = KeyMaterial::from_private_key(&"11".repeat(32)).unwrap();
        for (first, cause) in [(answer(503, server_busy()), BUSY), (Err(TransportError::new(Failure::Unreachable, "dns error")), UNREACHABLE)] {
            let script = Script::new(vec![first]);
            let site = Website::new("https://anubis.sivilization.com", script.clone()).unwrap().with_retry_pause(Duration::ZERO);
            let error = site.login(&material, &|_| {}).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Login);
            assert_eq!(error.msg().code, "login.failed");
            match error.msg().params.get("cause") {
                Some(crate::message::Param::Message(inner)) => assert_eq!(inner.code, cause),
                other => panic!("{other:?}"),
            }
            assert!(error.message().starts_with("Signing in to the website failed. "), "{error}");
            // The GET of the CSRF cookie is retried only when busy; nothing is posted.
            assert_eq!(script.sent(), vec!["GET https://anubis.sivilization.com/api/csrf"; if cause == BUSY { 2 } else { 1 }]);
        }
        // The challenge is posted once even when the website is busy.
        let script = Script::new(vec![answer(200, json!({})), no_answer()]);
        let site = Website::new("https://anubis.sivilization.com", script.clone()).unwrap().with_retry_pause(Duration::ZERO);
        let error = site.login(&material, &|_| {}).unwrap_err();
        assert_eq!(error.msg().code, "login.failed");
        assert_eq!(script.sent(), ["GET https://anubis.sivilization.com/api/csrf", "POST https://anubis.sivilization.com/api/auth/challenge"]);
        // A refusal is still a refusal.
        let script = Script::new(vec![answer(403, json!({"error": "x"}))]);
        let site = Website::new("https://anubis.sivilization.com", script.clone()).unwrap();
        assert_eq!(site.login(&material, &|_| {}).unwrap_err().msg().code, "login.refused");
    }

    /// A real connection: a server that accepts and never answers is busy,
    /// a closed port cannot be reached.
    #[test]
    fn real_timeouts_are_classified() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = std::thread::spawn(move || {
            let mut open = Vec::new();
            for _ in 0..2 {
                open.push(listener.accept().unwrap().0);
            }
            std::thread::sleep(Duration::from_secs(2));
        });
        let client: Arc<dyn HttpClient> = Arc::new(crate::net::UreqClient::default());
        let silent = Website::new(&format!("http://127.0.0.1:{port}"), client.clone()).unwrap().with_retry_pause(Duration::ZERO);
        let started = std::time::Instant::now();
        let error = silent.call("/api/grants", "GET", None, Duration::from_millis(300)).unwrap_err();
        assert_eq!(error.msg().code, BUSY, "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
        held.join().unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let refused = Website::new(&format!("http://127.0.0.1:{closed}"), client).unwrap().with_retry_pause(Duration::ZERO);
        let error = refused.call("/api/grants", "GET", None, Duration::from_millis(300)).unwrap_err();
        assert_eq!(error.msg().code, UNREACHABLE, "{error}");
    }

    #[test]
    fn statuses_labels_and_revoke_all() {
        let owner = "0x1111111111111111111111111111111111111111";
        let row = |id: &str, status: &str, revocable: bool, reason: Value| {
            json!({"grantId": id, "kind": "policy", "status": status, "revocable": revocable, "delegation": "none", "notRevocableReason": reason})
        };
        let listing = parse_listing(
            json!({"owner": owner, "grants": [
                row("0x01", "inactive", true, Value::Null),
                row("0x02", "inactive", false, json!("otherDelegation")),
                row("0x03", "unavailable", false, Value::Null),
                row("0x04", "missing", false, Value::Null),
                row("0x05", "frozen_by_dao", false, Value::Null),
                row("0x06", "expired", true, Value::Null),
            ]})
            .as_object()
            .unwrap(),
            owner,
        )
        .unwrap();
        // Revoke all: the dormant grant this signer can revoke, nothing else.
        let all: Vec<&str> = listing.active().iter().map(|row| row.grant_id.as_str()).collect();
        assert_eq!(all, ["0x01"]);
        assert_eq!(listing.rows[0].delegation, "none");
        assert_eq!(listing.rows[1].not_revocable_reason, "otherDelegation");
        let text: Vec<String> = listing.rows.iter().map(GrantRow::describe).collect();
        assert!(text[0].contains("status: inactive: this account is not delegated to Helix7702Account; it becomes active again if the account re-delegates"), "{}", text[0]);
        assert!(!text[0].contains("revocable here"));
        assert!(text[1].contains("delegated to another contract, so it cannot be revoked here"), "{}", text[1]);
        assert!(text[1].contains("revocable here: no"));
        assert!(text[2].contains("temporarily unreadable") && text[2].contains("run `grants list` again"), "{}", text[2]);
        assert!(text[3].contains("not installed (never on chain)"));
        assert!(text[4].contains("status: frozen by dao"), "{}", text[4]);
        // Self-explaining statuses keep the former lines.
        assert!(!text[5].contains("status:") && !text[5].contains("revocable here"), "{}", text[5]);
    }
}
