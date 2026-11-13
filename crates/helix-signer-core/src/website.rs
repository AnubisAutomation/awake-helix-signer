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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::address::Address;
use crate::error::{Error, ErrorKind, Result};
use crate::keys::KeyMaterial;
use crate::net::{error_body, is_loopback, json_object, origin, urlsplit, user_agent, validate_url, HttpClient, HttpRequest};
use crate::pyfmt::py_str;
use crate::summary::when;

const COOKIES: [&str; 2] = ["sessionid", "csrftoken"];
const ACTIVE_STATUSES: [&str; 2] = ["active", "not_yet_valid"];
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
    let not_ours = || Error::login("The website's sign-in message is not for this account; nothing was signed.");
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
    /// Linked bot, as text.
    pub bot: String,
    /// Unix seconds.
    pub valid_until: Option<i64>,
    /// Calls left.
    pub remaining_calls: Option<i64>,
    /// Whether the grant still has storage on chain.
    pub revocable: bool,
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
        format!(
            "{}  {}\n  key: {} ({})\n  bot: {}\n  valid until: {}\n  remaining calls: {}",
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
        return Err(Error::login("The website listed the grants of another account."));
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
            valid_until: optional_int(row.get("validUntilUnix")),
            remaining_calls: optional_int(row.get("remainingCalls")),
            revocable: row.get("revocable") == Some(&Value::Bool(true)),
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
    })
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
        Ok(Website { api, client, state: Mutex::new(State { owner: None, cookies: Vec::new(), origin }) })
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

    /// Send one API request with the session.
    pub fn call(&self, path: &str, method: &str, body: Option<&Value>, timeout: Duration) -> Result<Map<String, Value>> {
        let data = if body.is_none() && method == "GET" {
            None
        } else {
            Some(serde_json::to_vec(body.unwrap_or(&json!({}))).unwrap_or_default())
        };
        let (site, cookies) = {
            let state = self.state.lock().map_err(|_| Error::network("The website session is unavailable."))?;
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
        let request = HttpRequest { method: method.to_string(), url: format!("{}{path}", self.api), headers, body: data, timeout };
        let response = self
            .client
            .send(&request)
            .map_err(|error| Error::network(format!("Cannot reach {site}: {}", error.0)))?;
        self.remember(&response.headers);
        if !(200..300).contains(&response.status) {
            return Err(Error::http_status(response.status, error_body(&response.body)));
        }
        json_object(&response.body, &site)
    }

    /// Sign in with the loaded key (a signature only, never a transaction).
    pub fn login(&self, material: &KeyMaterial, log: &dyn Fn(&str)) -> Result<Address> {
        let owner = material.address();
        let timeout = Duration::from_secs(30);
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
            log(&format!("Signing in to {domain} as {owner} (a signature only; no transaction) ..."));
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
            ErrorKind::HttpStatus => Error::login(format!("The website refused the sign-in: {error}")),
            ErrorKind::Network => error.into_kind(ErrorKind::Login),
            _ => error,
        })?;
        if answer.get("wallet").map(py_str).unwrap_or_default().to_lowercase() != owner.to_lower() {
            return Err(Error::login("The website signed in another account."));
        }
        if let Ok(mut state) = self.state.lock() {
            state.owner = Some(owner);
        }
        Ok(owner)
    }

    /// End the session on the website (best effort) and forget the cookies.
    pub fn logout(&self) {
        if self.owner().is_some() {
            let _ = self.call("/api/auth/logout", "POST", None, Duration::from_secs(10));
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

    /// Every grant of the signed-in owner.
    pub fn grants(&self) -> Result<Listing> {
        let owner = self.owner().map(|owner| owner.to_checksum()).unwrap_or_default();
        parse_listing(&self.call("/api/grants", "GET", None, Duration::from_secs(30))?, &owner)
    }

    /// The website's exact revocation call of one grant (409: already revoked).
    pub fn revoke_call(&self, grant_id: &str) -> Result<Map<String, Value>> {
        self.call(&format!("/api/grants/{grant_id}/revoke-call"), "POST", None, Duration::from_secs(30))
    }

    /// Tell the website the mined revocation (it verifies it on chain).
    pub fn revoke_confirm(&self, grant_id: &str, tx_hash: &str) -> Result<Map<String, Value>> {
        self.call(&format!("/api/grants/{grant_id}/revoke-confirm"), "POST", Some(&json!({"txHash": tx_hash})), Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
