//! Parse ``awakehelix://`` links opened from the website.
//!
//! ``awakehelix://sign?plan=<token>&api=<website API>``,
//! ``awakehelix://revoke?plan=<token>&api=<website API>``, the install check
//! ``awakehelix://ping?token=<token>&api=<website API>`` and
//! ``awakehelix://grants?api=<website API>`` (opens the grants view, no
//! token). Any web page can open such a link, so the API origin is accepted
//! only when it is the official site (or one the user allowed explicitly with
//! ``--allow-api``); a loopback API only together with development constants.

use serde::Serialize;

use crate::constants::DEFAULT_API;
use crate::error::{Error, Result};
use crate::net::{is_loopback, origin, parse_qs, urlsplit, validate_url};
use crate::plan::{check_token, is_token};
use crate::pyfmt::str_repr;

/// The link scheme.
pub const SCHEME: &str = "awakehelix";

/// What a link asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkAction {
    /// Authorize a hosted bot.
    Sign,
    /// Revoke one grant.
    Revoke,
    /// Answer the install check.
    Ping,
    /// Open the grants view.
    Grants,
}

impl LinkAction {
    /// ``sign``, ``revoke``, ``ping`` or ``grants``.
    pub fn as_str(&self) -> &'static str {
        match self {
            LinkAction::Sign => "sign",
            LinkAction::Revoke => "revoke",
            LinkAction::Ping => "ping",
            LinkAction::Grants => "grants",
        }
    }
}

/// A parsed signer link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    /// The action.
    pub action: LinkAction,
    /// Plan token (``ping``: install-check token; ``grants``: "").
    pub token: String,
    /// Website API base.
    pub api: String,
}

/// Parse and validate one ``awakehelix://`` link.
pub fn parse_link(url: &str, allowed_apis: &[String], development: bool) -> Result<Link> {
    let parts = urlsplit(url.trim())?;
    if parts.scheme.to_lowercase() != SCHEME {
        return Err(Error::plan("Not an awakehelix:// link."));
    }
    let name = if parts.netloc.is_empty() { parts.path.trim_matches('/').to_string() } else { parts.netloc.clone() }.to_lowercase();
    let action = match name.as_str() {
        "sign" => LinkAction::Sign,
        "revoke" => LinkAction::Revoke,
        "ping" => LinkAction::Ping,
        "grants" => LinkAction::Grants,
        _ => return Err(Error::plan(format!("Unknown link action {}.", str_repr(&name)))),
    };
    let query = parse_qs(&parts.query);
    let first = |key: &str| query.iter().find(|(name, _)| name == key).and_then(|(_, values)| values.first().cloned());
    let token = match action {
        LinkAction::Ping => {
            let token = first("token").unwrap_or_default();
            if !is_token(&token) {
                return Err(Error::plan("The install-check token is malformed; click the verify button on the website again."));
            }
            token
        }
        LinkAction::Grants => String::new(),
        _ => {
            let token = first("plan").unwrap_or_default();
            check_token(&token)?;
            token
        }
    };
    let api = validate_url(&first("api").unwrap_or_else(|| DEFAULT_API.to_string()), "Website API")?;
    let mut trusted = vec![origin(DEFAULT_API)];
    trusted.extend(allowed_apis.iter().map(|item| origin(item)));
    let site = origin(&api);
    if !trusted.contains(&site) && !(development && is_loopback(&api)) {
        return Err(Error::plan(format!(
            "This link points to {site}, which is not the official Awake Helix website ({DEFAULT_API}). It was refused. If you really run your own instance, pass --allow-api {site}."
        )));
    }
    Ok(Link { action, token, api })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "tok_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn links() {
        let link = parse_link(&format!("awakehelix://revoke?plan={TOKEN}&api=https%3A%2F%2Fanubis.sivilization.com"), &[], false).unwrap();
        assert_eq!((link.action, link.token.as_str(), link.api.as_str()), (LinkAction::Revoke, TOKEN, "https://anubis.sivilization.com"));
        assert_eq!(parse_link(&format!("awakehelix://sign?plan={TOKEN}"), &[], false).unwrap().api, DEFAULT_API);
        let evil = format!("awakehelix://sign?plan={TOKEN}&api=https%3A%2F%2Fevil.example");
        assert!(parse_link(&evil, &[], false).is_err());
        assert_eq!(parse_link(&evil, &["https://evil.example".into()], false).unwrap().api, "https://evil.example");
        let local = format!("awakehelix://sign?plan={TOKEN}&api=http%3A%2F%2F127.0.0.1%3A8000");
        assert!(parse_link(&local, &[], false).is_err());
        assert_eq!(parse_link(&local, &[], true).unwrap().api, "http://127.0.0.1:8000");
        for bad in ["https://x".to_string(), format!("awakehelix://drain?plan={TOKEN}"), "awakehelix://sign?plan=short".to_string()] {
            assert!(parse_link(&bad, &[], false).is_err(), "{bad}");
        }
        assert_eq!(parse_link("awakehelix://grants", &[], false).unwrap().action, LinkAction::Grants);
        assert!(parse_link("awakehelix://grants?api=https://evil.example", &[], false).is_err());
        let ping = "chk_QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
        assert_eq!(parse_link(&format!("AwakeHelix://PING?token={ping}"), &[], false).unwrap().action, LinkAction::Ping);
        for api in ["https%3A%2F%2Fanubis.sivilization.com.evil.example", "http%3A%2F%2Fanubis.sivilization.com", "https%3A%2F%2Fu%3Ap%40anubis.sivilization.com"] {
            assert!(parse_link(&format!("awakehelix://ping?token={ping}&api={api}"), &[], false).is_err(), "{api}");
        }
        for bad in ["awakehelix://ping?token=short".to_string(), format!("awakehelix://ping?token={}", "a".repeat(200)), format!("awakehelix://ping?plan={ping}"), "awakehelix://ping".to_string()] {
            assert!(parse_link(&bad, &[], false).is_err(), "{bad}");
        }
    }
}
