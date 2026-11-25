//! Parse ``anubisauto://`` links opened from the website.
//!
//! ``anubisauto://sign?plan=<token>&api=<website API>``,
//! ``anubisauto://revoke?plan=<token>&api=<website API>``, the install check
//! ``anubisauto://ping?token=<token>&api=<website API>`` and
//! ``anubisauto://grants?api=<website API>`` (opens the grants view, no
//! token). Any web page can open such a link, so the API origin is accepted
//! only when it is the official site (or one the user allowed explicitly with
//! ``--allow-api``); a loopback API only together with development constants.
//!
//! The legacy scheme of the signers before 0.7.0 ([`LEGACY_SCHEME`]) is parsed
//! exactly like the primary one, so old links and QR codes still open this
//! app; nothing the app or the CLI makes uses it.

use serde::Serialize;

use crate::constants::DEFAULT_API;
use crate::error::{Error, ErrorKind, Result};
use crate::net::{is_loopback, origin, parse_qs, urlsplit, validate_url};
use crate::plan::{check_token, is_token};
use crate::pyfmt::str_repr;

/// The link scheme: every link the app and the CLI make use it.
pub const SCHEME: &str = "anubisauto";
/// The scheme of the signers before 0.7.0: still accepted, never generated.
pub const LEGACY_SCHEME: &str = "awakehelix";
/// Every scheme a link may use, the primary one first.
pub const SCHEMES: [&str; 2] = [SCHEME, LEGACY_SCHEME];

/// Whether ``text`` starts with one of [`SCHEMES`] and a colon (any case):
/// a link to hand to [`parse_link`], not yet a valid one.
pub fn has_scheme(text: &str) -> bool {
    SCHEMES.iter().any(|scheme| {
        text.get(..scheme.len()).is_some_and(|head| head.eq_ignore_ascii_case(scheme)) && text[scheme.len()..].starts_with(':')
    })
}

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

/// Parse and validate one ``anubisauto://`` (or legacy ``awakehelix://``) link.
pub fn parse_link(url: &str, allowed_apis: &[String], development: bool) -> Result<Link> {
    let parts = urlsplit(url.trim())?;
    if !SCHEMES.contains(&parts.scheme.to_lowercase().as_str()) {
        return Err(Error::coded(ErrorKind::Plan, crate::msg!("link.notOurs", "Not an anubisauto:// link.")));
    }
    let name = if parts.netloc.is_empty() { parts.path.trim_matches('/').to_string() } else { parts.netloc.clone() }.to_lowercase();
    let action = match name.as_str() {
        "sign" => LinkAction::Sign,
        "revoke" => LinkAction::Revoke,
        "ping" => LinkAction::Ping,
        "grants" => LinkAction::Grants,
        _ => return Err(Error::coded(ErrorKind::Plan, crate::msg!("link.unknownAction", "Unknown link action {action}.", action = str_repr(&name)))),
    };
    let query = parse_qs(&parts.query);
    let first = |key: &str| query.iter().find(|(name, _)| name == key).and_then(|(_, values)| values.first().cloned());
    let token = match action {
        LinkAction::Ping => {
            let token = first("token").unwrap_or_default();
            if !is_token(&token) {
                return Err(Error::coded(ErrorKind::Plan, crate::msg!("link.badCheckToken", "The install-check token is malformed; click the verify button on the website again.")));
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
        return Err(Error::coded(
            ErrorKind::Plan,
            crate::msg!(
                "link.foreignSite",
                "This link points to {site}, which is not the official Anubis Automation website ({official}). It was refused. If you really run your own instance, pass --allow-api {site}.",
                site = &site,
                official = DEFAULT_API
            ),
        ));
    }
    Ok(Link { action, token, api })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "tok_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PING: &str = "chk_QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";

    fn refused_as_not_ours(url: &str) {
        let error = parse_link(url, &[], true).expect_err(url);
        assert_eq!(error.msg().code, "link.notOurs", "{url}: {}", error.message());
    }

    #[test]
    fn links() {
        // The primary scheme and the legacy one parse alike.
        for scheme in SCHEMES {
            let link = parse_link(&format!("{scheme}://revoke?plan={TOKEN}&api=https%3A%2F%2Fanubis.sivilization.com"), &[], false).unwrap();
            assert_eq!((link.action, link.token.as_str(), link.api.as_str()), (LinkAction::Revoke, TOKEN, "https://anubis.sivilization.com"));
            assert_eq!(parse_link(&format!("{scheme}://sign?plan={TOKEN}"), &[], false).unwrap().api, DEFAULT_API);
            let evil = format!("{scheme}://sign?plan={TOKEN}&api=https%3A%2F%2Fevil.example");
            assert!(parse_link(&evil, &[], false).is_err());
            assert_eq!(parse_link(&evil, &["https://evil.example".into()], false).unwrap().api, "https://evil.example");
            let local = format!("{scheme}://sign?plan={TOKEN}&api=http%3A%2F%2F127.0.0.1%3A8000");
            assert!(parse_link(&local, &[], false).is_err());
            assert_eq!(parse_link(&local, &[], true).unwrap().api, "http://127.0.0.1:8000");
            for bad in ["https://x".to_string(), format!("{scheme}://drain?plan={TOKEN}"), format!("{scheme}://steal?plan={TOKEN}"), format!("{scheme}://sign?plan=short")] {
                assert!(parse_link(&bad, &[], false).is_err(), "{bad}");
            }
            assert_eq!(parse_link(&format!("{scheme}://grants"), &[], false).unwrap().action, LinkAction::Grants);
            assert_eq!(parse_link(&format!("{scheme}:grants"), &[], false).unwrap().action, LinkAction::Grants);
            assert!(parse_link(&format!("{scheme}://grants?api=https://evil.example"), &[], false).is_err());
            let shouted = format!("{}://PING?token={PING}", scheme.to_uppercase());
            assert_eq!(parse_link(&shouted, &[], false).unwrap().action, LinkAction::Ping);
            for api in ["https%3A%2F%2Fanubis.sivilization.com.evil.example", "http%3A%2F%2Fanubis.sivilization.com", "https%3A%2F%2Fu%3Ap%40anubis.sivilization.com"] {
                assert!(parse_link(&format!("{scheme}://ping?token={PING}&api={api}"), &[], false).is_err(), "{api}");
            }
            for bad in [format!("{scheme}://ping?token=short"), format!("{scheme}://ping?token={}", "a".repeat(200)), format!("{scheme}://ping?plan={PING}"), format!("{scheme}://ping")] {
                assert!(parse_link(&bad, &[], false).is_err(), "{bad}");
            }
        }
        assert_eq!(parse_link(&format!("AnubisAuto://Sign?plan={TOKEN}"), &[], false).unwrap().action, LinkAction::Sign);
        assert_eq!(parse_link(&format!("AwakeHelix://PING?token={PING}"), &[], false).unwrap().action, LinkAction::Ping);
        // An unknown action is refused as such under either scheme.
        for scheme in SCHEMES {
            let error = parse_link(&format!("{scheme}://drain?plan={TOKEN}"), &[], true).unwrap_err();
            assert_eq!(error.msg().code, "link.unknownAction", "{scheme}");
        }
    }

    #[test]
    fn other_schemes_and_look_alikes_are_refused() {
        for url in [
            format!("https://anubis.sivilization.com/sign?plan={TOKEN}"),
            format!("javascript:anubisauto://sign?plan={TOKEN}"),
            format!("anubis://sign?plan={TOKEN}"),
            format!("auto://sign?plan={TOKEN}"),
            format!("anubis-auto://sign?plan={TOKEN}"),
            format!("anubis.auto://sign?plan={TOKEN}"),
            format!("anubisautos://sign?plan={TOKEN}"),
            format!("anubisauto2://sign?plan={TOKEN}"),
            format!("xanubisauto://sign?plan={TOKEN}"),
            format!("anubisauto.evil.example://sign?plan={TOKEN}"),
            format!("anubisauto+evil://sign?plan={TOKEN}"),
            format!("awake-helix://sign?plan={TOKEN}"),
            format!("awakehelixx://sign?plan={TOKEN}"),
            format!("awakehelix-signer://sign?plan={TOKEN}"),
            format!("helix://sign?plan={TOKEN}"),
            // Cyrillic "а" / "е" in place of the Latin letters.
            format!("\u{430}nubisauto://sign?plan={TOKEN}"),
            format!("awak\u{435}helix://sign?plan={TOKEN}"),
            format!("anubisauto//sign?plan={TOKEN}"),
            format!("/anubisauto://sign?plan={TOKEN}"),
            TOKEN.to_string(),
            String::new(),
        ] {
            refused_as_not_ours(&url);
        }
    }

    #[test]
    fn scheme_prefix() {
        for yes in ["anubisauto://sign", "ANUBISAUTO:grants", "awakehelix://ping?token=x", "AwakeHelix:sign"] {
            assert!(has_scheme(yes), "{yes}");
        }
        for no in ["anubisauto", "awakehelix", "anubisautox://sign", "awakehelixx:sign", " anubisauto://sign", "https://anubisauto/", "\u{430}nubisauto://sign", "", "é"] {
            assert!(!has_scheme(no), "{no}");
        }
    }
}
