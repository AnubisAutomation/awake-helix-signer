//! Answer the website's install check (``anubisauto://ping?token=…&api=…``).
//!
//! The website cannot see which apps a computer has, so its "I have installed
//! it, verify" button creates a 10-minute check and opens the ping link. The
//! signer answers by POSTing its version, operating system and CPU to
//! ``<api>/api/signer/install-checks/<token>/ping``. Nothing else is sent: no
//! key, no address, no file name.

use std::time::Duration;

use serde::Serialize;
use serde_json::json;

use crate::error::{Error, ErrorKind, Result};
use crate::net::{http_json, validate_url, HttpClient};
use crate::plan::is_token;

/// Text shown after a confirmed check.
pub const LINKED: &str = "Anubis Automation Script Signer is installed and linked \u{2014} you can return to the browser.";

/// A confirmed install check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PingResult {
    /// Version sent.
    pub version: String,
    /// ``windows``, ``macos`` or ``linux``.
    pub os: String,
    /// ``x86_64`` or ``arm64``.
    pub arch: String,
    /// Website the check belongs to.
    pub api: String,
}

impl PingResult {
    /// Text shown in the window or terminal.
    pub fn message(&self) -> String {
        format!("{LINKED}\n(anubisauto-signer {}, {}/{}, {})", self.version, self.os, self.arch, self.api)
    }
}

/// Operating system name the website expects: ``windows``, ``macos``,
/// ``android``, ``ios``, and ``linux`` for anything else.
pub fn system_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else {
        "linux"
    }
}

/// CPU name the website expects.
pub fn cpu_name() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}

/// Ping endpoint of one check.
pub fn ping_url(api: &str, token: &str) -> String {
    format!("{api}/api/signer/install-checks/{token}/ping")
}

/// Confirm one install check.
pub fn send_ping(api: &str, token: &str, client: &dyn HttpClient) -> Result<PingResult> {
    if !is_token(token) {
        return Err(Error::coded(ErrorKind::Ping, crate::msg!("ping.malformed", "The check token is malformed; click \u{201c}I have installed it, verify\u{201d} on the website again.")));
    }
    let api = validate_url(api, "Website API").map_err(|error| error.into_kind(ErrorKind::Ping))?;
    let body = json!({"version": crate::VERSION, "os": system_name(), "arch": cpu_name()});
    let answer = match http_json(client, &ping_url(&api, token), "POST", Some(&body), Duration::from_secs(20)) {
        Ok(answer) => answer,
        Err(error) if error.kind() == ErrorKind::HttpStatus => {
            return Err(Error::coded(ErrorKind::Ping, match error.status() {
                Some(404) => crate::msg!("ping.unknown", "The website does not know this check. Click the verify button on the website again."),
                Some(409) => crate::msg!("ping.used", "This check was already confirmed; return to the browser."),
                Some(410) => crate::msg!("ping.expired", "This check expired (10 minutes). Click the verify button on the website again."),
                Some(429) => crate::msg!("flow.tooManyRequests", "Too many requests; wait a minute and try again."),
                _ => crate::msg!("ping.refused", "The website refused the check: {error}", error = &error),
            }))
        }
        Err(error) => return Err(error.into_kind(ErrorKind::Ping)),
    };
    if answer.get("status").and_then(|value| value.as_str()) != Some("confirmed") {
        return Err(Error::coded(ErrorKind::Ping, crate::msg!("ping.notConfirmed", "The website did not confirm the check; try again from the website.")));
    }
    Ok(PingResult { version: crate::VERSION.into(), os: system_name().into(), arch: cpu_name().into(), api })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_and_cpu_names_are_the_websites() {
        // The Anubis Automation website's install check accepts exactly these.
        assert!(["windows", "macos", "linux", "android", "ios"].contains(&system_name()));
        assert!(["x86_64", "arm64"].contains(&cpu_name()));
        if cfg!(target_os = "linux") {
            assert_eq!(system_name(), "linux");
        }
    }
}
