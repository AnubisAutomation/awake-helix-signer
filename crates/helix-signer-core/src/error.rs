//! One error type for the whole signer; its message is what the user reads.

use std::fmt;

use serde_json::{Map, Value};

use crate::message::{Message, SiteText};

/// What kind of step failed (maps the Python exception classes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorKind {
    /// The plan does not match what the signer is willing to sign (`PlanError`).
    Plan,
    /// The key source cannot be read (`KeyError_`); never contains secrets.
    Key,
    /// A flow step failed; the message explains what to do (`FlowError`).
    Flow,
    /// The website refused requested customize values; the old plan stays usable.
    CustomizeRefused,
    /// The chain state forbids signing, or a transaction failed (`ChainError`).
    Chain,
    /// An endpoint could not be reached or answered badly (`NetworkError`).
    Network,
    /// The website answered with an HTTP error status (`HttpStatusError`).
    HttpStatus,
    /// The website login could not be completed (`LoginError`).
    Login,
    /// The install check failed (`PingError`).
    Ping,
    /// A local file operation failed (`OSError`).
    Io,
    /// The user cancelled or the input closed (`EOFError`, `KeyboardInterrupt`).
    Cancelled,
}

impl ErrorKind {
    /// The code of a message of this kind that has no code of its own.
    pub fn code(&self) -> &'static str {
        match self {
            ErrorKind::Plan => "plan",
            ErrorKind::Key => "key",
            ErrorKind::Flow => "flow",
            ErrorKind::CustomizeRefused => "customizeRefused",
            ErrorKind::Chain => "chain",
            ErrorKind::Network => "network",
            ErrorKind::HttpStatus => "httpStatus",
            ErrorKind::Login => "login",
            ErrorKind::Ping => "ping",
            ErrorKind::Io => "io",
            ErrorKind::Cancelled => "cancelled",
        }
    }
}

/// A signer error with its user-facing message.
#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    msg: Box<Message>,
    status: Option<u16>,
    body: Map<String, Value>,
}

/// Result alias of the signer.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build an error of one kind.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, msg: Box::new(Message::plain(kind.code(), message)), status: None, body: Map::new() }
    }

    /// An error of one kind with a coded message (see [`msg!`](crate::msg)).
    pub fn coded(kind: ErrorKind, msg: Message) -> Self {
        Self { kind, msg: Box::new(msg), status: None, body: Map::new() }
    }

    /// `PlanError`.
    pub fn plan(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Plan, message)
    }

    /// `KeyError_`.
    pub fn key(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Key, message)
    }

    /// `FlowError`.
    pub fn flow(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Flow, message)
    }

    /// `CustomizeRefused`.
    pub fn customize_refused(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::CustomizeRefused, message)
    }

    /// `ChainError`.
    pub fn chain(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Chain, message)
    }

    /// `NetworkError`.
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Network, message)
    }

    /// `LoginError`.
    pub fn login(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Login, message)
    }

    /// `PingError`.
    pub fn ping(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Ping, message)
    }

    /// `OSError`.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, message)
    }

    /// Cancelled by the user (EOF or interrupt).
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Cancelled, message)
    }

    /// `HttpStatusError(status, body)`: the message is the body's `error` or `HTTP <status>`.
    pub fn http_status(status: u16, body: Map<String, Value>) -> Self {
        let text = |key: &str| body.get(key).filter(|value| crate::pyfmt::truthy(value)).map(crate::pyfmt::py_str);
        let msg = match text("error") {
            Some(message) => {
                let site = SiteText {
                    status,
                    code: body.get("code").and_then(Value::as_str).unwrap_or_default().to_string(),
                    params: body.get("params").and_then(Value::as_object).cloned().unwrap_or_default(),
                    zh: message.clone(),
                    en: text("errorEn").unwrap_or_default(),
                };
                Message::website(site, message)
            }
            None => crate::msg!("http.status", "HTTP {status}", status = status),
        };
        Self { kind: ErrorKind::HttpStatus, msg: Box::new(msg), status: Some(status), body }
    }

    /// The kind of failure.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The user-facing message (English).
    pub fn message(&self) -> &str {
        &self.msg.text
    }

    /// The message with its code and params (what the app translates).
    pub fn msg(&self) -> &Message {
        &self.msg
    }

    /// HTTP status of an `HttpStatus` error.
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    /// Parsed JSON error body of an `HttpStatus` error (may be empty).
    pub fn body(&self) -> &Map<String, Value> {
        &self.body
    }

    /// Whether this is a network failure (`NetworkError` or its `HttpStatusError` subclass).
    pub fn is_network(&self) -> bool {
        matches!(self.kind, ErrorKind::Network | ErrorKind::HttpStatus)
    }

    /// Same message, another kind (``raise FlowError(str(error)) from None``).
    pub fn into_kind(self, kind: ErrorKind) -> Self {
        let msg = if self.msg.code == self.kind.code() { Box::new(Message { code: kind.code(), ..*self.msg }) } else { self.msg };
        Self { kind, msg, status: None, body: Map::new() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg.text)
    }
}

impl std::error::Error for Error {}
