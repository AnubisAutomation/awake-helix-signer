//! One error type for the whole signer; its message is what the user reads.

use std::fmt;

use serde_json::{Map, Value};

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

/// A signer error with its user-facing message.
#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    status: Option<u16>,
    body: Map<String, Value>,
}

/// Result alias of the signer.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build an error of one kind.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into(), status: None, body: Map::new() }
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
        let message = match body.get("error") {
            Some(value) if crate::pyfmt::truthy(value) => crate::pyfmt::py_str(value),
            _ => format!("HTTP {status}"),
        };
        Self { kind: ErrorKind::HttpStatus, message, status: Some(status), body }
    }

    /// The kind of failure.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The user-facing message.
    pub fn message(&self) -> &str {
        &self.message
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
        Self { kind, message: self.message, status: None, body: Map::new() }
    }

    /// Prefix the message (``FlowError(f"Grant {id}: {error}")``).
    pub fn prefixed(self, kind: ErrorKind, prefix: &str) -> Self {
        Self::new(kind, format!("{prefix}{}", self.message))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
