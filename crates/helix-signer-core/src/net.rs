//! HTTPS JSON and JSON-RPC clients.
//!
//! Remote endpoints must use HTTPS with certificate verification; plain HTTP
//! is accepted only for loopback hosts (a local fork or test server). URLs
//! with credentials are refused. URL parsing follows Python's
//! ``urllib.parse.urlsplit`` so every check accepts and refuses the same
//! URLs as the Python signer.

use std::io::Read;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::pyfmt::py_str;

/// User-Agent of every request.
pub fn user_agent() -> String {
    format!("awake-helix-signer/{}", crate::VERSION)
}

/// Largest JSON answer read.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 65536;
const MAX_REDIRECTS: usize = 10;

/// The parts of a URL, as ``urllib.parse.urlsplit`` returns them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UrlParts {
    /// Lowercase scheme or "".
    pub scheme: String,
    /// ``user:pass@host:port`` or "".
    pub netloc: String,
    /// Path.
    pub path: String,
    /// Query without ``?``.
    pub query: String,
    /// Fragment without ``#``.
    pub fragment: String,
}

fn ipv6_ok(host: &str) -> bool {
    if let Some(future) = host.strip_prefix('v') {
        let (version, rest) = future.split_once('.').unwrap_or(("", ""));
        return !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_hexdigit()) && !rest.is_empty();
    }
    let address = host.split('%').next().unwrap_or(host);
    matches!(address.parse::<IpAddr>(), Ok(IpAddr::V6(_)))
}

/// ``urllib.parse.urlsplit``.
pub fn urlsplit(url: &str) -> Result<UrlParts> {
    let mut rest: String = url
        .trim_start_matches(|ch: char| (ch as u32) <= 0x20)
        .chars()
        .filter(|ch| !matches!(ch, '\t' | '\r' | '\n'))
        .collect();
    let mut parts = UrlParts::default();
    if let Some(index) = rest.find(':') {
        let candidate = &rest[..index];
        let first_ok = candidate.chars().next().map(|ch| ch.is_ascii_alphabetic()).unwrap_or(false);
        if index > 0 && first_ok && candidate.chars().all(|ch| ch.is_ascii_alphanumeric() || "+-.".contains(ch)) {
            parts.scheme = candidate.to_ascii_lowercase();
            rest = rest[index + 1..].to_string();
        }
    }
    if rest.starts_with("//") {
        let after = &rest[2..];
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        parts.netloc = after[..end].to_string();
        rest = after[end..].to_string();
        let open = parts.netloc.contains('[');
        let close = parts.netloc.contains(']');
        if open != close {
            return Err(Error::plan("Invalid IPv6 URL"));
        }
        if open {
            let host_port = parts.netloc.rsplit_once('@').map(|(_, host)| host).unwrap_or(&parts.netloc);
            let (before, bracketed) = host_port.split_once('[').unwrap_or((host_port, ""));
            let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            if !before.is_empty() || (!port.is_empty() && !port.starts_with(':')) || !ipv6_ok(host) {
                return Err(Error::plan("Invalid IPv6 URL"));
            }
        }
    }
    if let Some((before, fragment)) = rest.split_once('#') {
        parts.fragment = fragment.to_string();
        rest = before.to_string();
    }
    if let Some((before, query)) = rest.split_once('?') {
        parts.query = query.to_string();
        rest = before.to_string();
    }
    parts.path = rest;
    Ok(parts)
}

impl UrlParts {
    fn hostinfo(&self) -> (&str, &str) {
        let info = self.netloc.rsplit_once('@').map(|(_, host)| host).unwrap_or(&self.netloc);
        if let Some((_, bracketed)) = info.split_once('[') {
            let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            let port = port.split_once(':').map(|(_, port)| port).unwrap_or("");
            (host, port)
        } else {
            info.split_once(':').unwrap_or((info, ""))
        }
    }

    /// ``.hostname``: lowercase host without brackets and port, or None.
    pub fn hostname(&self) -> Option<String> {
        let (host, _) = self.hostinfo();
        if host.is_empty() {
            return None;
        }
        match host.split_once('%') {
            Some((name, zone)) => Some(format!("{}%{zone}", name.to_lowercase())),
            None => Some(host.to_lowercase()),
        }
    }

    /// ``.username`` (None without ``@``).
    pub fn username(&self) -> Option<String> {
        let (info, _) = self.netloc.rsplit_once('@')?;
        Some(info.split_once(':').map(|(user, _)| user).unwrap_or(info).to_string())
    }

    /// ``.password`` (None without ``:`` in the user info).
    pub fn password(&self) -> Option<String> {
        let (info, _) = self.netloc.rsplit_once('@')?;
        info.split_once(':').map(|(_, password)| password.to_string())
    }
}

/// Percent-decode (``urllib.parse.unquote``, UTF-8 with replacement).
pub fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let (high, low) = (bytes[index + 1], bytes[index + 2]);
            if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() {
                let digit = |byte: u8| (byte as char).to_digit(16).unwrap_or(0) as u8;
                out.push(digit(high) * 16 + digit(low));
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// ``urllib.parse.parse_qs(query, keep_blank_values=False)`` as ordered pairs.
pub fn parse_qs(query: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((name, value)) = pair.split_once('=') else { continue };
        if value.is_empty() {
            continue;
        }
        let name = unquote(&name.replace('+', " "));
        let value = unquote(&value.replace('+', " "));
        match out.iter_mut().find(|(key, _)| *key == name) {
            Some((_, values)) => values.push(value),
            None => out.push((name, vec![value])),
        }
    }
    out
}

/// Whether a URL points to this computer (``localhost``, 127.0.0.0/8, ``::1``).
pub fn is_loopback(url: &str) -> bool {
    let host = urlsplit(url).ok().and_then(|parts| parts.hostname()).unwrap_or_default();
    if host == "localhost" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.is_loopback(),
        // Python 3.11.4+ also treats IPv4-mapped loopback (::ffff:127.0.0.1) as loopback.
        Ok(IpAddr::V6(address)) => address.is_loopback() || address.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false),
        Err(_) => false,
    }
}

/// Require HTTPS (or HTTP on loopback) and no embedded credentials; returns
/// the URL without trailing slashes.
pub fn validate_url(url: &str, what: &str) -> Result<String> {
    let parts = urlsplit(url)?;
    let credentials = parts.username().map(|user| !user.is_empty()).unwrap_or(false)
        || parts.password().map(|password| !password.is_empty()).unwrap_or(false);
    if parts.hostname().is_none() || credentials {
        return Err(Error::plan(format!(
            "{what} URL is invalid or contains credentials: {}",
            crate::pyfmt::str_repr(url)
        )));
    }
    if parts.scheme == "https" || (parts.scheme == "http" && is_loopback(url)) {
        return Ok(url.trim_end_matches('/').to_string());
    }
    Err(Error::plan(format!(
        "{what} must use HTTPS (plain HTTP only on this computer): {}",
        crate::pyfmt::str_repr(url)
    )))
}

/// ``scheme://host[:port]`` of a URL, lowercase.
pub fn origin(url: &str) -> String {
    match urlsplit(url) {
        Ok(parts) => format!("{}://{}", parts.scheme, parts.netloc).to_lowercase(),
        Err(_) => String::from("://"),
    }
}

/// One HTTP request.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    /// ``GET``/``POST``/...
    pub method: String,
    /// Absolute URL.
    pub url: String,
    /// Headers in order.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Option<Vec<u8>>,
    /// Whole-request timeout.
    pub timeout: Duration,
}

impl HttpRequest {
    /// Header value (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// One HTTP response (any status; the transport never follows redirects).
#[derive(Clone, Debug, Default)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Headers in order (``Set-Cookie`` may repeat).
    pub headers: Vec<(String, String)>,
    /// Body (at most ``MAX_RESPONSE_BYTES + 1`` bytes are read).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// First header value (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    /// Every value of a header.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()).collect()
    }
}

/// The endpoint could not be reached (DNS, TLS, refused, timeout); the text
/// is the reason shown after ``Cannot reach <origin>:``.
#[derive(Clone, Debug)]
pub struct TransportError(pub String);

/// Something that sends HTTP requests. ``Transport::system()`` uses ureq with
/// rustls; tests and the app may provide their own.
pub trait HttpClient: Send + Sync {
    /// Send one request; HTTP error statuses are responses, not errors.
    fn send(&self, request: &HttpRequest) -> std::result::Result<HttpResponse, TransportError>;
}

/// The ureq + rustls client (system default).
pub struct UreqClient {
    agent: ureq::Agent,
}

impl Default for UreqClient {
    fn default() -> Self {
        Self { agent: ureq::AgentBuilder::new().redirects(0).build() }
    }
}

fn describe(error: &ureq::Transport) -> String {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(inner) = source {
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "timed out".into(),
                _ => io.to_string(),
            };
        }
        source = inner.source();
    }
    match error.message() {
        Some(message) => message.to_string(),
        None => error.kind().to_string(),
    }
}

impl HttpClient for UreqClient {
    fn send(&self, request: &HttpRequest) -> std::result::Result<HttpResponse, TransportError> {
        let mut call = self.agent.request(&request.method, &request.url).timeout(request.timeout);
        for (name, value) in &request.headers {
            call = call.set(name, value);
        }
        let answer = match &request.body {
            Some(body) => call.send_bytes(body),
            None => call.call(),
        };
        let response = match answer {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => return Err(TransportError(describe(&error))),
        };
        let status = response.status();
        let mut headers = Vec::new();
        for name in response.headers_names() {
            for value in response.all(&name) {
                headers.push((name.clone(), value.to_string()));
            }
        }
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| TransportError(error.to_string()))?;
        Ok(HttpResponse { status, headers, body })
    }
}

/// The clients a flow uses: one for the website, one for the RPC.
#[derive(Clone)]
pub struct Transport {
    /// Website API client.
    pub website: Arc<dyn HttpClient>,
    /// JSON-RPC client.
    pub rpc: Arc<dyn HttpClient>,
}

impl Transport {
    /// ureq + rustls for both.
    pub fn system() -> Transport {
        let client: Arc<dyn HttpClient> = Arc::new(UreqClient::default());
        Transport { website: client.clone(), rpc: client }
    }

    /// One client for both (tests).
    pub fn single(client: Arc<dyn HttpClient>) -> Transport {
        Transport { website: client.clone(), rpc: client }
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Transport")
    }
}

/// Parse an HTTP error body as a JSON object (empty when not one).
pub fn error_body(body: &[u8]) -> Map<String, Value> {
    let slice = &body[..body.len().min(MAX_ERROR_BYTES)];
    let text = if slice.is_empty() { b"{}".as_slice() } else { slice };
    match serde_json::from_slice::<Value>(text) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

/// Parse a successful JSON-object answer.
pub fn json_object(body: &[u8], site: &str) -> Result<Map<String, Value>> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(Error::network(format!("Response from {site} is too large.")));
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::network(format!("{site} did not answer with a JSON object."))),
        Err(_) => Err(Error::network(format!("{site} did not answer with JSON."))),
    }
}

/// Resolve a redirect ``Location`` against the current URL (``urljoin``).
pub fn urljoin(base: &str, location: &str) -> String {
    let Ok(target) = urlsplit(location) else { return location.to_string() };
    if !target.scheme.is_empty() {
        return location.to_string();
    }
    let Ok(parts) = urlsplit(base) else { return location.to_string() };
    if location.starts_with("//") {
        return format!("{}:{location}", parts.scheme);
    }
    if location.starts_with('/') {
        return format!("{}://{}{location}", parts.scheme, parts.netloc);
    }
    let directory = match parts.path.rfind('/') {
        Some(index) => &parts.path[..=index],
        None => "/",
    };
    format!("{}://{}{directory}{location}", parts.scheme, parts.netloc)
}

/// Send one JSON request and return the JSON object answer (``net.http_json``).
///
/// Redirects are followed as ``urllib.request.urlopen`` does: GET for any
/// 301/302/303/307/308, a POST only for 301/302/303 (re-sent as a GET).
pub fn http_json(client: &dyn HttpClient, url: &str, method: &str, body: Option<&Value>, timeout: Duration) -> Result<Map<String, Value>> {
    let site = origin(url);
    let data = body.map(|value| serde_json::to_vec(value).unwrap_or_default());
    let mut current = HttpRequest {
        method: method.to_string(),
        url: url.to_string(),
        headers: vec![("Accept".into(), "application/json".into()), ("User-Agent".into(), user_agent())],
        body: data.clone(),
        timeout,
    };
    if data.is_some() {
        current.headers.push(("Content-Type".into(), "application/json".into()));
    }
    for _ in 0..=MAX_REDIRECTS {
        let response = client
            .send(&current)
            .map_err(|error| Error::network(format!("Cannot reach {site}: {}", error.0)))?;
        if (200..300).contains(&response.status) {
            return json_object(&response.body, &site);
        }
        let redirect = matches!(response.status, 301 | 302 | 303 | 307 | 308);
        let follows = redirect
            && (current.method == "GET" || current.method == "HEAD" || (current.method == "POST" && response.status <= 303));
        match (follows, response.header("Location").or_else(|| response.header("URI"))) {
            (true, Some(location)) => {
                let next = urljoin(&current.url, location);
                let scheme = urlsplit(&next).map(|parts| parts.scheme).unwrap_or_default();
                if !["http", "https", "ftp"].contains(&scheme.as_str()) {
                    return Err(Error::http_status(response.status, error_body(&response.body)));
                }
                current.url = next;
                if current.method == "POST" {
                    current.method = "GET".into();
                    current.body = None;
                    current.headers.retain(|(name, _)| !name.eq_ignore_ascii_case("Content-Type"));
                }
            }
            _ => return Err(Error::http_status(response.status, error_body(&response.body))),
        }
    }
    Err(Error::http_status(310, Map::new()))
}

/// JSON-RPC client for one validated endpoint.
#[derive(Clone)]
pub struct Rpc {
    /// Endpoint (validated, without trailing slash).
    pub url: String,
    client: Arc<dyn HttpClient>,
    id: Arc<AtomicU64>,
}

impl std::fmt::Debug for Rpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rpc({})", self.url)
    }
}

impl Rpc {
    /// Validate and store the endpoint.
    pub fn new(url: &str, client: Arc<dyn HttpClient>) -> Result<Rpc> {
        Ok(Rpc { url: validate_url(url, "RPC")?, client, id: Arc::new(AtomicU64::new(0)) })
    }

    /// Call one JSON-RPC method and return its ``result``.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.id.fetch_add(1, Ordering::SeqCst) + 1;
        let request = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let answer = match http_json(self.client.as_ref(), &self.url, "POST", Some(&request), Duration::from_secs(30)) {
            Ok(answer) => answer,
            Err(error) if error.kind() == crate::ErrorKind::HttpStatus => {
                return Err(Error::network(format!("{method}: RPC HTTP {}", error.status().unwrap_or(0))))
            }
            Err(error) => return Err(error),
        };
        if let Some(detail) = answer.get("error") {
            let message = match detail {
                Value::Object(map) => map.get("message").map(py_str).unwrap_or_else(|| py_str(detail)),
                other => py_str(other),
            };
            return Err(Error::network(format!("{method}: {message}")));
        }
        match answer.get("result") {
            Some(result) => Ok(result.clone()),
            None => Err(Error::network(format!("{method}: RPC answer has no result."))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        assert_eq!(validate_url("https://a.example/", "API").unwrap(), "https://a.example");
        validate_url("http://127.0.0.1:8000", "API").unwrap();
        validate_url("http://localhost:8000", "API").unwrap();
        validate_url("http://[::1]:8000", "API").unwrap();
        for bad in ["http://example.com", "https://user:pw@example.com", "ftp://x", "file:///etc/passwd", "https://", "http://10.0.0.1:8545"] {
            assert!(validate_url(bad, "API").is_err(), "{bad}");
        }
        // An empty user name is not a credential (Python checks truthiness).
        validate_url("https://@example.com", "API").unwrap();
        assert!(validate_url("http://[::1", "API").unwrap_err().message().contains("Invalid IPv6"));
        assert!(is_loopback("http://127.1.2.3:1"));
        assert!(!is_loopback("http://127.0.0.1.evil.example"));
        assert_eq!(origin("https://Anubis.Sivilization.com/api/x"), "https://anubis.sivilization.com");
    }

    #[test]
    fn query_parsing() {
        let parsed = parse_qs("plan=abc&api=https%3A%2F%2Fx.example&empty=&plan=second&flag");
        assert_eq!(parsed[0], ("plan".to_string(), vec!["abc".to_string(), "second".to_string()]));
        assert_eq!(parsed[1], ("api".to_string(), vec!["https://x.example".to_string()]));
        assert_eq!(parsed.len(), 2);
        assert_eq!(unquote("a%20b%zz%4"), "a b%zz%4");
    }

    #[test]
    fn joins() {
        assert_eq!(urljoin("https://a.example/x/y", "/z"), "https://a.example/z");
        assert_eq!(urljoin("https://a.example/x/y", "z"), "https://a.example/x/z");
        assert_eq!(urljoin("https://a.example/x/y", "https://b.example/"), "https://b.example/");
    }
}
