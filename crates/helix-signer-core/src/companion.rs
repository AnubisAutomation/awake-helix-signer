//! ``awake-helix-signer serve``: a loopback companion the dashboard can call.
//!
//! Security model (unchanged from the Python signer):
//!
//! * **Loopback only.** The server binds 127.0.0.1 and refuses a ``Host``
//!   other than ``127.0.0.1:<port>``/``localhost:<port>`` (DNS rebinding).
//! * **Origin check.** Every request, including CORS and Private Network
//!   Access preflights, must come from [`SITE_ORIGIN`] or a loopback origin
//!   passed with ``--allow-origin``. Other origins get 403 without CORS
//!   headers, so their pages cannot read anything.
//! * **Pairing.** A short single-use code (10 minutes, five attempts) is
//!   exchanged once for a random 256-bit secret; every later request is
//!   signed: ``HMAC-SHA256(secret, METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body))``
//!   with a timestamp within 60 s and a single-use nonce. Pairings are kept in
//!   ``pairings.json`` (mode 0600 on POSIX).
//! * **Local confirmation.** The key is unlocked once and wiped after the idle
//!   timeout and on exit. Every authorization needs ``AUTHORIZE`` confirmed
//!   locally; revocations need ``REVOKE`` unless ``--auto-confirm-revoke``.
//!
//! Endpoints: ``GET /health``, ``POST /pair {code}``, ``POST /sign
//! {planToken}``, ``POST /revoke {revokeToken}``, ``GET /jobs/<id>``.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::constants::{self as c, Constants};
use crate::error::{Error, ErrorKind, Result};
use crate::flow::{self, Confirmer, RevokeSource};
use crate::keys::keystore::{random_bytes, uuid4};
use crate::keys::KeyMaterial;
use crate::net::{is_loopback, origin, urlsplit, Transport};

type HmacSha256 = Hmac<Sha256>;

/// Default loopback port.
pub const DEFAULT_PORT: u16 = 17702;
/// The official website origin.
pub const SITE_ORIGIN: &str = "https://anubis.sivilization.com";
/// Default idle timeout.
pub const IDLE_SECONDS: u64 = 15 * 60;
/// Allowed request clock skew.
pub const CLOCK_SKEW_MS: i64 = 60_000;
/// How long a nonce is remembered.
pub const NONCE_SECONDS: u64 = 180;
/// Lifetime of a pairing code.
pub const PAIR_SECONDS: u64 = 10 * 60;
/// Attempts per pairing code.
pub const PAIR_ATTEMPTS: u32 = 5;
/// Largest request body.
pub const MAX_BODY: usize = 4096;
/// Open jobs at most.
pub const MAX_JOBS: usize = 20;
/// Pairing code alphabet (no 0/O, 1/I/L).
pub const CODE_ALPHABET: &str = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// CORS allowed request headers.
pub const ALLOW_HEADERS: &str = "Content-Type, X-Helix-Pairing, X-Helix-Timestamp, X-Helix-Nonce, X-Helix-Signature";

/// SHA-256 of the constants a plan is verified against (``/health``), byte
/// for byte the Python companion's value.
pub fn constants_hash(constants: &Constants) -> String {
    let mut allowlist = Map::new();
    for (kind, entries) in c::RULE_ALLOWLIST {
        let mut rows: Vec<Vec<String>> =
            entries.iter().map(|(target, token_in, counterparty)| vec![target.to_lowercase(), token_in.to_lowercase(), counterparty.to_lowercase()]).collect();
        rows.sort();
        allowlist.insert(kind.to_string(), json!(rows));
    }
    let document = json!({
        "chainId": constants.chain_id,
        "implementation": constants.implementation.to_lower(),
        "implementationCodeHash": constants.implementation_code_hash,
        "entryPoint": constants.entry_point.to_lower(),
        "attestationAddress": constants.attestation_address.to_lower(),
        "legacySessionKey": constants.legacy_session_key.to_lower(),
        "ruleAllowlist": allowlist,
        "maxValiditySeconds": c::MAX_VALIDITY_SECONDS,
        "maxCalls": c::MAX_CALLS,
    });
    format!("0x{}", hex::encode(Sha256::digest(crate::pyjson::dumps(&document, true).as_bytes())))
}

/// The exact bytes a request signature covers.
pub fn signature_message(method: &str, path: &str, timestamp: &str, nonce: &str, body: &[u8]) -> Vec<u8> {
    format!("{}\n{path}\n{timestamp}\n{nonce}\n{}", method.to_uppercase(), hex::encode(Sha256::digest(body))).into_bytes()
}

fn hmac_hex(secret: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as i64).unwrap_or(0)
}

/// Headers of a signed request (clients: tests, the fork runner).
pub fn sign_request(secret_hex: &str, method: &str, path: &str, body: &[u8], now: Option<i64>) -> Vec<(String, String)> {
    let timestamp = now.unwrap_or_else(now_ms).to_string();
    let nonce = hex::encode(random_bytes::<16>());
    let secret = hex::decode(secret_hex).unwrap_or_default();
    let signature = hmac_hex(&secret, &signature_message(method, path, &timestamp, &nonce, body));
    vec![
        ("X-Helix-Timestamp".into(), timestamp),
        ("X-Helix-Nonce".into(), nonce),
        ("X-Helix-Signature".into(), signature),
    ]
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// A monotonic clock in seconds (injectable for tests).
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

fn monotonic() -> Clock {
    let start = Instant::now();
    Arc::new(move || start.elapsed().as_secs_f64())
}

/// The single-use code the terminal shows for pairing a browser.
pub struct PairingCode {
    /// ``XXXX-XXXX``.
    pub code: String,
    created: f64,
    /// Attempts so far.
    pub attempts: u32,
    used: bool,
    clock: Clock,
}

impl PairingCode {
    /// A fresh code.
    pub fn new(clock: Option<Clock>) -> PairingCode {
        let clock = clock.unwrap_or_else(monotonic);
        let alphabet: Vec<char> = CODE_ALPHABET.chars().collect();
        let mut raw = String::new();
        while raw.len() < 8 {
            let [byte] = random_bytes::<1>();
            // Rejection sampling keeps every character equally likely.
            if (byte as usize) < 256 - 256 % alphabet.len() {
                raw.push(alphabet[byte as usize % alphabet.len()]);
            }
        }
        let created = clock();
        PairingCode { code: format!("{}-{}", &raw[..4], &raw[4..]), created, attempts: 0, used: false, clock }
    }

    /// Whether the code can still be used.
    pub fn open(&self) -> bool {
        !self.used && self.attempts < PAIR_ATTEMPTS && (self.clock)() - self.created < PAIR_SECONDS as f64
    }

    /// Compare a typed code in constant time (dash and case ignored).
    pub fn check(&mut self, text: &str) -> bool {
        if !self.open() {
            return false;
        }
        self.attempts += 1;
        let typed: String = text.to_uppercase().chars().filter(|ch| ch.is_alphanumeric()).collect();
        if constant_time_eq(typed.as_bytes(), self.code.replace('-', "").as_bytes()) {
            self.used = true;
            return true;
        }
        false
    }
}

/// One paired browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pairing {
    /// Random ID (32 hex).
    pub id: String,
    /// The origin that paired.
    pub origin: String,
    /// 256-bit secret (64 hex).
    pub secret: String,
    /// Unix seconds.
    pub created: i64,
}

impl Pairing {
    fn to_json(&self) -> Value {
        json!({"id": self.id, "origin": self.origin, "secret": self.secret, "created": self.created})
    }
}

/// Paired browsers, persisted with mode 0600.
pub struct Pairings {
    path: Option<PathBuf>,
    items: Mutex<Vec<Pairing>>,
}

impl Pairings {
    /// Load existing pairings (an unreadable file starts empty).
    pub fn load(path: Option<PathBuf>) -> Pairings {
        let mut items = Vec::new();
        if let Some(file) = path.as_ref().filter(|file| file.is_file()) {
            let stored = std::fs::read_to_string(file).ok().and_then(|text| serde_json::from_str::<Value>(&text).ok());
            if let Some(Value::Array(entries)) = stored.as_ref().and_then(|stored| stored.get("pairings")) {
                for entry in entries.iter().filter_map(Value::as_object) {
                    let Some(id) = entry.get("id").and_then(Value::as_str) else { continue };
                    let text = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
                    let pairing = Pairing { id: id.to_string(), origin: text("origin"), secret: text("secret"), created: entry.get("created").and_then(Value::as_i64).unwrap_or(0) };
                    items.retain(|item: &Pairing| item.id != pairing.id);
                    items.push(pairing);
                }
            }
        }
        Pairings { path, items: Mutex::new(items) }
    }

    /// The file, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Create and save a pairing for an origin.
    pub fn add(&self, site: &str) -> Result<Pairing> {
        let created = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs() as i64).unwrap_or(0);
        let pairing = Pairing { id: uuid4().replace('-', ""), origin: site.to_string(), secret: hex::encode(random_bytes::<32>()), created };
        let mut items = self.items.lock().map_err(|_| Error::io("pairings unavailable"))?;
        items.push(pairing.clone());
        self.save(&items)?;
        Ok(pairing)
    }

    /// Find a pairing.
    pub fn get(&self, id: &str) -> Option<Pairing> {
        self.items.lock().ok()?.iter().find(|item| item.id == id).cloned()
    }

    fn save(&self, items: &[Pairing]) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| Error::io(error.to_string()))?;
        }
        let temporary = path.with_extension("tmp");
        let document = json!({"pairings": items.iter().map(Pairing::to_json).collect::<Vec<_>>()});
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|error| Error::io(error.to_string()))?;
        use std::io::Write;
        file.write_all(crate::pyjson::dumps(&document, false).as_bytes()).map_err(|error| Error::io(error.to_string()))?;
        drop(file);
        std::fs::rename(&temporary, path).map_err(|error| Error::io(error.to_string()))
    }
}

/// Loads the key (prompting in the terminal or the app).
pub type KeyLoader = Box<dyn Fn() -> Result<KeyMaterial> + Send + Sync>;

/// The unlocked key, wiped after an idle timeout or on exit.
pub struct KeyHolder {
    loader: KeyLoader,
    idle: Duration,
    clock: Clock,
    state: Mutex<(Option<KeyMaterial>, f64)>,
    unlocking: Mutex<()>,
}

impl KeyHolder {
    /// Remember how to unlock the key.
    pub fn new(loader: KeyLoader, idle: Duration, clock: Option<Clock>) -> KeyHolder {
        KeyHolder { loader, idle, clock: clock.unwrap_or_else(monotonic), state: Mutex::new((None, 0.0)), unlocking: Mutex::new(()) }
    }

    /// Whether a key is in memory now.
    pub fn loaded(&self) -> bool {
        self.expire_if_idle();
        self.state.lock().map(|state| state.0.is_some()).unwrap_or(false)
    }

    /// Address of the loaded key.
    pub fn address(&self) -> Option<crate::Address> {
        self.state.lock().ok()?.0.as_ref().map(KeyMaterial::address)
    }

    /// The key (a copy), unlocking it when needed; counts as use.
    pub fn unlock(&self) -> Result<KeyMaterial> {
        let _serial = self.unlocking.lock().map_err(|_| Error::key("The key holder is unavailable."))?;
        self.expire_if_idle();
        {
            let mut state = self.state.lock().map_err(|_| Error::key("The key holder is unavailable."))?;
            if let Some(material) = state.0.clone() {
                state.1 = (self.clock)();
                return Ok(material);
            }
        }
        let material = (self.loader)()?;
        let mut state = self.state.lock().map_err(|_| Error::key("The key holder is unavailable."))?;
        state.0 = Some(material.clone());
        state.1 = (self.clock)();
        Ok(material)
    }

    /// Wipe the key after the idle time without use; true when it was wiped.
    pub fn expire_if_idle(&self) -> bool {
        let Ok(mut state) = self.state.lock() else { return false };
        if state.0.is_some() && (self.clock)() - state.1 >= self.idle.as_secs_f64() {
            if let Some(mut material) = state.0.take() {
                material.wipe();
            }
            return true;
        }
        false
    }

    /// Zero and forget the key.
    pub fn wipe(&self) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(mut material) = state.0.take() {
                material.wipe();
            }
        }
    }
}

/// One sign or revoke request from a paired browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// ``grant`` or ``revoke``.
    pub kind: String,
    /// Plan token.
    pub token: String,
    /// Pairing that sent it.
    pub pairing_id: String,
    /// Random ID.
    pub id: String,
    /// queued, unlocking, awaiting-confirmation, broadcasting, done, failed, cancelled.
    pub state: String,
    /// Mined transaction.
    pub tx_hash: String,
    /// Outcome text.
    pub message: String,
}

impl Job {
    /// Status as JSON.
    pub fn public(&self) -> Value {
        json!({"jobId": self.id, "kind": self.kind, "state": self.state, "txHash": self.tx_hash, "message": self.message})
    }

    fn finished(&self) -> bool {
        matches!(self.state.as_str(), "done" | "failed" | "cancelled")
    }
}

/// How the companion runs.
#[derive(Clone)]
pub struct CompanionConfig {
    /// Website API base (validated).
    pub api: String,
    /// Anubis RPC.
    pub rpc_url: String,
    /// Pinned or development constants.
    pub constants: Constants,
    /// Extra loopback origins (``--allow-origin``).
    pub origins: Vec<String>,
    /// Sign revocations without asking.
    pub auto_confirm_revoke: bool,
    /// Port (0 picks a free one).
    pub port: u16,
    /// HTTP clients.
    pub transport: Transport,
}

/// Output of the companion (terminal lines).
pub type Output = Arc<dyn Fn(&str) + Send + Sync>;

/// Origin and pairing checks, the job queue and the local confirmations.
pub struct Companion {
    config: CompanionConfig,
    allowed: Vec<String>,
    keys: KeyHolder,
    pairings: Pairings,
    out: Output,
    confirmer: Arc<dyn Confirmer>,
    code: Mutex<PairingCode>,
    nonces: Mutex<HashMap<String, Instant>>,
    jobs: Mutex<HashMap<String, Job>>,
    queue: (Mutex<VecDeque<String>>, Condvar),
    port: AtomicU16,
    clock_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// An HTTP answer: status, JSON body (None: empty) and extra headers.
pub struct Answer {
    /// Status.
    pub status: u16,
    /// JSON body.
    pub body: Option<Value>,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// Allowed origin for the CORS headers.
    pub site: Option<String>,
}

fn answer(status: u16, body: Value, site: Option<&str>) -> Answer {
    Answer { status, body: Some(body), headers: Vec::new(), site: site.map(str::to_string) }
}

impl Companion {
    /// Configure the companion; ``origins`` must be loopback origins.
    pub fn new(config: CompanionConfig, keys: KeyHolder, pairings: Pairings, out: Output, confirmer: Arc<dyn Confirmer>) -> Result<Arc<Companion>> {
        for extra in &config.origins {
            if !is_loopback(extra) || origin(extra) != extra.trim_end_matches('/').to_lowercase() {
                return Err(Error::flow(format!(
                    "--allow-origin only accepts loopback origins such as https://localhost:3443, not {}.",
                    crate::pyfmt::str_repr(extra)
                )));
            }
        }
        let mut allowed = vec![SITE_ORIGIN.to_string()];
        for extra in &config.origins {
            let site = origin(extra);
            if !allowed.contains(&site) {
                allowed.push(site);
            }
        }
        allowed.sort();
        let port = config.port;
        Ok(Arc::new(Companion {
            config,
            allowed,
            keys,
            pairings,
            out,
            confirmer,
            code: Mutex::new(PairingCode::new(None)),
            nonces: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
            queue: (Mutex::new(VecDeque::new()), Condvar::new()),
            port: AtomicU16::new(port),
            clock_ms: Arc::new(now_ms),
        }))
    }

    /// The current pairing code.
    pub fn code(&self) -> String {
        self.code.lock().map(|code| code.code.clone()).unwrap_or_default()
    }

    /// Start a new pairing window and return its code.
    pub fn new_code(&self) -> String {
        let fresh = PairingCode::new(None);
        let text = fresh.code.clone();
        if let Ok(mut code) = self.code.lock() {
            *code = fresh;
        }
        text
    }

    /// The bound port.
    pub fn port(&self) -> u16 {
        self.port.load(Ordering::SeqCst)
    }

    /// The key holder.
    pub fn keys(&self) -> &KeyHolder {
        &self.keys
    }

    /// The pairings.
    pub fn pairings(&self) -> &Pairings {
        &self.pairings
    }

    /// Sorted allowed origins.
    pub fn allowed(&self) -> &[String] {
        &self.allowed
    }

    /// The request origin when it is allowed.
    pub fn allowed_origin(&self, value: Option<&str>) -> Option<String> {
        let normalized = value.filter(|value| !value.is_empty())?.trim_end_matches('/').to_lowercase();
        self.allowed.contains(&normalized).then_some(normalized)
    }

    /// Refuse DNS-rebinding hosts.
    pub fn allowed_host(&self, value: Option<&str>) -> bool {
        let host = value.unwrap_or_default().to_lowercase();
        let port = self.port();
        host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}")
    }

    /// Check a signed request; its pairing or None.
    pub fn verify(&self, site: &str, method: &str, path: &str, header: &dyn Fn(&str) -> Option<String>, body: &[u8]) -> Option<Pairing> {
        let pairing = self.pairings.get(&header("X-Helix-Pairing").unwrap_or_default())?;
        let timestamp = header("X-Helix-Timestamp").unwrap_or_default();
        let nonce = header("X-Helix-Nonce").unwrap_or_default();
        let signature = header("X-Helix-Signature").unwrap_or_default();
        if pairing.origin != site || timestamp.is_empty() || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let stamp: i128 = timestamp.parse().ok()?;
        if (((self.clock_ms)() as i128) - stamp).abs() > CLOCK_SKEW_MS as i128 || !(16..=128).contains(&nonce.chars().count()) {
            return None;
        }
        let secret = hex::decode(&pairing.secret).ok()?;
        let expected = hmac_hex(&secret, &signature_message(method, path, &timestamp, &nonce, body));
        if !constant_time_eq(expected.as_bytes(), signature.to_lowercase().as_bytes()) {
            return None;
        }
        let mut nonces = self.nonces.lock().ok()?;
        let now = Instant::now();
        nonces.retain(|_, seen| now.duration_since(*seen).as_secs() <= NONCE_SECONDS);
        if nonces.contains_key(&nonce) {
            return None;
        }
        nonces.insert(nonce, now);
        Some(pairing)
    }

    /// ``GET /health``.
    pub fn health(&self, paired: bool) -> Value {
        let loaded = self.keys.loaded();
        let pairing_open = self.code.lock().map(|code| code.open()).unwrap_or(false);
        json!({
            "name": "awake-helix-signer",
            "version": crate::VERSION,
            "constantsHash": constants_hash(&self.config.constants),
            "chainId": self.config.constants.chain_id,
            "keyLoaded": loaded,
            "owner": if loaded { self.keys.address().map(|address| Value::String(address.to_checksum())).unwrap_or(Value::Null) } else { Value::Null },
            "paired": paired,
            "pairingOpen": pairing_open,
            "autoConfirmRevoke": self.config.auto_confirm_revoke,
        })
    }

    /// ``POST /pair``.
    pub fn pair(&self, site: &str, body: &Map<String, Value>) -> (u16, Value) {
        let Ok(mut code) = self.code.lock() else { return (500, json!({"error": "Pairing is unavailable."})) };
        if !code.open() {
            return (410, json!({"error": "Pairing is closed. Restart `awake-helix-signer serve` for a new code."}));
        }
        let typed = body.get("code").map(crate::pyfmt::py_str).unwrap_or_default();
        if !code.check(&typed) {
            let left = PAIR_ATTEMPTS.saturating_sub(code.attempts);
            return (if left > 0 { 403 } else { 410 }, json!({"error": "Wrong pairing code.", "attemptsLeft": left}));
        }
        drop(code);
        match self.pairings.add(site) {
            Ok(item) => {
                (self.out)(&format!("Paired with {site}. This browser can now send plans; every authorization is still confirmed here."));
                (200, json!({"pairingId": item.id, "secret": item.secret}))
            }
            Err(error) => (500, json!({"error": error.message()})),
        }
    }

    /// ``POST /sign`` and ``POST /revoke``: queue a job.
    pub fn submit(&self, kind: &str, token: Option<&Value>, pairing: &Pairing) -> (u16, Value) {
        let Some(Value::String(token)) = token else { return (400, json!({"error": "Missing plan token."})) };
        let Ok(mut jobs) = self.jobs.lock() else { return (500, json!({"error": "Jobs are unavailable."})) };
        if jobs.values().filter(|job| !job.finished()).count() >= MAX_JOBS {
            return (429, json!({"error": "Too many pending requests."}));
        }
        let job = Job {
            kind: kind.to_string(),
            token: token.clone(),
            pairing_id: pairing.id.clone(),
            id: uuid4().replace('-', ""),
            state: "queued".into(),
            tx_hash: String::new(),
            message: String::new(),
        };
        let public = job.public();
        jobs.insert(job.id.clone(), job.clone());
        drop(jobs);
        let (queue, ready) = &self.queue;
        if let Ok(mut queue) = queue.lock() {
            queue.push_back(job.id);
            ready.notify_one();
        }
        (202, public)
    }

    /// ``GET /jobs/<id>`` (only the pairing's own jobs).
    pub fn job(&self, job_id: &str, pairing: &Pairing) -> (u16, Value) {
        let jobs = self.jobs.lock();
        match jobs.ok().and_then(|jobs| jobs.get(job_id).cloned()) {
            Some(job) if job.pairing_id == pairing.id => (200, job.public()),
            _ => (404, json!({"error": "Unknown job."})),
        }
    }

    fn update(&self, id: &str, state: &str, message: Option<&str>, tx_hash: Option<&str>) {
        if let Ok(mut jobs) = self.jobs.lock() {
            if let Some(job) = jobs.get_mut(id) {
                job.state = state.to_string();
                if let Some(message) = message {
                    job.message = message.to_string();
                }
                if let Some(tx_hash) = tx_hash {
                    job.tx_hash = tx_hash.to_string();
                }
            }
        }
    }

    /// The state of one job (tests and the app).
    pub fn job_state(&self, id: &str) -> Option<Job> {
        self.jobs.lock().ok()?.get(id).cloned()
    }

    /// Verify, confirm, sign, broadcast and report one job.
    pub fn run_job(&self, id: &str) {
        let Some(job) = self.job_state(id) else { return };
        let log = |line: &str| (self.out)(line);
        let progress = |line: &crate::message::Message| (self.out)(&line.text);
        let outcome = (|| -> Result<Option<flow::Outcome>> {
            if !self.keys.loaded() {
                self.update(id, "unlocking", None, None);
                log("A website request needs the key: unlock it below.");
            }
            let material = self.keys.unlock()?;
            self.update(id, "queued", None, None);
            log(&format!("\nRequest from the website: {}", if job.kind == "grant" { "AUTHORIZE a hosted bot" } else { "REVOKE a grant" }));
            let config = &self.config;
            let session = if job.kind == "grant" {
                flow::prepare_sign(&job.token, &config.api, &config.rpc_url, &config.constants, Some(&material), &config.transport, &progress)?
            } else {
                flow::prepare_revoke(
                    &config.rpc_url,
                    &config.constants,
                    RevokeSource::Plan { token: job.token.clone(), api: config.api.clone() },
                    Some(&material),
                    &config.transport,
                    &progress,
                )?
            };
            log(&"=".repeat(72));
            log(&session.summary_text());
            log(&"=".repeat(72));
            if job.kind == "revoke" && config.auto_confirm_revoke {
                log("Auto-confirmed (--auto-confirm-revoke): a revocation only removes permissions.");
            } else {
                self.update(id, "awaiting-confirmation", None, None);
                if !self.confirmer.confirm(&session, session.confirm_word())? {
                    return Ok(None);
                }
            }
            self.update(id, "broadcasting", None, None);
            let outcome = if job.kind == "grant" {
                flow::execute_sign(&session, material, &progress)?
            } else {
                flow::execute_revoke(&session, material, &progress)?
            };
            let _ = self.keys.unlock();
            Ok(Some(outcome))
        })();
        match outcome {
            Ok(Some(outcome)) => {
                let message = if outcome.reported { "Reported to the website." } else { "The dashboard detects it on chain." };
                self.update(id, "done", Some(message), Some(&outcome.tx_hash));
                log(&format!("Done: transaction {} (type {}, block {}).", outcome.tx_hash, outcome.tx_type, outcome.block));
            }
            Ok(None) => {
                let message = "Cancelled in the terminal; nothing was signed.";
                self.update(id, "cancelled", Some(message), None);
                log(message);
            }
            Err(error) if error.kind() == ErrorKind::Cancelled => {
                self.update(id, "cancelled", Some("Terminal input closed."), None);
            }
            Err(error) if matches!(error.kind(), ErrorKind::Flow | ErrorKind::Key | ErrorKind::Plan | ErrorKind::CustomizeRefused) => {
                self.update(id, "failed", Some(error.message()), None);
                log(&format!("Refused: {error}"));
            }
            Err(error) => {
                let message = format!("{:?}Error: {error}", error.kind());
                self.update(id, "failed", Some(&message), None);
                log(&format!("Error: {message}"));
            }
        }
    }

    /// Process jobs one at a time and expire the key when idle, until ``stop``.
    pub fn work(&self, stop: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            let next = {
                let (queue, ready) = &self.queue;
                let Ok(mut queue) = queue.lock() else { return };
                if queue.is_empty() {
                    queue = match ready.wait_timeout(queue, Duration::from_secs(1)) {
                        Ok((queue, _)) => queue,
                        Err(_) => return,
                    };
                }
                queue.pop_front()
            };
            match next {
                Some(id) => self.run_job(&id),
                None => {
                    if self.keys.expire_if_idle() {
                        (self.out)("Key wiped after the idle timeout; the next request asks for it again.");
                    }
                }
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn gate(&self, header: &dyn Fn(&str) -> Option<String>) -> std::result::Result<String, Answer> {
        if !self.allowed_host(header("Host").as_deref()) {
            return Err(answer(403, json!({"error": "Wrong Host."}), None));
        }
        self.allowed_origin(header("Origin").as_deref())
            .ok_or_else(|| answer(403, json!({"error": "This website may not use the Awake Helix Signer."}), None))
    }

    /// Answer one HTTP request (``Handler``): method, request target, headers, body.
    pub fn handle(&self, method: &str, target: &str, header: &dyn Fn(&str) -> Option<String>, body: Option<&[u8]>) -> Answer {
        let site = match self.gate(header) {
            Ok(site) => site,
            Err(refused) => return refused,
        };
        let path = urlsplit(target).map(|parts| parts.path).unwrap_or_else(|_| target.to_string());
        match method {
            "OPTIONS" => {
                let mut headers = vec![
                    ("Access-Control-Allow-Methods".to_string(), "GET, POST, OPTIONS".to_string()),
                    ("Access-Control-Allow-Headers".to_string(), ALLOW_HEADERS.to_string()),
                    ("Access-Control-Max-Age".to_string(), "600".to_string()),
                ];
                if header("Access-Control-Request-Private-Network").map(|value| value.to_lowercase() == "true").unwrap_or(false) {
                    headers.push(("Access-Control-Allow-Private-Network".into(), "true".into()));
                }
                Answer { status: 204, body: None, headers, site: Some(site) }
            }
            "GET" => {
                let pairing = self.verify(&site, "GET", &path, header, b"");
                if path == "/health" {
                    answer(200, self.health(pairing.is_some()), Some(&site))
                } else if let Some(id) = path.strip_prefix("/jobs/") {
                    match pairing {
                        None => answer(401, json!({"error": "Not paired or bad signature."}), Some(&site)),
                        Some(pairing) => {
                            let (status, body) = self.job(id, &pairing);
                            answer(status, body, Some(&site))
                        }
                    }
                } else {
                    answer(404, json!({"error": "Not found."}), Some(&site))
                }
            }
            "POST" => {
                let Some(raw) = body else { return answer(413, json!({"error": "Body too large."}), Some(&site)) };
                let parsed: Option<Map<String, Value>> = match serde_json::from_slice::<Value>(if raw.is_empty() { b"{}" } else { raw }) {
                    Ok(Value::Object(map)) => Some(map),
                    _ => None,
                };
                let Some(parsed) = parsed else { return answer(400, json!({"error": "Send a JSON object."}), Some(&site)) };
                if path == "/pair" {
                    let (status, body) = self.pair(&site, &parsed);
                    return answer(status, body, Some(&site));
                }
                if path != "/sign" && path != "/revoke" {
                    return answer(404, json!({"error": "Not found."}), Some(&site));
                }
                let Some(pairing) = self.verify(&site, "POST", &path, header, raw) else {
                    return answer(401, json!({"error": "Not paired or bad signature."}), Some(&site));
                };
                let (status, body) = if path == "/sign" {
                    self.submit("grant", parsed.get("planToken"), &pairing)
                } else {
                    self.submit("revoke", parsed.get("revokeToken"), &pairing)
                };
                answer(status, body, Some(&site))
            }
            _ => Answer { status: 501, body: Some(json!({"error": "Unsupported method."})), headers: Vec::new(), site: Some(site) },
        }
    }

    /// Bind 127.0.0.1 only (port 0 picks a free one).
    pub fn bind(self: &Arc<Self>) -> Result<Server> {
        let address = format!("127.0.0.1:{}", self.port());
        let server = tiny_http::Server::http(&address).map_err(|error| Error::io(format!("Cannot listen on {address}: {error}")))?;
        if let Some(bound) = server.server_addr().to_ip() {
            self.port.store(bound.port(), Ordering::SeqCst);
        }
        Ok(Server { server: Arc::new(server), companion: self.clone() })
    }
}

/// The bound HTTP server.
pub struct Server {
    server: Arc<tiny_http::Server>,
    companion: Arc<Companion>,
}

fn respond(request: tiny_http::Request, reply: Answer) {
    let body = reply.body.as_ref().map(|value| crate::pyjson::dumps(value, false).into_bytes()).unwrap_or_default();
    let mut response = tiny_http::Response::from_data(body).with_status_code(reply.status);
    let mut add = |name: &str, value: &str| {
        if let Ok(header) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response.add_header(header);
        }
    };
    if let Some(site) = &reply.site {
        add("Access-Control-Allow-Origin", site);
        add("Vary", "Origin, Access-Control-Request-Private-Network");
    }
    for (name, value) in &reply.headers {
        add(name, value);
    }
    add("Cache-Control", "no-store");
    if reply.body.is_some() {
        add("Content-Type", "application/json");
    }
    let _ = request.respond(response);
}

fn serve_one(companion: &Companion, mut request: tiny_http::Request) {
    let headers: Vec<(String, String)> =
        request.headers().iter().map(|header| (header.field.as_str().to_string(), header.value.as_str().to_string())).collect();
    let header = |name: &str| headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.clone());
    let method = request.method().as_str().to_uppercase();
    let target = request.url().to_string();
    let mut body: Option<Vec<u8>> = None;
    if method == "POST" {
        let length = match header("Content-Length") {
            None => Some(0),
            Some(value) if value.trim().is_empty() => Some(0),
            Some(value) => value.trim().parse::<usize>().ok(),
        };
        body = match length {
            Some(length) if length <= MAX_BODY => {
                let mut raw = Vec::with_capacity(length);
                let _ = request.as_reader().take(length as u64).read_to_end(&mut raw);
                Some(raw)
            }
            _ => None,
        };
    }
    let reply = companion.handle(&method, &target, &header, body.as_deref());
    respond(request, reply);
}

impl Server {
    /// The bound port.
    pub fn port(&self) -> u16 {
        self.companion.port()
    }

    /// Serve requests (one thread each) until ``stop`` is set.
    pub fn run(&self, stop: &AtomicBool) {
        while !stop.load(Ordering::SeqCst) {
            match self.server.recv_timeout(Duration::from_millis(500)) {
                Ok(Some(request)) => {
                    let companion = self.companion.clone();
                    std::thread::spawn(move || serve_one(&companion, request));
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    }
}

/// Run until ``stop`` is set; the key is wiped on exit. Prints like Python.
pub fn serve(companion: Arc<Companion>, stop: Arc<AtomicBool>) -> Result<()> {
    let server = companion.bind()?;
    let worker = {
        let companion = companion.clone();
        let stop = stop.clone();
        std::thread::spawn(move || companion.work(&stop))
    };
    let out = companion.out.clone();
    out(&format!("Listening on http://127.0.0.1:{} for {}.", server.port(), companion.allowed().join(", ")));
    out(&format!("Pairing code for the website: {} (single use, 10 minutes).", companion.code()));
    out("Keep this window open. Press Ctrl-C to stop; the key is wiped on exit.");
    server.run(&stop);
    out("\nStopping.");
    companion.keys.wipe();
    let _ = worker;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_expires_and_counts_attempts() {
        let now = Arc::new(Mutex::new(0.0f64));
        let clock_now = now.clone();
        let clock: Clock = Arc::new(move || *clock_now.lock().unwrap());
        let mut code = PairingCode::new(Some(clock.clone()));
        assert!(code.open());
        let text = code.code.clone();
        *now.lock().unwrap() = PAIR_SECONDS as f64 + 1.0;
        assert!(!code.check(&text));
        let mut fresh = PairingCode::new(Some(clock));
        for _ in 0..5 {
            assert!(!fresh.check("WRONG-CODE"));
        }
        assert!(!fresh.open());
        assert!(!fresh.check(&fresh.code.clone()));
        let mut lower = PairingCode::new(None);
        let typed = lower.code.to_lowercase().replace('-', " ");
        assert!(lower.check(&typed));
        assert!(!lower.open());
    }

    #[test]
    fn idle_timeout_wipes_key() {
        let now = Arc::new(Mutex::new(0.0f64));
        let clock_now = now.clone();
        let clock: Clock = Arc::new(move || *clock_now.lock().unwrap());
        let loads = Arc::new(Mutex::new(0));
        let counter = loads.clone();
        let holder = KeyHolder::new(
            Box::new(move || {
                *counter.lock().unwrap() += 1;
                KeyMaterial::from_private_key(&"11".repeat(32))
            }),
            Duration::from_secs(900),
            Some(clock),
        );
        let first = holder.unlock().unwrap();
        *now.lock().unwrap() = 899.0;
        assert_eq!(holder.unlock().unwrap().address(), first.address());
        assert_eq!(*loads.lock().unwrap(), 1);
        *now.lock().unwrap() = 899.0 + 900.0;
        assert!(holder.expire_if_idle());
        assert!(!holder.loaded());
        holder.unlock().unwrap();
        assert_eq!(*loads.lock().unwrap(), 2);
        holder.wipe();
        assert!(holder.address().is_none());
    }
}
