//! The companion (`serve`) over real loopback HTTP, with the in-memory chain
//! and website behind it: Host and Origin checks, preflight, pairing, HMAC,
//! confirmations and job states.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use helix_signer_core::companion::{self, Companion, CompanionConfig, KeyHolder, Pairings};
use helix_signer_core::{Confirmer, KeyMaterial, Result, Session, U256};
use serde_json::{json, Value};

struct Answers(Mutex<Vec<bool>>, Mutex<Vec<String>>);

impl Confirmer for Answers {
    fn confirm(&self, _: &Session, word: &str) -> Result<bool> {
        self.1.lock().unwrap().push(word.to_string());
        Ok(self.0.lock().unwrap().pop().unwrap_or(false))
    }
}

struct Running {
    port: u16,
    companion: Arc<Companion>,
    stop: Arc<AtomicBool>,
    answers: Arc<Answers>,
    fake: Fake,
    owner: helix_signer_core::Address,
    agent: ureq::Agent,
    folder: std::path::PathBuf,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

const SITE: &str = "https://anubis.sivilization.com";
const DEV: &str = "https://localhost:3443";

fn start(auto_confirm_revoke: bool, answers: Vec<bool>) -> Running {
    let fake = Fake::new();
    let key = key(&format!("companion owner {}", std::process::id()));
    let owner = key.address();
    fake.state.lock().unwrap().balances.insert(owner, U256::from(10u64).pow(U256::from(18)));
    let loader_key = key.clone();
    let holder = KeyHolder::new(Box::new(move || Ok(loader_key.clone())), Duration::from_secs(900), None);
    let folder = std::env::temp_dir().join(format!("helix-companion-{}-{}", std::process::id(), auto_confirm_revoke));
    let pairings = Pairings::load(Some(folder.join("pairings.json")));
    let config = CompanionConfig { api: API.into(), rpc_url: RPC.into(), constants: constants(), origins: vec![DEV.into()], auto_confirm_revoke, port: 0, transport: fake.transport() };
    let answers = Arc::new(Answers(Mutex::new(answers), Mutex::new(Vec::new())));
    let companion = Companion::new(config, holder, pairings, Arc::new(|_| {}), answers.clone()).unwrap();
    let server = companion.bind().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let port = server.port();
    {
        let stop = stop.clone();
        std::thread::spawn(move || server.run(&stop));
    }
    {
        let stop = stop.clone();
        let companion = companion.clone();
        std::thread::spawn(move || companion.work(&stop));
    }
    Running { port, companion, stop, answers, fake, owner, agent: ureq::AgentBuilder::new().build(), folder }
}

impl Running {
    fn call(&self, method: &str, path: &str, body: Option<Value>, origin: Option<&str>, host: Option<&str>, pairing: Option<&Value>) -> (u16, Vec<(String, String)>, Value) {
        let raw = body.map(|body| body.to_string()).unwrap_or_default();
        let mut request = self.agent.request(method, &format!("http://127.0.0.1:{}{path}", self.port)).set("Host", &host.map(str::to_string).unwrap_or(format!("127.0.0.1:{}", self.port)));
        if let Some(origin) = origin {
            request = request.set("Origin", origin);
        }
        if let Some(pairing) = pairing {
            request = request.set("X-Helix-Pairing", pairing["pairingId"].as_str().unwrap());
            for (name, value) in companion::sign_request(pairing["secret"].as_str().unwrap(), method, path, raw.as_bytes(), None) {
                request = request.set(&name, &value);
            }
        }
        let response = match if raw.is_empty() { request.call() } else { request.set("Content-Type", "application/json").send_string(&raw) } {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(error) => panic!("{error}"),
        };
        let status = response.status();
        let headers = response.headers_names().into_iter().map(|name| (name.clone(), response.header(&name).unwrap_or_default().to_string())).collect();
        let text = response.into_string().unwrap();
        (status, headers, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    fn pair(&self) -> Value {
        let (status, _, body) = self.call("POST", "/pair", Some(json!({"code": self.companion.code().to_lowercase()})), Some(SITE), None, None);
        assert_eq!(status, 200, "{body}");
        body
    }

    fn wait(&self, job: &str, pairing: &Value) -> Value {
        for _ in 0..400 {
            let (_, _, body) = self.call("GET", &format!("/jobs/{job}"), None, Some(SITE), None, Some(pairing));
            if ["done", "failed", "cancelled"].contains(&body["state"].as_str().unwrap_or_default()) {
                return body;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("job stuck");
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
}

#[test]
fn host_origin_preflight_pairing_and_hmac() {
    let running = start(false, vec![]);
    let (status, headers, body) = running.call("GET", "/health", None, Some(SITE), None, None);
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "Access-Control-Allow-Origin"), Some(SITE));
    assert_eq!((body["paired"].clone(), body["chainId"].clone(), body["keyLoaded"].clone()), (json!(false), json!(6714), json!(false)));
    assert_eq!(body["constantsHash"], json!(companion::constants_hash(&constants())));
    for origin in [Some("https://evil.example"), Some("https://anubis.sivilization.com.evil.example"), Some("null"), None] {
        let (status, headers, _) = running.call("GET", "/health", None, origin, None, None);
        assert_eq!(status, 403, "{origin:?}");
        assert!(header(&headers, "Access-Control-Allow-Origin").is_none());
    }
    assert_eq!(running.call("GET", "/health", None, Some(DEV), None, None).0, 200);
    assert_eq!(running.call("GET", "/health", None, Some(SITE), Some("attacker.example:17702"), None).0, 403);
    let (status, headers, _) = running.call("OPTIONS", "/sign", None, Some(SITE), None, None);
    assert_eq!(status, 204);
    assert!(header(&headers, "Access-Control-Allow-Headers").unwrap().contains("X-Helix-Signature"));
    for left in [4, 3, 2, 1] {
        let (status, _, body) = running.call("POST", "/pair", Some(json!({"code": "WRONG-CODE"})), Some(SITE), None, None);
        assert_eq!((status, body["attemptsLeft"].clone()), (403, json!(left)));
    }
    assert_eq!(running.call("POST", "/pair", Some(json!({"code": "WRONG-CODE"})), Some(SITE), None, None).0, 410);
    running.companion.new_code();
    let pairing = running.pair();
    assert_eq!(pairing["secret"].as_str().unwrap().len(), 64);
    assert_eq!(running.call("POST", "/pair", Some(json!({"code": running.companion.code()})), Some(SITE), None, None).0, 410);
    let (_, _, health) = running.call("GET", "/health", None, Some(SITE), None, Some(&pairing));
    assert_eq!(health["paired"], json!(true));
    let reloaded = Pairings::load(Some(running.folder.join("pairings.json")));
    assert_eq!(reloaded.get(pairing["pairingId"].as_str().unwrap()).unwrap().origin, SITE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(running.folder.join("pairings.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let body = json!({"revokeToken": TOKEN});
    assert_eq!(running.call("POST", "/revoke", Some(body.clone()), Some(SITE), None, None).0, 401);
    let wrong = json!({"pairingId": pairing["pairingId"], "secret": "11".repeat(32)});
    assert_eq!(running.call("POST", "/revoke", Some(body.clone()), Some(SITE), None, Some(&wrong)).0, 401);
    assert_eq!(running.call("POST", "/revoke", Some(body.clone()), Some(DEV), None, Some(&pairing)).0, 401);
    let (status, _, job) = running.call("POST", "/revoke", Some(body), Some(SITE), None, Some(&pairing));
    assert_eq!(status, 202);
    assert_eq!(running.call("GET", &format!("/jobs/{}", job["jobId"].as_str().unwrap()), None, Some(SITE), None, None).0, 401);
}

#[test]
fn authorize_needs_the_confirmation_and_revoke_may_be_automatic() {
    let running = start(true, vec![true, false]);
    let pairing = running.pair();
    running.fake.state.lock().unwrap().plans.insert(TOKEN.into(), grant_plan(&running.owner, dai_power(), 7 * 86400, 256));
    let (_, _, job) = running.call("POST", "/sign", Some(json!({"planToken": TOKEN})), Some(SITE), None, Some(&pairing));
    assert_eq!(running.wait(job["jobId"].as_str().unwrap(), &pairing)["state"], json!("cancelled"));
    assert!(running.fake.state.lock().unwrap().sent.is_empty());
    let token = "tok_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    running.fake.state.lock().unwrap().plans.insert(token.into(), grant_plan(&running.owner, dai_power(), 7 * 86400, 256));
    let (_, _, job) = running.call("POST", "/sign", Some(json!({"planToken": token})), Some(SITE), None, Some(&pairing));
    let done = running.wait(job["jobId"].as_str().unwrap(), &pairing);
    assert_eq!(done["state"], json!("done"), "{done}");
    assert_eq!(done["message"], json!("Reported to the website."));
    assert_eq!(*running.answers.1.lock().unwrap(), vec!["AUTHORIZE".to_string(), "AUTHORIZE".to_string()]);
    let grant = running.fake.state.lock().unwrap().plans[token]["grantId"].as_str().unwrap().to_string();
    let revoke = "tok_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";
    running.fake.state.lock().unwrap().plans.insert(revoke.into(), revoke_plan(&running.owner, &grant, helix_signer_core::GrantKind::Policy));
    let (_, _, job) = running.call("POST", "/revoke", Some(json!({"revokeToken": revoke})), Some(SITE), None, Some(&pairing));
    assert_eq!(running.wait(job["jobId"].as_str().unwrap(), &pairing)["state"], json!("done"));
    assert_eq!(running.answers.1.lock().unwrap().len(), 2, "the revocation was not asked");
    // A failed verification is reported to the website.
    let bad = "tok_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let mut plan = grant_plan(&running.owner, dai_power(), 7 * 86400, 256);
    plan["implementation"] = json!(format!("0x{}", "66".repeat(20)));
    running.fake.state.lock().unwrap().plans.insert(bad.into(), plan);
    let (_, _, job) = running.call("POST", "/sign", Some(json!({"planToken": bad})), Some(SITE), None, Some(&pairing));
    let failed = running.wait(job["jobId"].as_str().unwrap(), &pairing);
    assert_eq!(failed["state"], json!("failed"));
    assert!(failed["message"].as_str().unwrap().contains("Wrong delegate"));
}

#[test]
fn dev_origins_must_be_loopback() {
    for bad in ["https://evil.example", "http://192.168.1.2:3000"] {
        let holder = KeyHolder::new(Box::new(|| KeyMaterial::from_private_key(&"11".repeat(32))), Duration::from_secs(900), None);
        let config = CompanionConfig { api: API.into(), rpc_url: RPC.into(), constants: constants(), origins: vec![bad.into()], auto_confirm_revoke: false, port: 0, transport: Fake::new().transport() };
        let answers = Arc::new(Answers(Mutex::new(vec![]), Mutex::new(vec![])));
        assert!(Companion::new(config, holder, Pairings::load(None), Arc::new(|_| {}), answers).is_err());
    }
}
